import os, sys, json, time, logging
from google.cloud import storage, exceptions
from google.oauth2 import service_account
import googleapiclient.discovery
from googleapiclient.errors import HttpError

class GCPFactory:

    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s', level=logging.INFO)
    logger = logging.getLogger('GCPFactory')

    service_account_info = None

    project_id = None

    credentials = None


    def __init__(self):
        log_level = os.environ.get('DDF_LOG_LEVEL')
        if (log_level is not None):
            if (log_level == 'DEBUG'):
                self.logger.setLevel(logging.DEBUG)
            if (log_level == 'WARNING'):
                self.logger.setLevel(logging.WARNING)
            if (log_level == 'ERROR'):
                self.logger.setLevel(logging.ERROR)
            if (log_level == 'CRITICAL'):
                self.logger.setLevel(logging.CRITICAL)


    def __str__(self):
        return "GCP"


    def vendor(self):
        return "Google"


    def get_auth_config(self):
        if (self.service_account_info is None):
            filename = os.environ['GOOGLE_APPLICATION_CREDENTIALS']
            if (filename is not None):
                self.service_account_info = json.load(open(filename))
        return self.service_account_info


    def get_project_id(self, ddf):
        if (self.project_id is None):
            service_account_info = self.get_auth_config()
            self.project_id = service_account_info['project_id']
        return self.project_id


    def get_credentials(self):
        if (self.credentials is None):
            self.credentials = service_account.Credentials.from_service_account_info(self.get_auth_config())
        return self.credentials


    def get_iam_client(self):
        return googleapiclient.discovery.build('iam', 'v1', credentials=self.get_credentials(), cache_discovery=False)


    def get_storage_client(self):
        return storage.Client();


    def get_resman_client(self):
        return googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=self.get_credentials(), cache_discovery=False)


    def get_service_account_email(self, ddf, iam_role):
        return iam_role + '@' + self.get_project_id(ddf) + '.iam.gserviceaccount.com'


    def get_role_name(self, project_id, datalake_name, role_id):
        role_name = 'projects/' + project_id + '/roles/' + datalake_name + '_' + role_id.replace('-', '_')
        return role_name


    def build(self, ddf):
        datalakename = ddf['datalake']

        storage = dict()
        for name,path in ddf.get('storage').items():
            storage[name] = path.get('path')
        self.logger.info('Building ' + self.vendor() + ' Cloud artifacts for datalake named: ' + datalakename + '...')

        for name,role in ddf['datalake_roles'].items():
            instanceProfile = False
            if "instance_profile" in role:
                instanceProfile = role['instance_profile']

            iam_role = role['iam_role']
            permissions = role['permissions']
            i = 0
            self.logger.info('The datalake role: ' + name + ' is assigned the iam role: ' + iam_role)
            for perm in permissions:
                elements = perm.split(':')
                if elements[0] == 'storage':
                    perm_name = elements[1]
                    self.logger.debug('Processing storage permission name ' + perm_name)
                    filepath = 'templates/gcp/' + perm_name + '.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = storage
                        d['storage_location'] = storage[elements[2]]
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute({'datalake_name': datalakename})

                        filename = 'datalakes/' + datalakename + '/GCP/' + perm_name + '.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/GCP/' + perm_name + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        self.logger.info('    Granted permission ' + perm_name + ' for path: ' + d['storage_location'])
                    else:
                        self.logger.info('    Skipping permission \"' + elements[0] + ':' + perm_name + '\" : No template (check permissions in ddf file)')
            print()


    def push(self, ddf):
        if self.bucket_paths_are_unique(ddf) is True:
            print()
            self.create_iam_entities(ddf)
            self.create_custom_roles(ddf)
            self.create_bucket_paths(ddf)
        else:
            # TODO perhaps provide ability to get past this with something like:
            #      1. add number to end of existing names and recheck until unique
            #      2. ask user for a replacement bucket name
            self.logger.warning('Bucket already exists check your configured paths. Cannot push to cloud.')


    def recall(self, ddf):
        #if self.bucket_paths_are_unique(ddf) is False:
            print()
            self.delete_iam_entities(ddf)
            self.delete_bucket_paths(ddf)
            self.delete_custom_roles(ddf)
        #else:
            # TODO perhaps provide ability to get past this with something like:
            #      1. add number to end of existing names and recheck until unique
            #      2. ask user for a replacement bucket name
            #self.logger.info('Bucket does not exist check that this definition has been pushed.')


    '''
        Get the file contents associated with the specified datalake and policy.
    '''
    def load_role_policy(self, datalake_name, policy_name):
        persistence_dir = 'datalakes/' + datalake_name + '/GCP/'
        filepath = os.path.join(persistence_dir, policy_name + '.json')
        return self.load_role_policy_file(filepath)

    def load_role_policy_file(self, filepath):
        policy_dict = None
        if (os.path.isfile(filepath)):
            with open(filepath, 'r') as reader:
                policy = reader.read()
                policy_dict = json.loads(policy)
        return policy_dict


    '''
        Create the custom roles(policy) defined by the datalake definition.
    '''
    def create_custom_roles(self, ddf):
        persisted_roles = dict()

        project_id = self.get_project_id(ddf)
        iam = self.get_iam_client()

        # Load peristed roles
        persistence_dir = 'datalakes/' + ddf.get('datalake') + '/GCP/'
        self.logger.info('Loading role definitions from ' + persistence_dir + ' ...')
        # Iterate over persisted roles, loading them into a dict to satisfy references from IAM roles
        for f in os.listdir(persistence_dir):
            filepath = os.path.join(persistence_dir, f)
            if (os.path.isfile(filepath)):
                self.logger.info('  Found persisted policy definition ' + f)
                policy_dict = self.load_role_policy_file(filepath)

                existing_role = None
                try:
                    existing_role = iam.projects().roles().get(name=self.get_role_name(project_id, ddf.get('datalake'), f.split('.')[0])).execute()
                except HttpError as e:
                    self.logger.debug('  ' + json.loads(e.content).get('error').get('message'))
                    pass

                if (existing_role is not None):
                    existing_name = existing_role.get('name')
                    '''
                      N.B. Deleting a custom role is not something that is easily undone.
                           Therefore, recalled roles are actually disabled. If a previously-recalled role is encountered here,
                           re-enable it, and update the permissions in case they have changed from the previous creation/update.
                    '''
                    stage = existing_role.get('stage')
                    self.logger.info('  Custom role ' + existing_name + ' exists (stage=' + str(stage) + ')')
                    if (stage == 'DISABLED'):
                        try:
                            iam.projects().roles().patch(name=existing_name,
                                                         body={
                                                             "includedPermissions": policy_dict.get('includedPermissions'),
                                                             "stage": "GA"
                                                              }).execute()
                            self.logger.info('  Updated and re-enabled policy for ' + existing_name)
                        except HttpError as e:
                            parsedError = json.loads(e.content)
                            self.logger.error('  Failed to re-enable custom role : ' +  parsedError['error']['message'])
                    else:
                        self.logger.info('  ' + existing_name + ' exists, but is NOT in the deleted stage.')
                else:
                    try:
                        # Push the associated role descriptor on disk
                        created_role = self.get_iam_client().projects().roles().create(parent='projects/' + project_id,
                                                                                       body=policy_dict).execute()
                        self.logger.info('  Created custom role ' + created_role.get('name') + ' from ' + f)
                    except HttpError as e:
                        parsedError = json.loads(e.content)
                        self.logger.error('  Failed to create custom role from ' + f + ' : ' + parsedError.get('error').get('message'))
            print()


    '''
        Delete the custom roles defined by the datalake definition.
    '''
    def delete_custom_roles(self, ddf):
        permission_decls = ddf.get('permissions')
        for category in permission_decls.keys():
            self.logger.debug('Deleting permissions category ' + category)
            for role in permission_decls.get(category).keys():
                self.logger.debug('Deleting custom role ' + role)
                self.delete_custom_role(ddf, role)
        print()


    '''
        Delete the specified custom role.
    '''
    def delete_custom_role(self, ddf, role_id):
        role_name = self.get_role_name(self.get_project_id(ddf), ddf.get('datalake'), role_id)
        self.logger.info('Deleting custom role ' + role_name + ' for ' + role_id)
        iam = self.get_iam_client()
        if (iam.projects().roles().get(name=role_name) is not None):
            try:
                '''
                  N.B. Deleting a custom role is not something that is easily undone.
                       Therefore, rather than delete the role, the role is disabled, which is easily undone.
                '''
                #iam.projects().roles().delete(name=role_name).execute()
                iam.projects().roles().patch(name=role_name,
                                             body={
                                                 "stage": "DISABLED"
                                             }).execute()
                self.logger.info('  Disabled custom role ' + role_name)
            except HttpError as e:
                parsedError = json.loads(e.content)
                self.logger.warning('  Could not disable custom role for ' + role_id + ' : ' + parsedError['error']['message'])
            except Exception as e:
                self.logger.error('  Unable to disable custom role for ' + role_id + ' : ' + str(e))
        else:
            self.logger.info('Role does not exist: ' + role_name)
        print()


    '''
        Create the service accounts defined by the datalake definition roles.
    '''
    def create_iam_entities(self, ddf):
        iam = self.get_iam_client()

        # Identify any trusted roles
        # TODO: Should handle hierarchical trust (e.g., ROLE_3 trusts ROLE_2, which trusts ROLE_1 )? Could get complicated
        trusted_roles = []
        for name,role in ddf['datalake_roles'].items():
            trusted_role = role.get('trust')
            if (trusted_role is not None):
                trusted_roles.append(trusted_role)

        # Trusted role service account email map
        trusted_role_email = dict()
        trusted_role_permissions = dict()

        # Create the trusted roles
        for name,role in ddf['datalake_roles'].items():
            if (name in trusted_roles):
                self.logger.debug('Creating service account for trusted role ' + name)
                trusted_iam_role = role['iam_role']
                trusted_sa_email = None
                service_accounts = iam.projects().serviceAccounts().list(name='projects/' + self.get_project_id(ddf)).execute()
                for account in service_accounts['accounts']:
                    sa_email = account['email']
                    if (sa_email.startswith(trusted_iam_role)):
                        trusted_sa_email = sa_email

                if (trusted_sa_email is not None):
                    self.logger.info(name + ' service account already exists: ' + trusted_sa_email)
                else:
                    trusted_sa = self.create_service_account_for_role(ddf, name, trusted_iam_role , name + ' service account')
                    if (trusted_sa is not None):
                        self.logger.info('Created service account ' + trusted_sa['email'] + ' for trusted ' + name)
                    trusted_sa_email = trusted_sa['email']
                    trusted_role_email.update({name: trusted_sa_email})
                    
                    trusted_role_perm_decls = role.get('permissions')
                    for perm_decl in trusted_role_perm_decls:
                        decl_parts = perm_decl.split(":")
                        perm_category = self.translate_perm_category(decl_parts[0])
                        perm_role_name = self.translate_perm_name(decl_parts[1])
                        perm_role_list = trusted_role_permissions.get(perm_category)
                        if (perm_role_list is None):
                            perm_role_list = []
                        perm_role_list.append(perm_role_name)
                        trusted_role_permissions.update({perm_category: perm_role_list})
                    self.logger.debug('Declared ' + trusted_role + ' permissions : ' + json.dumps(trusted_role_permissions))
        print()

        # Create service accounts for the remaining roles, and apply any associated policy
        for name,role in ddf['datalake_roles'].items():
            iam_role_name = role['iam_role']
            if (name not in trusted_roles):
                instanceProfile = False
                sa = self.create_service_account_for_role(ddf, name, iam_role_name, iam_role_name)
                if (sa is not None):
                    self.logger.info('Created service account ' + sa['email'] + ' for ' + name)

                # If the service account trusts another service account, then bind the associated policy
                for trusted_role,trusted_sa in trusted_role_email.items():
                    if (role.get('trust') == trusted_role):
                        self.logger.debug(name + ' trusts ' + trusted_role)
                        self.bind_trusted_service_account_policy(ddf, trusted_sa, sa, trusted_role_permissions)
        print()


    '''
        Translate the DDF permission category into the GCP-specific equivalent
    '''
    def translate_perm_category(self, category):
        result = category
        if (category == 'sts'):
            result = 'iam'
        return result


    '''
        Translate the DDF permission name into the GCP-specific equivalent
    '''
    def translate_perm_name(self, name):
        result = name
        if (name == 'assume-roles'):
            result = 'serviceAccountTokenCreator'
        return result


    '''
        Create the specified service account.
    '''
    def create_service_account_for_role(self, ddf, role, sa_name, sa_display_name):
        sa = None
        try:
            iam = self.get_iam_client()
            sa = iam.projects().serviceAccounts().create(name='projects/' + self.get_project_id(ddf),
                            body={
                                'accountId': sa_name,
                                'serviceAccount': {
                                    'displayName': sa_display_name
                                 }
                            }).execute()
            self.logger.debug('Created service account: ' + sa['email'] + ' for ' + role)
        except HttpError as e:
            parsedError = json.loads(e.content)
            self.logger.error("Failed to create service account " + sa_name + ' for role ' + role + ' : ' + parsedError['error']['message'])
        return sa


    '''
        Define the service account policy corresponding to the associated trust relationship defined by the datalake definition.
        In this scenario, the trusting service account is treated as a resource to which the trusted service account's
        permissions(role(s)) are bound.
    '''
    def bind_trusted_service_account_policy(self, ddf, trusted_sa_email, service_account, trusted_role_permissions):
        iam = self.get_iam_client()

        sa_resource = 'projects/' + self.get_project_id(ddf) + '/serviceAccounts/' + service_account['email']

        # Query the current service account policy
        policy = iam.projects().serviceAccounts().getIamPolicy(resource=sa_resource).execute()

        bindings = policy.get('bindings')
        if (bindings is None):
            bindings = []
            policy.update({"bindings": bindings})

        # Create binding(s) for the  trusted servivce account based on the policy declarations
        for category in trusted_role_permissions.keys():
            for role in trusted_role_permissions.get(category):
                self.logger.debug('Preparing policy binding for roles/' + category + "." + role)
                bindings.append({"role": "roles/" + category + "." + role, "members": "serviceAccount:" + trusted_sa_email})
        self.logger.debug('Updated policy: ' + json.dumps(policy))

        # Push the updated service account policy
        iam.projects().serviceAccounts().setIamPolicy(resource=sa_resource,
                                                      body={"policy": policy, "updateMask": "bindings"}).execute()


    '''
        Delete the service accounts defined by the datalake definition roles.
    '''
    def delete_iam_entities(self, ddf):
        iam = self.get_iam_client()
        for name,role in ddf['datalake_roles'].items():
            sa_email = self.get_service_account_email(ddf, role['iam_role'])
            try:
                iam.projects().serviceAccounts().delete(name='projects/-/serviceAccounts/' + sa_email).execute()
                self.logger.info('Deleted service account: ' + sa_email + ' for ' + name)
            except HttpError as e:
                parsedError = json.loads(e.content)
                if (parsedError['error']['code'] == 404):
                    self.logger.error('Could not delete service account ' + sa_email + ' for ' + name + ' : Service account does not exist.')
                else:
                    self.logger.error('Could not delete service account ' + sa_email + ' for ' + name + ' : ' + str(e.content))
            except Exception as e:
                self.logger.error('Could not delete service account ' + sa_email  + ' for ' + name + ' : ' + str(e))
        print()


    '''
        Check whether the bucket paths defined in the datalake defintion are unique.
    '''
    def bucket_paths_are_unique(self, ddf):
        # Check storage locations for existing buckets which will prevent push
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
                bucket_name = dirs[0]
                if (self.bucket_exists(bucket_name) is True):
                    # TODO allow user to indicate that the existing bucket
                    # is intended and then skip trying to create it.
                    return False
        return True


    '''
        Create the bucket(s) and paths defined in the datalake defintion.
    '''
    def create_bucket_paths(self, ddf):
        # Create buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path = storage['path']
            self.logger.debug('Creating bucket path: ' + bucket_path)
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
                if (self.bucket_exists(dirs[0]) is False):
                    self.create_bucket(dirs[0])
                    self.bind_bucket_policy(ddf, dirs[0], None)
                if len(dirs) > 1:
                    path = bucket_path[len(dirs[0]) + 2:]
                    self.create_bucket_path(dirs[0], path)
                    self.bind_bucket_policy(ddf, dirs[0], path)


    '''
        Create the specified bucket path.
    '''
    def create_bucket_path(self, bucket_name, path):
        # This is a folder creation inside the bucket
        self.logger.debug('Creating path ' + path + ' within bucket ' + bucket_name)
        gcs_client = self.get_storage_client()
        bucket = gcs_client.get_bucket(bucket_name)
        blob = bucket.blob(path + '/')
        blob.upload_from_string('')            
        self.logger.info('Created path \"' + path + '\" within bucket \"' + bucket_name + '\"')


    '''
        Create the specified bucket.
    '''
    def create_bucket(self, bucket_name):
        # Create a new bucket in specific location with storage class
        storage_client = self.get_storage_client()

        bucket = storage_client.bucket(bucket_name)
        # TODO determine appropriate class for datalake defs
        bucket.storage_class = "COLDLINE"

        # Enable uniform bucket level access to allow for policy binding conditions
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True

        new_bucket = storage_client.create_bucket(bucket, location="us")
        self.logger.info(
            "Created bucket {} in {} with storage class {} and iam configuration {}".format(
                new_bucket.name, new_bucket.location, new_bucket.storage_class, new_bucket.iam_configuration
            )
        )
        return new_bucket


    '''
        Check whether the specified bucket exists.
    '''
    def bucket_exists(self, bucket_name):
        exists = True
        try:
            bucket = self.get_storage_client().get_bucket(bucket_name)
        except exceptions.NotFound as e:
            exists = False
        return exists


    '''
        Define the bucket policy corresponding to the roles and storage permissions associated with
        the specified storage location.
        Since policy cannot be bound to objects within a bucket, IAM Conditions are employed to
        specify the datalake definition's path-level permissions.
    '''
    def bind_bucket_policy(self, ddf, bucket_name, folder_path):
        # The policy version is required to be 3 or greater to support IAM Conditions
        bucket_policy_version = 3

        target_path = '/' + bucket_name
        if (folder_path is not None):
            target_path += '/' + folder_path

        # Determine the roles and permissions defined for this bucket/path
        storage_location_name = None
        for name, location in ddf.get('storage').items():
            location_path = location.get('path')
            if (location_path is not None):
                if (location_path == target_path):
                    storage_location_name = name
                    self.logger.debug('Found storage location ' + name + ' for ' + target_path)
                    break

        storage_reference_roles = dict()
        if (storage_location_name is not None):
            # Identify all the roles that reference the storage location
            for name, role in ddf.get('datalake_roles').items():
                for perm in role.get('permissions'):
                    if (perm.startswith('storage:')):
                        if (perm.endswith(storage_location_name)):
                            permission = perm.split(':')[1]
                            self.logger.debug(name + ' role references storage location ' + storage_location_name + ' with permission ' + permission)
                            role_perms = storage_reference_roles.get(name)
                            if (role_perms is None):
                                role_perms = []
                            role_perms.append(permission)
                            storage_reference_roles.update({name : role_perms})

        bindings = dict()

        storage_perms = ddf.get('permissions').get('storage')
        for role_name,role_perms in storage_reference_roles.items():
            self.logger.debug('Bind the custom role for ' + str(role_perms) + ' to the service account for ' + role_name + ' to the location ' + target_path)
            # Use role name to get the IAM service account name
            service_account_name = ddf.get('datalake_roles').get(role_name).get('iam_role')
            service_account_email = self.get_service_account_email(ddf, service_account_name)
            self.logger.debug(role_name + ' service account: ' + service_account_name + ' (' + service_account_email + ')')

            # role_perms elements are permmissions:storage entry names
            binding_roles = []
            for role_perm in role_perms:
                policy = self.load_role_policy(ddf.get('datalake'), role_perm)
                self.logger.debug('Loaded policy: ' + json.dumps(policy))
                binding_roles.append(policy.get('roleId'))
            bindings.update({service_account_email : binding_roles})

        project_id = self.get_project_id(ddf)

        gcs = self.get_storage_client()
        bucket = gcs.get_bucket(bucket_name)

        # The policy version is required to be 3 or greater for IAM Conditions to be used
        policy = bucket.get_iam_policy(requested_policy_version=bucket_policy_version)

        self.logger.debug('Original policy:\n' + str(policy.bindings) + '\n')
        bucket_bindings = policy.bindings
        if (bucket_bindings is None):
            bucket_bindings = []
            policy.update({"bindings": bindings})

        # The policy version might be less than the necessary version requested, so set it again
        if (policy.version < bucket_policy_version):
            policy.version = bucket_policy_version

        for sa,roles in bindings.items():
            self.logger.debug('Bind ' + sa + ' to ' + str(roles))
            for role in roles:
                self.logger.debug('Attempting to bind ' + role + ' to bucket')
                matching_binding = None
                for bucket_binding in bucket_bindings:
                    bucket_binding_role =  bucket_binding.get('role')
                    self.logger.debug('bucket_binding role: ' + bucket_binding_role)
                    role_members = None
                    if (bucket_binding_role == ('projects/' + project_id + '/roles/' + role)):
                        matching_binding = bucket_binding
                        self.logger.debug('Found matching bucket binding: ' + bucket_binding_role)
                        break

                if(matching_binding is None):
                    self.logger.debug('No existing binding for ' + project_id + '/roles/' + role)
                    new_binding = dict({
                                         'role': 'projects/' + project_id + '/roles/' + role,
                                         'members': [
                                               'serviceAccount:' + sa
                                         ]
                                       })

                    # Determine any path detail which should be used to qualify the bucket policy binding
                    path_condition_value = target_path[len(bucket_name)+2:len(target_path)]
                    if (path_condition_value is not None):
                        if (len(path_condition_value) > 0):
                            new_binding.update({
                                                 'condition': {
                                                      'description' : 'Path restriction',
                                                      'expression' : 'resource.name.startsWith("projects/_/buckets/' + bucket_name + '/objects/' + path_condition_value + '")'
                                                  }
                                               })

                    bucket_bindings.append(new_binding)
                    self.logger.info('  Applying permissions to ' + bucket_name + ':\n    ' + str(new_binding))

                    self.logger.debug('Added new role binding for projects/' + project_id + '/roles/' + role)
                else:
                    self.logger.debug('Update existing binding for projects/' + project_id + '/roles/' + role)
                    role_members = bucket_binding_role.get('members')
                    if(role_members is None):
                        role_members = []
                        bucket_binding_role.update({"members" : role_members})
                        role_members.append("serviceAccount:" + sa)
                        # TODO: PJZ: Check condition for path restriction

        self.logger.debug('Updated policy:\n' + str(policy.bindings) + '\n')

        # Push the updated service account policy
        bucket.set_iam_policy(policy)
        print()


    '''
        Delete the bucket defined in the datalake defintion.
    '''
    def delete_bucket_paths(self, ddf):
        # Delete buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
                if (self.bucket_exists(dirs[0]) is True):
                    self.delete_bucket(dirs[0])
        print()


    '''
        Delete the specified bucket.
    '''
    def delete_bucket(self, bucket_name):
        # Deletes a bucket.
        storage_client = self.get_storage_client()
        bucket = storage_client.get_bucket(bucket_name)
        bucket.delete(force=True)
        self.logger.info("Bucket {} deleted".format(bucket.name))


    '''
        Print the bindings associated with the specified policy.
    '''
    def dump_policy(self, policy):
        if (policy.bindings is not None):
            self.logger.debug('bindings: ' + str(policy.bindings))
        else:
            self.logger.debug('No policy bindings')

