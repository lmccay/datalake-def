import os, sys, json, time
from google.cloud import storage, exceptions
from google.oauth2 import service_account
import googleapiclient.discovery
from googleapiclient.errors import HttpError

class GCPFactory:

    def __str__(self):
        return "GCP"

    def vendor(self):
        return "Google"

    def get_project_id(self, ddf):
        return ddf['datalake']

    def get_credentials(self):
        return service_account.Credentials.from_service_account_file(filename=os.environ['GOOGLE_APPLICATION_CREDENTIALS'])

    def get_iam_client(self):
        return googleapiclient.discovery.build('iam', 'v1', credentials=self.get_credentials())

    def get_storage_client(self):
        return storage.Client();

    def get_resman_client(self):
        return googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=self.get_credentials())

    def build(self, ddf):
        datalakename = ddf['datalake']

        storage = dict()
        for name,path in ddf['storage'].items():
            storage[name] = path['path']
        print('Building ' + self.vendor() + ' Cloud artifacts for datalake named: ' + datalakename + '...')

        for name,role in ddf['datalake_roles'].items():
            instanceProfile = False
            if "instance_profile" in role:
                instanceProfile = role['instance_profile']

            iam_role = role['iam_role']
            permissions = role['permissions']
            i = 0
            print('The datalake role: ' + name + ' is assigned the iam role: ' + iam_role + '\n' + '    which has been granted: ')
            for perm in permissions:
                elements = perm.split(':')
                if elements[0] == 'storage':
                    perm_name = elements[1]
                    filepath = 'templates/gcp/' + perm_name + '.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = storage
                        d['storage_location'] = storage[elements[2]]
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute(d)

                        filename = 'datalakes/' + datalakename + '/GCP/' + iam_role + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/GCP/' + iam_role + '-policy' + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        print('        ' + perm_name + 
                              ' for path: ' + d['storage_location'])
                    else:
                        print('Unknown permissions element: ' + elements[1] + ' check permissions in ddf file')
                elif elements[0] == 'sts':
                    filepath = 'templates/gcp/assume-roles.json'
                    if os.path.exists(filepath):
                        with open(filepath, 'r') as reader:
                            t = reader.read()
                        filename = 'datalakes/' + datalakename + '/GCP/' + iam_role + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = '-' + str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/GCP/' + iam_role + '-policy' + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        print('        assumeRoles')
                i = i + 1

    def push(self, ddf):
        if self.bucket_paths_are_unique(ddf) is True:
            self.create_iam_entities(ddf)
            self.create_bucket_paths(ddf)
        else:
            # TODO perhaps provide ability to get past this with something like:
            #      1. add number to end of existing names and recheck until unique
            #      2. ask user for a replacement bucket name
            print('Bucket already exists check your configured paths. Cannot push to cloud.')

    def recall(self, ddf):
        #if self.bucket_paths_are_unique(ddf) is False:
            self.delete_iam_entities(ddf)
            self.delete_bucket_paths(ddf)
        #else:
            # TODO perhaps provide ability to get past this with something like:
            #      1. add number to end of existing names and recheck until unique
            #      2. ask user for a replacement bucket name
        #    print('Bucket does not exist check that this definition has been pushed.')

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

        # Create the trusted roles
        for name,role in ddf['datalake_roles'].items():
            if (name in trusted_roles):
                print('Creating service account for trusted role ' + name)
                trusted_iam_role = role['iam_role']
                trusted_sa_email = None
                service_accounts = iam.projects().serviceAccounts().list(name='projects/' + self.get_project_id(ddf)).execute()
                for account in service_accounts['accounts']:
                    sa_email = account['email']
                    if (sa_email.startswith(trusted_iam_role)):
                        trusted_sa_email = sa_email

                if (trusted_sa_email is not None):
                    print(name + ' service account already exists: ' + trusted_sa_email)
                else:
                    trusted_sa = self.create_service_account_for_role(ddf, name, trusted_iam_role , name + ' service account')
                    trusted_sa_email = trusted_sa['email']
                    trusted_role_email.update({name: trusted_sa_email})


        # Create service accounts for the remaining roles, and apply any associated policy
        for name,role in ddf['datalake_roles'].items():
            iam_role_name = role['iam_role']
            if (name not in trusted_roles):
                instanceProfile = False
                sa = self.create_service_account_for_role(ddf, name, iam_role_name, iam_role_name)

                # If the service account trusts another service account, then bind the associated policy
                for trusted_role,trusted_sa in trusted_role_email.items():
                    if (role.get('trust') == trusted_role):
                        print(name + ' trusts ' + trusted_role)
                        # Currently, this is hard-coded to service account token creator
                        # TODO: Determine the role(s) from the DDF permissions attached to the trusted role
                        self.bind_trusted_as_tokencreator(ddf, trusted_sa, sa)


    def create_service_account_for_role(self, ddf, role, sa_name, sa_display_name):
        iam = self.get_iam_client()

        sa = iam.projects().serviceAccounts().create(name='projects/' + self.get_project_id(ddf),
                        body={
                            'accountId': sa_name,
                            'serviceAccount': {
                                'displayName': sa_display_name
                             }
                        }).execute()
        print('Created service account: ' + sa['email'] + ' for ' + role)
        return sa
        

    def bind_trusted_as_tokencreator(self, ddf, trusted_sa_email, service_account):
        iam = self.get_iam_client()

        sa_resource = 'projects/' + self.get_project_id(ddf) + '/serviceAccounts/' + service_account['email']

        # Query the current service account policy
        policy = iam.projects().serviceAccounts().getIamPolicy(resource=sa_resource).execute()

        bindings = policy.get('bindings')
        if (bindings is None):
            bindings = []
            policy.update({"bindings": bindings})

        # TODO: Do we need to get the service account token creator role from the trusted role's permissions?
        # Add the trusted servivce account as the service account token creator for the target service account
        bindings.append({"role": "roles/iam.serviceAccountTokenCreator", "members": "serviceAccount:" + trusted_sa_email})
        #print('Updated policy: ' + json.dumps(policy))

        # Push the updated service account policy
        iam.projects().serviceAccounts().setIamPolicy(resource=sa_resource,
                                                      body={"policy": policy, "updateMask": "bindings"}).execute()


    def bucket_paths_are_unique(self, ddf):
        # check storage locations for existing buckets which will prevent push
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
                print('dirs: ' + str(dirs))
                print('bucket_name: ' + dirs[0])
                if (self.exists(dirs[0]) is True):
                    # TODO allow user to indicate that the existing bucket
                    # is intended and then skip trying to create it.
                    return False
        return True


    def create_bucket_paths(self, ddf):
        # create buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path = storage['path']
            print('bucket_path: ' + bucket_path)
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
                print('dirs: ' + str(dirs))
                if (self.exists(dirs[0]) is False):
                    self.create_bucket(dirs[0])
                if len(dirs) > 1:
                    path = bucket_path[len(dirs[0]) + 2:]
                    self.create_folders(dirs[0], path) # TODO: Bucket role policy bindings

    def create_folders(self, bucket_name, path):
        # This is a folder creation inside the bucket
        print('creating path: ' + path + ' within bucket: ' + bucket_name)
        gcs_client = self.get_storage_client()
        bucket = gcs_client.get_bucket(bucket_name)
        blob = bucket.blob(path + '/')
        blob.upload_from_string('')            
        print('created path: ' + path + ' within bucket: ' + bucket_name)            

    def create_bucket(self, bucket_name):
        # Create a new bucket in specific location with storage class
        storage_client = self.get_storage_client()

        bucket = storage_client.bucket(bucket_name)
        # TODO determine appropriate class for datalake defs
        bucket.storage_class = "COLDLINE"
        new_bucket = storage_client.create_bucket(bucket, location="us")
        print(
            "Created bucket {} in {} with storage class {}".format(
                new_bucket.name, new_bucket.location, new_bucket.storage_class
            )
        )

    def exists(self, bucket_name):
        exists = True
        try:
            bucket = self.get_storage_client().get_bucket(bucket_name)
        except exceptions.NotFound as e:
            exists = False
        return exists

    def delete_iam_entities(self, ddf):
        # Create IAM client
        iam = self.get_iam_client()

        for name,role in ddf['datalake_roles'].items():
            sa_email = role['iam_role'] + '@' + self.get_project_id(ddf) + '.iam.gserviceaccount.com'
            try:
                iam.projects().serviceAccounts().delete(name='projects/-/serviceAccounts/' + sa_email).execute()
                print('Deleted service account: ' + sa_email + ' for ' + name)
            except HttpError as e:
                parsedError = json.loads(e.content)
                if (parsedError['error']['code'] == 404):
                    print('Could not delete service account ' + sa_email + ' for ' + name + ' : Service account does not exist.')
                else:
                    print('Could not delete service account ' + sa_email + ' for ' + name + ' : ' + str(e.content))
            except Exception as e:
                print('Could not delete service account ' + sa_email  + ' for ' + name + ' : ' + str(e))


    def delete_bucket_paths(self, ddf):
        # Delete buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            if (bucket_path != '*'):
                dirs = bucket_path[1:].split('/')
#                print('dirs: ' + str(dirs))
                if (self.exists(dirs[0]) is True):
                    self.delete_bucket(dirs[0])

    def delete_bucket(self, bucket_name):
        # Deletes a bucket.
        storage_client = self.get_storage_client()
        bucket = storage_client.get_bucket(bucket_name)
        bucket.delete(force=True)
        print("Bucket {} deleted".format(bucket.name))

