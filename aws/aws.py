import os, boto3, sys, json, time, botocore

class AWSFactory:
    def vendor(self):
        return "Amazon"

    def build(self, ddf):
        datalakename = ddf['datalake']

        storage = dict()
        for name,path in ddf['storage'].items():
            # build dictionary for storage locations
            storage[name] = path['path']
        print('Building ' + self.vendor() + ' Cloud artifacts for datalake named: ' + datalakename + '...')
        #print(storage)

        for name,role in ddf['datalake_roles'].items():
            instanceProfile = False
            if "instance_profile" in role:
                instanceProfile = role['instance_profile']
            #print(name + ', iamRole=' + role['iam_role'] + ', instanceProfile=' + str(instanceProfile) + ', permissions=' + str(role['permissions']))

            permissions = role['permissions']
            i = 0
            for perm in permissions:
                #print(perm)
                elements = perm.split(':')
                if elements[0] == 'storage':
                    perm_name = elements[1]
                    filepath = 'templates/aws/' + perm_name + '.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = storage
                        d['storage_location']=storage[elements[2]]
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute(d)

                        filename = 'datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy' + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        print('The datalake role: ' + name + ' is assigned the iam role: ' + 
                              role['iam_role'] + ' which has been granted: ' + perm_name + 
                              ' for path: ' + d['storage_location'])
                    else:
                        print('Unknown permissions element: ' + elements[1] + ' check permissions in ddf file')
                elif elements[0] == 'sts':
                    filepath = 'templates/aws/assume-roles.json'
                    if os.path.exists(filepath):
                        with open(filepath, 'r') as reader:
                            t = reader.read()
                        filename = 'datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = '-' + str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy' + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        print('The datalake role: ' + name + ' is assigned the iam role: ' + 
                              role['iam_role'] + ' which has been granted: assumeRoles')
                elif elements[0] == 'db':
                    filepath = 'templates/aws/full-table-access.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = dict()
                        d['datalake_name']=elements[2]
                        d['table_name']=elements[2]
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute(d)
                        filename = 'datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = '-' + str(i)
                        # open output file
                        with open('datalakes/' + datalakename + '/AWS/' + role['iam_role'] + '-policy' + suffix + '.json', 'w') as writer:
                            writer.write(t)
                        print('The datalake role: ' + name + ' is assigned the iam role: ' + 
                              role['iam_role'] + ' which has been granted: full-table-access to table:' + elements[2])
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
        # Create IAM client
        iam = boto3.client('iam')

        # create iam entities

        # TODO determine the trusted roles up front and create them all rather than hardcode IDBROKER_ROLE
        # let's create IDBROKER_ROLE first as it is needed to create other roles with trust relationship
        idbrole = ddf['datalake_roles']['IDBROKER_ROLE']
        assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
            {
                 "Effect": "Allow",
                 "Principal": {
                     "Service": "ec2.amazonaws.com"
                 },
                 "Action": "sts:AssumeRole"
             }
           ]
        })
        print(assume_role_policy_document)

        create_role_response = iam.create_role(
            RoleName = idbrole['iam_role'],
            AssumeRolePolicyDocument = assume_role_policy_document
        )
        print (create_role_response)

        # Get a policy
        response = iam.get_role (RoleName=idbrole['iam_role'])
        idb_arn = response['Role']['Arn']

        time.sleep(10)

        for name,role in ddf['datalake_roles'].items():
            # TODO determine the trusted roles up front and check the list rather than hardcode IDBROKER_ROLE
            # get role name
            role_name = role['iam_role']
            if name != 'IDBROKER_ROLE':
                print(name)
                instanceProfile = False
                # TODO: process instance profile attachment
                #if "instance_profile" in role:
                #    instanceProfile = role['instance_profile']
                #print(name + ', iamRole=' + role['iam_role'] + ', instanceProfile=' + str(instanceProfile) + ', permissions=' + str(role['permissions']))

                # get the arn for the datalake_role trusted by this role rather than hardcode for idbroker_role
                # create role with trust policy document
                assume_role_policy_document2 = json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": idb_arn
                        },
                        "Action": "sts:AssumeRole"
                    }
                    ]
                })

                print(assume_role_policy_document)

                create_role_response = iam.create_role(
                    RoleName = role_name,
                    AssumeRolePolicyDocument = assume_role_policy_document2
                )

            # find policy files based on iam_role name
            path = 'datalakes/' + ddf['datalake'] + '/AWS/'
            filename_base = path + role_name + '-policy'
            suffix = ''
            count = 0
            while os.path.exists(filename_base + suffix + '.json'):
                # open file
                with open(filename_base + suffix + '.json', 'r') as reader:
                    policy = reader.read()

                print(policy)
                print(filename_base + suffix)
                response = iam.create_policy(
                     PolicyName=role_name + '-policy' + suffix,
                     PolicyDocument=policy)
                print(response)

                # attach each policy to the corresponding role
                time.sleep(5)
                response = iam.attach_role_policy(
                    RoleName=role_name, PolicyArn=response['Policy']['Arn'])

                print(response)
                count = count + 1
                suffix = '-' + str(count)

    def bucket_paths_are_unique(self, ddf):
        # check storage locations for existing buckets which will prevent push
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            dirs = bucket_path[1:].split('/')
            print('dirs: ' + str(dirs))
            print('bucket_name: ' + dirs[0])
            if (self.exists(dirs[0]) is True):
                # TODO allow user to indicate that the existing bucket
                # is intended and then skip trying to create it.
                return False
            return True

    def create_bucket_paths(self, ddf):
        # create storage locations
        # create buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            dirs = bucket_path[1:].split('/')
            print('dirs: ' + str(dirs))
            if (self.exists(dirs[0]) is False):
                self.create_bucket(dirs[0])
            if len(dirs) > 1:
                path = bucket_path[len(dirs[0]) + 2:]
                self.create_folders(dirs[0], path)

    def create_folders(self, bucket, path):
        # this is a folder creation inside the bucket
        # parse bucket name from the first path element and folder path from the remaining
        # create s3 client
        print('creating path: ' + path + ' within bucket: ' + bucket)
        s3 = boto3.client('s3')
        s3.put_object(Bucket=bucket, Key=(path + '/'))
        print('created path: ' + path + ' within bucket: ' + bucket)

    def create_bucket(self, bucket):
        print('creating bucket: ' + bucket)
        # create s3 client
        s3 = boto3.client('s3')
        s3.create_bucket(Bucket=bucket)
        print('created bucket: ' + bucket)

    def exists(self, bucket_name):
        print('bucket name: ' + bucket_name)
        # create s3 client
        s3 = boto3.resource('s3')
        bucket = s3.Bucket(bucket_name)
        exists = True
        try:
            s3.meta.client.head_bucket(Bucket=bucket_name)
        except botocore.exceptions.ClientError as e:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = e.response['Error']['Code']
            print(e)
            if error_code == '404':
                exists = False
        return exists

    def delete_iam_entities(self, ddf):
        # Create IAM client
        iam = boto3.client('iam')

        # delete iam entities

        for name,role in ddf['datalake_roles'].items():
            # TODO determine the trusted roles up front and check the list rather than hardcode IDBROKER_ROLE
            print(name)
            instanceProfile = False
            # TODO: process instance profile attachment
            #if "instance_profile" in role:
            #    instanceProfile = role['instance_profile']
            #print(name + ', iamRole=' + role['iam_role'] + ', instanceProfile=' + str(instanceProfile) + ', permissions=' + str(role['permissions']))

            # get role name
            role_name = role['iam_role']

            # TODO detach all policies before deleting role
            iam_resource = boto3.resource('iam')
            r = iam_resource.Role(role_name)
            policies = r.attached_policies.all()
            for policy in policies:
                response = r.detach_policy(
                    PolicyArn=policy.arn
                )
                policy.delete()
                #print(str(policy))
                #response = iam.delete_policy(
                #     PolicyArn=policy.arn)
                #print(response)

            create_role_response = iam.delete_role(
               RoleName = role_name
            )

    def delete_bucket_paths(self, ddf):
        # create storage locations
        # create buckets based on storage paths in DDF
        for name,storage in ddf['storage'].items():
            bucket_path=storage['path']
            dirs = bucket_path[1:].split('/')
            print('dirs: ' + str(dirs))
            if (self.exists(dirs[0]) is True):
                self.delete_bucket(dirs[0])

    def delete_bucket(self, bucket):
        print('deleting bucket: ' + bucket)
        # delete s3 client
        s3 = boto3.client('s3')
        s3.delete_bucket(Bucket=bucket)
        print('deleted bucket: ' + bucket)

    def __str__(self):
        return "AWS"

