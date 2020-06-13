import os, boto3, sys, json, time

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
        # Create IAM client
        iam = boto3.client('iam')

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
            if name != 'IDBROKER_ROLE':
                print(name)
                instanceProfile = False
                # TODO: process instance profile attachment
                #if "instance_profile" in role:
                #    instanceProfile = role['instance_profile']
                #print(name + ', iamRole=' + role['iam_role'] + ', instanceProfile=' + str(instanceProfile) + ', permissions=' + str(role['permissions']))

                # get role name
                role_name = role['iam_role']

                # TODO get the arn for the datalake_role trusted by this role rather than hardcode for idbroker_role
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

                    # TODO: attach each policy to the corresponding role
                    time.sleep(10)
                    response = iam.attach_role_policy(
                        RoleName=role_name, PolicyArn=response['Policy']['Arn'])

                    print(response)
                    count = count + 1
                    suffix = '-' + str(count)

    def __str__(self):
        return "AWS"

