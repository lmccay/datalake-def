import os

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
                elif elements[0] == 'assumeRoles':
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

                i = i + 1

    def __str__(self):
        return "AWS"

