#!/usr/bin/env python
"""A simple cmd2 application."""
import cmd2, argparse, yaml, os, shutil, sys

class App(cmd2.Cmd):
    """A simple cmd2 application."""
    prompt = 'ddt> '
    datalakename = 'mydatalake'
    paths = {}
    ddf = {'datalake': 'mydatalake', 'datalake_roles': {}, 'storage': {}}

    def __init__(self):
        super().__init__()
        # Make datalake_name settable at runtime
        self.datalakename = 'mydatalake'
        self.add_settable(cmd2.Settable('datalakename', str, 'name of the datalake definition'))
        #self.datalakeRoles = []
        #self.add_settable(cmd2.Settable('datalakeRoles', str, 'datalake roles'))

    role_parser = argparse.ArgumentParser()
    role_parser.add_argument('-r', '--role', type=str, help='Datalake role')
    role_parser.add_argument('-iam', '--iamrole', type=str, help='Cloud Vendor IAM role')
    role_parser.add_argument('-i', '--instanceprofile', action='store_true', help='VM attached role?')
    role_parser.add_argument('-p', '--permissions', type=str, help='Permissions for Cloud Services')
	
    @cmd2.with_argparser(role_parser)
    def do_add_role(self, args):
        """Add a DataLake Role to the Definition."""
        roles = self.ddf["datalake_roles"]
        newrole = {}
#{'datalake': 'ljm3', 'datalake_roles': {'IDBROKER_ROLE': {'iam_role': 'cdp-ljm3-idbroker-assume-role', 'instance_profile': True, 'permissions': ['assumeRoles']}, 'LOG_ROLE': {'iam_role': 'cdp-ljm3-log-role', 'instance_profile': True, 'permissions': ['storage:rw:path-3']}, 'RANGER_AUDIT_ROLE': {'iam_role': 'cdp-ljm3-ranger-audit-role', 'permissions': ['storage:w:path-2']}, 'DATALAKE_ADMIN_ROLE': {'iam_role': 'cdp-ljm3-admin-role', 'permissions': ['storage:lrwd:path-1']}}, 'storage': {'path-1': {'path': '/ljm3/data'}, 'path-2': {'path': '/ljm3/ranger/audit'}, 'path-3': {'path': '/ljm3/logs'}}}
        newrole['iam_role'] = args.iamrole
        instanceProfile = False
        if(args.instanceprofile is True):
           instanceProfile = True
        newrole['instance_profile'] = instanceProfile
        perms = [args.permissions]
        newrole['permissions'] = perms

        roles[args.role] = newrole
        print(self.ddf)

    def do_roles(self, args):
        """List all DataLake Roles in the Definition."""
        for name,role in self.ddf['datalake_roles'].items():
            instanceProfile = False
            if "instance_profile" in role:
                instanceProfile = role['instance_profile']
            print(name + ', iamRole=' + role['iam_role'] + ', instanceProfile=' + str(instanceProfile) + ', permissions=' + str(role['permissions']))

    role_perm_parser = argparse.ArgumentParser()
    role_perm_parser.add_argument('-r', '--role', type=str, help='Datalake role')
    role_perm_parser.add_argument('-p', '--permission', help='Permissions string {type:perm:target-name} ie. storage:read-write:LOGPATH')

    @cmd2.with_argparser(role_perm_parser)
    def do_add_role_perm(self, args):
        """Add a Permission to the DataLake Role."""
        role = self.ddf["datalake_roles"][args.role]
        perms = role["permissions"]
        perms.append(args.permission)

    path_parser = argparse.ArgumentParser()
    path_parser.add_argument('-n', '--name', type=str, help='Storage path name')
    path_parser.add_argument('-p', '--path', type=str, help='Cloud storage path')

    @cmd2.with_argparser(path_parser)
    def do_add_path(self, args):
        """Add a Storage Path to the Definition."""
        paths = self.ddf['storage']
        path = {}
        path['path'] = args.path
        paths[args.name] = path
        print(args.name + ' added')

    def do_paths(self, args):
        """List all Storage paths in the Definition."""
        for name,path in self.ddf['storage'].items():
            print(name + ', path=' + str(path['path']))

    load_datalake_parser = argparse.ArgumentParser()
    load_datalake_parser.add_argument('-n', '--name', type=str, help='Datalake name')

    @cmd2.with_argparser(load_datalake_parser)
    def do_load_datalake(self, args):
        """Load a DataLake from persisted DDF."""
        self.datalakename = args.name
        self.internal_load_datalake(self.datalakename)

    def internal_load_datalake(self, datalakename):
        ddf = open('datalakes/' + datalakename + '/ddf.yaml')
        self.ddf = yaml.load(ddf)

    save_datalake_parser = argparse.ArgumentParser()
    save_datalake_parser.add_argument('-n', '--name', type=str, help='Datalake name')

    @cmd2.with_argparser(save_datalake_parser)
    def do_save_datalake(self, args):
        """Persist a DataLake DDF."""
        if(args.name is not None):
            self.datalakename = args.name

        self.ddf['datalake'] = self.datalakename
        if not os.path.exists('datalakes/' + self.datalakename):
            os.makedirs('datalakes/' + self.datalakename)

        # open output file
        with open('datalakes/' + self.datalakename + '/ddf.yaml', 'w') as writer:
            writer.write(yaml.dump(self.ddf))

    new_datalake_parser = argparse.ArgumentParser()
    new_datalake_parser.add_argument('-n', '--name', type=str, help='Datalake name')

    @cmd2.with_argparser(new_datalake_parser)
    def do_new_datalake(self, args):
        """Create a new DataLake DDF."""
        self.datalakename = args.name;

        if not os.path.exists('datalakes/' + self.datalakename):
            os.makedirs('datalakes/' + self.datalakename)

        from string import Template
 
        # open template file
        d = dict(datalake_name=self.datalakename)
        with open('templates/ddf.yaml', 'r') as reader:
            ddf = Template(reader.read())
            ddf = ddf.safe_substitute(d)

        # open output file
        with open('datalakes/' + self.datalakename + '/ddf.yaml', 'w') as writer:
            writer.write(ddf)

        # load the new ddf
        self.internal_load_datalake(self.datalakename)
        #self.do_load_datalake(args)
        print(yaml.dump(self.ddf))

    build_parser = argparse.ArgumentParser()
    build_parser.add_argument('-n', '--name', type=str, help='Datalake name')
    build_parser.add_argument('-c', '--cloud', type=str, help='Cloud vendor name: AWS|Azure|GCP')

    @cmd2.with_argparser(build_parser)
    def do_build_datalake(self, args):
        """Build IAM artifacts for given vendor from the DataLake DDF."""
        if (args.name is not None):
            self.datalakename = args.name
        self.internal_load_datalake(self.datalakename)
        cloudname = args.cloud

        # prep the destination folder
        if os.path.exists('datalakes/' + self.datalakename + '/' + cloudname):
            shutil.rmtree('datalakes/' + self.datalakename + '/' + cloudname)
        os.makedirs('datalakes/' + self.datalakename + '/' + cloudname)

        # build the artifacts
        factory = CloudFactory.instance(self, cloudname)
        factory.build(self.ddf)

    push_parser = argparse.ArgumentParser()
    push_parser.add_argument('-n', '--name', type=str, help='Datalake name')
    push_parser.add_argument('-c', '--cloud', type=str, help='Cloud vendor name: AWS|Azure|GCP')

    @cmd2.with_argparser(push_parser)
    def do_push_datalake(self, args):
        """Publish IAM artifacts and buckets to given vendor."""
        if (args.name is not None):
            self.datalakename = args.name
        self.internal_load_datalake(self.datalakename)
        cloudname = args.cloud

        # build the artifacts
        factory = CloudFactory.instance(self, cloudname)
        factory.push(self.ddf)

    recall_parser = argparse.ArgumentParser()
    recall_parser.add_argument('-n', '--name', type=str, help='Datalake name')
    recall_parser.add_argument('-c', '--cloud', type=str, help='Cloud vendor name: AWS|Azure|GCP')

    @cmd2.with_argparser(recall_parser)
    def do_recall_datalake(self, args):
        """Unpublish IAM artifacts and buckets from given vendor."""
        if (args.name is not None):
            self.datalakename = args.name
        self.internal_load_datalake(self.datalakename)
        cloudname = args.cloud

        # build the artifacts
        factory = CloudFactory.instance(self, cloudname)
        factory.recall(self.ddf)

sys.path.insert(1, 'aws')
sys.path.insert(2, 'azure')
sys.path.insert(3, 'gcp')
import aws, azure, gcp

class CloudFactory:
    """A cloud factory"""

    def __init__(self, factory=None):
        """cloud_factory is our abstract factory.  We can set it at will."""
        self.cloud_factory = factory

    def build(self, ddf):
        """Generates IAM artifacts for cloud using the abstract factory"""
        cloud = self.cloud_factory()
        print("Cloud Type: {}".format(cloud))
        print("Vendor: {}".format(cloud.vendor()))
        cloud.build(ddf)

    def push(self, ddf):
        """Pushes IAM artifacts for cloud using the abstract factory"""
        cloud = self.cloud_factory()
        print("Cloud Type: {}".format(cloud))
        print("Vendor: {}".format(cloud.vendor()))
        cloud.push(ddf)

    def recall(self, ddf):
        """Recalls IAM artifacts for cloud using the abstract factory"""
        cloud = self.cloud_factory()
        print("Cloud Type: {}".format(cloud))
        print("Vendor: {}".format(cloud.vendor()))
        cloud.recall(ddf)

    @staticmethod
    def instance(self, cloudname):
        if (cloudname == "AWS"):
            from aws import AWSFactory
            factory = CloudFactory(AWSFactory)
        elif (cloudname == "Azure"):
            from azure import AzureFactory
            factory = CloudFactory(AzureFactory)
        elif (cloudname == "GCP"):
            from gcp import GCPFactory
            factory = CloudFactory(GCPFactory)
        return factory

if __name__ == '__main__':
    import sys
    c = App()
    sys.exit(c.cmdloop())

