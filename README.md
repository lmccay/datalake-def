# datalake-def
## Cloud neutral datalake defiition file format and management CLI

By introducing a specific format for defining the shape of your datalake, we can easily use simple templating mechanisms in order to generate the needed artifacts for publishing the datalake to a cloud vendor. Unlike other templating options, this does not result in a restricted datalake shape. You may add as many datalake paths (buckets, containers, filesystems, etc) or as many datalake roles to the definition as you like. The resulting artifacts can be further transformed into terraform scripts, used with cloud vendor APIs or CLIs or copy and pasted manually.

The same file can then be used by additional consumers in order to map users to the most appropriate IAM Roles based on identity and paths being accessed, provide meaningful visualizations of the datalake for use in UIs, etc.

Your datalake definitions may also be commited to SCM systems to share them and allow multiple admins to maintain them over the lifetime of your datalakes.

## Installation

1. Clone this project to your local machine
2. Install python modules needed by app

        python setup.py install

3. cd datalake-def
4. ../ddt.py "set debug true" "new_datalake --name {name}" "build_datalake \[--name {name}\] --cloud AWS" quit

## Commands
     ddt> lmccay@strange:~/Projects/datalake-def$ ./ddt.py 
     ddt> help -v
     
     Documented commands (use 'help -v' for verbose/'help <topic>' for details):
     ================================================================================
     add_path            Add a Storage Path to the Definition.
     add_role            Add a DataLake Role to the Definition.
     alias               Manage aliases
     build_datalake      Build IAM artifacts for given vendor from the DataLake DDF.
     edit                Run a text editor and optionally open a file with it
     help                List available commands or provide detailed help for a specific command
     history             View, run, edit, save, or clear previously entered commands
     load_datalake       Load a DataLake from persisted DDF.
     macro               Manage macros
     new_datalake        Create a new DataLake DDF.
     paths               List all Storage paths in the Definition.
     push_datalake       Publish IAM artifacts and buckets to given vendor.
     py                  Invoke Python command or shell
     quit                Exit this application
     recall_datalake     Unpublish IAM artifacts and buckets from given vendor.
     roles               List all DataLake Roles in the Definition.
     run_pyscript        Run a Python script file inside the console
     run_script          Run commands in script file that is encoded as either ASCII or UTF-8 text
     save_datalake       Persist a DataLake DDF.
     set                 Set a settable parameter or show current settings of parameters
     shell               Execute a command as if at the OS prompt
     shortcuts           List available shortcuts

## Example use:
     lmccay@strange:~/Projects/datalake-def$ ./ddt.py "set debug true" "new_datalake -n ljm" "build_datalake -c AWS" quit
     debug - was: False
     now: True
     datalake: ljm
     datalake_roles:
       DATALAKE_ADMIN_ROLE:
         iam_role: cdp-ljm-admin-s3-role
         permissions: ['storage:full-access:STORAGE_LOCATION_BASE']
       IDBROKER_ROLE:
         iam_role: cdp-ljm-idbroker-assume-role
         instance_profile: true
         permissions: ['sts:assume-roles']
       LOG_ROLE:
         iam_role: cdp-ljm-log-role
         instance_profile: true
         permissions: ['storage:read-write:LOGS_LOCATION_BASE']
       RANGER_AUDIT_ROLE:
         iam_role: cdp-ljm-ranger-audit-s3-role
         permissions: ['storage:full-object-access:RANGER_AUDIT_LOCATION', 'storage:list-only:DATALAKE_BUCKET']
     nosql: {TABLE_NAME: ljm}
     permissions:
       storage:
         full-access: {description: the force, rank: 1}
         full-object-access: {description: jedi master, rank: 2}
         list-only: {description: youngling, rank: 5}
         read-only: {description: padawan, rank: 4}
         read-write: {description: jedi knight, rank: 3}
       sts:
         assume-roles: {description: shapeshifter, rank: 1}
     storage:
       DATALAKE_BUCKET: {path: /ljm/data}
       LOGS_BUCKET: {path: /ljm}
       LOGS_LOCATION_BASE: {path: /ljm/logs}
       RANGER_AUDIT_LOCATION: {path: /ljm/ranger/audit}
       STORAGE_LOCATION_BASE: {path: /ljm}
     
     Cloud Type: AWS
     Vendor: Amazon
     Building Amazon Cloud artifacts for datalake named: ljm...
     The datalake role: IDBROKER_ROLE is assigned the iam role: cdp-ljm-idbroker-assume-role which has been granted: assumeRoles
     The datalake role: LOG_ROLE is assigned the iam role: cdp-ljm-log-role which has been granted: read-write for path: /ljm/logs
     The datalake role: RANGER_AUDIT_ROLE is assigned the iam role: cdp-ljm-ranger-audit-s3-role which has been granted: full-object-access for path: /ljm/ranger/audit
     The datalake role: RANGER_AUDIT_ROLE is assigned the iam role: cdp-ljm-ranger-audit-s3-role which has been granted: list-only for path: /ljm/data
     The datalake role: DATALAKE_ADMIN_ROLE is assigned the iam role: cdp-ljm-admin-s3-role which has been granted: full-access for path: /ljm
     

## Generated datalake directories:

     lmccay@strange:~/Projects/datalake-def$ ls datalakes/ljm/
     AWS/      ddf.yaml  

## Generated AWS Policy Artifacts:

     lmccay@strange:~/Projects/datalake-def$ ls datalakes/ljm/AWS/
     cdp-ljm-admin-s3-role-policy.json  cdp-ljm-idbroker-assume-role-policy.json  cdp-ljm-log-role-policy.json  cdp-ljm-ranger-audit-s3-role-policy1.json  cdp-ljm-ranger-audit-s3-role-policy.json

## Generated YAML DDF (Datalake Definition File):

     lmccay@strange:~/Projects/datalake-def$ cat datalakes/ljm/ddf.yaml 
     ---
     datalake: ljm
     datalake_roles:
         IDBROKER_ROLE:
                 iam_role: cdp-ljm-idbroker-assume-role
                 instance_profile: true
                 permissions:
                     - "sts:assume-roles"
         LOG_ROLE:
                 iam_role: cdp-ljm-log-role
                 instance_profile: true
                 permissions:
                     - "storage:read-write:LOGS_LOCATION_BASE"
         RANGER_AUDIT_ROLE:
                 iam_role: cdp-ljm-ranger-audit-s3-role
                 permissions:
                     - "storage:full-object-access:RANGER_AUDIT_LOCATION"
                     - "storage:list-only:DATALAKE_BUCKET"
         DATALAKE_ADMIN_ROLE:
                 iam_role: cdp-ljm-admin-s3-role
                 permissions:
                     - "storage:full-access:STORAGE_LOCATION_BASE"
                     - "db:full-table-access:ljm-table"
     storage:
         STORAGE_LOCATION_BASE:
                 # main data directory
                 path: /ljm
         DATALAKE_BUCKET:
                 # main data directory
                 path: /ljm/data
         RANGER_AUDIT_LOCATION:
                 # ranger audit logs
                 path: /ljm/ranger/audit
         LOGS_LOCATION_BASE:
                 # logs for fluentd usecases
                 path: /ljm/logs
         LOGS_BUCKET:
                 # logs for fluentd usecases
                 path: /ljm
     permissions:
         storage:
             full-access:
                 rank: 1
                 description: the force
             full-object-access:
                 rank: 2
                 description: jedi master
             read-write:
                 rank: 3
                 description: jedi knight
             read-only:
                 rank: 4
                 description: padawan
             list-only:
                 rank: 5
                 description: youngling
         sts:
             assume-roles:
                 rank: 1
                 description: shapeshifter
         db:
             full-table-access:
                 rank: 1
                 description: dba

# Azure Setup
Following steps describe a way to set up and run scripts for Azure.

## Prerequisite
* [Azure account with Active subscription](https://azure.microsoft.com/free/?utm_source=campaign&utm_campaign=python-dev-center&mktingSource=environment-setup)
* [Python 2.7+ or 3.5.3+](https://www.python.org/downloads)
* [Azure Command-Line Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

## Environment Setup
* Sign-in to Azure account

        az login

* Create Service Principal (if not already created) - make sure the SP has Owner role at subscription level

        az ad sp create-for-rbac --name KnoxSP --password knox-password > local-sp.json

   NOTE: If you explicitly want to set permissions use the option ``--skip-assignment`` and assign Owner permissions at subscription level later.
   NOTE: Service Principal should have Owner permissions at subscription level
* Get subscription id

        az account show 

* Setup environemnt variables (update values as necessarily) - Required

        AZURE_SUBSCRIPTION_ID="aa11bb33-cc77-dd88-ee99-0918273645aa"
        AZURE_TENANT_ID="00112233-7777-8888-9999-aabbccddeeff"
        AZURE_CLIENT_ID="12345678-1111-2222-3333-1234567890ab"
        AZURE_CLIENT_SECRET="abcdef00-4444-5555-6666-1234567890ab"

* Setup environemnt variables (update values as necessarily) - Optional

        AZURE_RESOURCE_GROUP="myResourceGroup" #Resource group under which MSIs will be created, else default is <datalakename>RG

For more information see [Azure Configure Authentication](https://docs.microsoft.com/en-us/azure/developer/python/configure-local-development-environment?tabs=bash#configure-authentication) docs

## Examples
* Create a default DDF 

        ddt.py "set debug true" "new_datalake -n srm" "build_datalake -c Azure" "push_datalake -c Azure" quit



# Google Cloud Platform Setup
Set up and run scripts for Google Cloud Platform (GCP).


## Prerequisites
* A Google Cloud Platform account with permissions associated with the following GCP roles:
  * StorageAdmin (bucket/path creation/removal)
  * ServiceAccountAdmin (service account creation/removal)
  * SecurityAdmin (IAM policy attachment)


## Environment Setup
* Download the key file for the Google Cloud Platform account to be used by the Datalake Definition tool
* Set the GOOGLE_APPLICATION_CREDENTIALS environment variable to point to that key file


## Examples
> N.B. Datalake names are translated into Google Cloud Storage bucket names, which must be __globally__ unique.
>      Attempts to access buckets which don't belong to you will result in HTTP 403 errors, even though your
>      permissions include the StorageAdmin role.

* Create a Google Cloud Platform datalake definition

		---
		datalake: mydl
		datalake_roles:
		    IDBROKER_ROLE:
		            iam_role: cdp-mydl-idbroker
		            instance_profile: true
		            permissions:
		                - "iam:serviceAccountTokenCreator"
		    LOG_ROLE:
		            iam_role: cdp-mydl-log
		            instance_profile: true
		            trust: IDBROKER_ROLE
		            permissions:
		                - "storage:read-write-storage:LOGS_LOCATION_BASE"
		    RANGER_AUDIT_ROLE:
		            iam_role: cdp-mydl-ranger-audit
		            trust: IDBROKER_ROLE
		            permissions:
		                - "storage:full-object-access-storage:RANGER_AUDIT_LOCATION"
		                - "storage:read-only-storage:DATALAKE_BUCKET"
		    DATALAKE_ADMIN_ROLE:
		            iam_role: cdp-mydl-admin
		            trust: IDBROKER_ROLE
		            permissions:
		                - "storage:full-access-storage:STORAGE_LOCATION_BASE"
		storage:
		    STORAGE_LOCATION_BASE:
		            description: data directory
		            path: /mydl
		    DATALAKE_BUCKET:
		            description: main data directory
		            path: /mydl/data
		    RANGER_AUDIT_LOCATION:
		            description: ranger audit logs
		            path: /mydl/ranger/audit
		    LOGS_LOCATION_BASE:
		            description: logs for fluentd usecases
		            path: /mydl/logs
		    LOGS_BUCKET:
		            description: logs for fluentd usecases
		            path: /mydl
		    ALL_LOCATIONS:
		            description: wildcard resource locations
		            path: '*'
		permissions:
		    storage:
		        full-access-storage:
		            rank: 1
		            description: the force
		        full-object-access-storage:
		            rank: 2
		            description: jedi master
		        read-write-storage:
		            rank: 3
		            description: jedi knight
		        execute-storage:
		            rank: 4
		            description: padawan
		        read-only-storage:
		            rank: 5
		            description: youngling 
		        list-only-storage:
		            rank: 6 
		            description: hmmmm 
		    iam:
		        serviceAccountTokenCreator:
		            rank: 1
		            description: shapeshifter
		    roles:
		        token-creator:
		            rank: 1
		            description: shapeshifter

* Push a Google Cloud Platform datalake definition

        ddt.py "push_datalake -n mydl -c GCP" quit

* Recall a Google Cloud Platform datalake definition

        ddt.py "recall_datalake -n mydl -c GCP" quit

