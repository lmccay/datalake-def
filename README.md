# datalake-def
Cloud neutral datalake defiition file format and management CLI

By introducing a specific format for defining the shape of your datalake, we can easily use simple templating mechanisms in order to generate the needed artifacts for publishing the datalake to a cloud vendor. Unlike other templating options, this does not result in a restricted datalake shape. You may add as many datalake paths (buckets, containers, filesystems, etc) or as many datalake roles to the definition as you like. The resulting artifacts can be further transformed into terraform scripts, used with cloud vendor APIs or CLIs or copy and pasted manually.

The same file can then be used by additional consumers in order to map users to the most appropriate IAM Roles based on identity and paths being accessed, provide meaningful visualizations of the datalake for use in UIs, etc.

Your datalake definitions may also be commited to SCM systems to share them and allow multiple admins to maintain them over the lifetime of your datalakes.

## Installation

1. Clone this project to your local machine
2. Install Cmd2 python module (added initial setup.py - try it!)

     pip install -U cmd2
          or try new
     python setup.py install

3. cd datalake-def
4. ../ddt.py "set debug true" "new_datalake --name {name}" "build_datalake \[--name {name}\] --cloud AWS" quit

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
         permissions: ['sts:assumeRoles']
       LOG_ROLE:
         iam_role: cdp-ljm-log-role
         instance_profile: true
         permissions: ['storage:read-write:LOGS_LOCATION_BASE']
       RANGER_AUDIT_ROLE:
         iam_role: cdp-ljm-ranger-audit-s3-role
         permissions: ['storage:full-object-access:RANGER_AUDIT_LOCATION', 'storage:list-only:DATALAKE_BUCKET']
     nosql: {TABLE_NAME: ljm}
     permission_weights:
       storage: {full-access: 1, full-object-access: 2, list-only: 5, read-only: 4, read-write: 3}
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

## Generated AWS Policy Aritfacts:

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
                     - "sts:assumeRoles"
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
     nosql:
         TABLE_NAME: ljm
     permission_weights:
         storage:
             full-access: 1
             full-object-access: 2
             read-write: 3
             read-only: 4
             list-only: 5
