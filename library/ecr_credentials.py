#!/usr/bin/python
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: ecr_credentials
short_description: Retrieves AWS ECR credentials valid for 12 hours.
description:
  - Gets ECR credentials details to be used with docker_login.
requirements:
    - boto3
    - botocore
    - json
options:
  registry_ids:
    description:
      - List of registry ids to get login info for.
    required: false
    default: None
author: Karen Cheng(@Etherdaemon)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Simple example of listing all nat gateways
- name: Get ecr credentials
  ecr_credentials:
    registry_ids:
      - '771234567890'
    region: us-east-1
    profile: personal
  register: retrieved_credentials

'''

RETURN = '''
result:
  description: List of dictionaries for each registry ID containing the credentials.
  returned: success
  type: list
  sample:
    result:
      - username: 'AWS'
        password: 'base64decoded_password'
        registry: 'https://771234567890..dkr.ecr.us-east-1.amazonaws.com'
        expiry: '2016-02-15T22:10:38.430000+10:00'
'''

try:
    import json
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import time


def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def get_token(client, module):
    params = dict()
    if module.params.get('registry_ids'):
        params['registryIds'] = module.params.get('registry_ids')

    try:
        result = json.loads(json.dumps(client.get_authorization_token(**params), default=date_handler))['authorizationData']
    except botocore.exceptions.EndpointConnectionError as e:
        module.fail_json(msg=str(e) + ' - Please check your input params')

    return result


def get_usable_login(client, module):
    parsed_logins = list()
    returned_logins = get_token(client, module)
    for login in returned_logins:
        parsed_login = dict()
        b64decoded_token = login['authorizationToken'].decode('base64').split(':')
        parsed_login['username'] = b64decoded_token[0]
        parsed_login['password'] = b64decoded_token[1]
        parsed_login['registry'] = login['proxyEndpoint']
        parsed_login['expiry'] = login['expiresAt']
        parsed_logins.append(parsed_login)

    return parsed_logins


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        registry_ids=dict(default=None, type='list'),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,)

    # Validate Requirements
    if not HAS_BOTO3:
        module.fail_json(msg='json and botocore/boto3 is required.')

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    except NameError as e:
        # Getting around the get_aws_connection_info boto reliance for region
        if "global name 'boto' is not defined" in e.message:
            module.params['region'] = botocore.session.get_session().get_config_variable('region')
            if not module.params['region']:
                module.fail_json(msg="Error - no region provided")
        else:
            module.fail_json(msg="Can't retrieve connection information - "+str(e))

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        ecr = boto3_conn(module, conn_type='client', resource='ecr', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg=str(e))

    results = get_usable_login(ecr, module)

    module.exit_json(result=results)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()