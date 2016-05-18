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
module: ec2_addresses
short_description: Allocate, associate, disassociate and release ec2 addresses.
  This module does not support EC2-Classic as its intended for
  private-addresses which are EC2-VPC only.
description:
  - Allocate and deallocate secondary private ip's from an interface
  - Associates and if required allocate Elastic IP to private IP
  - Disassociate Elastic IPs and release if required
requirements:
  - "ansible >= 2.0"
  - boto3
  - botocore
  - json
options:
  type:
    description:
      - secondary_private allows for allocation of secondary
        private ip addresses to a given interface
      - eip_to_private allows for association of an elastic IP to
        a provided secondary private IP address. An EIP can be
        allocated if no EIP is provided
    required: true
    choices: ["secondary_private", "eip_to_private"]
  public_ip:
    description:
      - Elastic IP for use with either associating with a private_ip,
        or unassociating required: false.
    required: false
  private_ip:
    description:
      - Private IP address for either associating an EIP to,
        or unassociating an EIP from
    required: false
  count:
    description:
      - "The number of secondary private IPs to ensure is attached
        to an interface. Note that AWS interface limits based on
        instance type do apply.
        Refer to http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI
        for more details."
  reassociation:
    description:
      - Allow an EIP to be reassociated to another private ip
        even if the EIP is associated to something else
    required: false
    choices: ["yes", "no"]
    default: no
  release_on_disassociation:
    description:
      - Release Elastic IP on disassocation from private IP address
    required: false
  interface_id:
    description:
      - Interface ID, required for association EIP's to private IP's,
        assigning more private ips, unassigning private ips.
    required: false
  state:
    description:
      - present to ensure resource is created or updated.
      - absent to remove resource
    required: false
    default: present
    choices: [ "present", "absent"]
author: Karen Cheng(@Etherdaemon)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Simple example of attaching 2 secondary private ips to
# an interface. Returns a list of secondary addresses
- name: Ensure interface has 2 seconday private addresses
  ec2_addresses:
    type: secondary_private
    state: present
    count: 2
    interface_id: eni-12345678
    profile: "{{ boto_profile }}"
    region: "{{ region }}"
  register: interface_results

- name: Get the last secondary private ip address
  set_fact:
    last_secondary_private_details:
      ip_address: "{{ interface_results.result.PrivateIpAddresses | selectattr('Primary', 'equalto', false) | map(attribute='PrivateIpAddress') | list | last }}"
      interface_id: "{{ interface_results.result.NetworkInterfaceId }}"

- name: Allocate Elastic IP and assign to the last secondary private ip address
  ec2_addresses:
    type: eip_to_private
    state: present
    private_ip: "{{ last_secondary_private_details.ip_address }}"
    interface_id: "{{ last_secondary_private_details.interface_id }}"
    profile: "{{ boto_profile }}"
    region: "{{ region }}"
    reassociation: true

- name: Associate existing public ip to private address
  ec2_addresses:
    type: eip_to_private
    state: present
    public_ip: 52.1.1.1
    private_ip: 10.1.1.1
    interface_id: eni-12345678

- name: Disassociate elastic ip from private address and release elastic ip
  ec2_addresses:
    type: eip_to_private
    state: absent
    public_ip: 52.1.1.1
    release_on_disassociation: yes

- name: Disassociate all elastic ips from interface and release elastic ips
  ec2_addresses:
    type: eip_to_private
    state: absent
    interface_id: eni-12345678
    release_on_disassociation: yes

- name: Unassign 10.1.1.1 from interface
  ec2_addresses:
    type: secondary_private
    state: absent
    private_ip: 10.1.1.1
    interface_id: eni-12345678

- name: Unassign all secondary addresses from interface
  ec2_addresses:
    type: secondary_private
    state: absent
    interface_id: eni-12345678

'''

try:
    import json
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def get_interface_details(client, module):
    params = dict()
    if not module.params.get('interface_id'):
        module.fail_json(msg='interface_id is required')
    else:
        params['NetworkInterfaceIds'] = [module.params.get('interface_id')]

    try:
        interface_details = client.describe_network_interfaces(**params)
    except botocore.exceptions.ClientError, e:
        module.fail_json(msg="Issue getting interface details - "+str(e.response['Error']['Code']))

    return interface_details


def unassign_secondary_private_addresses(client, module, private_ips):
    params = dict()
    params['NetworkInterfaceId'] = module.params.get('interface_id')
    params['PrivateIpAddresses'] = private_ips

    client.unassign_private_ip_addresses(**params)


def remove_eip_to_private_addresses(client, module):
    params = dict()
    changed = False
    if module.params.get('public_ip'):
        public_ip = module.params.get('public_ip')
        eip_details = get_eip_details(client, module, public_ip)
        params['AssociationId'] = eip_details['AssociationId']
        client.disassociate_address(**params)
        result = release_eip_address(client, module, eip_details['AllocationId'])
        changed = True
    elif module.params.get('interface_id'):
        elastic_ips = get_interface_eips(client, module)
        if elastic_ips != []:
            changed = True
            for eip in elastic_ips:
                eip_details = get_eip_details(client, module, eip)
                params['AssociationId'] = eip_details['AssociationId']
                client.disassociate_address(**params)
                result = release_eip_address(client, module, eip_details['AllocationId'])

    return changed, result


def release_eip_address(client, module, allocation_id):
    params = dict()
    if module.params.get('release_on_disassociation'):
        params['AllocationId'] = allocation_id
        client.release_address(**params)


def get_interface_eips(client, module):
    params = dict()
    if module.params.get('interface_id'):
        interface_details = get_interface_details(client, module)
        all_public_ips = [n['Association'] for n in
            interface_details['NetworkInterfaces'][0]['PrivateIpAddresses']
                 if 'Association' in n]
        elastic_ips = [n['PublicIp'] for n in all_public_ips if 'AllocationId' in n]
    else:
        module.fail_json(msg='interface_id is required.')

    return elastic_ips


def return_secondary_address_details(client, module):
    if not module.params.get('interface_id'):
        module.fail_json(msg='interface_id is required')
    else:
        interface_details = get_interface_details(client, module)

    existing_secondaries = [i for i in
        interface_details['NetworkInterfaces'][0]['PrivateIpAddresses']
            if not i['Primary']]
    return existing_secondaries


def remove_secondary_private_addresses(client, module):
    params = dict()
    changed = False
    if not module.params.get('interface_id'):
        module.fail_json(msg='interface_id is required')

    if module.params.get('private_ip'):
        private_ips = [module.params.get('private_ip')]
    else:
        interface_details = get_interface_details(client, module)
        private_ips = [i['PrivateIpAddress']
            for i in interface_details['NetworkInterfaces'][0]['PrivateIpAddresses']
                if not i['Primary']]

    if private_ips != []:
        result = unassign_secondary_private_addresses(client, module, private_ips)
        changed = True
    else:
        result = {}

    return changed, result


def allocate_secondary_private_addresses(client, module):
    params = dict()
    changed = False

    if not module.params.get('interface_id'):
        module.fail_json(msg='interface_id is required')
    else:
        params['NetworkInterfaceId'] = module.params.get('interface_id')

    interface_details = get_interface_details(client, module)
    existing_secondaries = [i for i in
        interface_details['NetworkInterfaces'][0]['PrivateIpAddresses']
            if not i['Primary']]

    if module.params.get('count') > len(existing_secondaries):
        params['SecondaryPrivateIpAddressCount'] = \
            (module.params.get('count') - len(existing_secondaries))
        client.assign_private_ip_addresses(**params)
        interface_details = get_interface_details(client, module)
        changed = True
    elif module.params.get('count') < len(existing_secondaries):
        unassign_count = len(existing_secondaries) - module.params.get('count')
        private_ips = [n['PrivateIpAddress'] for n in existing_secondaries[-unassign_count:]]
        unassign_secondary_private_addresses(client, module, private_ips)
        changed = True

    updated_details = json.loads(json.dumps(get_interface_details
        (client, module), default=date_handler))['NetworkInterfaces'][0]

    result = updated_details
    return changed, result


def get_eip_details(client, module, public_ip):
    params = dict()
    params['PublicIps'] = [public_ip]
    try:
        eip_details = client.describe_addresses(**params)['Addresses'][0]
    except botocore.exceptions.ClientError, e:
        module.fail_json(msg="Issue getting public IP details - "+str(e.response['Error']['Code']))

    return eip_details


def perform_association(client, module, **args):
    try:
        client.associate_address(**args)
    except botocore.exceptions.ClientError, e:
        module.fail_json(msg="Issue with associating - "+str(e))


def associate_eip_to_private_address(client, module):
    params = dict()
    changed = False
    if not module.params.get('private_ip'):
        module.fail_json(msg='public_ip and private_ip is required')

    if not module.params.get('interface_id'):
        module.fail_json(msg='interface_id is required')
    else:
        params['NetworkInterfaceId'] = module.params.get('interface_id')
        params['PrivateIpAddress'] = module.params.get('private_ip')
        params['AllowReassociation'] = module.params.get('reassociation')

    if not module.params.get('public_ip'):
        existing_secondaries = return_secondary_address_details(client, module)
        address_found = False
        for secondary in existing_secondaries:
            if secondary['PrivateIpAddress'] == params['PrivateIpAddress']:
                address_found = True
                if 'Association' in secondary:
                    public_ip = secondary['Association']['PublicIp']
                else:
                    allocated_address = client.allocate_address(Domain='vpc')
                    public_ip = allocated_address['PublicIp']

        if not address_found:
            module.fail_json(msg=params['PrivateIpAddress'] +
                ' is not attached to ' + params['NetworkInterfaceId'])

    eip_details = get_eip_details(client, module, public_ip)
    params['AllocationId'] = eip_details['AllocationId']

    if 'PrivateIpAddress' not in eip_details:
        perform_association(client, module, **params)
        changed = True
    elif eip_details['PrivateIpAddress'] != params['PrivateIpAddress']:
        perform_association(client, module, **params)
        changed = True

    result = get_eip_details(client, module, public_ip)

    return changed, result


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        type=dict(choices=[
            'secondary_private',
            'eip_to_private'
        ], required=True),
        public_ip=dict(),
        private_ip=dict(),
        count=dict(type='int', default=1),
        reassociation=dict(type='bool', default=False),
        release_on_disassociation=dict(type='bool', default=False),
        interface_id=dict(),
        state=dict(default='present', choices=['present', 'absent']),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    # Validate Requirements
    if not HAS_BOTO3:
        module.fail_json(msg='json and botocore/boto3 is required.')

    state = module.params.get('state').lower()

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        ec2 = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg="Can't authorize connection - "+str(e))

    present_invocations = {
        'secondary_private': allocate_secondary_private_addresses,
        'eip_to_private': associate_eip_to_private_address,
    }

    absent_invocations = {
        'secondary_private': remove_secondary_private_addresses,
        'eip_to_private': remove_eip_to_private_addresses,
    }

    #Ensure resource is present
    if state == 'present':
        (changed, results) = present_invocations[module.params.get('type')](ec2, module)
    else:
        (changed, results) = absent_invocations[module.params.get('type')](ec2, module)

    module.exit_json(changed=changed, result=results)


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
