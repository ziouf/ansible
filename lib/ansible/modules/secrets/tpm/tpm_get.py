#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Cyril MARIN <marin.cyril@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadatavertion': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}


DOCUMENTATION = r'''
---
module: tpm_get

short_description: Get data from Team Password Manager

version_added: "2.9"

description: 
- Query TPM to get passwords data

options:
    tpm_hostname:
        description: 
        - Hostname of targeted TPM instance without scheme. (ex: teampasswordmanager.com)
        required: true
        type: str

    tpm_username:
        description: 
        - Username used to connect TPM
        required: true
        type: str

    tpm_password:
        description: 
        - Password used to connect TPM
        required: true
        type: str

    tpm_ssl_verify:
        description:
        - Flag defining if ssl certificates must be check at connection time
        required: false
        default: false
        type: bool

    id:
        description:
        - ID of wanted data
        required: true
        type: int
'''

EXAMPLES = r'''

'''

RETURN = r'''
result:
    description: Data returned by TPM
    returned: On success
    type: json

error_type:
    description: Error type
    returned: On error
    type: str
    sample:
        - Unauthorized

msg:
    description: Human readable error message
    returned: On error
    type: str
    sample:
        - Incorrect or missing username or password
'''

import json
import traceback

try:
    from urllib import quote        # Python 2.x
except ImportError:
    from urllib.parse import quote  # Python 3+

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url

from _tpm_commons import (
    init_arg_spec,
    TpmBase,
)


class GetFailedError(Exception):
    """Get call to TPM api failed"""


class TpmGet(TpmBase):
    def get(self, id):
        '''
        Return data found from Team Password Manager database for specified ID
        '''
        path = 'api/v4/passwords/{}.json'.format(id)
        url_params = self.get_urlparams(path=path,
            method='GET',
            url='https://{}/index.php/{}'.format(
                self._module.params.get('tpm_hostname'), path)
        )
        r = open_url(**url_params)
        if r.status is not 200:
            raise GetFailedError('[{}] {} : {} - {}'.format(r.version, r.status, r.msg, r.reason))
        return json.load(r)


def _generate_ansible_facts(result):
    ansible_facts = {}
    if module.params.get('fact_prefix') is not None:
        ansible_facts.update({
            '{}_{}'.format(module.params.get('fact_prefix'), k): v
            for k, v in result.items()
        })
    return ansible_facts


def main():
    module = AnsibleModule(argument_spec=init_arg_spec(
        id=dict(type='int', required=True),
        fact_prefix=dict(type='str', required=False, default=None),
    ))

    try:
        result = TpmGet(module).get(module.params.get('id'))

    except Exception as e:
        stack = traceback.format_exc().splitlines()
        module.fail_json(msg="Error", error=str(e), stacktrace=stack)

    else:
        module.exit_json(changed=False, result=result, ansible_facts=_generate_ansible_facts(result))


if __name__ == "__main__":
    main()
