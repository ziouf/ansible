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
module: tpm_generate

short_description: Generate password from Team Password Manager

version_added: "2.9"

description: 
- Query TPM to get new generated password

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url

from _tpm_commons import (
    init_arg_spec,
    TpmBase,
)


class GenerateFailedError(Exception):
    """Generate call to TPM api failed"""


class TpmGenerate(TpmBase):
    def generate(self):
        '''
        Generate password from Team Password Manager
        '''
        path = 'api/v4/generate_password.json'
        url_params = self.get_urlparams(path=path,
            method='GET',
            url='https://{}/index.php/{}'.format(
                self._module.params.get('tpm_hostname'), path)
        )
        r = open_url(**url_params)
        if r.status is not 200:
            raise GenerateFailedError('[{}] {} : {} - {}'.format(r.version, r.status, r.msg, r.reason))
        return json.load(r)


def main():
    module = AnsibleModule(argument_spec=init_arg_spec())

    try:
        result = TpmGenerate(module).generate()

    except Exception as e:
        stack = traceback.format_exc().splitlines()
        module.fail_json(is_error=True, error_type=type(e).__name__, msg=str(e), stacktrace=stack)

    else:
        module.exit_json(changed=True, result=result)


if __name__ == "__main__":
    main()
