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
module: tpm_search

short_description: Search passwords from Team Password Manager

version_added: "2.9"

description: 
- Search data from TPM 

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

    pattern:
        description:
        - Pattern to search
        required: true
        type: str
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


class SearchFailedError(Exception):
    """Search call to TPM api failed"""


class TpmSearch(TpmBase):
    def search(self, pattern):
        '''
        Return data found from Team Password Manager database for specified pattern
        '''
        path = 'api/v4/passwords/search/{}.json'.format(
            quote(pattern.encode('utf-8')))
        url_params = self.get_urlparams(path=path,
            method='GET',
            url='https://{}/index.php/{}'.format(
                self._module.params.get('tpm_hostname'), path)
        )
        r = open_url(**url_params)
        if r.status is not 200:
            raise SearchFailedError('[{}] {} : {} - {}'.format(r.version, r.status, r.msg, r.reason))
        return json.load(r)


def main():
    module = AnsibleModule(argument_spec=init_arg_spec(
        pattern=dict(type='str', required=True),
    ))

    try:
        result = TpmSearch(module).search(module.params.get('pattern'))

    except Exception as e:
        stack = traceback.format_exc().splitlines()
        module.fail_json(msg="Error", error=str(e), stacktrace=stack)

    else:
        module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    main()
