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
    ItemFoundError,
)
from tpm_get import TpmGet
from tpm_search import TpmSearch
from tpm_generate import TpmGenerate


class UpdateFailedError(Exception):
    """Update call to TPM api failed"""


class CreateFailedError(Exception):
    """Create call to TPM api failed"""


class TpmCreate(TpmBase):
    def _convertData(self, data):
        rules = {
            'default': (lambda v : v),
            'tags'   : (lambda v : ','.join(v)),
        }
        return { 
            k: rules.get(k, rules['default'])(v)
            for k, v in data.items() 
            if v is not None
        }


    def _searchData(self, *args, **kwargs):
        A = { k: v for k, v in kwargs.items() if v is not None }

        if len(A.keys()) == 0:
            return {}
        
        if 'id_' in A:
            return TpmGet(self._module).get(id=A.get('id_'))

        result = TpmSearch(self._module).search(
            pattern=A.get('pattern', 'name:\"[{}]\"'.format(A.get('old_name')))
        )
        result_count = len(result)

        if result_count is not 1:
            raise ItemFoundError("Expected 1 result but found {}".format(result_count))

        return result[0]


    def createOrUpdate(self, data, id_=None, old_name=None, pattern=None):
        '''
        Create or Update data in TPM
        Return id of created data or nothing if update
        '''
        id_found = self._searchData(id_=id_, old_name=old_name, pattern=pattern).get('id', None)

        if not id_found:
            self.create(data=self._convertData(data))
        else:
            self.update(id_=id_found, data=self._convertData(data))


    def create(self, data):
        '''
        Create data in TPM
        Return id of created data
        '''
        path = 'api/v4/passwords.json'
        data.update(TpmGenerate(self._module).generate())
        body = json.dumps(data)
        url_params = self.get_urlparams(path=path, body=body,
            method='POST',
            url='https://{}/index.php/{}'.format(
                self._module.params.get('tpm_hostname'), path),
            data=bytes(body, encoding='utf-8')
        )
        r = open_url(**url_params)
        if r.status is not 201:
            raise CreateFailedError('[{}] {} : {} - {}'.format(r.version, r.status, r.msg, r.reason))
        return json.load(r)


    def update(self, id_, data):
        '''
        Update data in TPM
        Return nothing
        '''
        data.pop('project_id')
        path = 'api/v4/passwords/{}.json'.format(id_)
        body = json.dumps(data)
        url_params = self.get_urlparams(path=path, body=body, 
            method='PUT',
            url='https://{}/index.php/{}'.format(
                self._module.params.get('tpm_hostname'), path),
            data=bytes(body, encoding='utf-8')
        )
        r = open_url(**url_params)
        if r.status is not 204:
            raise UpdateFailedError('[{}] {} : {} - {}'.format(r.version, r.status, r.msg, r.reason))


def main():
    module = AnsibleModule(argument_spec=init_arg_spec(
        id=dict(type='int', required=False, default=None),
        old_name=dict(type='str', required=False, default=None),
        pattern=dict(type='str', required=False, default=None),
        data=dict(type='dict', required=True, options=dict(
            name=dict(type='str', required=True),
            project_id=dict(type='int', required=False),
            tags=dict(type='list', required=False),
            access_info=dict(type='str', required=False),
            username=dict(type='str', required=False),
            email=dict(type='str', required=False),
            password=dict(type='str', required=False),
            expiry_date=dict(type='str', required=False),
            notes=dict(type='str', required=False),
            custom_data1=dict(type='str', required=False),
            custom_data2=dict(type='str', required=False),
            custom_data3=dict(type='str', required=False),
            custom_data4=dict(type='str', required=False),
            custom_data5=dict(type='str', required=False),
            custom_data6=dict(type='str', required=False),
            custom_data7=dict(type='str', required=False),
            custom_data8=dict(type='str', required=False),
            custom_data9=dict(type='str', required=False),
            custom_data10=dict(type='str', required=False),
        )),
    ))

    try:
        result = TpmCreate(module).createOrUpdate(
            data=module.params.get('data'),
            id_=module.params.get('id'),
            old_name=module.params.get('old_name'),
            pattern=module.params.get('pattern'),
        )

    except Exception as e:
        stack = traceback.format_exc().splitlines()
        module.fail_json(is_error=True, error_type=type(e).__name__, msg=str(e), stacktrace=stack)

    else:
        module.exit_json(changed=True, result=result)


if __name__ == "__main__":
    main()
