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
module: microfocus_oo_getFlow

short_description: Manage execution flows from Microfocus Operations Orchestration

version_added: "2.9"

description: 
- 

options:
    oo_hostname:
        description: 
        - Hostname of targeted OO instance without scheme. (ex: microfocus.com)
        required: true
        type: str

    oo_username:
        description: 
        - 
        required: true
        type: str

    oo_password:
        description:
        -
        required: true
        type: str

    ssl_verify:
        description:
        -
        required: false
        type: bool
        default: false

    force_basic_auth:
        description:
        -
        required: false
        type: bool
        default: true

    path_or_id:
        description:
        -
        type: str
        required: true

    runName:
        description:
        -
        type: str
        required: false

    inputs:
        type: dict
        required: false

    logLevel:
        type: str
        required: false
        default: INFO
        choices:
            - DEBUG
            - INFO
            - ERROR

'''

EXAMPLES = r'''

'''

RETURN = r'''

result:
    type: list


'''


import json
from fnmatch import fnmatch

try:
    from urllib import (quote,urlencode,HTTPError) # Python 2.x
except ImportError:
    from urllib.parse import (quote,urlencode)     # Python 3+
    from urllib.error import (HTTPError)

from ansible.module_utils.basic import (AnsibleModule)
from ansible.module_utils.urls  import (open_url)

from _microfocus_oo_commons import (
    generate_argument_spec,
    OOBase,
)


class OOGetFlow(OOBase):
    def __init__(self, module):
        super().__init__(module)

    def _path_or_uuid(self, path_or_uuid=None):
        return path_or_uuid or self._module.params.get('path_or_id')

    def get(self, path_or_uuid=None):
        path_or_uuid = self._path_or_uuid(path_or_uuid)
        return self._by_uuid(self.get_id(path_or_uuid))

    def get_id(self, path_or_uuid=None):
        path_or_uuid = self._path_or_uuid(path_or_uuid)
        return path_or_uuid if self._isUuid(path_or_uuid) else self._query(path_or_uuid)

    def _query(self, path=None):
        path_splited = path.split('/')
        level = '/'.join(path_splited[:-1])
        r = open_url(**self.get_url_params(
            path='flows/tree/level?path={}'.format(quote(level)),
        ))
        try:
            response = next(i for i in json.load(r) if i['path'] == path)
        except StopIteration as e:
            self._module.fail_json(
                change=False,
                msg='Empty result returned by server',
                error_type='EmptyResult',
            )
        else:
            return response['id']

    def _by_path(self, path):
        return self._by_uuid(uuid=self.get_id(path))

    def _by_uuid(self, uuid):
        r = open_url(**self.get_url_params(
            path='flows/{}'.format(uuid)
        ))
        return json.load(r)


def main():
    argument_spec = generate_argument_spec(
        path_or_id   = dict(type='str', required=True),
    )

    try:
        module = AnsibleModule(argument_spec=argument_spec)
        result = OOGetFlow(module).get(path_or_uuid=module.params.get('path_or_id'))
    
    except HTTPError as e:
        module.fail_json(
            msg=e.msg, 
            error_type='HTTP', 
            error_code=e.code, 
        )
    
    else:
        module.exit_json(change=False, result=result)


if __name__ == '__main__':
    main()
