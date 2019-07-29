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
module: microfocus_oo_getExecution

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

    exec_ids:
        description:
        -
        type: list
        elements: str
        required: true

'''

EXAMPLES = r'''

'''

RETURN = r'''
result:
    type: list

'''


import re
import json
import base64
from fnmatch import fnmatch

try:
    from urllib import (quote,urlencode,HTTPError) # Python 2.x
except ImportError:
    from urllib.parse import (quote,urlencode)     # Python 3+
    from urllib.error import (HTTPError)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls  import open_url

from _microfocus_oo_commons import (
    get_url_params_from_module,
    generate_argument_spec,
    OOBase,
)


class OOGetExec(OOBase):
    def __init__(self, module):
        super().__init__(module)

    def get(self, ids=None):
        ids = ids or self._module.params.get('exec_ids') 
        url_params = self.get_url_params(
            path='executions/{:s}/summary'.format(','.join(ids)),
        )
        r = open_url(**url_params)
        return json.load(r)

    def get_log(self, id):
        url_params = self.get_url_params(
            path = 'executions/{:s}/execution-log'.format(id)
        )
        r = open_url(**url_params)
        return json.load(r)


def main():
    argument_spec = generate_argument_spec(
        exec_ids  = dict(type='list', elements='str', required=True),
    )

    try:
        module = AnsibleModule(argument_spec=argument_spec)
        result = OOGetExec(module).get()
    
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
