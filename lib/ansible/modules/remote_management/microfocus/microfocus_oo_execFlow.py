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
module: microfocus_oo_execFlow

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls  import open_url

from _microfocus_oo_commons import (
    get_url_params_from_module,
    generate_argument_spec,
    OOBase,
)
from microfocus_oo_getFlow import (
    OOGetFlow,
)
from microfocus_oo_getExecution import (
    OOGetExec,
)

class OOExecFlow(OOBase):
    def __init__(self, module):
        super().__init__(module)
        self._path = 'executions
        self._url_method = 'POST'

    def exec(self, path_or_id, logLevel='STANDARD', inputs=dict()):
        data = dict(
            flowUuid=OOGetFlow(self._module).get_id(path_or_id),
            logLevel=logLevel,
            inputs=inputs,
        )
        r = open_url(**self.get_url_params(
            path=self._path, 
            data=bytes(json.dumps(data), encoding='utf-8')),
        )
        response = r.read().decode('utf-8')

        # Wait until execution end
        if self._module.params.get('synchronized'):
            from time import sleep
            status = 'RUNNING'
            while status is not in ['COMPLETED', 'SYSTEM_FAILURE', 'CANCELED']:
                exec_ = OOGetExec(self._module).get_log(id=response)
                status = exec_.get('status')
                sleep(5)

        return response

def main():
    argument_spec = generate_argument_spec(
        path_or_id   = dict(type='str', required=True),
        runName      = dict(type='str', required=False),
        inputs       = dict(type='dict', required=False),
        logLevel     = dict(type='str', required=False, choices=_LOG_LEVELS, default='INFO'),
        synchronized = dict(type='bool', required=False, default=False),
    )

    try:
        module = AnsibleModule(argument_spec=argument_spec)
        result = OOExecFlow(module).exec(path_or_id=module.params.get('path_or_id'))
    
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
