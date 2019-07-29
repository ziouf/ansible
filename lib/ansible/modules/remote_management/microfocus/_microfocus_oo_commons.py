#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Cyril MARIN <marin.cyril@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import re


_UUID_MATCHER = re.compile(
    '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z', re.I)
_LOG_LEVELS = [
    'DEBUG',
    'STANDARD',
    'INFO',
    'ERROR',
]


class OOBase():
    def __init__(self, module):
        self._module = module
        self._base_url = 'https://{:s}/oo/rest'.format(module.params.get('oo_hostname'))
        self._url_method = 'GET'

    def _isUuid(self, path_or_uuid):
        return bool(_UUID_MATCHER.match(path_or_uuid))

    def get_url_params(self, path='', headers={}, data=None):
        headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })
        return dict(
            method=self._url_method,
            url='{:s}/{:s}'.format(self._base_url, path),
            url_username=self._module.params.get('oo_username'),
            url_password=self._module.params.get('oo_password'),
            validate_certs=self._module.params.get('ssl_verify'),
            force_basic_auth=self._module.params.get('force_basic_auth'),
            headers=headers,
            data=data,
        )


_ARG_SPEC = dict(
    oo_hostname=dict(type='str', required=True),
    oo_username=dict(type='str', required=True),
    oo_password=dict(type='str', required=True, no_log=True),
    oo_api_version=dict(type='int', required=False, default=2),
    ssl_verify=dict(type='bool', required=False, default=False),
    force_basic_auth=dict(type='bool', required=False, default=True),
)

def generate_argument_spec(*args, **kwargs):
    from collections import ChainMap
    return dict(ChainMap(_ARG_SPEC, kwargs))
