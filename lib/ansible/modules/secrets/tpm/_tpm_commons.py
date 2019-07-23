#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Cyril MARIN <marin.cyril@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json
import time

from ansible.module_utils.basic import env_fallback


### Exceptions
class NoneTypeError(Exception):
    """Value must not be None"""


class ItemFoundError(Exception):
    """Not as many item found as expected"""


### Classes
class TpmBase():
    def __init__(self, module):
        self._auth_method = module.params.get('tpm_auth_method')
        self._auth_methods = dict(
            basic=self._auth_basic,
            hmac=self._auth_hmac,
        )
        self._module = module

    def _auth_basic(self, *args, **kwargs):
        return {
            "headers": {
                'Content-Type': 'application/json; charset=utf-8',
            },
            "url_username": self._module.params.get('tpm_username'),
            "url_password": self._module.params.get('tpm_password'),
            "validate_certs": self._module.params.get('tpm_ssl_verify'),
            "force_basic_auth": True,
            **kwargs
        }

    def _auth_hmac(self, path, body, *args, **kwargs):
        if path is None:
            raise NoneTypeError("'path' is not defined")

        timestamp = str(int(time.time()))
        public_key = self._module.params.get('tpm_username')
        private_key = self._module.params.get('tpm_password')
        unhashed = [ path, timestamp, body ]
        return {
            "headers": {
                "X-Public-Key": public_key,
                "X-Request-Hash": self._sha256_signature(
                    key=private_key.encode('utf-8'),
                    msg=''.join(unhashed).encode('utf-8'),
                ),
                "X-Request-Timestamp": timestamp,
                "Content-Type": "application/json; charset=utf-8",
            },
            "validate_certs": self._module.params.get('tpm_ssl_verify'),
            **kwargs
        }

    def _sha256_signature(self, key, msg):
        import hmac, hashlib

        return hmac.new(
            digestmod=hashlib.sha256,
            key=key, msg=msg,
        ).hexdigest()

    def get_urlparams(self, path, body='', *args, **kwargs):
        return self._auth_methods[self._auth_method](path, body, **kwargs)


### Functions
def init_arg_spec(**more_arg_specs):
    arg_spec = _BASE_ARGUMENT_SPEC
    arg_spec.update({**more_arg_specs})
    return arg_spec


### Ansible custom module specifics
_BASE_ARGUMENT_SPEC = dict(
    tpm_hostname=dict(
        type='str', 
        required=True, 
        aliases=['tpm_host'],
        fallback=(env_fallback, ['TPM_HOST']),
    ),
    tpm_auth_method=dict(
        type='str', 
        required=False,
        default='basic', 
        choices=['basic', 'hmac'],
    ),
    tpm_username=dict(
        type='str', 
        required=True, 
        aliases=['tpm_user','tpm_public_key'], 
        fallback=(env_fallback, ['TPM_USER']),
    ),
    tpm_password=dict(
        type='str', 
        required=True, 
        aliases=['tpm_pass','tpm_private_key'], 
        fallback=(env_fallback, ['TPM_PASS']),
        no_log=True,
    ),
    tpm_ssl_verify=dict(
        type='bool', 
        required=False, 
        default=False,
    ),
)
