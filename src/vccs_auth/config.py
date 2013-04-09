#!/usr/bin/python
#
# Copyright (c) 2013, NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import os
import ConfigParser

import pyhsm.util

from vccs_auth.common import VCCSAuthenticationError

_CONFIG_DEFAULTS = {'debug': False, # overwritten in VCCSAuthConfig.__init__()
                    'yhsm_device': '/dev/ttyACM0',
                    'num_threads': '8',
                    'nettle_path': '',
                    'mongodb_uri': '127.0.0.1',
                    'add_creds_allow': '', # comma-separated list of IP addresses
                    'listen_port': '8550',
                    'kdf_min_iterations': '20000',
                    'kdf_max_iterations': '500000',
                    'add_creds_password_version': 'NDNv1',
                    'add_creds_password_key_handle': None,
                    'add_creds_password_kdf_iterations': '50000',
                    'add_creds_password_salt_bytes': str(128 / 8),
                    'add_creds_oath_version': 'NDNv1',
                    'add_creds_oath_key_handle': None,
                    }

_CONFIG_SECTION = 'vccs_authbackend'

class VCCSAuthConfig():

    def __init__(self, filename, debug):
        self.section = _CONFIG_SECTION
        _CONFIG_DEFAULTS['debug'] = str(debug)
        self.config = ConfigParser.ConfigParser(_CONFIG_DEFAULTS)
        if not self.config.read([filename]):
            raise VCCSAuthenticationError("Failed loading config file {!r}".format(filename))
        # split on comma and strip. cache result.
        self._parsed_add_creds_allow = \
            [x.strip() for x in self.config.get(self.section, 'add_creds_allow').split(',')]

    @property
    def yhsm_device(self):
        return self.config.get(self.section, 'yhsm_device')

    @property
    def num_threads(self):
        return self.config.getint(self.section, 'num_threads')

    @property
    def nettle_path(self):
        res = self.config.get(self.section, 'nettle_path')
        if not res:
            res = None
        return res

    @property
    def mongodb_uri(self):
        return self.config.get(self.section, 'mongodb_uri')

    @property
    def add_creds_allow(self):
        return self._parsed_add_creds_allow

    @property
    def debug(self):
        return self.config.getboolean(self.section, 'debug')

    @property
    def kdf_min_iterations(self):
        return self.config.getint(self.section, 'kdf_min_iterations')

    @property
    def kdf_max_iterations(self):
        return self.config.getint(self.section, 'kdf_max_iterations')

    @property
    def listen_port(self):
        return self.config.getint(self.section, 'listen_port')

    @property
    def add_creds_password_version(self):
        return self.config.get(self.section, 'add_creds_password_version')

    @property
    def add_creds_password_key_handle(self):
        res = self.config.get(self.section, 'add_creds_password_key_handle')
        if not res:
            raise VCCSAuthenticationError("add_creds_password_key_handle not set")
        return pyhsm.util.key_handle_to_int(res)

    @property
    def add_creds_password_kdf_iterations(self):
        return self.config.getint(self.section, 'add_creds_password_kdf_iterations')

    @property
    def add_creds_password_salt_bytes(self):
        return self.config.getint(self.section, 'add_creds_password_salt_bytes')

    @property
    def add_creds_oath_version(self):
        return self.config.get(self.section, 'add_creds_oath_version')

    @property
    def add_creds_oath_key_handle(self):
        res = self.config.get(self.section, 'add_creds_oath_key_handle')
        if not res:
            raise VCCSAuthenticationError("add_creds_oath_key_handle not set")
        return pyhsm.util.key_handle_to_int(res)

