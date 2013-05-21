#
# Copyright (c) 2013 NORDUnet A/S
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
"""
Configuration (file) handling for VCCS.
"""

import ConfigParser

import pyhsm.util

from vccs_auth.common import VCCSAuthenticationError

_CONFIG_DEFAULTS = {'debug': False, # overwritten in VCCSAuthConfig.__init__()
                    'yhsm_device': '/dev/ttyACM0',
                    'num_threads': '8',
                    'nettle_path': '',
                    'logdir': None,
                    'mongodb_uri': '127.0.0.1',
                    'add_creds_allow': '', # comma-separated list of IP addresses
                    'revoke_creds_allow': '', # comma-separated list of IP addresses
                    'listen_port': '8550',
                    'kdf_min_iterations': '20000',
                    'kdf_max_iterations': '500000',
                    'add_creds_password_version': 'NDNv1',
                    'add_creds_password_key_handle': None,
                    'add_creds_password_kdf_iterations': '50000',
                    'add_creds_password_salt_bytes': str(128 / 8),
                    'add_creds_oath_version': 'NDNv1',
                    'add_creds_oath_key_handles_allow': [], # comma-separated list of integers
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
        self._parsed_revoke_creds_allow = \
            [x.strip() for x in self.config.get(self.section, 'revoke_creds_allow').split(',')]
        tmp_key_handles = self.config.get(self.section, 'add_creds_oath_key_handles_allow').split(',')
        self._parsed_add_creds_oath_key_handles_allow = \
            [pyhsm.util.key_handle_to_int(x.strip()) for x in tmp_key_handles]

    @property
    def yhsm_device(self):
        """
        YubiHSM device filename (string), typically '/dev/ttyACM0'.
        """
        return self.config.get(self.section, 'yhsm_device')

    @property
    def num_threads(self):
        """
        Number of worker threads to start (integer).

        VCCS spawns multiple threads to make use of all CPU cores in the KDF function.
        Number of threads should probably be about 2x number of cores to 4x number of
        cores (if hyperthreading is available).
        """
        return self.config.getint(self.section, 'num_threads')

    @property
    def nettle_path(self):
        """
        Path to Nettle library (string), if the system's Nettle is not new enough.

        This parameter is passed to ndnkdf. See ndnkdf for more detailed requirements.
        """
        res = self.config.get(self.section, 'nettle_path')
        if not res:
            res = None
        return res

    @property
    def logdir(self):
        """
        Path to CherryPy logfiles (string). Something like '/var/log/vccs' maybe.
        """
        res = self.config.get(self.section, 'logdir')
        if not res:
            res = None
        return res

    @property
    def mongodb_uri(self):
        """
        MongoDB connection URI (string). See MongoDB documentation for details.
        """
        return self.config.get(self.section, 'mongodb_uri')

    @property
    def add_creds_allow(self):
        """
        List of IP addresses from which to accept add_creds commands (string).

        Comma-separated list of IP addresses.
        """
        return self._parsed_add_creds_allow

    @property
    def revoke_creds_allow(self):
        """
        List of IP addresses from which to accept revoke_creds commands (string).

        Comma-separated list of IP addresses.
        """
        return self._parsed_revoke_creds_allow

    @property
    def debug(self):
        """
        Set to True to log debug messages (boolean).
        """
        return self.config.getboolean(self.section, 'debug')

    @property
    def kdf_min_iterations(self):
        """
        Key derivation function minumum number of iterations to accept (integer).

        The default is set to 20000, but this should be increased substantially
        for every year that passes after 2013.
        """
        return self.config.getint(self.section, 'kdf_min_iterations')

    @property
    def kdf_max_iterations(self):
        """
        Key derivation function maximum number of iterations to accept (integer).

        A credential with a huge number of iterations would cause a denial of
        service when used.
        """
        return self.config.getint(self.section, 'kdf_max_iterations')

    @property
    def listen_port(self):
        """
        The port the VCCS authentication backend should listen on (integer).
        """
        return self.config.getint(self.section, 'listen_port')

    @property
    def add_creds_password_version(self):
        """
        Add password credentials using this version (string).

        This is just a tunable parameter in case more than one version of
        password credentials exists in the future.
        """
        return self.config.get(self.section, 'add_creds_password_version')

    @property
    def add_creds_password_key_handle(self):
        """
        Add password credentials using this key handle (integer).

        When computing the local parameter, using a YubiHSM presumably, this is the
        key handle that will be used.
        """
        res = self.config.get(self.section, 'add_creds_password_key_handle')
        if not res:
            raise VCCSAuthenticationError("add_creds_password_key_handle not set")
        return pyhsm.util.key_handle_to_int(res)

    @property
    def add_creds_password_kdf_iterations(self):
        """
        Use this number of KDF iterations when adding password credentials (integer).
        """
        return self.config.getint(self.section, 'add_creds_password_kdf_iterations')

    @property
    def add_creds_password_salt_bytes(self):
        """
        Use this many bytes of salt when adding password credentials (integer).
        """
        return self.config.getint(self.section, 'add_creds_password_salt_bytes')

    @property
    def add_creds_oath_version(self):
        """
        Add OATH credentials using this version (string).

        This is just a tunable parameter in case more than one version of
        OATH credentials exists in the future.
        """
        return self.config.get(self.section, 'add_creds_oath_version')

    @property
    def add_creds_oath_key_handles_allow(self):
        """
        Allow new OATH credentials protected using one of these key handles (integer).

        Comma-separated list of integers (decimal or hexadecimal).

        This is really a requirement for the generating application to use one of
        these key handles, or the AEADs generated can't be validated and will not
        be accepted for addition to the credential store.
        """
        return self._parsed_add_creds_oath_key_handles_allow
