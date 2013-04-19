#!/usr/bin/python
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
Test OATH authentication.
"""

import os
import sys
import struct
import unittest
import pkg_resources
from pprint import pprint, pformat

import pyhsm

import vccs_auth

class FakeCredentialStore():

    def __init__(self, aeads, key_handle, cred_id):
        # aeads is dict {cred_id: (nonce, aead,)}
        self.aeads = aeads
        self.key_handle = key_handle
        self.cred_data = {cred_id: {'status' : 'active',
                                    'nonce' : self.aeads[cred_id][0],
                                    'version' : 'NDNv1',
                                    'credential_id' : cred_id,
                                    'key_handle' : self.key_handle,
                                    'aead' : self.aeads[cred_id][1],
                                    'type' : 'oath-hotp',
                                    'digits' : 6,
                                    'oath_counter' : 1,
                                    },
                          }

    def get_credential(self, cred_id):
        data = {}
        metadata = {}
        if cred_id not in self.cred_data:
            raise ValueError('Test have no credential with id {!r}'.format(cred_id))
        return vccs_auth.credential.from_dict(self.cred_data[cred_id], metadata)

    def update_credential(self, cred, safe=True):
        data = cred.to_dict()
        self.cred_data[data['credential_id']] = data
        return True


class FakeLogger():

    def audit(self, data):
        sys.stdout.write("AUDIT: {!r}\n".format(data))

class TestOathAuthentication(unittest.TestCase):

    def setUp(self):
        debug = False
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(datadir, 'test_config.ini')
        self.config = vccs_auth.config.VCCSAuthConfig(self.config_file, debug)
        key_handle = 0x2001
        self.keys = {key_handle: str('2001' * 16).decode('hex'),
                     }
        self.hasher = vccs_auth.hasher.VCCSSoftHasher(self.keys, vccs_auth.hasher.NoOpLock())
        self.logger = FakeLogger()
        # Generate an AEAD with the OATH RFC test key
        self.cred_id1 = 4712
        test_key = '3132333435363738393031323334353637383930'.decode('hex')
        nonce = '010203040506'.decode('hex')
        flags = struct.pack('< I', pyhsm.defines.YSM_HMAC_SHA1_GENERATE)
        aead = pyhsm.soft_hsm.aesCCM(self.keys[key_handle], key_handle, nonce,
                                     test_key + flags, decrypt = False)
        print "Generated AEAD {!r}".format(aead.encode('hex'))
        aeads = {self.cred_id1: (nonce, aead,),
                 }
        self.credstore = FakeCredentialStore(aeads, key_handle, self.cred_id1)

    def test_OATH_HOTP_1(self):
        """
        Test OATH TOTP authentication.
        """
        # this request matches the examples/example-oath-json output
        req = {
            'credential_id': self.cred_id1,
            'type': 'oath-hotp',
            'user_code': '338314',
            }
        factor = vccs_auth.oath.from_factor(req, 'auth', self.credstore, self.config)
        self.assertTrue(factor.authenticate(self.hasher, None, self.logger))

        # test with the same code again (should fail)
        self.assertFalse(factor.authenticate(self.hasher, None, self.logger))

        # test with next code (OATH RFC test vector, counter = 5)
        req['user_code'] = '254676'
        factor = vccs_auth.oath.from_factor(req, 'auth', self.credstore, self.config)
        self.assertTrue(factor.authenticate(self.hasher, None, self.logger))
