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
Test the VCCS authbackend.
"""

import os
import sys
import bcrypt
import unittest
import pkg_resources
import simplejson as json
from pprint import pprint, pformat

import vccs_auth
from vccs_auth.vccs_authbackend import AuthBackend
import ndnkdf

import cherrypy
import cptestcase


class FakeCredentialStore():

    def get_credential(self, cred_id):
        data = {}
        metadata = {}
        if cred_id == 4711:
            data = {'status' : 'active',
                    'derived_key' : '41f8f2950cd0304999346d250aef82c5ff99ef45fe8437af470e421348300af7'
                                    '256cb3b55d48459fa9787ecfb963d2b2a77070d64b647f71c460b2399c451fb7',
                    'version' : 'NDNv1',
                    'iterations' : 50000,
                    'key_handle' : 0x2000,
                    'salt' : '7e1d2271b58a779a5936a656218faedb',
                    'kdf' : 'PBKDF2-HMAC-SHA512',
                    'type' : 'password',
                    'credential_id' : 4711
                    }
        else:
            raise ValueError('Test have no credential with id {!r}'.format(cred_id))
        return vccs_auth.credential.from_dict(data, metadata)


class FakeLogger():

    def set_context(self, _ctx):
        return

    def audit(self, data):
        sys.stdout.write("AUDIT: {!r}\n".format(data))

    def error(self, data, traceback=False):
        sys.stdout.write("ERROR: {!r}\n".format(data))

class TestAuthBackend(cptestcase.BaseCherryPyTestCase):

    def setUp(self):
        debug = False
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(datadir, 'test_config.ini')
        self.config = vccs_auth.config.VCCSAuthConfig(self.config_file, debug)
        self.credstore = FakeCredentialStore()
        self.kdf = ndnkdf.NDNKDF(self.config.nettle_path)
        self.keys = {0x2000: str('2000' * 16).decode('hex'),
                     }
        self.hasher = vccs_auth.hasher.VCCSSoftHasher(self.keys, vccs_auth.hasher.NoOpLock())
        self.logger = FakeLogger()

        #cherrypy.root = AuthBackend(self.hasher, self.kdf, self.logger, self.credstore, self.config)

        cherrypy.tree.mount(AuthBackend(self.hasher, self.kdf, self.logger, self.credstore,
                                        self.config, expose_real_errors=True), '/')
        cherrypy.engine.start()

    def tearDown(self):
        cherrypy.engine.exit()

    def test_bad_request(self):
        """
        Verify bad requests are rejected
        """
        response = self.request('/')
        self.assertEqual(response.output_status, '404 Not Found')

    def test_bad_request2(self):
        """
        Verify bad requests are rejected (right URL, no param)
        """
        response = self.request('/authenticate', return_error=True)
        self.assertIn('Failed parsing request', response.body[0])

    def test_auth_request_wrong_version(self):
        """
        Verify auth request with wrong version is rejected
        """
        a = {'auth':
                 {'version': 9999,
                  'user_id': 'ft@example.net',
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        self.assertIn('Unknown request version : 9999', response.body[0])

    def test_auth_request1(self):
        """
        Verify correct authenticate request
        """
        bcrypt_salt = '$2a$08$Ahy51oCM6Vg6d.1ScOPxse'
        bcrypt_plaintext = 'plaintext'
        bcrypt_hashed = bcrypt.hashpw(bcrypt_plaintext, bcrypt_salt)
        H1 = bcrypt_hashed[len(bcrypt_salt):]
        a = {'auth':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': 4711,
                     }
                    ]
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        res = json.loads(response.body[0])
        expected = {'auth_response':
                        {'version': 1,
                         'authenticated': True,
                         }
                    }
        self.assertEqual(res, expected)



    def test_auth_request1(self):
        """
        Verify correct authenticate request with incorrect password
        """
        bcrypt_salt = '$2a$08$Ahy51oCM6Vg6d.1ScOPxse'
        bcrypt_plaintext = 'textplain'
        bcrypt_hashed = bcrypt.hashpw(bcrypt_plaintext, bcrypt_salt)
        H1 = bcrypt_hashed[len(bcrypt_salt):]
        a = {'auth':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': 4711,
                     }
                    ]
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        res = json.loads(response.body[0])
        expected = {'auth_response':
                        {'version': 1,
                         'authenticated': False,
                         }
                    }
        self.assertEqual(res, expected)
