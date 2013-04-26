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
import time
import bcrypt
import unittest
import pkg_resources
import simplejson as json
from pprint import pprint, pformat

import vccs_auth
from vccs_auth.vccs_authbackend import AuthBackend
import ndnkdf

import pyhsm
import struct

import cherrypy
import cptestcase


class FakeCredentialStore():

    def __init__(self, creds=None):
        if not creds:
            creds = {4711: {'status' : 'active',
                            'derived_key' : '41f8f2950cd0304999346d250aef82c5ff99ef45fe8437af470e421348300af7'
                            '256cb3b55d48459fa9787ecfb963d2b2a77070d64b647f71c460b2399c451fb7',
                            'version' : 'NDNv1',
                            'iterations' : 50000,
                            'key_handle' : 0x2000,
                            'salt' : '7e1d2271b58a779a5936a656218faedb',
                            'kdf' : 'PBKDF2-HMAC-SHA512',
                            'type' : 'password',
                            'credential_id' : 4711
                            },
                     }
        self.creds = creds

    def get_credential(self, cred_id, check_revoked=True):
        if cred_id in self.creds:
            metadata = {}
            return vccs_auth.credential.from_dict(self.creds[cred_id], metadata, check_revoked=check_revoked)
        else:
            #raise ValueError('Test have no credential with id {!r}'.format(cred_id))
            return None

    def add_credential(self, cred):
        cred_id = cred.id()
        if cred_id in self.creds:
            raise ValueError('Test already have credential with id {!r}'.format(cred_id))
        self.creds[cred_id] = cred.to_dict()
        return True

    def update_credential(self, cred):
        cred_id = cred.id()
        if cred_id not in self.creds:
            raise ValueError('Test does not have credential with id {!r}'.format(cred_id))
        self.creds[cred_id] = cred.to_dict()
        return True


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
                     0x2001: str('2001' * 16).decode('hex'),
                     }
        self.hasher = vccs_auth.hasher.VCCSSoftHasher(self.keys, vccs_auth.hasher.NoOpLock())
        self.logger = FakeLogger()

        #cherrypy.root = AuthBackend(self.hasher, self.kdf, self.logger, self.credstore, self.config)

        self.authbackend = AuthBackend(self.hasher, self.kdf, self.logger, self.credstore,
                                       self.config, expose_real_errors=True)
        cherrypy.tree.mount(self.authbackend, '/')
        cherrypy.engine.start()

        self.bcrypt_salt1 = '$2a$08$Ahy51oCM6Vg6d.1ScOPxse'

    def tearDown(self):
        cherrypy.engine.exit()

    def _bcrypt_hash(self, plaintext):
        bcrypt_hashed = bcrypt.hashpw(plaintext, self.bcrypt_salt1)
        return bcrypt_hashed[len(self.bcrypt_salt1):]

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

        # try again with blinding
        self.authbackend.expose_real_errors = False
        response = self.request('/authenticate', request=j, return_error=True)
        self.assertEqual(response.output_status, '500 Internal Server Error')

    def test_auth_missing_data(self):
        """
        Verify auth request with missing data is rejected
        """
        for req_field in ['version', 'user_id', 'factors']:
            a = {'auth':
                     {'version': 1,
                      'user_id': 'ft@example.net',
                      'factors': [],
                      }
                 }
            del a['auth'][req_field]
            j = json.dumps(a)
            response = self.request('/authenticate', request=j, return_error=True)
            self.assertIn("No '{!s}' in request".format(req_field), response.body[0])


    def test_auth_request1(self):
        """
        Verify correct authentication request
        """
        H1 = self._bcrypt_hash('plaintext')
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


    def test_auth_request2(self):
        """
        Verify correct authenticate request with incorrect password
        """
        H1 = self._bcrypt_hash('textplain')
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

    def test_auth_request3(self):
        """
        Verify authenticate request without credentials
        """
        H1 = self._bcrypt_hash('plaintext')
        a = {'auth':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': []
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '501 Not Implemented')
        self.assertEqual(response.body, [])

    def test_auth_request4(self):
        """
        Verify authenticate request with imaginary credential type
        """
        a = {'auth':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [{'type': 'promise'}]
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '200 OK')
        res = json.loads(response.body[0])
        expected = {'auth_response':
                        {'version': 1,
                         'authenticated': False,
                         }
                    }
        self.assertEqual(res, expected)

    def test_auth_request5(self):
        """
        Verify correct authentication request but with unknown credential
        """
        H1 = self._bcrypt_hash('plaintext')
        a = {'auth':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': 9898,
                     }
                    ]
                  }
             }
        j = json.dumps(a)
        response = self.request('/authenticate', request=j, return_error=True)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '500 Internal Server Error')
        self.assertIn('Unknown credential: 9898', response.body[0])


    def test_add_creds_request1(self):
        """
        Verify correct add_credentials password request
        """
        H1 = self._bcrypt_hash('foobar')
        cred_id = 4720
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': cred_id,
                     }
                    ]
                  }
             }
        j = json.dumps(a)

        # make sure credential does not exist in credstore
        self.assertIsNone(self.credstore.get_credential(cred_id))

        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        res = json.loads(response.body[0])
        expected = {'add_creds_response':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)

        cred = self.credstore.get_credential(cred_id)
        print "CRED {!r}".format(cred)
        self.assertEqual(cred.id(), cred_id)
        self.assertEqual(cred.status(), 'active')
        self.assertGreater(cred.iterations(), 20000)


    def test_add_creds_request2(self):
        """
        Verify correct add_credentials OATH request
        """
        key_handle = self.config.add_creds_oath_key_handle
        test_key = str('aa' * 20).decode('hex')
        nonce = '010203040506'.decode('hex')
        flags = struct.pack('< I', pyhsm.defines.YSM_HMAC_SHA1_GENERATE)
        aead = pyhsm.soft_hsm.aesCCM(self.keys[key_handle], key_handle, nonce,
                                     test_key + flags, decrypt = False)
        cred_id = 4740
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'aead': aead.encode('hex'),
                     'credential_id': cred_id,
                     'digits': 6,
                     'nonce': nonce.encode('hex'),
                     'oath_counter': 0,
                     'type': 'oath-hotp',
                     },
                    ]
                  }
             }
        j = json.dumps(a)

        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        res = json.loads(response.body[0])
        expected = {'add_creds_response':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)

        cred = self.credstore.get_credential(cred_id)
        print "CRED {!r}".format(cred)
        self.assertEqual(cred.id(), cred_id)
        self.assertEqual(cred.type(), 'oath-hotp')

    def test_add_creds_request3(self):
        """
        Verify add_credentials from wrong source IP
        """
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [],
                  },
             }
        j = json.dumps(a)

        response = self.request('/add_creds', return_error=True, remote_hp='127.128.129.130:50001',
                                request=j)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '403 Forbidden')

    def test_add_creds_request4(self):
        """
        Verify correct add_credentials password request with more than one factor

        More than one factor is currently not allowed, as it is not specified how
        error handling would work (one factor succeeds, next does not).
        """
        H1 = self._bcrypt_hash('foobar')
        cred_id = 4750
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': cred_id,
                     },
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': cred_id + 1,
                     }
                    ]
                  }
             }
        j = json.dumps(a)

        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '501 Not Implemented')

    def test_add_creds_request5(self):
        """
        Test adding credential that already exists
        """
        H1 = self._bcrypt_hash('foobar')
        cred_id = 4711
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': cred_id,
                     }
                    ]
                  }
             }
        j = json.dumps(a)

        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE1 {!r}: {!r}".format(response.status, response.body)
        self.assertIn('Test already have credential with id 4711', response.body[0])
        self.assertEqual(response.output_status, '500 Internal Server Error')

        # try again with blinding
        self.authbackend.expose_real_errors = False
        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE2 {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '500 Internal Server Error')
        self.assertEqual(response.body, [])


    def test_revoke_creds_request1(self):
        """
        Verify correct revoke_creds request
        """
        H1 = self._bcrypt_hash('foobar')
        cred_id = 4721
        a = {'add_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': cred_id,
                     }
                    ]
                  }
             }
        j = json.dumps(a)

        # make sure credential does not exist in credstore
        self.assertIsNone(self.credstore.get_credential(cred_id))

        response = self.request('/add_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        res = json.loads(response.body[0])
        expected = {'add_creds_response':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)

        cred = self.credstore.get_credential(cred_id)
        print "ADDED CRED {!r}".format(cred)
        self.assertEqual(cred.status(), 'active')

        # Now, revoke the credential we added
        a = {'revoke_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'reason': 'Just testing',
                     'reference': '',
                     'credential_id': cred_id,
                     }
                    ]
                  }
             }
        j = json.dumps(a)
        response = self.request('/revoke_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        res = json.loads(response.body[0])
        expected = {'revoke_creds_response':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)

        revoked = self.credstore.get_credential(cred_id, check_revoked=False)
        print "REVOKED CRED {!r}".format(revoked)
        self.assertEqual(revoked.status(), 'revoked')
        got_info = revoked.revocation_info()
        print "REVOCATION INFO: {!r}".format(got_info)
        expected_info = {'timestamp': got_info.get('timestamp'),  # copy since it is a timestamp
                         'client_ip': '127.0.0.127',
                         'reason': 'Just testing',
                         'reference': '',
                         }
        self.assertEqual(revoked.revocation_info(), expected_info)
        # check the timestamp
        now = int(time.time())
        self.assertGreater(got_info.get('timestamp'), now - 10)
        self.assertLess(got_info.get('timestamp'), now + 1)

        with self.assertRaises(vccs_auth.credential.VCCSAuthCredentialError):
            # make sure an exception is raised for revoked credential without check_revoked=False
            self.credstore.get_credential(cred_id)

    def test_revoke_creds_request2(self):
        """
        Verify revoke_creds for unknown credential
        """
        H1 = self._bcrypt_hash('foobar')
        cred_id = 0
        a = {'revoke_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [
                    {'reason': 'Just testing',
                     'reference': '',
                     'credential_id': cred_id,
                     }
                    ]
                  }
             }
        j = json.dumps(a)

        response = self.request('/revoke_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE1 {!r}: {!r}".format(response.status, response.body)
        self.assertIn('Unknown credential: 0', response.body[0])
        self.assertEqual(response.output_status, '500 Internal Server Error')

        # try again with blinding
        self.authbackend.expose_real_errors = False
        response = self.request('/revoke_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                request=j)
        print "RESPONSE2 {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '500 Internal Server Error')
        self.assertEqual(response.body, [])

    def test_revoke_missing_data(self):
        """
        Verify revoke request with missing data is rejected
        """
        for req_field in ['credential_id', 'reason', 'reference']:
            a = {'revoke_creds':
                     {'version': 1,
                      'user_id': 'ft@example.net',
                      'factors': [
                        {'reason': 'Just testing',
                         'reference': '',
                         'credential_id': 4750,
                         }
                        ]
                      }
                 }
            del a['revoke_creds']['factors'][0][req_field]
            j = json.dumps(a)
            response = self.request('/revoke_creds', return_error=True, remote_hp='127.0.0.127:50001',
                                    request=j)
            self.assertIn("No '{!s}' in credential to revoke".format(req_field), response.body[0])

    def test_revoke_creds_request3(self):
        """
        Verify revoke_creds from wrong source IP
        """
        a = {'revoke_creds':
                 {'version': 1,
                  'user_id': 'ft@example.net',
                  'factors': [],
                  },
             }
        j = json.dumps(a)

        response = self.request('/revoke_creds', return_error=True, remote_hp='127.128.129.130:50001',
                                request=j)
        print "RESPONSE {!r}: {!r}".format(response.status, response.body)
        self.assertEqual(response.output_status, '403 Forbidden')
