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

"""
Test (MongoDB-based) credential store. Requires a mongod on localhost.
"""

import pymongo
import unittest
from pprint import pprint, pformat

import vccs_auth
from vccs_auth.credstore import VCCSAuthCredentialStoreMongoDB as VCCS_MongoDB

class TestCredStore(unittest.TestCase):

    def setUp(self):
        try:
            self.mdb = VCCS_MongoDB(host='127.0.0.1', port=27017, collection="TEST_vccs_auth_credstore_TEST")
        except:
            raise unittest.SkipTest("requires accessible MongoDB server on 127.0.0.1")
        self.cred_data = {'type':          'password',
                          'kdf':           'PBKDF2-HMAC-SHA512',
                          'status':        'active',
                          'version':       'NDNv1',
                          'derived_key':   'aa' * (512 / 8),
                          'key_handle':    0x2000,
                          'iterations':    100,
                          'credential_id': 4711,
                          'salt':          '12345678901234567890123456789012',
                          }

    def test_mdb_aaa_empty_collection(self):
        """
        Empty collection of any leftovers from previous runs.
        """
        res = self.mdb.credentials.remove()
        self.assertEqual(res['err'], None)

    def test_mdb_add_credential(self):
        """
        Test adding a credential to MongoDB credential store.
        """
        cred = vccs_auth.credential.from_dict(self.cred_data, None)
        id_ = self.mdb.add_credential(cred)
        print("Added credential -> id : {!r}".format(id_))

        cred2 = self.mdb.get_credential(self.cred_data['credential_id'])
        print("Fetched credential :\n{}".format(pformat(cred2)))

        self.assertEqual(cred2.to_dict(), self.cred_data)

    def test_mdb_add_duplicate_credential(self):
        """
        Test adding a duplicate credential to MongoDB credential store.
        """
        this_id = 9797
        data = self.cred_data
        data['credential_id'] = this_id
        cred = vccs_auth.credential.from_dict(data, None)
        self.mdb.add_credential(cred)
        with self.assertRaises(pymongo.errors.DuplicateKeyError):
            self.mdb.add_credential(cred)

    def test_mdb_get_unknown_credential(self):
        """
        Test fetching unknown credential.
        """
        res = self.mdb.get_credential(1234567890)
        self.assertEqual(res, None)

    def test_mdb_revoking_credential(self):
        """
        Test revoking a credential.
        """
        this_id = 9898
        data = self.cred_data
        data['credential_id'] = this_id
        cred = vccs_auth.credential.from_dict(data, None)
        self.mdb.add_credential(cred)

        # assert no exception
        cred2 = self.mdb.get_credential(this_id)

        print("Revoking credential :\n{}".format(pformat(cred2)))

        cred2.revoke({'reason': 'unit testing'})
        self.mdb.update_credential(cred2)

        # assert exception when fetching revoked credential
        with self.assertRaises(vccs_auth.credential.VCCSAuthCredentialError):
            self.mdb.get_credential(this_id)

        # assert exception when trying to activate credential again
        with self.assertRaises(ValueError):
            cred2.status('active')

    def test_mdb_credential_repr(self):
        """
        Test the __repr__ method of a credential.
        """
        cred = vccs_auth.credential.from_dict(self.cred_data, None)
        res = repr(cred)
        print "Credential : {!r}".format(res)
        self.assertTrue(hex(self.cred_data['key_handle']) in res)
        self.assertTrue(self.cred_data['type'] in res)
