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
Common code for VCCS tests.
"""

import vccs_auth

class FakeCredentialStore():

    def __init__(self, creds=None):
        if not creds:
            creds = {'4711':
                         {'status' : 'active',
                          'derived_key' : '839bd4e7e3f5d06c460999a4fee460c8928a04eb19f52193d1d2fe8e0a3626ae'
                                          'a1bf5eb9faa211673a25946a0d7f1c3ae6e0d62a31a5b1149b64e84dde41b619',
                          'version' : 'NDNv1',
                          'iterations' : 50000,
                          'key_handle' : 0x2000,
                          'salt' : '7e1d2271b58a779a5936a656218faedb',
                          'kdf' : 'PBKDF2-HMAC-SHA512',
                          'type' : 'password',
                          'credential_id' : '4711',
                          },
                     }
        self.creds = creds

    def get_credential(self, cred_id, check_revoked=True):
        if not isinstance(cred_id, basestring):
            raise TypeError("non-string cred_id")
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

    def update_credential(self, cred, safe=True):
        cred_id = cred.id()
        if cred_id not in self.creds:
            raise ValueError('Test does not have credential with id {!r}'.format(cred_id))
        self.creds[cred_id] = cred.to_dict()
        return True
