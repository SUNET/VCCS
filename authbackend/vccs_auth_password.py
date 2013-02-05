#!/usr/bin/python
#
# Copyright (c) 2012, 2013, NORDUnet A/S
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

import vccs_auth_common
from vccs_auth_common import AuthenticationError

class VccsPasswordFactor():
    """
    Password authentication factor.

    The backend part of password based authentication is basically to use a YubiHSM
    to implement a "local parameter" (meaning a transformation of the password using
    a cryptographic key that can't be known to a remote attacker - the key is assumed
    to never, ever, be available on a host connected to the Internet), and the use
    of the NIST approved PBKDF2-HMAC-SHA512 algorithm for key stretching.
    """

    _MIN_ITERATIONS = 5000
    _MAX_ITERATIONS = 100000
    _NDNv1_DIGEST_SIZE = 64

    def __init__(self, req, user_id):
        self.type = 'password'
        self._user_id = str(user_id)
        self._H1 = str(req['H1'])
        self._credential_id = str(req['credential_id'])
        (self._salt_version, self._kdf, self._key_handle, self._iterations, self._credential_stored_hash) = \
            self._parse_credential_hash(req['credential'])
        if self._salt_version == 'NDNv1':
            # check if the stored hash has any chance of matching our hash output, before computing
            if len(self._credential_stored_hash) != (self._NDNv1_DIGEST_SIZE * 2):
                raise AuthenticationError("Bad NDNv1 credential hash : {!r}".format(self._credential_stored_hash))

    def authenticate(self, hasher, kdf, logger):
        """
        Handle a password authentication request, along the following pseudo-code :

        On backend :
        ------------
        T = 'A' | user_id | credential_id | H1  // Lock down key usage & credential to auth
        salt = yhsm_hmac_sha1(T)
        H2 = PBKDF2-HMAC-SHA512(T, salt)        // Go from 192+160=352 to 512 bits

        audit_log(frontend_id, credential_id, H2, credential_stored_hash)

        return (H2 == credential_stored_hash)
        """

        # Lock down key usage & credential to auth
        T = '|'.join(['A', self.user_id(), self.cred_id(), self.H1()])

        try:
            salt = hasher.safe_hmac_sha1(self.key_handle(), T)
        except Exception, e:
            raise AuthenticationError("Hashing operation failed : {!s}".format(e))

        # Go from 192+160=352 to 512 bits
        H2 = kdf.pbkdf2_hmac_sha512(T, self.iterations(), salt)

        self._audit_log(logger, self.cred_id(), H2, self.cred_hash())

        return (H2.encode('hex') == self.cred_hash())

    def _audit_log(self, logger, credential_id, H2, credential_stored_hash):
        """
        Create audit trail.
        """
        H2_hex = H2.encode('hex')
        if H2_hex == credential_stored_hash:
            logger.audit("result=OK, factor=password, credential_id={cid!r}, H2={h2!r}".format( \
                    cid = credential_id, h2 = H2_hex))
        else:
            logger.audit("result=FAIL, factor=password, credential_id={cid!r}, H2={h2!r}, stored={stored!r}".format( \
                    cid = credential_id, h2 = H2_hex, stored = credential_stored_hash))

    def _parse_credential_hash(self, data):
        """
        Parse credential_stored_hash received from frontend.
        (format: $NDNv1$hex_key_handle$iterations$pwhash-as-hex$)
        """
        cred_parts = data.split('$')
        if len(cred_parts) > 1 and cred_parts[1] == 'NDNv1':
            try:
                (_empty, _kdfver, key_handle, iterations, pwhash, _empty,) = cred_parts
                if not pwhash:
                    raise ValueError
            except ValueError, e:
                raise AuthenticationError("Bad NDNv1 salt : {!r}".format(cred_parts))

            try:
                # decode hex
                key_handle = int(key_handle, 16)
            except ValueError:
                raise AuthenticationError("Invalid NDNv1 key_handle: {!r}".format(key_handle))

            # too few iterations is insecure, too large might be a DoS
            try:
                iterations = int(iterations)
            except ValueError:
                raise AuthenticationError("Bad NDNv1 iterations: {!r}".format(iterations))
            if iterations < self._MIN_ITERATIONS or iterations > self._MAX_ITERATIONS:
                raise AuthenticationError("Bad NDNv1 iterations count: {}".format(iterations))

            # 16 bytes minimum (pwhash is hex encoded, so 32)
            if len(pwhash) < 32:
                raise AuthenticationError("Bad NDNv1 pwhash length: {}".format(len(pwhash)))
            return(cred_parts[1], 'PBKDF2-HMAC-SHA512', key_handle, iterations, pwhash)
        else:
            raise AuthenticationError("Unknown salt format : {!r}".format(data))

    def H1(self):
        """
        Return the H1 parameter, which is computed on the authentication frontend
        and sent to backend as part of authentication request.
        """
        return self._H1

    def user_id(self):
        """
        The user id, fetched from userdb on authentication frontend and
        sent to backend as part of authentication request.
        """
        return self._user_id

    def cred_id(self):
        """
        The credential id, fetched from userdb on authentication frontend and
        sent to backend as part of authentication request.
        """
        return self._credential_id

    def cred_hash(self):
        """
        The credentials stored hash, fetched from userdb on authentication
        frontend and sent to backend as part of authentication request.
        """
        return self._credential_stored_hash

    def kdf(self):
        """
        The Key Derivation Function in use. Encoded in the credential_stored_salt2
        the frontend sends to the backend as part of authentication request.

        Currently this backend only supports KDF 'NDNv1'.
        """
        return self._kdf

    def key_handle(self):
        """
        The iterations to pass to the KDF. Encoded in the credential_stored_salt2
        the frontend sends to the backend as part of authentication request.
        """
        return self._key_handle

    def iterations(self):
        """
        The iterations to pass to the KDF. Encoded in the credential_stored_salt2
        the frontend sends to the backend as part of authentication request.
        """
        return self._iterations
