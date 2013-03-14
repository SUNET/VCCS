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

from vccs_auth_common import VCCSAuthenticationError

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

    def __init__(self, req, user_id, credstore):
        self.type = 'password'
        self._user_id = str(user_id)
        self._H1 = str(req['H1'])
        self.cred = credstore.get_credential(req['credential_id'])
        if not self.cred:
            raise VCCSAuthenticationError("Unknown credential: {!r}".format(req['credential_id']))

        if self.cred.version() != 'NDNv1':
            raise VCCSAuthenticationError("Unknown credential version: {!r}".format(
                    self.cred))

        # too few iterations is insecure, too large might be a DoS
        if self.cred.iterations() < self._MIN_ITERATIONS or \
                self.cred.iterations() > self._MAX_ITERATIONS:
            raise VCCSAuthenticationError("Bad NDNv1 iterations count: {}".format(
                    self.cred.iterations()))

        # 16 bytes minimum (pwhash is hex encoded, so 32)
        if len(self.cred.derived_key()) < 32:
            raise VCCSAuthenticationError("Bad NDNv1 derived_key length: {}".format(
                    len(self.cred.derived_key())))


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

        See the README file for a longer reasoning about this scheme.
        """

        # Lock down key usage & credential to auth
        T = '|'.join(['A', self.user_id(), self.cred.id(), self.H1()])

        try:
            salt = hasher.safe_hmac_sha1(self.cred.key_handle(), T)
        except Exception, e:
            raise VCCSAuthenticationError("Hashing operation failed : {!s}".format(e))

        # Go from 192+160=352 to 512 bits
        H2 = kdf.pbkdf2_hmac_sha512(T, self.cred.iterations(), salt)

        self._audit_log(logger, H2, self.cred)

        return (H2.encode('hex') == self.cred.derived_key())

    def _audit_log(self, logger, H2, cred):
        """
        Create audit trail.

        Avoid logging the full hashes to make the audit logs less sensitive.
        16 chars (8 bytes) should still be unique enough for 'all' purposes.
        """
        H2_hex = H2.encode('hex')
        if H2_hex == cred.derived_key():
            logger.audit("result=OK, factor=password, credential_id={cid!r}, H2[16]={h2!r}".format( \
                    cid = cred.id(), h2 = H2_hex[:16]))
        else:
            logger.audit(("result=FAIL, factor=password, credential_id={cid!r}, "
                          "H2[16]={h2!r}, stored[16]={stored!r}").format( \
                    cid = cred.id(), h2 = H2_hex[:16], stored = cred.derived_key()[:16]))

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
