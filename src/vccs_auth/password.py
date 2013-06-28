#
# Copyright (c) 2012, 2013 NORDUnet A/S
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

import vccs_auth.credential
from vccs_auth.common import VCCSAuthenticationError
from vccs_auth.factors import VCCSFactor

class VCCSPasswordFactor(VCCSFactor):
    """
    Password authentication factor.

    The backend part of password based authentication is basically to use a YubiHSM
    to implement a "local parameter" (meaning a transformation of the password using
    a cryptographic key that can't be known to a remote attacker - the key is assumed
    to never, ever, be available on a host connected to the Internet), and the use
    of the NIST approved PBKDF2-HMAC-SHA512 algorithm for key stretching.
    """
    def __init__(self, action, req, user_id, credstore, config):
        VCCSFactor.__init__(self, 'password')
        self._user_id = str(user_id)
        self._H1 = str(req['H1'])
        self.config = config
        self.credstore = credstore

        if len(self._H1) != 31:
            # A full bcrypt is 60 chars. the frontend should NOT send the whole
            # bcrypt digest to the authentication backend. bcrypt - salt = 31.
            raise VCCSAuthenticationError("Bad H1: {!r}".format(self._H1))

        if action == 'auth':
            _cred_id = str(req['credential_id'])
            self.cred = credstore.get_credential(_cred_id)
            if not self.cred:
                raise VCCSAuthenticationError("Unknown credential: {!r}".format(_cred_id))
            if self.cred.type() != self.type:
                raise VCCSAuthenticationError("Credential {!r} has unexpected type: {!r}".format(
                        self.cred.type()))
            if self.cred.version() != 'NDNv1':
                raise VCCSAuthenticationError("Unknown credential version: {!r}".format(
                        self.cred))
            # too few iterations is insecure, too many might be a DoS
            if self.cred.iterations() < config.kdf_min_iterations or \
                    self.cred.iterations() > config.kdf_max_iterations:
                raise VCCSAuthenticationError("Bad NDNv1 iterations count: {}".format(
                        self.cred.iterations()))
            # 16 bytes minimum (pwhash is hex encoded, so 32)
            if len(self.cred.derived_key()) < 32:
                raise VCCSAuthenticationError("Bad NDNv1 derived_key length: {}".format(
                        len(self.cred.derived_key())))
        elif action == 'add_creds':
            if config.add_creds_password_version != 'NDNv1':
                raise VCCSAuthenticationError("Add password credentials of version {!r} not implemented".format(
                        config.add_creds_password_version))
            if not config.add_creds_password_key_handle:
                raise VCCSAuthenticationError("Add password credentials key_handle not set".format(
                        config.add_creds_password_version))
            cred_data = {'type':          'password',
                         'status':        'active',
                         'version':       'NDNv1',
                         'kdf':           'PBKDF2-HMAC-SHA512',
                         'derived_key':   None,  # will be calculated later, in add_credential()
                         'key_handle':    config.add_creds_password_key_handle,
                         'iterations':    config.add_creds_password_kdf_iterations,
                         'salt':          None,  # will be added later, in add_credential()
                         'credential_id': str(req['credential_id']),
                         }
            self.cred = vccs_auth.credential.from_dict(cred_data, None)
        else:
            raise VCCSAuthenticationError("Unknown action {!r}".format(action))

    def authenticate(self, hasher, kdf, logger):
        """
        Handle a password authentication request, along the following pseudo-code :

        On backend :
        ------------
        T1 = 'A' | user_id | credential_id | H1
        T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
        local_salt = yhsm_hmac_sha1(T2)
        H2 = PBKDF2-HMAC-SHA512(T2, iterations=1, local_salt)

        audit_log(frontend_id, credential_id, H2, credential_stored_hash)

        return (H2 == credential_stored_hash)

        See the VCCS/README file for a longer reasoning about this scheme.

        :returns: True on successful authentication, False otherwise
        """
        H2 = self._calculate_cred_hash(hasher, kdf)
        self._audit_log(logger, H2, self.cred)
        # XXX need to log successful login in credential_store to be able to ban
        # accounts after a certain time of inactivity (Kantara AL2_CM_CSM#050)
        # XXX can as well log counter of invalid attempts per credential too -
        # so that credentials that have had a total of too many failed logins
        # can be blocked based on that
        return (H2.encode('hex') == self.cred.derived_key())

    def add_credential(self, hasher, kdf, logger):
        """
        Add a credential to the credential store.

        This works very much like authenticate(), but obviously adds an entry to the
        credential store instead of compare a candidate hash with the hash of an already
        existing entry in the credential store.

        :returns: True on success, False otherwise
        """
        self.cred.salt(hasher.safe_random(self.config.add_creds_password_salt_bytes).encode('hex'))
        H2 = self._calculate_cred_hash(hasher, kdf)
        self.cred.derived_key(H2)
        res = self.credstore.add_credential(self.cred)
        logger.audit("Add credential credential_id={!r}, H2[16]={!r}, res={!r}".format(
                self.cred.id(), H2[:8].encode('hex'), res))
        return res == True

    def _calculate_cred_hash(self, hasher, kdf):
        """
        Calculate the expected password hash value for a credential, along this
        pseudo code :

        T1 = 'A' | user_id | credential_id | H1
        T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
        local_salt = yhsm_hmac_sha1(T2)
        H2 = PBKDF2-HMAC-SHA512(T2, iterations=1, local_salt)
        """
        # Lock down key usage & credential to auth
        T1 = ''
        for this in [str(x) for x in ['A', self._user_id, self.cred.id(), self._H1]]:
            if len(this) > 255:
                raise VCCSAuthenticationError("Too long T1 component ({!r}... length {!r})".format(
                        this[:10], len(this)))
            # length-encode each part, to avoid having a designated delimiter that
            # could potentially be misused
            T1 += chr(len(this))
            T1 += this

        # This is the really time consuming PBKDF2 step.
        T2 = kdf.pbkdf2_hmac_sha512(T1, self.cred.iterations(), self.cred.salt_as_bytes())

        try:
            # If speed becomes an issue, truncating T2 to 48 bytes would decrease the
            # time it takes the YubiHSM to compute the HMAC-SHA-1 from around 1.9 ms
            # to around 1.2 ms.
            #
            # The difference is likely due to > 48 bytes requiring more USB transactions.
            local_salt = hasher.safe_hmac_sha1(self.cred.key_handle(), T2)
        except Exception, e:
            raise VCCSAuthenticationError("Hashing operation failed : {!s}".format(e))

        # PBKDF2 again with iter=1 to mix in the local_salt into the final H2.
        H2 = kdf.pbkdf2_hmac_sha512(T2, 1, local_salt)
        return H2

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

def from_factor(req, action, user_id, credstore, config):
    """
    Part of parsing authentication/add_credentials requests received.

    Figure out what kind of object should be initialized, and return it.

    :params req: parsed request as dict
    :params action: String, either 'auth' or 'add_creds'
    :params user_id: string, persistent user id
    :params credstore: VCCSAuthCredentialStore instance
    :params config: VCCSAuthConfig instance
    :returns: VCCSPasswordFactor instance
    """
    return VCCSPasswordFactor(action, req, user_id, credstore, config)
