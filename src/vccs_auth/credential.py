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
Authentication credential data objects.
"""

from vccs_auth.common import VCCSAuthenticationError

_VALID_STATUS_VALUES = ['active', 'revoked']

_VALID_OATH_CODE_LENGTHS = [6, 8]
_VALID_CREDENTIAL_TYPES = ['password', 'oath-hotp', 'oath-totp']

class VCCSAuthCredentialError(VCCSAuthenticationError):
    pass

class VCCSAuthCredential():

    def __init__(self, data, metadata, check_revoked):
        self._data = data
        self._metadata = metadata
        # validate known data
        self.status(data['status'])
        self.type(data['type'])
        if check_revoked and self.status() != 'active':
            raise VCCSAuthCredentialError("Non-active credential requested")

    def status(self, new=None):
        """
        Get or set status of credential. Either 'active' or 'revoked'.

        :returns: string, value before any update
        """
        val = self._data['status']
        if new is not None:
            if new not in _VALID_STATUS_VALUES:
                raise ValueError("Invalid 'status' value: {!r}".format(new))
            if val == 'revoked' and new != 'revoked':
                # In VCCS, you add new credentials rather than resurrecting revoked ones
                raise ValueError("Refusing to change status of revoked credential")
            self._data['status'] = str(new)
        return val

    def type(self, new=None):
        """
        Get or set credential type. Either 'password', 'oath-hotp' or 'oath-totp'.

        :returns: string, value before any update
        """
        val = self._data['type']
        if new is not None:
            if new not in _VALID_CREDENTIAL_TYPES:
                raise ValueError("Invalid 'type' value: {!r}".format(new))
            self._data['type'] = str(new)
        return val

    def id(self, new=None):
        val = self._data['credential_id']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'credential_id': {!r}".format(new))
            self._data['credential_id'] = str(new)
        return val

    def revocation_info(self, new=None):
        """
        Get or set status of credential. Either 'active' or 'revoked'.

        :returns: string, value before any update
        """
        val = self._data.get('revocation_info')
        if new is not None:
            if val is not None:
                # Once revocation_info is set, it should not be modified. In VCCS, you
                # add new credentials rather than resurrect old ones.
                raise ValueError("Refusing to modify revocation_info of credential")
            if type(new) is not dict:
                raise ValueError("Invalid 'revocation_info' value: {!r}".format(new))
            self._data['revocation_info'] = new
        return val

    def metadata(self):
        """
        Return opaque data about this credential. This data is owned by
        VCCSAuthCredentialStore.
        """
        return self._metadata

    def to_dict(self):
        """
        Convert credential to a dict, that can be used to reconstruct the
        credential later.
        """
        return self._data

    def revoke(self, info):
        """
        Revoke a credential.

        :param info: dict with data documenting revocation
        :returns: None
        """
        if self.status() != 'active':
            raise VCCSAuthCredentialError("Revocation of non-active credential")
        if not isinstance(info, dict):
            raise TypeError("Non-dict revocation 'info': {!r}".format(info))
        self.revocation_info(info)
        self.status('revoked')

class VCCSAuthPasswordCredential(VCCSAuthCredential):

    def __init__(self, data, metadata, check_revoked):
        VCCSAuthCredential.__init__(self, data, metadata, check_revoked)

        # validate known data specific to this class
        self.version(self._data['version'])
        self.kdf(self._data['kdf'])
        self.iterations(self._data['iterations'])
        self.key_handle(self._data['key_handle'])
        self.derived_key(self._data['derived_key'])
        self.salt(self._data['salt'])

    def version(self, new=None):
        val = self._data['version']
        if new is not None:
            if new != 'NDNv1':
                raise ValueError("Invalid 'version': {!r}".format(new))
            self._data['version'] = str(new)
        return val

    def kdf(self, new=None):
        val = self._data['kdf']
        if new is not None:
            if new != 'PBKDF2-HMAC-SHA512':
                raise ValueError("Invalid 'kdf': {!r}".format(new))
            self._data['kdf'] = str(new)
        return val

    def iterations(self, new=None):
        val = self._data['iterations']
        if new is not None:
            if not isinstance(new, int) or new < 0:
                raise ValueError("Invalid 'iterations': {!r}".format(new))
            self._data['iterations'] = new
        return val

    def key_handle(self, new=None):
        val = self._data['key_handle']
        if new is not None:
            if not isinstance(new, int) or new < 0:
                raise ValueError("Invalid 'key_handle': {!r}".format(new))
            self._data['key_handle'] = new
        return val

    def derived_key(self, new=None):
        val = self._data['derived_key']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'derived_key': {!r}".format(new))
            if len(new) == 64:
                # 64 byte digests for HMAC-SHA-512
                new = new.encode('hex')
            if len(new) != 128:
                raise ValueError("Invalid 'derived_key' (expect 128 chars hex string): {!r}".format(new))
            self._data['derived_key'] = new
        return val

    def salt(self, new=None):
        val = self._data['salt']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'salt': {!r}".format(new))
            try:
                new.decode('hex')
            except Exception:
                raise ValueError("Non-hex string 'salt' : {!r}".format(new))
            if len(new) < 32:
                # require at least 128 bits of salt
                raise ValueError("Too short 'salt' ({} < 32): {!r}".format(len(new), new))
            self._data['salt'] = new
        return val

    def salt_as_bytes(self):
        """
        Convenience function to return the salt in a known format.
        """
        return self._data['salt'].decode('hex')

    def __repr__(self):
        return ('<{} instance at {:#x}: id={id_!r},type={type_!r},status={status!r},'
                'ver={ver!r},kdf={kdf!r},iter={iter_!r},key_handle={kh:#x}>').format(
            self.__class__.__name__,
            id(self),
            id_=self.id(),
            type_=self.type(),
            status=self.status(),
            ver=self.version(),
            kdf=self.kdf(),
            iter_=self.iterations(),
            kh=self.key_handle(),
            )


class VCCSAuthOATHCredential(VCCSAuthCredential):

    def __init__(self, data, metadata, check_revoked):
        VCCSAuthCredential.__init__(self, data, metadata, check_revoked)

        # validate known data specific to this class
        self.version(self._data['version'])
        self.key_handle(self._data['key_handle'])
        self.nonce(self._data['nonce'])
        self.aead(self._data['aead'])
        self.digits(self._data['digits'])
        self.oath_counter(self._data['oath_counter'])
        self.user_id(self._data['user_id'])

    def version(self, new=None):
        val = self._data['version']
        if new is not None:
            if new != 'NDNv1':
                raise ValueError("Invalid 'version': {!r}".format(new))
            self._data['version'] = str(new)
        return val

    def key_handle(self, new=None):
        val = self._data['key_handle']
        if new is not None:
            if not isinstance(new, int) or new < 0:
                raise ValueError("Invalid 'key_handle': {!r}".format(new))
            self._data['key_handle'] = new
        return val

    def nonce(self, new=None):
        val = self._data['nonce']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'nonce': {!r}".format(new))
            if len(new) == 6:
                new = new.encode('hex')
            if len(new) != 12:
                raise ValueError("Invalid 'nonce' (expect 6 bytes/12 chars hex string): {!r}".format(new))
            self._data['nonce'] = str(new)
        return val

    def aead(self, new=None):
        val = self._data['aead']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'aead': {!r}".format(new))
            # AEADs are 20 bytes HMAC secret, 4 bytes YHSM flags, 8 bytes YHSM MAC -- 32 bytes
            if len(new) == 32:
                new = new.encode('hex')
            if len(new) != 64:
                raise ValueError("Invalid 'aead' (expect 32 bytes/64 chars hex string): {!r}".format(new))
            self._data['aead'] = str(new)
        return val

    def digits(self, new=None):
        val = self._data['digits']
        if new is not None:
            if new not in _VALID_OATH_CODE_LENGTHS:
                raise ValueError("Invalid 'digits': {!r}".format(new))
            self._data['digits'] = new
        return val

    def oath_counter(self, new=None):
        val = self._data['oath_counter']
        if new is not None:
            if not isinstance(new, int) or new < 0:
                raise ValueError("Invalid 'oath_counter': {!r}".format(new))
            self._data['oath_counter'] = new
        return val

    def user_id(self, new=None):
        val = self._data['user_id']
        if new is not None:
            if not isinstance(new, basestring):
                raise ValueError("Invalid 'user_id': {!r}".format(new))
            self._data['user_id'] = new
        return val


def from_dict(data, metadata, check_revoked=True):
    """
    Create a suitable VCCSAuthCredential object based on the 'type' of 'data'.

    :param data: dict with credential data - probably from a database
    :param metadata: opaque data about this credential
    :param check_revoked: boolean controlling check of credential status after creation
    :returns: VCCSAuthCredential object
    """
    credtype = data.get('type')
    if credtype == 'password':
        return VCCSAuthPasswordCredential(data, metadata, check_revoked)
    elif credtype == 'oath-hotp' or credtype == 'oath-totp':
        return VCCSAuthOATHCredential(data, metadata, check_revoked)
    else:
        raise ValueError("Bad 'type': {!r}".format(credtype))
