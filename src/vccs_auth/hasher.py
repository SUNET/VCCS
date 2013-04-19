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

import os
import stat
import pyhsm

import hmac
from hashlib import sha1

class VCCSHasher():

    def __init__(self, lock):
        self.lock = lock

    def safe_hmac_sha1(self, _key_handle, _data):
        raise NotImplementedError('Subclass should implement safe_hmac_sha1')

    def hmac_sha1(self, _key_handle, _data):
        raise NotImplementedError('Subclass should implement hmac_sha1')

    def load_temp_key(self, _nonce, _key_handle, _aead):
        raise NotImplementedError('Subclass should implement load_temp_key')

    def safe_random(self, _byte_count):
        raise NotImplementedError('Subclass should implement safe_random')

    def lock_acquire(self):
        return self.lock.acquire()

    def lock_release(self):
        return self.lock.release()


class VCCSYHSMHasher(VCCSHasher):

    def __init__(self, device, lock, debug=False):
        VCCSHasher.__init__(self, lock)
        self.yhsm = pyhsm.base.YHSM(device, debug)

    def safe_hmac_sha1(self, key_handle, data):
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        self.lock_acquire()
        try:
            return self.hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def hmac_sha1(self, key_handle, data):
        return self.yhsm.hmac_sha1(key_handle, data).get_hash()

    def load_temp_key(self, nonce, key_handle, aead):
        return self.yhsm.load_temp_key(nonce, key_handle, aead)

    def safe_random(self, byte_count):
        """
        Generate random bytes using both YubiHSM random function and host OS.

        Acquires a lock first if a lock instance was given at creation time.
        """
        from_os = os.urandom(byte_count)
        self.lock_acquire()
        try:
            from_hsm = self.yhsm.random(byte_count)
            xored = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(from_hsm, from_os)])
            return xored
        finally:
            self.lock_release()

class VCCSSoftHasher(VCCSHasher):

    """
    Hasher implementation without any real extra security benefits
    (except perhaps separating HMAC keys from credential store).
    """

    def __init__(self, keys, lock, debug=False):
        VCCSHasher.__init__(self, lock)
        self.keys = keys

    def safe_hmac_sha1(self, key_handle, data):
        """
        Perform HMAC-SHA-1 operation using YubiHSM.

        Acquires a lock first if a lock instance was given at creation time.
        """
        self.lock_acquire()
        try:
            return self.hmac_sha1(key_handle, data)
        finally:
            self.lock_release()

    def hmac_sha1(self, key_handle, data):
        hmac_key = self.keys[key_handle]
        return hmac.new(hmac_key, msg=data, digestmod=sha1).digest()

    def load_temp_key(self, nonce, key_handle, aead):
        pt = pyhsm.soft_hsm.aesCCM(self.keys[key_handle], key_handle, nonce, aead, decrypt = True)
        self.keys[pyhsm.defines.YSM_TEMP_KEY_HANDLE] = pt[:-4]  # skip the last four bytes which are permission bits
        return True

    def safe_random(self, byte_count):
        """
        Generate random bytes from urandom.
        """
        return os.urandom(byte_count)


class NoOpLock():
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """
    def __init__(self):
        pass

    def acquire(self):
        pass

    def release(self):
        pass


def hasher_from_string(name, lock = None, debug = False):
    """
    Create a hasher instance from a name. Name can currently only be a
    name of a YubiHSM device, such as '/dev/ttyACM0'.

    An optional lock is passed in as an argument, to keep this module
    unaware of if threading is being used, and how. If a lock instance
    is given, it will be lock.acquire()'d and lock.release()'d when
    hashers hash.

    The lock must be reentrant to support OATH.
    """
    if not lock:
        lock = NoOpLock()
    try:
        mode = os.stat(name).st_mode
        if stat.S_ISCHR(mode):
            return VCCSYHSMHasher(name, lock, debug)
        raise ValueError("Not a character device : {!r}".format(name))
    except OSError:
        raise ValueError("Unknown hasher {!r}".format(name))
