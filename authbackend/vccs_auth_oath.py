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

import time
import struct

import pyhsm.oath_hotp

import vccs_auth_common
from vccs_auth_common import VCCSAuthenticationError

_OATH_TOTP_TIME_DIVIDER = 30

class OathCommon():
    """
    Base class for authentication factors based on the OATH-HOTP algorithm
    specified in RFC4226. Currently, these is event based and time based.

    Do note that the authentication backend is stateless, and won't detect
    a replayed OTP. The logic to detect replays must be in the frontends,
    that - after a successful authentication - must compare the current
    code with previous ones to make sure it hasn't been used in a previous
    request, or a simultaneous request to another frontend server.
    """
    def __init__(self, req):
        (self._aead_version, self._key_handle, self._nonce, self._aead) = \
            self._parse_credential_aead(req['credential_aead'])
        self._credential_id = str(req['credential_id'])
        self.type = 'unknown' # overwrite in subclass __init__
        # user_code needs to be a string, since we use len() on it to figure out number
        # of digits (and the code might start with '0')
        self._user_code = int(req['user_code'])
        self._digits = len(req['user_code'])

    def authenticate(self, hasher, kdf, logger):
        """
        This function must be overridden.
        """
        raise NotImplementedError('sub-class must implement authenticate()')

    def _look_for_match(self, start_counter, offsets, hasher, logger):
        """
        Check if the user supplied code matches the expected code, or one within the
        acceptable range of codes.

        The acceptable range is given as an array of offsets to increase the start_counter
        with. To try the current counter, the next and then the previous one use
        offsets = [0, 1, -1].
        """
        hasher.lock_acquire()
        try:
            for offset in offsets:
                counter = struct.pack("> Q", start_counter + offset)

                try:
                    hasher.load_temp_key(self._nonce, self._key_handle, self._aead)
                    hmac_result = hasher.hmac_sha1(pyhsm.defines.YSM_TEMP_KEY_HANDLE, counter).get_hash()
                except Exception, e:
                    raise VCCSAuthenticationError("Hashing operation failed : {!s}".format(e))

                    this_code = pyhsm.oath_hotp.truncate(hmac_result, length=self._digits)
                    #print "OATH: counter=%i, user_code=%i, this_code=%i" % (start_counter + offset, code, this_code)
                    if this_code == self._user_code:
                        logger.audit("result=OK, factor={name}, counter={ctr!r}, offset={offs!r}".format( \
                                name = self.type, ctr = start_counter, offs = offset))
                        return True
        finally:
            hasher.lock_release()
        logger.audit("result=FAIL, factor={name}, counter={ctr!r}, offsets={offsets!r}".format( \
                name = self.type, ctr = start_counter, offsets = offsets))
        return False

    def _parse_credential_aead(self, data):
        """
        Parse credential_aead received from frontend.
        (format: $NDNv1$hex_key_handle$nonce$aead$)
        """
        aead_parts = data.split('$')
        if len(aead_parts) > 1 and aead_parts[1] == 'NDNv1':
            try:
                (_empty, _aeadver, key_handle, nonce, aead_str, _empty,) = aead_parts
                if not aead_str:
                    raise ValueError
            except ValueError, e:
                raise VCCSAuthenticationError("Bad NDNv1 AEAD : {!r}".format(aead_parts))

            try:
                # decode hex
                key_handle = int(key_handle, 16)
            except ValueError:
                raise VCCSAuthenticationError("Invalid NDNv1 AEAD key_handle: {!r}".format(key_handle))

            # AEADs are 20 bytes HMAC secret, 4 bytes YHSM flags, 8 bytes YHSM MAC -- 32 bytes
            aead = aead_str.decode('hex')
            if len(aead) != 32:
                raise VCCSAuthenticationError("Bad NDNv1 AEAD length: {}".format(len(aead)))
            return(aead_parts[1], key_handle, nonce.decode('hex'), aead)
        else:
            raise VCCSAuthenticationError("Unknown AEAD format : {!r}".format(data))

class OathHotpFactor(OathCommon):
    """
    OATH-HOTP (event based) authentication.

    For event based tokens, the user might have a token that produces codes when
    a button is pressed (and thus increases it's OATH counter once per button press).
    The user might have pressed the tokens button any number of times since the last
    successful authentication, so our stored counter value for the token might be
    for example 35, but the tokens counter is 42. Only accepting counter=35 in this
    situation will likely lead to unacceptably many authentication problems, but
    allowing codes 35-42 might be too insecure (if the code is 6 digits long,
    accepting any one of 7 codes would mean a 1 in 142857 chance of guessing the
    right code for a user. If the attacker can try 3 times before the account is
    locked, that is a 1 in 47619 chance. With enough accounts to guess against, the
    attacker is sure to guess the right code in a rather short timeframe.
    """
    def __init__(self, req):
        OathCommon.__init__(self, req)
        self.type = 'oath-hotp'
        self._credential_stored_counter = req['credential_stored_counter']

    def authenticate(self, hasher, _kdf, logger):
        # Compare the user supplied code with expected, expected + 1, ... expected + 3
        offsets = [0, 1, 2, 3]
        res = self._look_for_match(self._credential_stored_counter, offsets, hasher, logger)
        return res

class OathTotpFactor(OathCommon):
    """
    OATH-TOTP (time based) authentication.

    For time based tokens, the counter value is the UNIX time divided by a fixed
    interval. We currently always use 30 seconds as this interval. Some servers
    will go through great lengths to handle clock drift in the token, but we have
    this far chosen not to do that. We expect tokens to know the current time, so
    the only thing we compensate for is the user (or network) being slow in entering
    the code - meaning we accept the current expected code, and the last one.
    """
    def __init__(self, req):
        OathCommon.__init__(self, req)
        self.type = 'oath-totp'

    def authenticate(self, hasher, _kdf, logger):
        # Compare the user supplied code with current time, and current time - 30
        now = int(time.time() / _OATH_TOTP_TIME_DIVIDER)
        offsets = [0, -1]
        res = self._look_for_match(now, offsets, hasher, logger)
        return res
