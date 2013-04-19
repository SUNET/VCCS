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

import vccs_auth.credential
from vccs_auth.common import VCCSAuthenticationError

_OATH_TOTP_TIME_DIVIDER = 30

class OATHCommon():
    """
    Base class for authentication factors based on the OATH-HOTP algorithm
    specified in RFC4226. Currently, these is event based and time based.

    Do note that the authentication backend is stateless, and won't detect
    a replayed OTP. The logic to detect replays must be in the frontends,
    that - after a successful authentication - must compare the current
    code with previous ones to make sure it hasn't been used in a previous
    request, or a simultaneous request to another frontend server.
    """
    def __init__(self, oath_type, action, req, credstore, config):
        self.type = oath_type
        self.credstore = credstore
        config = config
        if action == 'auth':
            self.cred = credstore.get_credential(req['credential_id'])
            if not self.cred:
                raise VCCSAuthenticationError("Unknown credential: {!r}".format(req['credential_id']))

            if self.cred.version() != 'NDNv1':
                raise VCCSAuthenticationError("Unknown credential version: {!r}".format(
                        self.cred))

            self._user_code = int(req['user_code'])
        elif action == 'add_creds':
            if config.add_creds_oath_version != 'NDNv1':
                raise VCCSAuthenticationError("Add OATH credentials of version {!r} not implemented".format(
                        config.add_creds_password_version))
            if not config.add_creds_oath_key_handle:
                raise VCCSAuthenticationError("Add password credentials key_handle not set".format(
                        config.add_creds_password_version))
            cred_data = {'type':          self.type,
                         'status':        'active',
                         'version':       'NDNv1',
                         'key_handle':    config.add_creds_oath_key_handle,
                         'nonce':         req['nonce'],
                         'aead':          req['aead'],
                         'digits':        req['digits'],
                         'credential_id': req['credential_id'],
                         'oath_counter':  req['oath_counter'],
                         }
            self.cred = vccs_auth.credential.from_dict(cred_data, None)
        else:
            raise VCCSAuthenticationError("Unknown action {!r}".format(action))

    def add_credential(self, hasher, _kdf, logger):
        """
        Add a credential to the credential store.

        The credential (OATH HMAC key) has to be provided in an AEAD generated
        elsewhere. The YubiHSM:s connected to authentication backends should be
        unable to generate AEAD:s through configuration.

        :returns: True on success
        """
        hasher.lock_acquire()
        try:
            # test load AEAD
            if not hasher.load_temp_key(self.cred.nonce().decode('hex'),
                                        self.cred.key_handle(),
                                        self.cred.aead().decode('hex'),
                                        ):
                raise VCCSAuthenticationError("Loading HMAC key failed")
        except Exception, e:
            raise VCCSAuthenticationError("Loading HMAC key failed : {!s}".format(e))
        finally:
            hasher.lock_release()
        res = self.credstore.add_credential(self.cred)
        logger.audit("Added credential credential_id={!r}, res={!r}".format(
                self.cred.id(), res))
        return True

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
            try:
                if not hasher.load_temp_key(self.cred.nonce().decode('hex'),
                                            self.cred.key_handle(),
                                            self.cred.aead().decode('hex'),
                                            ):
                    raise VCCSAuthenticationError("Loading HMAC key failed")
            except Exception, e:
                raise VCCSAuthenticationError("Loading HMAC key failed : {!s}".format(e))

            for offset in offsets:
                counter = struct.pack("> Q", start_counter + offset)

                try:
                    # key_handle None says to use the temp key loaded above
                    hmac_result = hasher.hmac_sha1(None, counter)
                except Exception, e:
                    raise VCCSAuthenticationError("Hashing operation failed : {!r}".format(e))

                this_code = pyhsm.oath_hotp.truncate(hmac_result, length=self.cred.digits())
                #print "OATH: counter=%i, user_code=%i, this_code=%i" % (start_counter + offset, self._user_code, this_code)
                if this_code == self._user_code:
                    # Make sure this OTP has in fact not been used before
                    if self._increase_oath_counter(start_counter, offset, logger):
                        logger.audit("result=OK, factor={name}, counter={ctr!r}, offset={offs!r}".format( \
                                name = self.type, ctr = start_counter, offs = offset))
                        return True
                    else:
                        return False
        finally:
            hasher.lock_release()
        logger.audit("result=FAIL, factor={name}, counter={ctr!r}, offsets={offsets!r}".format( \
                name = self.type, ctr = start_counter, offsets = offsets))
        return False

    def _increase_oath_counter(self, start_counter, offset, logger):
        """
        Update counter value of credential in database provided that the new counter
        is greater than (NOT equal) to the current value.
        """
        counter = start_counter + offset
        if counter <= self.cred.oath_counter():
            logger.audit(("result=FAIL, factor={name}, counter={ctr!r}, "
                          "offset={offs!r}, reason=OTP_REUSE").format( \
                    name = self.type, ctr = start_counter, offs = offset))
            return False
        self.cred.oath_counter(counter)
        return self.credstore.update_credential(self.cred, safe=True)


class OATHHOTPFactor(OATHCommon):
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
    def __init__(self, action, req, credstore, config):
        OATHCommon.__init__(self, 'oath-hotp', action, req, credstore, config)

    def authenticate(self, hasher, _kdf, logger):
        # Compare the user supplied code with expected, expected + 1, ... expected + 3
        offsets = [1, 2, 3, 4]
        res = self._look_for_match(self.cred.oath_counter(), offsets, hasher, logger)
        return res

class OATHTOTPFactor(OATHCommon):
    """
    OATH-TOTP (time based) authentication.

    For time based tokens, the counter value is the UNIX time divided by a fixed
    interval. We currently always use 30 seconds as this interval. Some servers
    will go through great lengths to handle clock drift in the token, but we have
    this far chosen not to do that. We expect tokens to know the current time, so
    the only thing we compensate for is the user (or network) being slow in entering
    the code - meaning we accept the current expected code, and the last one.
    """
    def __init__(self, action, req, credstore, config):
        OATHCommon.__init__(self, 'oath-totp', action, req, credstore, config)

    def authenticate(self, hasher, _kdf, logger):
        # Compare the user supplied code with current time, and current time - 30
        now = int(time.time() / _OATH_TOTP_TIME_DIVIDER)
        offsets = [0, -1]
        res = self._look_for_match(now, offsets, hasher, logger)
        return res

def from_factor(req, action, credstore, config):
    """
    Part of parsing authentication/add_credentials requests received.

    Figure out what kind of object should be initialized, and return it.
    """
    if action == 'auth' or action == 'add_creds':
        if req['type'] == 'oath-hotp' :
            return OATHHOTPFactor(action, req, credstore, config)
        elif req['type'] == 'oath-totp' :
            return OATHTOTPFactor(action, req, credstore, config)
