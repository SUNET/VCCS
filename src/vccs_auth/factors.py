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
VCCS authentication factors
"""

# yuck, VCCSFactor must be declared above the imports of vccs_auth.{password,oath}
# since they in turn import VCCSFactor.
class VCCSFactor():
    """
    VCCS authentication factor base class.
    """
    def __init__(self, type_):
        self.type = type_

    def authenticate(self, _hasher, _kdf, _logger):
        raise NotImplementedError("Subclass should implement authenticate")

    def add_credential(self, _hasher, _kdf, _logger):
        raise NotImplementedError("Subclass should implement add_credential")


import vccs_auth.password
import vccs_auth.oath

# import these into the vccs_auth.factors namespace
from vccs_auth.password import VCCSPasswordFactor
from vccs_auth.oath import OATHHOTPFactor, OATHTOTPFactor

from vccs_auth.common import VCCSAuthenticationError


class FailFactor(VCCSFactor):
    """
    Eventually fail authentication.
    """
    def __init__(self, reason):
        VCCSFactor.__init__(self, 'fail')
        self.reason = reason

    def authenticate(self, _hasher, _kdf, logger):
        logger.audit("result=FAIL, factor=fail, reason={}".format(self.reason))
        return False

    def add_credential(self, _hasher, _kdf, _logger):
        raise VCCSAuthenticationError("Impossible to add_credential of type FailFactor")


def from_dict(data, top_node, user_id, credstore, config):
    """
    Convert a dict into an VCCSFactor instance.

    The type of factor is identified by the 'type' element in the dict. If the type of factor
    is not recognized, a FailFactor instance is returned.

    :params data: dict
    :params top_node: String, either 'auth' or 'add_creds' - part of JSON request to parse
    :params user_id: string, persistent user id
    :params credstore: VCCSAuthCredentialStore instance
    :params config: VCCSAuthConfig instance
    :returns: VCCSFactor instance
    """
    this = None
    if top_node in ['auth', 'add_creds']:
        if data['type'] == 'password':
            this = vccs_auth.password.from_factor(data, top_node, user_id, credstore, config)
        elif data['type'] == 'oath-hotp' or data['type'] == 'oath-totp':
            this = vccs_auth.oath.from_factor(data, top_node, user_id, credstore, config)

    if not this:
        # eventually fail on unknown type (or action), but continue processing to consume any OTPs
        this = FailFactor(('Unknown authentication factor type '
                           '{!r} or action {!r}').format(data['type'], top_node))
    return this
