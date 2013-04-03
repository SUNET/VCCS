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

"""
VCCS authentication backend service.

This is a network service that processes authentication requests received
over the network in a multi-factor authentication fashion.

See the README file for a more in-depth description.
"""

import os
import sys
import logging
import logging.handlers
import argparse
import threading

import cherrypy
import simplejson

import ndnkdf
import vccs_auth_oath
import vccs_auth_common
import vccs_auth_config
import vccs_auth_hasher
import vccs_auth_password
import vccs_auth_credstore

from vccs_auth_common import VCCSAuthenticationError
from vccs_auth_credstore import VCCSAuthCredentialStoreMongoDB

default_config_file = "/etc/vccs/vccs_authbackend.ini"
default_debug = False

myname = 'vccs_backend'

def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "Authentication backend server",
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-c', '--config-file',
                        dest='config_file',
                        default=default_config_file,
                        help='Config file',
                        metavar='PATH',
                        )

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=default_debug,
                        help='Enable debug operation',
                        )

    return parser.parse_args()

class AuthRequest():

    """
    Parse JSON body into auth request object.

    Example (request) body, two-factor authentication with password and OATH-TOTP code :

    {
        "auth": {
            "version": 1,
            "user_id": "something-uniquely-identifying-user",
            "factors": [
                {
                    "H1": "227ALNnVn0y1IuhmbsjmlsCHDLIJ5xq",
                    "credential_id": "4711",
                    "type": "password"
                },
                {
                    "credential_id": 4712,
                    "type": "oath-totp",
                    "user_code": "893712"
                }
            ]
        }
    }
    """

    def __init__(self, json, credstore, config, top_node):
        """
        :params top_node: String, either 'auth' or 'add_creds'
        """
        #print "\n\nDecoding JSON : '%s'\n\n" % (json)
        try:
            body = simplejson.loads(json)
        except Exception, ex:
            cherrypy.log.error("Failed parsing JSON body :\n{!r}\n-----\n".format(json), traceback=True)
            raise VCCSAuthenticationError("Failed parsing request")
        req = body[top_node]
        for req_field in ['version', 'user_id', 'factors']:
            if req_field not in req:
                raise VCCSAuthenticationError("No {!r} in request".format(req_field))
        if int(req['version']) is not 1:
            raise VCCSAuthenticationError("Unknown request version : {!r}".format(req['version']))

        self._user_id = req['user_id']

        self._factors = []
        for factor in req['factors']:
            this = None
            if factor['type'] == 'password':
                this = vccs_auth_password.from_factor(factor, top_node, self._user_id, credstore, config)
            elif factor['type'] == 'oath-hotp' or factor['type'] == 'oath-totp':
                this = vccs_auth_oath.from_factor(factor, top_node, credstore, config)

            if this:
                self._factors.append(this)
            else:
                # eventually fail on unknown type (or action), but continue processing to consume any OTPs
                self._factors.append(FailFactor('Unknown authentication factor type {!r} or action {!r}'.format(
                            factor['type'], top_node)))

    def factors(self):
        return self._factors

    def user_id(self):
        return self._user_id

class FailFactor():
    """
    Eventually fail authentication.
    """
    def __init__(self, reason):
        self.type = 'fail'
        self.reason = reason

    def authenticate(self, hasher, kdf, logger):
        logger.audit("result=FAIL, factor=fail, reason={}".format(self.reason))
        return False

class VCCSLogger():
    def __init__(self, context = '', debug = False):
        self.context = context

        self.logger = logging.getLogger(myname)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        self.logger.addHandler(syslog_h)

    def audit(self, data):
        self.logger.info("AUDIT: {context}, {data}".format(context = self.context, data = data))

    def set_context(self, context):
        self.context = ', '.join([k + '=' + v for (k, v) in context.items()])


class AuthBackend(object):

    def __init__(self, hasher, kdf, logger, credstore, config):
        """
        :params hasher: VCCSHasher() instance
        :params kdf: NDNKDF() instance
        :params logger: VCCSLogger() instance for audit logging
        :params credstore: VCCSAuthCredentialStore() instance
        :params config: VCCSAuthConfig() instance
        """
        self.hasher = hasher
        self.kdf = kdf
        self.logger = logger
        self.credstore = credstore
        self.config = config

    @cherrypy.expose
    def authenticate(self, request=None):
        result = False

        auth, result, = self._evaluate(request, 'auth')
        if not auth:
            # Don't disclose anything on our internal failures
            return None

        self.logger.audit("factors={factors}, auth_result={res}".format( \
                factors = [x.type for x in auth.factors()], res = result))

        response = {'auth_response': {'version': 1,
                                      'authenticated': result,
                                      }
                    }
        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def add_creds(self, request=None):
        result = False
        if not cherrypy.request.remote.ip in self.config.add_creds_allow:
            cherrypy.log.error("Denied add_creds request from {} not in add_creds_allow ({})".format(
                    cherrypy.request.remote.ip, self.config.add_creds_allow))
            cherrypy.response.status = 403
            # Don't disclose anything about our internal issues
            return None

        auth, result, = self._evaluate(request, 'add_creds')
        if not auth:
            # Don't disclose anything on our internal failures
            return None

        if len(auth.factors() > 1):
            cherrypy.log.error("REJECTING add_creds request with > 1 factor : {!r}".format( \
                    auth.factors()))
            cherrypy.response.status = 501
            # Don't disclose anything about our internal issues
            return None

        self.logger.audit("factors={factors}, result={res}".format( \
                factors = [x.type for x in auth.factors()], res = result))

        response = {'add_creds_response': {'version': 1,
                                           'success': result,
                                           }
                    }
        return "{}\n".format(simplejson.dumps(response))

    def _evaluate(self, request, action):
        """
        Go through all the factors in the request and perform the requested action
        (either authentication or add_credential).

        :returns: True if all went well, False otherwise
        """
        try:
            auth = AuthRequest(request, self.credstore, self.config, top_node=action)

            log_context = {'client': cherrypy.request.remote.ip,
                           'user_id': auth.user_id(),
                           'req': action,
                           }
            self.logger.set_context(log_context)

            # Go through the list of authentication factors in the request
            fail = 0
            for factor in auth.factors():
                if action == 'add_creds':
                    if not factor.add_credential(self.hasher, self.kdf, self.logger):
                        fail += 1
                elif action == 'auth':
                    if not factor.authenticate(self.hasher, self.kdf, self.logger):
                        fail += 1
                else:
                    raise VCCSAuthenticationError("Unknown action {!r}".format(action))
            result = (fail == 0)
        except VCCSAuthenticationError, autherr:
            cherrypy.log.error("FAILED processing request from {ip!r}: {reason!r}".format( \
                    ip = cherrypy.request.remote.ip, reason = autherr.reason))
            cherrypy.response.status = 500
            # Don't disclose anything about our internal issues
            return None, False
        except Exception, ex:
            cherrypy.log.error("FAILED handling request from {ip!r}: {reason!r}\n".format( \
                    ip = cherrypy.request.remote.ip, reason = ex), traceback=True)
            cherrypy.response.status = 500
            # Don't disclose anything about our internal issues
            return None, False

        if not auth.factors():
            result = False

        return auth, result,


def main():
    """
    Initialize everything and start the authentication backend.
    """
    args = parse_args()

    # initialize various components
    config = vccs_auth_config.VCCSAuthConfig(args.config_file, args.debug)
    kdf = ndnkdf.NDNKDF(config.nettle_path)
    hsm_lock = threading.RLock()
    hasher = vccs_auth_hasher.hasher_from_string(config.yhsm_device, hsm_lock, debug=config.debug)
    logger = VCCSLogger()
    credstore = VCCSAuthCredentialStoreMongoDB(config.mongodb_uri, None)

    cherrypy.config.update( {'server.thread_pool': config.num_threads,
                             'server.socket_port': config.listen_port,
                             } )
    cherrypy.quickstart(AuthBackend(hasher, kdf, logger, credstore, config))

if __name__ == '__main__':
    newname = os.path.basename(sys.argv[0])
    if newname:
        global myname
        myname = newname

    try:
        if main():
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
