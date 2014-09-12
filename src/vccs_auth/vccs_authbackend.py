#!/usr/bin/python
#
# Copyright (c) 2012, 2013, 2014 NORDUnet A/S
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
import time
import logging
import logging.handlers
import argparse
import threading

import cherrypy
import simplejson

import ndnkdf
import vccs_auth

from vccs_auth.common import VCCSAuthenticationError, VCCSRevokedCredential
from vccs_auth.credstore import VCCSAuthCredentialStoreMongoDB

default_config_file = "/etc/vccs/vccs_authbackend.ini"
default_debug = False


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


class BaseRequest():
    """
    Base authentication/revocation request.
    """
    def __init__(self, json, top_node, logger):
        self.top_node = top_node
        try:
            body = simplejson.loads(json)
        except Exception:
            logger.error("Failed parsing JSON body :\n{!r}\n-----\n".format(json), traceback=True)
            raise VCCSAuthenticationError("Failed parsing request")
        # XXX no check if top_node in body
        req = body[top_node]

        # XXX is it really body["version"] we want to check in BaseRequest()?
        if req.get('version', 1) is not 1:
            # really handle missing version below
            raise VCCSAuthenticationError("Unknown request version : {!r}".format(req['version']))

        for req_field in ['version', 'user_id', 'factors']:
            if req_field not in req:
                raise VCCSAuthenticationError("No {!r} in request".format(req_field))

        self._user_id = req['user_id']
        self._parsed_req = req
        # make pylint happy
        self._factors = []

    def __repr__(self):
        return ('<{} @{:#x}: action={action!r},user_id={uid!r}'.format(
            self.__class__.__name__,
            id(self),
            action=self.top_node,
            uid=self.user_id(),
            ))

    def factors(self):
        """
        Get the authentication factors in a request.
        """
        return self._factors

    def user_id(self):
        """
        Get the user_id from the request.
        """
        return self._user_id


class AuthRequest(BaseRequest):

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

    def __init__(self, json, credstore, config, top_node, logger):
        """
        :params json: string, request
        :params credstore: VCCSAuthCredentialStore instance
        :params config: VCCSAuthConfig instance
        :params top_node: String, either 'auth' or 'add_creds' - part of JSON request to parse
        :params logger: VCCSLogger instance
        """
        BaseRequest.__init__(self, json, top_node, logger)

        self._factors = []
        for factor in self._parsed_req['factors']:
            this = vccs_auth.factors.from_dict(factor, top_node, self._user_id, credstore, config)
            if this:
                self._factors.append(this)


class RevokeRequest(BaseRequest):

    """
    Parse JSON body into revoke request object.

    Example (request) body :

    {
        "revoke": {
            "version": 1,
            "user_id": "something-uniquely-identifying-user",
            "credentials": [
                {
                    "credential_id": "4711",
                    "reason": "Revoked upon user request",
                    "reference: "timestamp=1366627173, client_ip=192.0.2.111"
                }
            ]
        }
    }
    """

    def __init__(self, json, top_node, logger):
        #print "\n\nDecoding JSON : '%s'\n\n" % (json)
        BaseRequest.__init__(self, json, top_node, logger)

        self._factors = []
        # credentials called factors to match AuthRequest
        for factor in self._parsed_req['factors']:
            for req_field in ['credential_id', 'reason', 'reference']:
                if req_field not in factor:
                    raise VCCSAuthenticationError("No {!r} in credential to revoke".format(req_field))
            for str_field in ['reason', 'reference']:
                if not isinstance(factor[str_field], basestring):
                    raise VCCSAuthenticationError("Invalid {!r} (not string)".format(str_field))
            self._factors.append(factor)


class VCCSLogger():
    """
    Simple class to do logging in a unified way.
    """

    def __init__(self, myname, config, context = ''):
        """
        :params myname: string with name of application
        :params context: string with auxillary data to appear in all audit log messages
        :params config: VCCSAuthConfig instance
        """
        cherrypy.request.vccs_log_context = context

        self.logger = logging.getLogger(myname)
        self.debug = self.logger.debug  # pass through debug calls to the logging logger
        if config.debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        if config.syslog_socket:
            syslog_h = logging.handlers.SysLogHandler(config.syslog_socket)
            formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
            syslog_h.setFormatter(formatter)
            if config.debug:
                syslog_h.setLevel(logging.DEBUG)
            self.logger.addHandler(syslog_h)

    def audit(self, data):
        """
        Audit log data.

        :param data: Audit data as string
        """
        self.logger.info("AUDIT: {context}, {data}".format(context = cherrypy.request.vccs_log_context, data = data))

    def error(self, msg, traceback=False):
        """
        Log an error message, additionally appending a traceback.
        :param msg: Error message as string
        :param traceback: Append a traceback or not, True or False
        """
        self.logger.error(msg, exc_info=traceback)
        # get error messages into the cherrypy error log as well
        cherrypy.log.error(msg)

    def set_context(self, context):
        """
        Set data to be included in all future audit logs.
        :param context: dict with data to log with every line of logging
        """
        # Add logging context to cherrypy.request (it is encouraged to do so, for request specific state)
        # since there is only one VCCSLogger() instance for the whole application, and more than one
        # thread serving requests.
        cherrypy.request.vccs_log_context = ', '.join([k + '=' + v for (k, v) in context.items()])


class AuthBackend(object):

    """
    VCCS authentication backend CherryPy application.

    :param hasher: VCCSHasher() instance
    :param kdf: NDNKDF() instance
    :param logger: VCCSLogger() instance for audit logging
    :param credstore: VCCSAuthCredentialStore() instance
    :param config: VCCSAuthConfig() instance
    :param expose_real_errors: boolean, mask errors or expose them (for devel/debug/test)
    """

    def __init__(self, hasher, kdf, logger, credstore, config, expose_real_errors=False):
        assert isinstance(hasher, vccs_auth.hasher.VCCSHasher)
        assert isinstance(config, vccs_auth.config.VCCSAuthConfig)
        self.hasher = hasher
        self.kdf = kdf
        self.logger = logger
        self.credstore = credstore
        self.config = config
        self.expose_real_errors = expose_real_errors
        # make pylint happy
        self.remote_ip = 'UNKNOWN'

    @cherrypy.expose
    def authenticate(self, request=None):
        """
        Handle HTTP requests to authenticate users using one or more factors.

        :param request: HTTP parameter as string
        :return: None or HTTP respobnse data as string
        """
        self.remote_ip = cherrypy.request.remote.ip

        # XXX should check remote IP against self.config.authenticate_allow, if that is set

        # Parse request
        top_node = 'auth'
        parse_fun = lambda: AuthRequest(request, self.credstore, self.config, top_node, self.logger)
        auth = self._safe_parse_request(parse_fun, 'auth', max_factors=10)
        if not isinstance(auth, BaseRequest):
            if type(auth) == int:
                cherrypy.response.status = auth
            # Don't disclose anything on our internal failures
            return None

        # Process parsed request
        process_fun = lambda(factor): factor.authenticate(self.hasher, self.kdf, self.logger)
        result = self._safe_process_factors(auth, process_fun)

        if type(result) == int:
            cherrypy.response.status = result
            # Don't disclose anything on our internal failures
            return None

        self.logger.audit("factors={factors}, auth_result={res}".format(
            factors = [x.type for x in auth.factors()], res = result))

        response = {'auth_response': {'version': 1,
                                      'authenticated': result,
                                      }
                    }
        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def add_creds(self, request=None):
        """
        Handle requests to add credentials to the credential store.

        :param request: HTTP parameter as string
        :return: None or HTTP respobnse data as string
        """
        self.remote_ip = cherrypy.request.remote.ip

        if not self.remote_ip in self.config.add_creds_allow:
            self.logger.error("Denied add_creds request from {} not in add_creds_allow ({})".format(
                self.remote_ip, self.config.add_creds_allow))
            cherrypy.response.status = 403
            # Don't disclose anything about our internal issues
            return None

        # Parse request
        top_node = 'add_creds'
        parse_fun = lambda: AuthRequest(request, self.credstore, self.config, top_node, self.logger)
        auth = self._safe_parse_request(parse_fun, 'add_creds')
        if not isinstance(auth, BaseRequest):
            if type(auth) == int:
                cherrypy.response.status = auth
            # Don't disclose anything on our internal failures
            return None

        # Process parsed request
        process_fun = lambda(factor): factor.add_credential(self.hasher, self.kdf, self.logger)
        result = self._safe_process_factors(auth, process_fun)

        if type(result) == int:
            cherrypy.response.status = result
            # Don't disclose anything on our internal failures
            return None

        self.logger.audit("factors={factors}, result={res}".format(
            factors = [x.type for x in auth.factors()], res = result))

        response = {'add_creds_response': {'version': 1,
                                           'success': result,
                                           }
                    }
        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def revoke_creds(self, request=None):
        """
        Handle requests to revoke credentials from the credential store.

        :param request: HTTP parameter as string
        :return: None or HTTP respobnse data as string
        """
        self.remote_ip = cherrypy.request.remote.ip
        if not self.remote_ip in self.config.revoke_creds_allow:
            self.logger.error("Denied revoke_creds request from {} not in revoke_creds_allow ({})".format(
                self.remote_ip, self.config.revoke_creds_allow))
            cherrypy.response.status = 403
            # Don't disclose anything about our internal issues
            return None

        # Parse request
        action = 'revoke_creds'
        parse_fun = lambda: RevokeRequest(request, action, self.logger)
        revoke = self._safe_parse_request(parse_fun, action)
        if not isinstance(revoke, BaseRequest):
            if type(revoke) == int:
                cherrypy.response.status = revoke
            # Don't disclose anything on our internal failures
            return None

        # Process parsed request
        process_fun = lambda(factor): revoke_credential(factor, self.credstore, self.remote_ip)
        result = self._safe_process_factors(revoke, process_fun)

        self.logger.audit("credentials={credentials}, result={res}".format(
            credentials = [x['credential_id'] for x in revoke.factors()], res = result))

        if type(result) == int:
            cherrypy.response.status = result
            # Don't disclose anything on our internal failures
            return None

        response = {'revoke_creds_response': {'version': 1,
                                              'success': result,
                                              }
                    }
        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def status(self):
        """
        Status requests testing HSM communication.
        Useful in monitoring the authentication backend.

        :return: None or HTTP respobnse data as string
        """
        self.remote_ip = cherrypy.request.remote.ip
        self.logger.debug("Status request from {!r}".format(self.remote_ip))
        if not self.remote_ip in self.config.status_allow:
            self.logger.error("Denied status request from {} not in status_allow ({})".format(
                self.remote_ip, self.config.status_allow))
            cherrypy.response.status = 403
            # Don't disclose anything about our internal issues
            return None

        response = {'version': 1,
                    'status': 'OK',
                    }

        try:
            res = self.hasher.safe_hmac_sha1(self.config.add_creds_password_key_handle, chr(0x0))
        except Exception:
            self.logger.error("Failed hashing test data with add_creds_password_key_handle {!r}".format(
                self.config.add_creds_password_key_handle), traceback=True)
            res = 'Hashing failed'
        if len(res) >= 20:  # length of HMAC-SHA-1
            response['add_creds_hmac'] = 'OK'
        else:
            response['status'] = 'FAIL'

        self.logger.debug("Served status result {!r} to {!r}".format(response['status'], self.remote_ip))
        return "{}\n".format(simplejson.dumps(response))


    def _safe_parse_request(self, parse_fun, action, min_factors=1, max_factors=1):
        """
        Parse a received request.

        This function deliberately does not return any details on failures, but instead
        just return HTTP error response codes -- this keeps stack traces from being
        shown to the client.

        :param parse_fun: callable resulting in a BaseRequest() subclass instance
        :param action: Name of action as string
        :param min_factors: Minimum number of authentication factors required
        :param max_factors: Maximum number of authentication factors allowed

        :returns: BaseRequest() subclass instance or integer with HTTP response code
        :rtype : BaseRequest
        """
        try:
            parsed = parse_fun()

            log_context = {'client': self.remote_ip,
                           'user_id': parsed.user_id(),
                           'req': action,
                           }
            self.logger.set_context(log_context)

            if len(parsed.factors()) > max_factors or len(parsed.factors()) < min_factors:
                self.logger.error("REJECTING request {!r} with {!r} factors : {!r}".format(
                    parsed, len(parsed.factors()), parsed.factors()))
                return 501

            return parsed
        except VCCSRevokedCredential, err:
            self.logger.error("FAILED parsing request from {ip!r}: {reason!r}".format(
                ip = self.remote_ip, reason = err.reason))
            if self.expose_real_errors:
                raise
            return 410
        except VCCSAuthenticationError, autherr:
            self.logger.error("FAILED parsing request from {ip!r}: {reason!r}".format(
                ip = self.remote_ip, reason = autherr.reason))
            if self.expose_real_errors:
                raise
            return 500
        except Exception, ex:
            self.logger.error("FAILED handling request from {ip!r}: {reason!r}\n".format(
                ip = self.remote_ip, reason = ex), traceback=True)
            if self.expose_real_errors:
                raise
            return 500

    def _safe_process_factors(self, parsed, process_fun):
        """
        Go through all the factors in the request and perform the requested action
        (either authentication, add_credential or revocation).

        :returns: boolean (True if all went well, False otherwise) or integer HTTP response code
        """
        try:
            # Go through the list of authentication/revocation factors in the request
            fail = 0
            for factor in parsed.factors():
                if not process_fun(factor):
                    fail += 1
            result = (fail == 0)

            return result
        except VCCSAuthenticationError, autherr:
            self.logger.error("FAILED processing request from {ip!r}: {reason!r}".format(
                ip = self.remote_ip, reason = autherr.reason))
            if self.expose_real_errors:
                raise
            return 500
        except Exception, ex:
            self.logger.error("FAILED handling request from {ip!r}: {reason!r}\n".format(
                ip = self.remote_ip, reason = ex), traceback=True)
            if self.expose_real_errors:
                raise
            return 500


def revoke_credential(parsed, credstore, remote_ip):
    """
    Revoke a credential in the credential store.

    Construct revocation info with current time, IP of client requesting revocation and
    some self-stated reason for revocation, together with an opaque reference from the client.

    Both the reason and reference must be strings (verified to be in RevokeRequest.__init__()).

    :param parsed: Parsed revoke request as dict
    :param credstore: VCCSAuthCredentialStore() instance
    :param remote_ip: IP request was received from as string
    """
    try:
        cred = credstore.get_credential(parsed['credential_id'])
    except VCCSAuthenticationError:
        raise VCCSRevokedCredential("Credential {!r} is already revoked".format(parsed['credential_id']))
    if not cred:
        raise VCCSAuthenticationError("Unknown credential: {!r}".format(parsed['credential_id']))
    info = {'timestamp': int(time.time()),
            'client_ip': remote_ip,
            'reason': parsed['reason'],
            'reference': parsed['reference'],
            }
    cred.revoke(info)
    credstore.update_credential(cred)
    return True


def main(myname = 'vccs_authbackend'):
    """
    Initialize everything and start the authentication backend.

    :param myname: String used for logging
    """
    args = parse_args()

    # initialize various components
    config = vccs_auth.config.VCCSAuthConfig(args.config_file, args.debug)
    logger = VCCSLogger(myname, config)
    kdf = ndnkdf.NDNKDF(config.nettle_path)
    hsm_lock = threading.RLock()
    hasher = vccs_auth.hasher.hasher_from_string(config.yhsm_device, hsm_lock, debug=config.debug)
    credstore = VCCSAuthCredentialStoreMongoDB(config.mongodb_uri, logger)

    cherry_conf = {'server.thread_pool': config.num_threads,
                   'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
                   }
    if config.logdir:
        cherry_conf['log.access_file'] = os.path.join(config.logdir, 'access.log')
        cherry_conf['log.error_file'] = os.path.join(config.logdir, 'error.log')
    else:
        sys.stderr.write("NOTE: Config option 'logdir' not set.\n")
        cherry_conf['log.screen'] = True

    cherrypy.config.update(cherry_conf)

    logger.logger.info("Starting server listening on {!s}:{!s} (loglevel {!r})".format(
            config.listen_addr, config.listen_port, logger.logger.getEffectiveLevel()))

    cherrypy.quickstart(AuthBackend(hasher, kdf, logger, credstore, config))

if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
