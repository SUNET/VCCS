#!/usr/bin/python
#
# Copyright (c) 2012, NORDUnet A/S
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
Configuration (key management) interface to YubiHSM.
"""

import os
import re
import serial
import logging

from vccs_hsm_keydb import HsmKey


class VCCSCfgError(Exception):
    """
    Base class for all exceptions relating to the VCCS HSM communication.

    :param reason: reason as string
    """

    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.reason,
        )


class VCCSCfgInteractError(VCCSCfgError):
    """
    Exception class with extra information about when our HSM interactions fail.
    """

    def __init__(self, reason, all_commands, all_data, expected, got, last_send, ):
        VCCSCfgError.__init__(self, reason)
        self.all_commands = all_commands
        self.all_data = all_data
        self.expected = expected
        self.got = got
        self.last_send = last_send

    def __str__(self):
        return '<%s instance at %s: %s\n(last send %s, expected %s, got %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.reason,
            repr(self.last_send),
            repr(self.expected),
            repr(self.got),
        )


class HsmSerial():
    """
    Low-end interface to HSM. Read, write, those kinds of things.
    """

    def __init__(self, device, logger):
        self.device = device
        self.logger = logger
        self.ser = serial.Serial(device, 115200, timeout = 0.1)

    def __repr__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.device
        )

    def __del__(self):
        self.logger.debug("Destroying %s", str(self))
        if self.ser:
            self.ser.close()

    def close(self):
        """
        Close the HSM.

        :return: True on success
        """
        self.logger.debug("Closing %s", str(self))
        self.ser.close()
        self.ser = None
        return True

    def read(self, num_bytes):
        """
        Read num_bytes from HSM.

        :param num_bytes: Number of bytes to read.
        :returns: Data as string
        """
        data = self.ser.read(num_bytes)
        return data

    def write(self, data):
        """
        Write data to HSM.
        :param data: Data to write as string
        """
        self.ser.write(data)
        self.logger.debug("WRITE: %s" % (repr(data)))

    def drain(self):
        """
        Read until the read times out.
        """
        data = ''
        while True:
            x = self.read(1)
            if not x:
                break
            data += x
        if data:
            self.logger.debug("DRAIN : %s" % (repr(data)))

    def interact(self, commands, retry_count = 5, add_cr = True):
        """
        Process a list of 'send' or 'expect' command tuples.

        e.g.
           commands = [('send', 'sysinfo'),
                       ('expect', '^YubiHSM version'),
                       ...
                       ]
        :param commands: List of command-tuples
        :param retry_count: Number of times to retry reading the expected result
        :param add_cr: Add a Carriage-Return to the command sent or not
        :returns: Command output as string
        """
        data = ''
        last_send = None
        self.logger.debug("INTERACT: %s" % commands)
        for (cmd, arg) in commands:
            if cmd == 'send':
                if arg or add_cr:
                    if add_cr:
                        arg += '\r'
                    self.write(arg)
                    last_send = arg
            elif cmd == 'expect':
                if not arg:
                    continue
                cmd_data = ''
                match = False
                while not match:
                    this = self.readline(retry = 3)
                    if this:
                        cmd_data += this
                    else:
                        retry_count -= 1
                        if not retry_count:
                            raise VCCSCfgInteractError('YubiHSM did not produce the expected data "{!s}"'.format(arg),
                                                       commands, data, arg, cmd_data, last_send,
                                                       )
                    for line in cmd_data.split('\n'):
                        if re.match(arg, line):
                            match = True
                data += cmd_data
            else:
                assert ()
        return data

    def readline(self, retry):
        """ Read until the YubiHSM stops sending, or we spot a newline.

        :param retry: Number of times to retry, integer
        :returns: Read data as string (might be partial)
        """
        data = ''
        while True:
            this = self.read(1)
            if not this:
                retry -= 1
                if retry:
                    continue
                self.logger.debug("READ: %s (timeout)" % (repr(data)))
                return data
            retry = 1  # No retrys when the HSM has started sending
            data += this
            if this == '\n' or this == '\r':
                if len(data) > 1:
                    self.logger.debug("READ: %s" % (repr(data[:-1])))
                return data


class HsmConfigurator():
    """
    Class modelling the HSM to be configured.

    :param args: argsparse data
    :param logger: logging logger
    :param cfg_password: HSM configuration password as string
    :param master_key: HSM master key as string
    :raise: VCCSCfgError on initialization error
    """

    _DEVICE_BY_ID_DIR = '/dev/serial/by-id/'

    class HsmLogFilter(logging.Filter):
        """
        Logger filter implementing simple ON-OFF semantics.
        """

        def filter(self, record):
            """
            Filter function.

            :param record: Something about to get logged.
            :return: bool, Whether to log or not.
            """
            if hasattr(self, 'enabled'):
                return self.enabled
            return True

    def __init__(self, args, logger, cfg_password, master_key = None):
        """

        :param args:
        :param logger:
        :param cfg_password:
        :param master_key:
        :raise:
        """
        self.debug = args.debug
        self.logger = logger
        self.configured = None
        self.yhsm_id = None
        self.master_key = master_key
        self.cfg_password = cfg_password
        self.unprotected = False
        self.hsm = HsmSerial(args.device, logger)
        self.logger.debug("Opened %s" % self.hsm)
        try:
            if not self.execute('sysinfo', '^YubiHSM version'):
                self.hsm.close()
                raise VCCSCfgError('Failed executing sysinfo')
        except Exception:
            self.hsm.close()
            raise
        self.yhsm_id = self.hsm_id()
        # set up contextual logger with our HSM id
        try:
            # self.logger is probably a LoggerAdapter already - use it's parent or our yhsm_id
            # won't be visible
            self.logger = logging.LoggerAdapter(self.logger.logger, {'yhsm_id': self.yhsm_id})
        except Exception:
            self.logger = logging.LoggerAdapter(self.logger, {'yhsm_id': self.yhsm_id})
        self.logfilter = HsmConfigurator.HsmLogFilter()
        self.logger.logger.addFilter(self.logfilter)
        self.logger.debug("Opened %s", str(self))
        self.hsm.logger = self.logger

    def logging(self, status):
        """
        Enable or disable logging.

        :param status: bool, True to enable logging
        """
        self.logfilter.enabled = status

    def execute(self, command, expect, add_cr = True):
        """
        Send one or more commands to the YubiHSM and read until we get the expected response,
        and another prompt.

        For better control, use interact() instead.

        :param command: YubiHSM command to execute, string
        :param expect: String expected to occur as a result of the executed command
        :param add_cr: Add a Carriage-Return to the command sent or not
        """
        self.hsm.drain()
        next_prompt = '^(NO_CFG|HSM).*> .*'
        data = self.hsm.interact([('send', ''),
                                  ('expect', next_prompt),
                                  ('send', command),
                                  ('expect', expect),
                                  ('expect', next_prompt),
                                  ], add_cr)
        lines = data.split('\n')
        if re.match('^(NO_CFG|HSM).*> .*', lines[-1]):
            old = self.configured
            self.configured = lines[-1].startswith('HSM')
            if self.configured != old:
                self.logger.debug(
                    "HSM configured status update : %s (based on '%s')" % (self.configured, lines[-1][:-1]))
                # expected data seen (or none expected) and new prompt too
        return data

    def hsm_id(self):
        """
        Get the CPU unique identifier of the HSM.

        We have to look in /dev/serial/by-id/ to figure out the unique ID when the
        HSM is in configuration mode.
        """
        if self.yhsm_id:
            return self.yhsm_id
        (dirpath, dirnames, filenames) = os.walk(self._DEVICE_BY_ID_DIR).next()
        for this in filenames:
            link = os.readlink(os.path.join(self._DEVICE_BY_ID_DIR, this))
            if os.path.abspath(os.path.join(dirpath, link)) == self.hsm.device:
                m = re.match('usb-Yubico_Yubico_YubiHSM_([0-9A-F]+)-if00', this)
                if m:
                    self.yhsm_id = m.groups()[0]
                    return self.yhsm_id
                return this
        raise Exception('Failed finding link to %s in %s' % (self.hsm.device, self._DEVICE_BY_ID_DIR))

    def get_random(self, byte_count):
        """
        Get random data from the HSM, and then XOR it with random data from /dev/urandom
        to ensure against bad randomness in either source.
        :param byte_count: Number of random bytes to return
        :returns: Random data as string
        """
        bsize = 16
        # get 256 bytes extra to stir up the pool
        output = self.execute('rng %i' % ((256 / bsize) + (byte_count / bsize)), '').split('\n')
        hex_str = output[-2][:-1]  # second last line, and remove \r
        self.logger.debug("Got %s bytes of randomness from HSM" % (len(hex_str) / 2))
        # select bytes to use like OATH does (last byte is offset from end)
        last_byte = int(hex_str[-2:], 16)
        self.logger.debug(
            "Offset 0x%x, will use bytes %i-%i from end." % (last_byte, (byte_count + last_byte), last_byte))
        from_hsm = hex_str.decode('hex')[-(byte_count + last_byte):-last_byte]
        from_os = os.urandom(byte_count)
        xored = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(from_hsm, from_os)])
        self.logger.debug("Got %i bytes of randomness from HSM : '%s'" % (byte_count, from_hsm.encode('hex')))
        self.logger.debug("Got %i bytes of randomness from OS  : '%s'" % (byte_count, from_os.encode('hex')))
        self.logger.debug("HSM and OS data xored together : '%s'" % (xored.encode('hex')))
        return xored

    def get_crypto_key(self, text, length = None, generate = False, pad = True):
        """
        Prompt the user for a crypto key or, if generate==True, generate one using
        a combination of the YubiHSM random number generator and the host OS RNG.

        :param text: User prompt as string
        :param length: Expected length in bytes, integer
        :param generate: Generate or not, bool
        :param pad: Pad or not, bool
        :return: :raise:
        """
        while True:
            print ""
            data_str = raw_input(text)
            if not data_str:
                if not generate:
                    continue
                self.logger.info("No key given, will generate one using HSM and OS random generators.")
                return self.get_random(length)
            try:
                data = data_str.decode('hex')
                if length is not None:
                    if pad:
                        data = data.ljust(length, chr(0x0))
                    if length is not None and len(data) != length:
                        raise Exception('Key given is not %i bytes long (%i)' % (length, len(data)))
                return data
            except Exception as e:
                self.logger.error("Failed decoding input : %s" % e)

    def unlock_keystore(self, skip_test = False):
        """
        Decrypt the key store in the HSM using the master key.

        Prompt for the master key unless self.master_key is set already.
        :param skip_test: Skip validating the keystore is accessible
        """
        if not skip_test:
            # check if we need to decrypt the keystore
            prompt = self.execute('', '')[:-1]
            if "keys not decrypted" not in prompt:
                return True

        if not self.master_key:
            self.master_key = self.get_crypto_key("Enter the master key as hex : ",
                                                  length = 32, pad = True, generate = False).encode('hex')
        master_key = self.master_key
        (send, expect,) = ('send', 'expect',)  # for color highlighting clarity below
        commands = [(send, ''), (expect, '^HSM.*keys not decrypted.*> .*'),
                    (send, 'keydecrypt'), (expect, '.*Enter key.*'),
                    (send, master_key), (expect, '^Key decrypt succeeded'),
                    ]
        self.hsm.interact(commands)
        return True

    def unprotect(self):
        """
        Remove write protect mode, using the cfg password.
        """
        if self.unprotected:
            return
        (send, expect,) = ('send', 'expect',)  # for color highlighting clarity below
        commands = [(send, ''), (expect, '^HSM.*> .*'),
                    (send, 'unprot'), (expect, '.*enter password.*'),
                    (send, self.cfg_password), (expect, '.*ok.*'),
                    ]
        self.hsm.interact(commands)
        self.unprotected = True

    def keyload(self, key):
        """
        Load this key into a HSM.
        :param key: HsmKey()
        """
        self.unprotect()
        (send, expect,) = ('send', 'expect',)  # for color highlighting clarity below
        escape_char = chr(27)
        commands = [(send, ''), (expect, '^HSM.*> .*'),
                    (send, 'flags %x' % key.flags), (expect, 'Enabled flags 0*%x = ' % key.flags),
                    (send, 'keyload'), (expect, '.*Load key data now.*'),
                    (send, '%s,%s,,,\r%c' % (key.keyid.rjust(8, '0'), key.key, escape_char)), (expect, '.*stored ok.*'),
                    (send, ''), (expect, '^HSM.*keys changed.*> .*'),
                    ]
        self.hsm.interact(commands)

    def keylist(self):
        """
        List all the keys in the HSM. Return a list of HsmKey instances.
        """
        self.unlock_keystore()

        response = self.execute('keylist', 'Entries.*invalid 00000 free.*')  # safeguard against bad entries
        keys = []
        for line in response.split('\n'):
            # format : "121113ab,00010002" or "121113ab,key-goes-here-if-debug,00010002"
            match = re.match('^([0-9a-f]{8}),([0-9a-f,]+)*([0-9a-f]{8})\r$', line)
            if match:
                keyid = match.groups()[0]
                # don't need the secret, so leave it out
                flags = match.groups()[2]
                keys.append(HsmKey(keyid, None, int(flags, 16), 'unknown'))
        return sorted(keys, key = lambda this: this.keyid)

    def disable_key(self, key):
        """
        Disable a key handle. Overwrites the secret in the YubiHSM, but keeps the key
        handle id occupied so a new key can't be written to an old id.
        :param key: HsmKey to disable
        """
        self.unprotect()
        self.execute("keydis {s}".format(key.keyid), '')

    def keycommit(self, check_with_user = True):
        """
        Commit HSM keys to non-volatile storage inside the HSM, optionally verifying
        this is the users intent.

        :param check_with_user: Check with user before committing or not
        """
        while check_with_user and True:
            res = raw_input("Commit changes to keystore? Enter 'yes' or 'no' : ")
            if res == "no":
                self.logger.info("Keys NOT committed to permanent storage in HSM.")
                # XXX should maybe 'keydecrypt' here to revert any added keys?
                return False
            elif res == "yes":
                break

        self.execute('keycommit', '.*Done')
        self.logger.info("Keys committed to keystore.")
        return True
