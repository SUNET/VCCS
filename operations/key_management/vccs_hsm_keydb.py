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
HSM key related code. For use when configuring HSMs.
"""

import os
import re
import json
import datetime


class HsmKey():
    """
    Hold data about a key to load into one or more HSMs (or seen in one).
    """

    def __init__(self, keyid, key, flags, usage):
        assert (type(keyid) == str or type(keyid) == unicode)
        assert (type(flags) == int)
        assert (type(usage) == str or type(usage) == unicode)
        self.keyid = str(keyid)
        self.key = key
        self.flags = flags
        self.active = (self.flags != 0)
        self.usage = usage

    def __repr__(self):
        if self.flags == 0:
            return '{s} (disabled)'.format(self.keyid)
        return '{s} (age: {s} day(s), flags=0x{x}, usage={s})'.format(
            self.keyid, self.days_old(), self.flags, self.usage)

    def days_old(self):
        """
        For keys with keyid following the convention YYMMDDnn, figure out how
        many days old the key is.

        :return: Age in days as integer or False
        """
        match = re.match('^(\d\d)(\d\d)(\d\d)([a-f][a-f])$', self.keyid)
        if match:
            groups = match.groups()
            now = datetime.date.today()
            then = datetime.date(int(groups[0]) + 2000, int(groups[1]), int(groups[2]))
            return (now - then).days
        return False


class NDN_KeyDb():
    """
    JSON based file backup key database.
    """

    def __init__(self):
        self.keys = []

    def load(self, filename):
        """
        Read database from file.
        :param filename: string
        :return: Parsed JSON, should be dict
        """
        f = open(filename, 'r')
        data = f.read()
        f.close()
        return self.from_json(data)

    def save(self, filename):
        """
        Save database to file (in JSON format).

        :param filename: string
        """
        # serialize
        keys = [{'id': x.keyid,
                 'key': x.key,
                 'flags': hex(x.flags),
                 'usage': x.usage,
                 } for x in self.keys]
        data_j = json.dumps({'keydb': {'version': 1,
                                       'keys': keys,
                                       }
                             },
                            sort_keys = True,
                            indent = 4,
                            )
        f = open(filename + '.new', 'w')
        f.write(data_j)
        f.close()
        os.rename(filename + '.new', filename)

    def from_json(self, data_j):
        """
        Load database from JSON format.

        :param data_j: JSON string
        :return: NDN_KeyDb()
        :raise: Exception() on bad input data
        """
        data = json.loads(data_j)
        assert (type(data) == dict)
        if 'keydb' not in data:
            raise Exception("No keydb in JSON")
        if data['keydb'].get('version') != 1:
            raise Exception("Unknown keydb version")
            # de-serialize
        self.keys = [HsmKey(x['id'],
                            x['key'],
                            int(x['flags'], 16),
                            x['usage'],
                            ) for x in data['keydb']['keys']]
        return self

    def add_key(self, key):
        """
        Add a key to the (in-memory) database.

        :param key: HsmKey()
        :raise: Exception() on duplicate key
        """
        if self.get_key(key.keyid):
            raise Exception("Key '{s}' already in database".format(key.keyid))
        self.keys.append(key)

    def get_key(self, keyid):
        """
        Fetch a key from the (in-memory) database.

        :param keyid: Key id as string
        :return: None or HsmKey()
        """
        match = [x for x in self.keys if x.keyid == keyid]
        assert (len(match) < 2)
        if len(match) == 1:
            return match[0]

    def get_ids(self):
        """
        Get key id of all keys in (in-memory) database.

        :return: List of strings
        """
        return [x.keyid for x in self.keys]
