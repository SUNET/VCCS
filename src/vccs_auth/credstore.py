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
Store VCCSAuthCredential objects in database.
"""

import pymongo
import bson
import time

import vccs_auth.credential
from vccs_auth.credential import VCCSAuthCredential


class VCCSAuthCredentialStore():

    """
    Class providing access to the VCCS authentication backend private
    credential store.
    """

    def __init__(self):
        pass

    def get_credential(self, credential_id, check_active=True):
        """
        Get a credential from the database.

        Unless check_active is False, it will be verified that this is not a
        revoked credential.

        :param credential_id: unique identifier as string
        :param check_active: If True, do not return revoked credentials
        :returns: VCCSAuthCredential object
        """
        raise NotImplementedError("Subclass should implement get_credential")

    def add_credential(self, cred):
        """
        Add a new credential to the database.

        :param cred: VCCSAuthCredential object
        :returns: True on success
        """
        raise NotImplementedError("Subclass should implement add_credential")

    def update_credential(self, cred, safe=True):
        """
        Update an existing credential in the database.

        :param cred: VCCSAuthCredential object
        :param safe: boolean, sub-class specific meaning
        :returns: True on success
        """
        raise NotImplementedError("Subclass should implement update_credential")


class VCCSAuthCredentialStoreMongoDB(VCCSAuthCredentialStore):
    """
    Store VCCSAuthCredential objects in MongoDB.

    The MongoDB documents look like this :

    {'_id': mongodb's unique id,
     'revision': integer - used to do atomic updates,
     'credential': dict that can be turned into VCCSAuthCredential,
     }
    """

    def __init__(self, uri, logger, conn=None, db_name="vccs_auth_credstore", **kwargs):
        VCCSAuthCredentialStore.__init__(self)
        if conn is not None:
            self.connection = conn
        else:
            if "replicaSet=" in uri:
                self.connection = pymongo.mongo_replica_set_client.MongoReplicaSetClient(uri, **kwargs)
            else:
                self.connection = pymongo.MongoClient(uri, **kwargs)
        self.db = self.connection[db_name]
        self.credentials = self.db.credentials
        retries = 5
        for this in xrange(retries):
            try:
                self.credentials.ensure_index('credential.credential_id', name='credential_id_idx', unique=True)
                break
            except pymongo.errors.AutoReconnect as exc:
                if this == (retries - 1):
                    raise
                logger.error("Failed ensuring mongodb index, retrying ({!r})".format(exc))
            except bson.errors.InvalidDocument as exc:
                # When VCCS starts at the same time as MongoDB (e.g. on reboot), this
                # error can be returned while MongoDB sorts out it's replica set status
                if this == (retries - 1):
                    raise
                logger.error("Failed ensuring mongodb index, retrying ({!r})".format(exc))
            time.sleep(1)

    def get_credential(self, credential_id, check_revoked=True):
        """
        Retrieve a credential from the database based on it's credential_id (not _id).

        The credential_id is a string supplied to the authentication backends
        from the frontend servers.

        :param credential_id: string
        :param check_revoked: boolean - True to raise exception on revoked credentials
        :return: VCCSAuthCredential object
        """
        if not isinstance(credential_id, basestring):
            raise TypeError("non-string credential_id")
        query = {'credential.credential_id': str(credential_id)}
        res = self.credentials.find_one(query)
        if res is None:
            return None
        metadata = {'id': res['_id'],
                    'revision': res['revision'],
                    }
        cred = vccs_auth.credential.from_dict(res['credential'],
                                              metadata,
                                              check_revoked=check_revoked,
                                              )
        return cred

    def add_credential(self, cred):
        """
        Add a new credential to the MongoDB collection.

        :param cred: VCCSAuthCredential object
        :returns: True on success, False or result of MongoDB insert()
        """
        if not isinstance(cred, VCCSAuthCredential):
            raise TypeError("non-VCCSAuthCredential cred")
        docu = {'revision': 1,
                'credential': cred.to_dict(),
                }
        try:
            res = self.credentials.insert(docu)
            if isinstance(res, bson.ObjectId):
                return True
            return res
        except pymongo.errors.DuplicateKeyError:
            return False

    def update_credential(self, cred, safe=True):
        """
        Update an existing credential in the MongoDB collection.

        Ensures atomic update using an increasing 'revision' attribute.

        :param cred: VCCSAuthCredential object
        :param safe: If True, block until write operation has completed
        :returns: True on success, False or result of MongoDB update()
        """
        if not isinstance(cred, VCCSAuthCredential):
            raise TypeError("non-VCCSAuthCredential cred")
        metadata = cred.metadata()
        spec = {'_id': metadata['id'],
                'revision': metadata['revision'],
                }
        data = {'revision': metadata['revision'] + 1,
                'credential': cred.to_dict(),
                }
        # XXX this function should return True on success
        return self.credentials.update(spec, {'$set': data}, safe=safe)
