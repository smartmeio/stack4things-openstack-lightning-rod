# Copyright 2017 MDSLAB - University of Messina
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

__author__ = "Nicola Peditto <n.peditto@gmail.com>"

import json

SUCCESS = 'SUCCESS'
ERROR = 'ERROR'
WARNING = 'WARNING'
RUNNING = 'RUNNING'


def deserialize(received):
    m = json.loads(received)
    return WampMessage(**m)


class WampMessage(object):
    def __init__(self, message, result, req_id=None):
        self.message = message
        self.result = result
        if req_id != None:
            self.req_id = req_id

    def serialize(self):
        return json.dumps(self, default=lambda o: o.__dict__)


class WampSuccess(WampMessage):
    def __init__(self, msg=None, req_id=None):
        super(WampSuccess, self).__init__(msg, SUCCESS, req_id)


class WampError(WampMessage):
    def __init__(self, msg=None, req_id=None):
        super(WampError, self).__init__(msg, ERROR, req_id)


class WampWarning(WampMessage):
    def __init__(self, msg=None, req_id=None):
        super(WampWarning, self).__init__(msg, WARNING, req_id)


class WampRunning(WampMessage):
    def __init__(self, msg=None, req_id=None):
        super(WampRunning, self).__init__(msg, RUNNING, req_id)
