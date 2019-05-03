# Copyright 2017 MDSLAB - University of Messina
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

__author__ = "Nicola Peditto <n.peditto@gmail.com>"

import importlib as imp
import inspect
import os
import subprocess
import threading
import time

from autobahn.wamp import exception
from datetime import datetime

from iotronic_lightningrod.common import utils
from iotronic_lightningrod.config import package_path
from iotronic_lightningrod.lightningrod import RPC_devices
from iotronic_lightningrod.lightningrod import wampNotify
from iotronic_lightningrod.modules import Module
from iotronic_lightningrod.modules import utils as lr_utils
import iotronic_lightningrod.wampmessage as WM


from oslo_log import log as logging
LOG = logging.getLogger(__name__)


class DeviceManager(Module.Module):

    def __init__(self, board, session):

        # Module declaration
        super(DeviceManager, self).__init__("DeviceManager", board)

        self.device_session = session

        device_type = board.type

        path = package_path + "/devices/" + device_type + ".py"

        if os.path.exists(path):

            device_module = imp.import_module(
                "iotronic_lightningrod.devices." + device_type
            )

            LOG.info(" - Device '" + device_type + "' module imported!")

            device = device_module.System()

            dev_meth_list = inspect.getmembers(
                device,
                predicate=inspect.ismethod
            )

            RPC_devices[device_type] = dev_meth_list

            self._deviceWampRegister(dev_meth_list, board)

            board.device = device

        else:
            LOG.warning("Device '" + device_type + "' not supported!")

    def finalize(self):
        pass

    def restore(self):
        pass

    def _deviceWampRegister(self, dev_meth_list, board):

        LOG.info(" - " + str(board.type).capitalize()
                 + " device registering RPCs:")

        for meth in dev_meth_list:

            if (meth[0] != "__init__") & (meth[0] != "finalize"):
                LOG.info(" - " + str(meth[0]))
                # rpc_addr = u'iotronic.' + board.uuid + '.' + meth[0]
                rpc_addr = u'iotronic.' + str(board.session_id) + '.' + \
                           board.uuid + '.' + meth[0]

                # LOG.debug(" --> " + str(rpc_addr))
                self.device_session.register(meth[1], rpc_addr)

                LOG.info("   --> " + str(meth[0]) + " registered!")

    async def DevicePing(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        command = "hostname"

        try:
            out = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE
            )

            output = out.communicate()[0].decode('utf-8').strip()

        except Exception as err:
            LOG.error("Error in parameters: " + str(err))
            output = "N/A"

        message = str(output) + " @ " + \
            str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
        w_msg = WM.WampSuccess(message)

        return w_msg.serialize()

    async def DeviceReboot(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        delay = 3  # default delay

        try:

            if parameters['delay'] > 3:
                delay = parameters['delay']

        except Exception as err:
            LOG.error("Error in 'delay' parameter: " + str(err))
            LOG.warning("--> default 'delay' parameter set: " + str(delay))

        LOG.info("--> delay: " + str(delay))

        def delayBoardReboot():
            time.sleep(delay)
            subprocess.call("reboot", shell=True)

        threading.Thread(target=delayBoardReboot).start()

        if parameters == None:
            message = "Rebooting board in few seconds @" + \
                      str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
        else:
            message = "Rebooting board in " + str(delay) + " seconds (" \
                      + datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') \
                      + ")..."

        w_msg = WM.WampSuccess(message)

        return w_msg.serialize()

    async def DeviceRestartLR(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        delay = 3  # default delay

        try:

            if parameters['delay'] > 3:
                delay = parameters['delay']

        except Exception as err:
            LOG.error("Error in 'delay' parameter: " + str(err))
            LOG.warning("--> default 'delay' parameter set: " + str(delay))

        LOG.info("--> delay: " + str(delay))

        # LR restarting
        lr_utils.LR_restart_delayed(delay)

        message = "Restarting LR in " + str(delay) \
                  + " seconds (" \
                  + datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') + ")..."

        w_msg = WM.WampSuccess(message)

        return w_msg.serialize()

    async def DeviceUpgradeLR(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        try:

            version = parameters['version']

        except Exception as err:
            LOG.info("--> version not specified: set 'latest'")
            version = None  # latest

        if (version != None) and (version != "latest"):

            command = "pip3 install iotronic-lightningrod==" + str(version)

        else:
            command = "pip3 install --upgrade iotronic-lightningrod"

        def upgradingLR():

            out = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE
            )

            output = out.communicate()[0].decode('utf-8').strip()
            LOG.info("\n" + str(output))

            try:

                w_msg = WM.WampSuccess(
                    msg="LR upgraded", req_id=req_id
                ).serialize()

            except Exception as e:
                LOG.error(" - Wamp Message error in '"
                          + rpc_name + "': " + str(e))

            try:

                notify = wampNotify(self.device_session, self.board, w_msg)

                LOG.info(
                    " - Notify result '" + rpc_name + "': "
                    + str(notify.result) + " - " + str(notify.message)
                )

            except exception.ApplicationError as e:
                LOG.error(" - Notify result '"
                          + rpc_name + "' error: " + str(e))

            # Restart LR to start new version
            lr_utils.LR_restart_delayed(2)

        try:

            threading.Thread(target=upgradingLR).start()

        except Exception as err:
            LOG.error("Error in parameters: " + str(err))

        w_msg = WM.WampRunning("LR upgrading...")

        return w_msg.serialize()

    async def DevicePackageAction(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        try:

            mng = parameters['manager']  # apt | apt-get | pip | pip3 | npm
            opt = parameters['options']  # -f| --upgrade | etc
            cmd = parameters['command']  # install | update | remove
            pkg = parameters['package']
            version = parameters['version']

            command = str(mng)

            if opt == None:
                command = command + " " + str(cmd) + " " + str(pkg)
            else:
                command = command + " " + str(opt) + " " + str(cmd) \
                    + " " + str(pkg)

            if version != None:

                if (mng == "pip") or (mng == "pip3"):
                    command = command + "==" + str(version)

                elif (mng == "apt") or (mng == "apt-get"):
                    command = command + "=" + str(version)

                elif mng == "npm":
                    command = command + "@" + str(version)

            else:
                command = command + " " + str(pkg)

        except Exception as err:
            LOG.warning(err)

        def actionOnPackage():
            out = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE
            )

            output = out.communicate()[0].decode('utf-8').strip()
            LOG.info(str(output))

            try:

                w_msg = WM.WampSuccess(
                    msg="Package Action completed", req_id=req_id
                ).serialize()

            except Exception as e:
                LOG.error(" - Wamp Message error in '"
                          + rpc_name + "': " + str(e))

            try:

                notify = wampNotify(self.device_session, self.board, w_msg)

                LOG.info(
                    " - Notify result '" + rpc_name + "': "
                    + str(notify.result) + " - " + str(notify.message)
                )

            except exception.ApplicationError as e:
                LOG.error(" - Notify result '"
                          + rpc_name + "' error: " + str(e))

        try:

            threading.Thread(target=actionOnPackage).start()

        except Exception as err:
            LOG.error("Error in parameters: " + str(err))

        w_msg = WM.WampSuccess("LR upgrading...")

        return w_msg.serialize()

    async def DeviceEcho(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        try:

            message = str(parameters['say']) + " @ " + \
                str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
            LOG.info("--> Echo: " + str(message))

        except Exception as err:
            LOG.warning("Error in parameters: " + str(err))
            message = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
            LOG.info("--> Echo (no-params): " + str(message))

        w_msg = WM.WampSuccess(message)

        return w_msg.serialize()

    async def DeviceNetConfig(self, req_id, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        LOG.info("--> Parameters: " + str(parameters))

        message = getIfconfig()
        w_msg = WM.WampSuccess(message)

        return w_msg.serialize()


def getIfconfig():

    try:

        command = "ifconfig"

        out = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE
        )

        output = str(out.communicate()[0].decode('utf-8').strip())

    except Exception as err:
        LOG.error("Error in 'ifconfig' command: " + str(err))
        output = "N/A"

    return output
