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
import json
import requests

from autobahn.wamp import exception
from datetime import datetime

from iotronic_lightningrod.common import utils
# from iotronic_lightningrod.common.exception import timeout
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

    # SC
    async def DevicePing(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def Ping():

            try:

                command = "hostname"

                out = subprocess.Popen(
                    command,
                    shell=True, stdout=subprocess.PIPE
                )

                output = out.communicate()[0].decode('utf-8').strip()

                message = str(output) + " @ " + \
                    str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
                w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            except Exception as err:
                message = "Error in " + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))

            try:

                threading.Thread(target=Ping).start()

                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = Ping()

        return w_msg.serialize()

    # SC
    async def DeviceReboot(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

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

    # SC
    async def DeviceRestartLR(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        delay = 3  # default delay

        try:

            if parameters['delay'] > 3:
                delay = parameters['delay']

        except Exception as err:
            LOG.error(" - Error in 'delay' parameter: " + str(err))
            LOG.warning("--> default 'delay' parameter set: " + str(delay))

        LOG.info("--> delay: " + str(delay))

        # LR restarting
        lr_utils.LR_restart_delayed(delay)

        message = "Restarting LR in " + str(delay) \
                  + " seconds (" \
                  + datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') + ")..."

        w_msg = WM.WampSuccess(msg=message, req_id=req_id)

        return w_msg.serialize()

    # LONG
    async def DeviceUpgradeLR(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        if 'version' in parameters:
            version = parameters['version']
            if version == "":
                version = None
        else:
            version = None  # latest

        if 'update_conf' in parameters:
            update_conf = parameters['update_conf']
            if update_conf == "":
                update_conf = False
            elif update_conf == "false":
                update_conf = False
            elif update_conf == "true":
                update_conf = True
        else:
            update_conf = False

        if (version != None) and (version != "latest") and (version != ""):
            LOG.info("--> version specified: " + str(version))
            command = "pip3 install iotronic-lightningrod==" + str(version)
        else:
            LOG.info("--> version not specified: set 'latest'")
            command = "pip3 install --upgrade iotronic-lightningrod"

        if update_conf:
            LOG.info("--> overwrite iotronic.conf: True")
            command = command + " && lr_install"

        LOG.info("--> command: " + str(command))

        def upgradingLR():

            out = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            (stdout, stderr) = out.communicate()

            message = "--> Upgrading process result: " + str(out.returncode)
            LOG.info(message)
            print(message)

            if out.returncode != 0:

                LOG.error('--> Error executing upgrade command [%s]' % command)

                if stderr != None:
                    message = stderr.decode('utf-8').strip()
                    LOG.error('|--> stderr: \n%s' % str(message))
                    print(message)

                if stdout != None:
                    message = stdout.decode('utf-8').strip()
                    LOG.error('|--> stdout: \n%s' % str(message))
                    print(message)

                print("\n\n --> Lightning-rod not upgraded!")

                try:

                    w_msg = WM.WampError(
                        msg=str(stdout), req_id=req_id
                    ).serialize()

                except Exception as e:
                    message = " - Wamp Message error in '" \
                              + rpc_name + "': " + str(e)
                    LOG.error(message)
                    print(message)
                    w_msg = WM.WampError(
                        msg="WM error[" + str(e) + "]", req_id=req_id
                    ).serialize()

            else:

                message = "--> Upgrade output:\n\n"\
                          + str(stdout.decode('utf-8').strip()) + "\n\n"
                LOG.info(message)
                print(message)

                try:

                    w_msg = WM.WampSuccess(
                        msg="LR upgraded",
                        req_id=req_id
                    ).serialize()

                except Exception as e:
                    LOG.error(
                        " - Wamp Message error in '" + rpc_name + "': "
                        + str(e)
                    )

            try:

                wampNotify(self.device_session, self.board, w_msg, rpc_name)

            except exception.ApplicationError as e:
                LOG.error(
                    " - Notify result '" + rpc_name + "' error: " + str(e)
                )

            if out.returncode == 0:
                # Restart LR to start new version
                print("\n\n\nRestarting Lightning-rod after upgrade...")
                lr_utils.LR_restart_delayed(2)

        try:

            threading.Thread(target=upgradingLR).start()

        except Exception as err:
            LOG.error("Error in parameters: " + str(err))

        if version == None:
            version = "latest"

        out_msg = "LR upgrading to " + str(version) + " version..."

        w_msg = WM.WampRunning(msg=out_msg, req_id=req_id)

        return w_msg.serialize()

    # LONG
    async def DevicePkgOperation(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        pkg_error = False

        PKG_MNGS = ['apt', 'apt-get', 'pip', 'pip3', 'npm']
        PKG_CMDS = ['install', 'update', 'upgrade', 'remove', 'uninstall']

        cmd = None
        mng = None
        pkg = None
        opt = None
        version = None

        print("\nPackage manager operation: ")

        def actionOnPackage():
            out = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            (stdout, stderr) = out.communicate()

            message = "--> package operation result: " + str(out.returncode)
            LOG.info(message)

            if out.returncode != 0:

                msg = 'Error executing package operation: ' + str(command)
                LOG.error('--> ' + msg)

                if stderr != None:
                    message = stderr.decode('utf-8').strip()
                    LOG.error('|--> stderr: \n%s' % str(message))

                if stdout != None:
                    message = stdout.decode('utf-8').strip()
                    LOG.error('|--> stdout: \n%s' % str(message))

                try:

                    w_msg = WM.WampError(
                        msg=str(stdout), req_id=req_id
                    ).serialize()

                except Exception as e:
                    message = " - Wamp Message error in '" \
                              + rpc_name + "': " + str(e)
                    LOG.error(message)
                    print(message)
                    w_msg = WM.WampError(
                        msg="WM error[" + str(e) + "]", req_id=req_id
                    ).serialize()

            else:

                try:

                    message = "Package operation completed!"
                    print("--> " + str(message))
                    w_msg = WM.WampSuccess(
                        msg=message, req_id=req_id
                    ).serialize()

                except Exception as e:
                    message = "--> Notify result '" \
                              + rpc_name + "' error: " + str(e)
                    LOG.error(message)
                    print(message)
                    w_msg = WM.WampError(
                        msg="WM error[" + str(e) + "]", req_id=req_id
                    ).serialize()

            try:

                wampNotify(self.device_session, self.board, w_msg, rpc_name)

            except exception.ApplicationError as e:
                LOG.error(
                    " - Notify result '" + rpc_name + "' error: " + str(e)
                )

        try:

            if 'manager' in parameters:

                mng = parameters['manager']  # apt | apt-get | pip | pip3 | npm

                if mng not in PKG_MNGS:

                    if mng == "":
                        raise Exception("package manager not specified!")
                    else:
                        raise Exception("package manager '"
                                        + mng + "' not supported!")

                command = str(mng)

                if 'command' in parameters:

                    cmd = parameters['command']  # install | update | remove

                    if cmd not in PKG_CMDS:
                        if cmd == "":
                            raise Exception("operation not specified!")
                        else:
                            raise Exception("operation '"
                                            + cmd + "' not supported!")

                    if 'package' in parameters:
                        pkg = parameters['package']

                        if pkg == "":
                            raise Exception("package not specified!")

                        if 'options' in parameters:
                            opt = parameters['options']  # -f| --upgrade | etc

                            if opt != "":

                                command = command + " " + str(opt) \
                                    + " " + str(cmd) + " " + str(pkg)
                            else:
                                command = command + " " + str(cmd) \
                                    + " " + str(pkg)

                        else:
                            command = command + " " + str(cmd) \
                                + " " + str(pkg)

                        if 'version' in parameters:

                            version = parameters['version']

                            if version != "":
                                if (mng == "pip") or (mng == "pip3"):
                                    command = command + "==" + str(version)

                                elif (mng == "apt") or (mng == "apt-get"):
                                    command = command + "=" + str(version)

                                elif mng == "npm":
                                    command = command + "@" + str(version)

                    else:
                        raise Exception("package name not specified!")

                else:
                    raise Exception("command not specified!")

            else:
                raise Exception("package manager not specified!")

            # If no errors in parsing parameters, start execution
            try:

                threading.Thread(target=actionOnPackage).start()

                message = "Executing '" + str(cmd) \
                          + "' operation on package '" + str(pkg) + "'"

                w_msg = WM.WampRunning(
                    msg=message, req_id=req_id
                )
                LOG.info(message)

            except Exception:
                message = "Error executing '" + str(cmd) \
                          + "' operation on package '" + str(pkg) + "'"
                w_msg = WM.WampError(
                    msg=message, req_id=req_id
                )
                LOG.warning(message)

        except Exception as err:
            # LOG.warning(err)
            message = "Error in parameters: " + str(err)
            w_msg = WM.WampError(
                msg=message, req_id=req_id
            )
            LOG.warning(message)

        return w_msg.serialize()

    # SC
    async def DeviceEcho(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def Echo():

            try:

                message = str(parameters['say']) + " @ " + \
                    str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
                LOG.info("--> Echo: " + str(message))
                w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            except Exception as err:
                LOG.warning("--> Error in " + rpc_name + ": " + str(err))
                message = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
                LOG.info("--> Echo (no-params): " + str(message))
                w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))
            try:
                threading.Thread(target=Echo).start()
                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = Echo()

        return w_msg.serialize()

    # SC
    async def DeviceMountFs(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def MountFs():
            try:

                command = None

                # mount_rw|mount_ro|mount_status
                action = str(parameters['mnt_cmd'])

                if action == "mount_rw":
                    command = "rootrw"

                elif action == "mount_ro":
                    command = "rootro"

                elif action == "mount_status":
                    command = "cat /proc/mounts"

                else:
                    command = None

                LOG.info(" - " + str(action) + " -> " + str(command))

                if command != None:

                    out = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )

                    (stdout, stderr) = out.communicate()

                    if out.returncode != 0:
                        message = "Error code " + str(out.returncode) + ": '" \
                                  + str(stderr.decode('utf-8').strip()) + "'"
                        LOG.warning(message)
                        w_msg = WM.WampError(msg=message, req_id=req_id)
                    else:
                        message = stdout.decode('utf-8').strip()
                        w_msg = WM.WampSuccess(msg=message, req_id=req_id)

                else:
                    message = "Mount command '" + str(action) \
                              + "' not supported!"
                    w_msg = WM.WampError(msg=message, req_id=req_id)

            except Exception as err:
                LOG.warning("--> Error in " + rpc_name + ": " + str(err))
                message = str(err)
                w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))
            try:
                threading.Thread(target=MountFs).start()
                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = MountFs()

        LOG.info(" - Result sent to Iotronic.")

        return w_msg.serialize()

    # SC
    async def DeviceFactoryReset(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def FactoryReset():
            message = factory_reset()
            w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))
            try:
                threading.Thread(target=FactoryReset).start()
                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = FactoryReset()

        return w_msg.serialize()

    # SC
    async def DeviceNetConfig(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def Ifconfig():
            message = getIfconfig()
            w_msg = WM.WampSuccess(msg=message, req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))
            try:
                threading.Thread(target=Ifconfig).start()
                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = Ifconfig()

        return w_msg.serialize()

    # SC
    async def DeviceRestSubmit(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def RestSubmit():

            try:

                if 'url' in parameters:
                    url = str(parameters['url'])
                else:
                    message = "Error RestSubmit: no url specified."
                    LOG.error(message)
                    w_msg = WM.WampError(msg=message, req_id=req_id)
                    return w_msg

                if 'method' in parameters:
                    method = str(parameters['method'])
                else:
                    message = "Error RestSubmit: no REST method specified."
                    LOG.error(message)
                    w_msg = WM.WampError(msg=message, req_id=req_id)
                    return w_msg

                response = requests.request(
                    method,
                    url,
                    params=json.dumps(parameters['params']) \
                        if 'params' in parameters else None,
                    data=json.dumps(parameters['data']) \
                        if 'data' in parameters else None,
                    json=parameters['json'] \
                        if 'json' in parameters else None,
                    headers=parameters['headers'] \
                        if 'headers' in parameters else None,
                    cookies=parameters['cookies'] \
                        if 'cookies' in parameters else None,
                    files=parameters['files'] \
                        if 'files' in parameters else None,
                    auth=parameters['auth'] \
                        if 'auth' in parameters else None,
                    timeout=float(parameters['timeout']) \
                        if 'timeout' in parameters else None,
                    allow_redirects=parameters['allow_redirects'] \
                        if 'allow_redirects' in parameters else True,
                    proxies=parameters['proxies'] \
                        if 'proxies' in parameters else None,
                    verify=parameters['verify'] \
                        if 'verify' in parameters else True,
                    stream=parameters['stream'] \
                        if 'stream' in parameters else False,
                    cert=parameters['cert'] \
                        if 'cert' in parameters else None,

                )

                res = json.loads(response.text)

                w_msg = WM.WampSuccess(msg=res, req_id=req_id)

            except Exception as err:
                return WM.WampError(msg=str(err), req_id=req_id)

            if (req['main_request_uuid'] != None):
                wampNotify(self.device_session,
                           self.board, w_msg.serialize(), rpc_name)
            else:
                return w_msg

        if (req['main_request_uuid'] != None):

            LOG.info(" - main request: " + str(req['main_request_uuid']))
            try:

                threading.Thread(target=RestSubmit).start()
                w_msg = WM.WampRunning(msg=rpc_name, req_id=req_id)

            except Exception as err:
                message = "Error in thr_" + rpc_name + ": " + str(err)
                LOG.error(message)
                w_msg = WM.WampError(msg=message, req_id=req_id)

        else:
            w_msg = RestSubmit()

        return w_msg.serialize()


def lr_install():
    bashCommand = "lr_install"
    process = subprocess.Popen(bashCommand.split(),
                                stdout=subprocess.PIPE)
    output, error = process.communicate()

    return


def factory_reset():

    LOG.info("Lightning-rod factory reset: ")

    # delete nginx conf.d files
    os.system("rm /etc/nginx/conf.d/lr_*")
    LOG.info("--> NGINX settings deleted.")

    # delete letsencrypt
    os.system("rm -r /etc/letsencrypt/*")
    LOG.info("--> LetsEncrypt settings deleted.")

    # delete var-iotronic
    os.system("rm -r /var/lib/iotronic/*")
    LOG.info("--> Iotronic data deleted.")

    # delete etc-iotronic
    os.system("rm -r /etc/iotronic/*")
    LOG.info("--> Iotronic settings deleted.")

    # exec lr_install
    lr_install()

    # restart LR
    LOG.info("--> LR restarting in 5 seconds...")
    lr_utils.LR_restart_delayed(5)

    return "Device reset completed"


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


def getSerialDevice():

    try:

        command = "cat /proc/cpuinfo |grep Serial| awk '{print $3}'"

        out = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE
        )

        output = str(out.communicate()[0].decode('utf-8').strip())

        if(output == ""):
            output = "N/A"

    except Exception as err:
        LOG.error("Error getting serial device: " + str(err))
        output = "N/A"

    return output
