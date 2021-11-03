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

import asyncio
import pkg_resources
from six import moves
from stevedore import extension
from threading import Timer

import os
import psutil
import subprocess
import sys
import threading
import time
import signal


from iotronic_lightningrod.common import utils
from iotronic_lightningrod.config import entry_points_name
from iotronic_lightningrod.modules import Module
from iotronic_lightningrod.modules import utils as lr_utils


from oslo_log import log as logging
LOG = logging.getLogger(__name__)

global connFailureRecovery
connFailureRecovery = None

global gdbPid
gdbPid = None


class Utility(Module.Module):

    def __init__(self, board, session):
        super(Utility, self).__init__("Utility", board)

        self.session = session

    def finalize(self):
        pass

    def restore(self):
        pass

    async def hello(self, req_id, client_name, message, parameters=None):

        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        import random
        s = random.uniform(0.5, 3.0)
        await asyncio.sleep(s)
        result = "Hello by board to Conductor " + client_name + \
                 " that said me " + message + " - Time: " + '%.2f' % s
        LOG.info("DEVICE hello result: " + str(result))

        return result

    async def plug_and_play(self, req_id, new_module, new_class,
                            parameters=None):

        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        LOG.info("LR modules loaded:\n\t" + new_module)

        # Updating entry_points
        with open(entry_points_name, 'a') as entry_points:
            entry_points.write(
                new_module +
                '= iotronic_lightningrod.modules.' + new_module + ':'
                + new_class
            )

            # Reload entry_points
            refresh_stevedore('s4t.modules')
            LOG.info("New entry_points loaded!")

        # Reading updated entry_points
        named_objects = {}
        for ep in pkg_resources.iter_entry_points(group='s4t.modules'):
            named_objects.update({ep.name: ep.load()})

        await named_objects

        self.session.disconnect()

        return str(named_objects)

    async def changeConf(self, req_id, conf, parameters=None):
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        await self.board.getConf(conf)

        self.board.setUpdateTime()

        result = "Board configuration changed!"
        LOG.info("PROVISIONING RESULT: " + str(result))

        return result

    async def destroyNode(self, req_id, conf, parameters=None):

        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]:")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        await self.board.setConf(conf)

        result = "Board configuration cleaned!"
        LOG.info("DESTROY RESULT: " + str(result))

        return result


def refresh_stevedore(namespace=None):
    """Trigger reload of entry points.

    Useful to have dynamic loading/unloading of stevedore modules.
    """
    # NOTE(sheeprine): pkg_resources doesn't support reload on python3 due to
    # defining basestring which is still there on reload hence executing
    # python2 related code.
    try:
        del sys.modules['pkg_resources'].basestring
    except AttributeError:
        # python2, do nothing
        pass
    # Force working_set reload
    moves.reload_module(sys.modules['pkg_resources'])
    # Clear stevedore cache
    cache = extension.ExtensionManager.ENTRY_POINT_CACHE
    if namespace:
        if namespace in cache:
            del cache[namespace]
    else:
        cache.clear()


def LR_restart_delayed(seconds):

    try:
        if seconds < 3:
            seconds = 3

        LOG.warning("Lightning-rod restarting in "
                    + str(seconds) + " seconds...")

        def delayLRrestarting():
            time.sleep(seconds)
            python = sys.executable
            os.execl(python, python, *sys.argv)

        threading.Thread(target=delayLRrestarting).start()
    except Exception as err:
        LOG.error("Lightning-rod restarting error: " + str(err))


def LR_restart():
    try:
        LOG.warning("Lightning-rod restarting in few seconds...")
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as err:
        LOG.error("Lightning-rod restarting error: " + str(err))


def destroyWampSocket():

    LR_PID = os.getpid()

    global connFailureRecovery
    if connFailureRecovery != None:
        LOG.info(
            "WAMP Connection Recovery timer: CLEANED."
        )
        connFailureRecovery.cancel()

    def timeout():
        LOG.warning("WAMP Connection Recovery timer: EXPIRED")
        lr_utils.LR_restart()

    def timeoutGDB():
        LOG.warning("WAMP Connection Recovery GDB timer: EXPIRED")

        global gdbPid
        os.kill(gdbPid, signal.SIGKILL)
        LOG.warning("WAMP Connection Recovery GDB process: KILLED")

        LOG.warning("WAMP Connection Recovery GDB process: LR restarting...")
        lr_utils.LR_restart()

    connFailureRecovery = Timer(30, timeout)
    connFailureRecovery.start()
    LOG.warning("WAMP Connection Recovery timer: STARTED")

    try:

        gdbTimeoutCheck = Timer(30, timeoutGDB)
        gdbTimeoutCheck.start()
        LOG.debug("WAMP Connection Recovery GDB timer: STARTED")

        process = subprocess.Popen(
            ["gdb", "-p", str(LR_PID)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )

        global gdbPid
        gdbPid = process.pid

        proc = psutil.Process()

        conn_list = proc.connections()
        proc_msg = "WAMP RECOVERY: " + str(conn_list)
        print(proc_msg)
        LOG.info(proc_msg)

        wamp_conn_set = False

        for socks in conn_list:
            # print(socks.raddr, socks.fd)
            if socks.raddr != ():
                # print(socks.raddr.port, socks.fd)
                if socks.raddr.port == 8181:
                    socks_msg = "FD selected: " + str(socks.fd) \
                                + " [port " + str(socks.raddr.port) + "]"

                    print(socks_msg)
                    LOG.info(socks_msg)

                    ws_fd = socks.fd
                    first = b"call ((void(*)()) shutdown)("
                    fd = str(ws_fd).encode('ascii')
                    last = b"u,0)\nquit\ny"
                    commands = b"%s%s%s" % (first, fd, last)
                    process.communicate(input=commands)[0]

                    msg = "Websocket-Zombie closed! Restoring..."
                    LOG.warning(msg)
                    print(msg)
                    # WAMP connection found!
                    wamp_conn_set = True
                    # LOG.info("WAMP CONNECTION FOUND")
                    LOG.info(
                        "WAMP Connection Recovery timer: CANCELLED."
                    )
                    connFailureRecovery.cancel()

        gdbTimeoutCheck.cancel()
        LOG.debug("WAMP Connection Recovery GDB timer: CLEANED")

        if wamp_conn_set == False:
            LOG.warning("WAMP CONNECTION NOT FOUND: LR restarting...")
            # In conn_list there is not the WAMP connection!
            lr_utils.LR_restart()

    except Exception as e:
        LOG.warning("RPC-ALIVE - destroyWampSocket error: " + str(e))
        lr_utils.LR_restart()


def get_socket_info(wport):

    sock_bundle = "N/A"

    try:
        for socks in psutil.Process().connections():
            if len(socks.raddr) != 0:
                if (socks.raddr.port == wport):
                    lr_net_iface = socks
                    print("WAMP SOCKET: " + str(lr_net_iface))
                    dct = psutil.net_if_addrs()
                    for key in dct.keys():
                        if isinstance(dct[key], dict) == False:
                            iface = key
                            for elem in dct[key]:
                                ip_addr = elem.address
                                if ip_addr == str(lr_net_iface.laddr.ip):
                                    for snicaddr in dct[iface]:
                                        if snicaddr.family == 17:
                                            lr_mac = snicaddr.address
                                            sock_bundle = [iface, ip_addr,
                                                           lr_mac]
                                            return sock_bundle

        return sock_bundle

    except Exception as e:
        LOG.warning("Error getting socket info " + str(e))
        sock_bundle = "N/A"
        return sock_bundle

    return sock_bundle
