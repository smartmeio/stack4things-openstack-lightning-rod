#    Copyright 2017 MDSLAB - University of Messina. All Rights Reserved.
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

from iotronic_lightningrod.common import utils
from iotronic_lightningrod.config import package_path
from iotronic_lightningrod.lightningrod import RPC_proxies
from iotronic_lightningrod.lightningrod import wampNotify
from iotronic_lightningrod.modules import Module
import iotronic_lightningrod.wampmessage as WM

from autobahn.wamp import exception
import threading
import importlib as imp
import inspect
import json
import OpenSSL.crypto
import os
import time


from oslo_config import cfg
from oslo_log import log as logging
LOG = logging.getLogger(__name__)

proxy_opts = [
    cfg.StrOpt(
        'proxy',
        choices=[('nginx', ('nginx proxy')), ],
        help=('Proxy for WebServices Manager')
    ),
]

CONF = cfg.CONF

webservice_group = cfg.OptGroup(
    name='webservices', title='WebServices options'
)
CONF.register_group(webservice_group)
CONF.register_opts(proxy_opts, group=webservice_group)


class WebServiceManager(Module.Module):

    def __init__(self, board, session):
        super(WebServiceManager, self).__init__("WebServiceManager", board)

        LOG.info(" - Proxy used: " + CONF.webservices.proxy.upper())

        self.session = session

        try:
            proxy_type = CONF.webservices.proxy
            path = package_path + "/modules/proxies/" + proxy_type + ".py"

            if os.path.exists(path):

                proxy_module = imp.import_module(
                    "iotronic_lightningrod.modules.proxies." + proxy_type
                )

                LOG.info(" --> " + proxy_type.upper() + " module imported!")

                proxy = proxy_module.ProxyManager()

                proxy_meth_list = inspect.getmembers(
                    proxy,
                    predicate=inspect.ismethod
                )

                RPC_proxies[proxy_type] = proxy_meth_list

                board.proxy = proxy

                self._proxyWampRegister(proxy_meth_list, board)

            else:
                LOG.warning("Proxy '" + proxy_type + "' not supported!")

        except Exception as err:
            LOG.error("Error init WebServiceManager: " + str(err))

    def finalize(self):

        try:

            proxy_status = json.loads(self.board.proxy._proxyInfo())
            LOG.info("--> Proxy " + self.board.proxy.type.upper()
                     + " status:\n Active: " + str(proxy_status['status'])
                     + "\n Info: " + str(proxy_status['log']))

            LOG.info("Webservice exposed on device:")
            active_webservice_list = self.board.proxy._webserviceList()
            if len(active_webservice_list) != 0:
                for ws in active_webservice_list:
                    ws = ws.replace('.conf', '')
                    LOG.info("-> " + ws)
            else:
                LOG.info("-> NO WebService!")

            LOG.info("Certificates on device:")
            active_certs_list = self._certsList()
            if len(active_certs_list) != 0:
                for certificate in active_certs_list:
                    LOG.info("-> " + certificate)

                    c = open('/etc/letsencrypt/live/'
                             + certificate + '/cert.pem').read()
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, c)

                    LOG.info("--> Subject: " + str(cert.get_subject()))
                    LOG.info("--> ISSUER Organization:" +
                             str(cert.get_issuer()))
                    LOG.info("--> Expire date: " + str(
                        cert.get_notAfter().decode("utf-8")))
                    LOG.info("--> Expired: " + str(cert.has_expired()))

            else:
                LOG.info("-> NO certificates!")

            # Safe apply changes on proxy
            self.board.proxy._proxyReload()
            time.sleep(3)

            LOG.info("WebService Manager initialized!")

        except Exception as err:
            LOG.error("Error finalize init WebServiceManager: " + str(err))

    def restore(self):
        LOG.info("WebService Manager restored.")

    def _certsList(self):

        letsencrypt_path = "/etc/letsencrypt/live/"

        if os.path.exists(letsencrypt_path):
            certs_list = [
                f for f in os.listdir(letsencrypt_path)
                if os.path.isdir(os.path.join(letsencrypt_path, f))
            ]
        else:
            certs_list = []

        return certs_list

    def _proxyWampRegister(self, proxy_meth_list, board):

        LOG.info(" - " + str(board.proxy.type).upper()
                 + " proxy registering RPCs:")

        for meth in proxy_meth_list:
            if (meth[0] != "__init__") & (meth[0] != "finalize") \
                    & (meth[0] != "restore"):
                # LOG.info(" - " + str(meth[0]))
                rpc_addr = u'iotronic.' + str(board.session_id) + '.' + \
                           board.uuid + '.' + meth[0]

                # LOG.debug(" --> " + str(rpc_addr))
                if not meth[0].startswith('_'):
                    self.session.register(meth[1], rpc_addr)
                    LOG.info("   --> " + str(meth[0]))

    # LONG
    async def ExposeWebservice(self, req, board_dns, service_dns,
                               local_port, dns_list, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        response = self.board.proxy._exposeWebservice(board_dns, service_dns,
                                                      local_port, dns_list)

        response = json.loads(response)

        if(response['result'] == "SUCCESS"):
            message = "Webservice '" + service_dns + "' successfully exposed!"
            LOG.info("--> " + str(message))
            w_msg = WM.WampSuccess(msg=response, req_id=req_id)
        else:
            LOG.warning("--> " + str(response['message']))
            w_msg = WM.WampWarning(msg=response, req_id=req_id)

        return w_msg.serialize()

    # LONG
    async def UnexposeWebservice(self, req, service, dns_list,
                                 parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        response = self.board.proxy._disableWebservice(service, dns_list)

        response = json.loads(response)

        if (response['result'] == "SUCCESS"):
            LOG.info("--> " + str(response['message']))
            w_msg = WM.WampSuccess(msg=response, req_id=req_id)
        else:
            LOG.warning("--> " + str(response['message']))
            w_msg = WM.WampWarning(msg=response, req_id=req_id)

        return w_msg.serialize()

    # LONG
    async def EnableWebService(self, req, board_dns, owner_email,
                               parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        message = self.board.proxy._proxyEnableWebService(
            board_dns,
            owner_email
        )
        w_msg = WM.WampSuccess(msg=message, req_id=req_id)

        return w_msg.serialize()

    # LONG
    async def DisableWebService(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        message = self.board.proxy._proxyDisableWebService()

        w_msg = WM.WampSuccess(msg=message, req_id=req_id)

        return w_msg.serialize()

    """
    # LONG
    async def RenewWebservice(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        message = self.board.proxy._proxyRenewWebservice()

        w_msg = WM.WampSuccess(msg=message, req_id=req_id)

        return w_msg.serialize()
    """

    # LONG
    async def RenewWebservice(self, req, parameters=None):
        req_id = req['uuid']
        rpc_name = utils.getFuncName()
        LOG.info("RPC " + rpc_name + " CALLED [req_id: " + str(req_id) + "]")
        if parameters is not None:
            LOG.info(" - " + rpc_name + " parameters: " + str(parameters))

        def renewing():
            message = self.board.proxy._proxyRenewWebservice()

            try:

                message = json.loads(message)

                w_msg = WM.WampMessage(
                    message=message['message'],
                    result=message['result'],
                    req_id=req_id
                )

            except Exception as e:
                LOG.error(e)
                w_msg = WM.WampError(
                    msg="Error returning message",
                    req_id=req_id
                )

            try:

                wampNotify(
                    self.session,
                    self.board,
                    w_msg.serialize(),
                    rpc_name
                )

            except exception.ApplicationError as e:
                LOG.error(
                    " - Notify result '" + rpc_name + "' error: " + str(e)
                )

        try:

            threading.Thread(target=renewing).start()

        except Exception as err:
            LOG.error("Error in renewing thread: " + str(err))

        out_msg = "LR is renewing webservice certificates..."

        w_msg = WM.WampRunning(msg=out_msg, req_id=req_id)

        return w_msg.serialize()
