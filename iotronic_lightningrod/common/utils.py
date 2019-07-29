# Copyright 2018 MDSLAB - University of Messina
#    All Rights Reserved.
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

from oslo_log import log as logging
LOG = logging.getLogger(__name__)

import inspect
import os
import pkg_resources
import site


def getFuncName():
    return inspect.stack()[1][3]


def checkIotronicConf(lr_CONF):

    try:

        if(lr_CONF.log_file == "None"):
            LOG.warning("'log_file' is not specified!")
        else:
            print("View logs in " + lr_CONF.log_file)

        return True

    except Exception as err:
        print(err)
        return False


def get_version(package):
    package = package.lower()
    return next((p.version for p in pkg_resources.working_set if
                 p.project_name.lower() == package), "No version")


def backupConf():
    try:
        os.system(
            'cp /etc/iotronic/settings.json /etc/iotronic/settings.json.bkp'
        )
    except Exception as e:
        LOG.warning("Error restoring configuration " + str(e))


def restoreConf():
    try:
        result = os.system(
            'cp /etc/iotronic/settings.json.bkp /etc/iotronic/settings.json'
        )
    except Exception as e:
        LOG.warning("Error restoring configuration " + str(e))
        result = str(e)

    return result


def restoreFactoryConf():
    try:
        py_dist_pack = site.getsitepackages()[0]
        os.system(
            'cp ' + py_dist_pack + '/iotronic_lightningrod/'
            + 'templates/settings.example.json '
            + '/etc/iotronic/settings.json'
        )
    except Exception as e:
        LOG.warning("Error restoring configuration " + str(e))
