##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

"""
Change description for offset datapoint.
"""

import logging
log = logging.getLogger('zen.NtpMonitor.migrate.{}'.format(__name__))

from Products.ZenModel.migrate.Migrate import Version
from Products.ZenModel.ZenPack import ZenPackMigration
from Products.Zuul.interfaces import IDataPointInfo


class ChangeDatapointDescription(ZenPackMigration):
    """
    Change description for offset datapoint.
    """
    version = Version(3, 0, 0)

    def migrate(self, pack):
        try:
            devices = pack.getDmdRoot("Devices")
            log.info("Changing description for offset datapoint")
            datapoint = devices.getObjByPath(
                '/zport/dmd/Devices/rrdTemplates/NtpMonitor/'
                'datasources/NtpMonitor/datapoints/offset'
            )
            info = IDataPointInfo(datapoint)
            info.setDescription('The difference between the reference time and the system clock.')
            log.info("Description for offset datapoint changed")
        except Exception:
            log.info("Description for offset datapoint was not changed")

migration = ChangeDatapointDescription()
