##############################################################################
#
# Copyright (C) Zenoss, Inc. 2015-2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import Globals
from Products.ZenUtils.Utils import unused
unused(Globals)
from ZenPacks.zenoss.NtpMonitor.datasources import NtpMonitorDataSource
from ZenPacks.zenoss.NtpMonitor.ntp import *
import unittest
from mock import Mock


class TestNtpMonitorDataSource(unittest.TestCase):
    """
    Test NtpMonitor's datasource plugin.
    """
    def setUp(self):
        super(TestNtpMonitorDataSource, self).setUp()

    def _collector(self):
        return NtpMonitorDataSource.NtpMonitorDataSourcePlugin()


    def testOnSuccessOffsetOk(self):
        collector = self._collector()
        config = Mock()
        ds = Mock()
        ds.datasource = 'testdatasource'
        config.datasources = [ds]
        config.id = 'adeviceid'

        result = {
            "offset": 0.136,
            "offsetResult": 0,
            "status": 0,
            "syncSource": True,
            "liAlarm": False,
            "warning": 60.0,
            "critical": 120.0
        }

        newData = collector.onSuccess(result, config)

        self.assertDictEqual(newData['values'][None], {'offset': 0.136})

    def testOnSuccessEventOk(self):
        collector = self._collector()
        config = Mock()
        ds = Mock()
        ds.datasource = 'testdatasource'
        config.datasources = [ds]
        config.id = 'adeviceid'

        result = {
            "offset": 0.136,
            "offsetResult": 0,
            "status": 0,
            "syncSource": True,
            "liAlarm": False,
            "warning": 60.0,
            "critical": 120.0
        }

        newData = collector.onSuccess(result, config)

        self.assertEquals(
            newData['events'][0]['message'],
            'NTP OK: Offset 0.136 secs|offset=0.136s;60.000000;120.000000;'
        )
        self.assertEquals(
            newData['events'][0]['summary'],
            'NTP OK: Offset 0.136 secs'
        )

    def testOnSuccessEventNoSyncSource(self):
        collector = self._collector()
        config = Mock()
        ds = Mock()
        ds.datasource = 'testdatasource'
        config.datasources = [ds]
        config.id = 'adeviceid'

        result = {
            "offset": 0,
            "offsetResult": 1,
            "status": 2,
            "syncSource": False,
            "liAlarm": False,
            "warning": 60.0,
            "critical": 120.0
        }

        newData = collector.onSuccess(result, config)

        self.assertEquals(
            newData['events'][0]['message'],
            'NTP CRITICAL: Server not synchronized Offset unknown'
        )
        self.assertEquals(
            newData['events'][0]['summary'],
            'NTP CRITICAL: Server not synchronized Offset unknown'
        )

    def testOnSuccessEventLiAlarm(self):
        collector = self._collector()
        config = Mock()
        ds = Mock()
        ds.datasource = 'testdatasource'
        config.datasources = [ds]
        config.id = 'adeviceid'

        result = {
            "offset": 0.136,
            "offsetResult": 0,
            "status": 2,
            "syncSource": True,
            "liAlarm": True,
            "warning": 60.0,
            "critical": 120.0
        }

        newData = collector.onSuccess(result, config)

        self.assertEquals(
            newData['events'][0]['message'],
            (
                'NTP WARNING: Server has the LI_ALARM bit set Offset 0.136 '
                'secs (WARNING)|offset=0.136s;60.000000;120.000000;'
            )
        )
        self.assertEquals(
            newData['events'][0]['summary'],
            (
                'NTP WARNING: Server has the LI_ALARM bit set Offset 0.136 '
                'secs (WARNING)'
            )
        )


def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestNtpMonitorDataSource))
    return suite


if __name__ == '__main__':
    from zope.testrunner.runner import Runner
    runner = Runner(found_suites=[test_suite()])
    runner.run()
