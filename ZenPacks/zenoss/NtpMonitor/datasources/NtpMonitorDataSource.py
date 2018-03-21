##############################################################################
#
# Copyright (C) Zenoss, Inc. 2007-2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

"""
NtpMonitorDataSource.py

Defines datasource for NtpMonitor
"""

import logging
from twisted.internet.defer import Deferred
from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource import \
    PythonDataSource, PythonDataSourcePlugin
from ZenPacks.zenoss.NtpMonitor.ntp import NtpProtocol, NtpController, \
    STATUS_MAP, STATE_UNKNOWN, STATE_CRITICAL, STATE_WARNING
from Products.ZenEvents import ZenEventClasses


log = logging.getLogger("zen.NtpMonitor")


class NtpMonitorDataSource(PythonDataSource):
    """
    Datasource for NTP protocol.
    """
    ZENPACKID = "ZenPacks.zenoss.NtpMonitor"
    NTP_MONITOR = "NtpMonitor"

    sourcetypes = (NTP_MONITOR,)
    sourcetype = NTP_MONITOR

    plugin_classname = "ZenPacks.zenoss.NtpMonitor.datasources." \
                       "NtpMonitorDataSource.NtpMonitorDataSourcePlugin"

    timeout = 60
    eventClass = "/Status/Ntp"

    hostname = "${dev/id}"
    port = 123
    warning = 60
    critical = 120

    _properties = PythonDataSource._properties + (
        {"id": "hostname", "type": "string", "mode": "w"},
        {"id": "port", "type": "int", "mode": "w"},
        {"id": "warning", "type": "string", "mode": "w"},
        {"id": "critical", "type": "string", "mode": "w"},
        {"id": "timeout", "type": "int", "mode": "w"},
    )


class NtpMonitorDataSourcePlugin(PythonDataSourcePlugin):
    """
    Datasource plugin for NTP protocol.
    """
    @classmethod
    def params(cls, datasource, context):
        params = {
            "hostname": datasource.talesEval(datasource.hostname, context),
            "port": datasource.talesEval(datasource.port, context),
            "warning": datasource.talesEval(datasource.warning, context),
            "critical": datasource.talesEval(datasource.critical, context),
            "timeout": datasource.talesEval(datasource.timeout, context),
            "eventKey": datasource.talesEval(datasource.eventKey, context),
            "eventClass": datasource.talesEval(datasource.eventClass, context)
        }
        return params

    def collect(self, config):
        ds0 = config.datasources[0]
        hostname = ds0.params["hostname"]
        port = ds0.params["port"]
        timeout = ds0.params["timeout"]
        warning = ds0.params["warning"]
        critical = ds0.params["critical"]

        protocol = NtpProtocol(hostname, port, timeout, warning, critical)
        controller = NtpController()

        d = Deferred()
        d.addCallback(controller.success)
        d.addErrback(controller.failure)
        protocol.d = d

        controller.start(protocol)

        return d

    def onSuccess(self, result, config):
        data = self.new_data()
        datasource = config.datasources[0]
        eventKey = datasource.eventKey or "NtpMonitor"
        severity = ZenEventClasses.Error

        if result["offsetResult"] == STATE_UNKNOWN:
            result["status"] = STATE_CRITICAL
        summary = STATUS_MAP.get(result["status"], "NTP UNKNOWN:")
        if not result["syncSource"]:
            summary += " Server not synchronized"
        elif result["liAlarm"]:
            summary += " Server has the LI_ALARM bit set"
        if result["offsetResult"] == STATE_UNKNOWN:
            summary += " Offset unknown"
        elif result["status"] == STATE_WARNING:
            summary += " Offset %.10g secs (WARNING)" % result["offset"]
        elif result["status"] == STATE_CRITICAL:
            summary += " Offset %.10g secs (CRITICAL)" % result["offset"]
        else:
            summary += " Offset %.10g secs" % result["offset"]
        if result["offsetResult"] != STATE_UNKNOWN:
            output = summary + "|offset=%.10gs;%.6f;%.6f;" % (
                result["offset"], result["warning"], result["critical"]
            )
            severity = ZenEventClasses.Clear
            data["values"][None]["offset"] = result["offset"]
        else:
            output = summary

        data["events"].append({
            "eventKey": eventKey,
            "summary": summary,
            "message": output,
            "device": config.id,
            "eventClass": datasource.eventClass,
            "severity": severity
        })

        return data

    def onError(self, result, config):
        data = self.new_data()
        datasource = config.datasources[0]
        eventKey = datasource.eventKey or "NtpMonitor"
        severity = ZenEventClasses.Error
        output = "NTP CRITICAL: " + result.getErrorMessage()

        data["events"].append({
            "eventKey": eventKey,
            "summary": output,
            "message": output,
            "device": config.id,
            "eventClass": datasource.eventClass,
            "severity": severity
        })

        return data
