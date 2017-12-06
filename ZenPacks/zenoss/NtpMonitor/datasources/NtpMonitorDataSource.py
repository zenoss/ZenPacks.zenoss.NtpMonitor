##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
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
import socket
from twisted.internet.defer import inlineCallbacks, returnValue
from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource import \
    PythonDataSource, PythonDataSourcePlugin
from ZenPacks.zenoss.NtpMonitor.ntp import NTPPeerChecker, NTPException, \
    STATUS_TABLE, STATE_UNKNOWN, STATE_CRITICAL, STATE_WARNING
from Products.ZenEvents import ZenEventClasses


log = logging.getLogger("zen.NtpMonitor")


class NtpMonitorDataSource(PythonDataSource):
    """
    Ntp data source plugin.
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
    warning = ""
    critical = ""

    _properties = PythonDataSource._properties + (
        {"id": "hostname", "type": "string", "mode": "w"},
        {"id": "port", "type": "int", "mode": "w"},
        {"id": "warning", "type": "string", "mode": "w"},
        {"id": "critical", "type": "string", "mode": "w"},
        {"id": "timeout", "type": "int", "mode": "w"},
    )


class NtpMonitorDataSourcePlugin(PythonDataSourcePlugin):

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

    @inlineCallbacks
    def collect(self, config):
        ds0 = config.datasources[0]
        hostname = ds0.params["hostname"]
        port = ds0.params["port"]
        timeout = ds0.params["timeout"]
        warning = ds0.params["warning"]
        critical = ds0.params["critical"]

        data = self.new_data()

        try:
            result = {}
            checker = NTPPeerChecker(
                version=2, host=hostname, port=port, timeout=timeout,
                warning=warning, critical=critical
            )
            # setup socket and set timeout
            checker.setup_socket()
            peers_to_check = yield checker.readstat_exchange()
            # number of candidates for READVAR requests
            peer_candidates = 0
            log.debug("Processing READSTAT responses for %d peers.", len(peers_to_check))
            for peer, peer_status in peers_to_check.iteritems():
                # check clock selection flag, bits 6-8
                # 0x02 PEER TRUECHIMER
                # 0x04 PEER INCLUDED
                # 0x06 PEER SYNCSOURCE
                clock_select = peer_status >> 8 & 0x07
                if clock_select == 6:
                    checker.min_peer_source = 6
                    checker.sync_source = True
                    log.debug("Synchronization source found, peer: %d", peer)
                    peer_candidates += 1
                elif clock_select == 4:
                    peer_candidates += 1
            log.debug("%d candidate peers available", peer_candidates)
            checker.update_readstat_status()
            result = yield checker.readvar_exchange(peers_to_check)
        except socket.timeout:
            result["timeout"] = "NTP CRITICAL: Timeout. No response from NTP server."
        except NTPException as ex:
            result["exception"] = "NTP CRITICAL: " + ex.message
        finally:
            checker.socket.close()

        self.process_result(config, ds0, result, data)

        returnValue(data)

    def process_result(self, config, datasource, result, data):
        event_key = datasource.eventKey or "NtpMonitor"
        severity = ZenEventClasses.Error

        if result.get("timeout", None):
            output = result["timeout"]
        elif result.get("exception", None):
            output = result["exception"]
        else:
            if result["offset_result"] == STATE_UNKNOWN:
                result["status"] = STATE_CRITICAL
            output = STATUS_TABLE.get(result["status"], "NTP UNKNOWN:")
            if not result["sync_source"]:
                output += " Server not synchronized"
            elif result["li_alarm"]:
                output += " Server has the LI_ALARM bit set"
            if result["offset_result"] == STATE_UNKNOWN:
                output += " Offset unknown"
            elif result["status"] == STATE_WARNING:
                output += " Offset %.10g secs (WARNING)" % result["offset"]
            elif result["status"] == STATE_CRITICAL:
                output += " Offset %.10g secs (CRITICAL)" % result["offset"]
            else:
                output += " Offset %.10g secs" % result["offset"]
            if result["offset_result"] != STATE_UNKNOWN:
                output += "|offset=%.10gs;%.6f;%.6f;" % (
                    result["offset"], result["warning"], result["critical"]
                )
                severity = ZenEventClasses.Clear
                data["values"][None]["offset"] = result["offset"]                

        data["events"].append({
            "eventKey": event_key,
            "summary": output,
            "message": output,
            "device": config.id,
            "eventClass": datasource.eventClass,
            "severity": severity
        })
