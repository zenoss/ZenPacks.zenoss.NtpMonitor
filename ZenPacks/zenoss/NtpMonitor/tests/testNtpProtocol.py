##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import Globals
from Products.ZenUtils.Utils import unused
unused(Globals)
from ZenPacks.zenoss.NtpMonitor.ntp import *
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet.defer import Deferred

__doc__= """
Look at RFC #1119 for more info: https://tools.ietf.org/html/rfc1119

Exchange process:
-----------------------------------------------------------
    _______                            _______
   /______/|                          /______/|
   | ===  ||       ------------>      | ===  ||
   |  _   ||                          |  _   ||
   | ZEN  ||       <------------      | NTP  ||
   |______|/                          |______|/

   Collector                          NTP Server
-----------------------------------------------------------

READSTAT request   ------------>
                   <------------   READSTAT response
READVAR request*   ------------>
                   <------------   READVAR response**


* n times - READVAR request-reponses for every peer
** READVAR response may be splitted into couple of packets   

-----------------------------------------------------------

Dumped data:
- peer: 26611
- leap indicator: no warning
- peer's selection: current synchronization source
- peer's offset: 5.280

which were get from:
- READSTAT response
  "\x16\x81\x00\x01\x06\x18\x00\x00\x00\x00\x00\x04\xe5\x85\x96Z"
- READVAR response
  "\x16\x82\x00\x02\x96Z\xe5\x85\x00\x00\x00\x0eoffset=5.280\r\n\x00\x00" 
"""

class TestableDatagramTransport(proto_helpers.FakeDatagramTransport):
    def __init__(self):
        proto_helpers.FakeDatagramTransport.__init__(self)
        self.connected = False

    def connect(self, host, port):
        self.connected = True


class TestableDatagramTransportWithTimeout(proto_helpers.FakeDatagramTransport):
    def __init__(self, timeout):
        proto_helpers.FakeDatagramTransport.__init__(self)
        self.timeout = timeout
        self.connected = False

    def connect(self, host, port):
        self.connected = True

    def write(self, packet, addr=None):
        import time
        time.sleep(self.timeout)


class TestNtpProtocolDynamic(unittest.TestCase):
    """
    Test exchange between NTP server and collector on dumped data.
    """
    protocol = None

    def setUp(self):
        super(TestNtpProtocolDynamic, self).setUp()

    def testExchange(self):
        def success(result):
            offset = 2.063
            offsetToReturn = float(offset) / 1000
            liAlarm = False
            offsetResult = 0
            syncSource = True
            self.assertEqual(result["offset"], offsetToReturn)
            self.assertEqual(result["offsetResult"], offsetResult)
            self.assertEqual(result["liAlarm"], liAlarm)
            self.assertEqual(result["syncSource"], syncSource)

        def failure(err):
            self.fail(err.getErrorMessage())

        timeout = 60.0
        self.protocol = NtpProtocol(host="127.0.0.1", timeout=timeout)
        self.protocol.transport = TestableDatagramTransport()
        d = Deferred()

        d.addCallback(success)
        d.addErrback(failure)
        self.protocol.d = d

        # normally invoked by reactor.listenUDP method
        self.protocol.startProtocol()
        readstat = '\x16\x81\x00\x01\x06\x18\x00\x00\x00\x00\x00\x04g\xf3\x96Z'
        self.protocol.datagramReceived(data=readstat, addr=None)
        readvar = '\x16\x82\x00\x02\x96Zg\xf3\x00\x00\x00\x0eoffset=2.063\r\n\x00\x00'
        self.protocol.datagramReceived(data=readvar, addr=None)

        return d

    def testTimeout(self):
        def final(err):
            errMsg = 'Timeout. No response from NTP server'
            ex = err.value
            self.assertEqual(err.getErrorMessage(), errMsg)
            self.assertIsInstance(ex, NtpException)

        testTimeout = 0.5
        self.protocol = NtpProtocol(host="127.0.0.1", timeout=testTimeout)
        self.protocol.transport = TestableDatagramTransportWithTimeout(testTimeout)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        # normally invoked by reactor.listenUDP method
        self.protocol.startProtocol()

        return d


class TestNtpProtocolStatic(unittest.TestCase):
    """
    Test particular elements from NTP protocol's exchange.
    Data is the same as for TestNtpProtocolDynamic.
    """

    offset = 5.280
    offsetToReturn = float(offset) / 1000
    liAlarm = False
    offsetResult = 0
    syncSource = True
    readstatResponse = "\x16\x81\x00\x01\x06\x18\x00\x00\x00\x00\x00\x04\xe5\x85\x96Z"
    readvarResponse = "\x16\x82\x00\x02\x96Z\xe5\x85\x00\x00\x00\x0eoffset=5.280\r\n\x00\x00"
    timeout = 60.0
    protocol = None
    peer = 26611
    peersToCheck = {26611: 38490}

    def setUp(self):
        super(TestNtpProtocolStatic, self).setUp()
        self.protocol = NtpProtocol(host="127.0.0.1")
        self.protocol.transport = TestableDatagramTransport()

    def testParsePortCorrect(self):
        testPort = 1337
        self.protocol.parsePort(testPort)
        self.assertEqual(self.protocol.port, testPort)

    def testParsePortWrongValue(self):
        origPort = self.protocol.port
        wrongPort = "what is port?"
        self.protocol.parsePort(wrongPort)
        self.assertEqual(self.protocol.port, origPort)

    def testParsePortWrongType(self):
        origPort = self.protocol.port
        wrongPort = object()
        self.protocol.parsePort(wrongPort)
        self.assertEqual(self.protocol.port, origPort)

    def testParseTimeoutCorrect(self):
        testTimeout = 13.37
        self.protocol.parseTimeout(testTimeout)
        self.assertEqual(self.protocol.timeout, testTimeout)

    def testParseTimeoutWrongValue(self):
        origTimeout = self.protocol.timeout
        wrongTimeout = "what is timeout?"
        self.protocol.parseTimeout(wrongTimeout)
        self.assertEqual(self.protocol.timeout, origTimeout)

    def testParseTimeoutWrongType(self):
        origTimeout = self.protocol.timeout
        wrongTimeout = object()
        self.protocol.parseTimeout(wrongTimeout)
        self.assertEqual(self.protocol.timeout, origTimeout)

    def testParseThresholdsWarnCorrect(self):
        testWarn = 13
        parsedTestWarn = float(testWarn)
        self.protocol.parseThresholds(warning=testWarn, critical=None)
        self.assertEqual(self.protocol.warning, parsedTestWarn)

    def testParseThresholdsWarnWrongValue(self):
        origWarn = self.protocol.warning
        wrongWarn = "what is warning?"
        self.protocol.parseThresholds(warning=wrongWarn, critical=None)
        self.assertEqual(self.protocol.warning, origWarn)

    def testParseThresholdsWarnWrongType(self):
        origWarn = self.protocol.warning
        wrongWarn = object()
        self.protocol.parseThresholds(warning=wrongWarn, critical=None)
        self.assertEqual(self.protocol.warning, origWarn)

    def testParseThresholdsCritCorrect(self):
        testCrit = 37
        parsedTestCrit = float(testCrit)
        self.protocol.parseThresholds(warning=None, critical=testCrit)
        self.assertEqual(self.protocol.critical, parsedTestCrit)

    def testParseThresholdsCritWrongValue(self):
        origCrit = self.protocol.critical
        wrongCrit = "what is critical?"
        self.protocol.parseThresholds(warning=None, critical=wrongCrit)
        self.assertEqual(self.protocol.critical, origCrit)

    def testParseThresholdsCritWrongType(self):
        origCrit = self.protocol.critical
        wrongCrit = object()
        self.protocol.parseThresholds(warning=None, critical=wrongCrit)
        self.assertEqual(self.protocol.critical, origCrit)

    def testUpdateOffset(self):
        testOffset = 0.1337
        self.protocol.updateOffset(testOffset)
        self.assertEqual(self.protocol.offset, testOffset)

    def testUpdateOffsetLower(self):
        testOffset = 0.1337
        self.protocol.updateOffset(testOffset)
        testLowerOffset = 0.001
        self.protocol.updateOffset(testLowerOffset)
        self.assertEqual(self.protocol.offset, testLowerOffset)

    def testUpdateOffsetUnknownState(self):
        testLowerOffset = 0.001
        self.protocol.updateOffset(testLowerOffset)
        self.protocol.offsetResult = STATE_UNKNOWN
        testOffset = 0.1337
        self.protocol.updateOffset(testOffset)
        self.assertEqual(self.protocol.offset, testOffset)

    def testUpdateOffsetOkState(self):
        origOffset = 0.001
        self.protocol.offset = origOffset
        self.protocol.offsetResult = STATE_OK
        testOffset = 0.1337
        self.protocol.updateOffset(testOffset)
        self.assertEqual(self.protocol.offset, origOffset)

    def testUpdateOffsetLowerOkState(self):
        origOffset = 0.1337
        self.protocol.offset = origOffset
        self.protocol.offsetResult = STATE_OK
        testOffset = 0.001
        self.protocol.updateOffset(testOffset)
        self.assertEqual(self.protocol.offset, testOffset)

    def testGetProcessedOffsetOk(self):
        self.protocol.offsetResult = STATE_OK
        self.protocol.offset = 1.0
        self.protocol.warning = 10.0
        self.protocol.critical = 10.0
        result = self.protocol.getProcessedOffset()
        self.assertEqual(result, STATE_OK)

    def testGetProcessedOffsetResultUnknown(self):
        self.protocol.offsetResult = STATE_UNKNOWN
        result = self.protocol.getProcessedOffset()
        self.assertEqual(result, STATE_UNKNOWN)

    def testGetProcessedOffsetCrit(self):
        self.protocol.offsetResult = STATE_OK
        self.protocol.offset = 10.0
        self.protocol.critical = 1.0
        result = self.protocol.getProcessedOffset()
        self.assertEqual(result, STATE_CRITICAL)

    def testGetProcessedOffsetWarn(self):
        self.protocol.offsetResult = STATE_OK
        self.protocol.offset = 10.0
        self.protocol.warning = 1.0
        result = self.protocol.getProcessedOffset()
        self.assertEqual(result, STATE_WARNING)

    def testMaxStatusGetter(self):
        # STATE_OK < STATE_UNKNOWN < STATE_WARNING < STATE_CRITICAL
        self.protocol.status = STATE_OK
        self.protocol.offsetResult = STATE_CRITICAL
        self.assertEqual(self.protocol.getMaxStatus(), STATE_CRITICAL)

    def testClockStatusGetter(self):
        peerStatus = self.peersToCheck[self.peer]  # 0x06 SYNCSOURCE
        result = self.protocol.getClockStatus(peerStatus)
        self.assertEqual(result, 6)

    def testStartProtocolWithoutHost(self):
        def final(err):
            ex = err.value
            self.assertIsInstance(ex, NtpException)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d

        self.protocol.host = None
        self.protocol.startProtocol()

        return d

    def testStartProtocolWithoutHostMsg(self):
        def final(err):
            errMsg = "Host is not specified"
            self.assertEqual(err.getErrorMessage(), errMsg)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.host = None
        self.protocol.startProtocol()

        return d

    def testStartProtocolConnected(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            self.assertTrue(self.protocol.transport.connected)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.startProtocol()
        d.cancel()

        return d

    def testStartProtocolReadstatSent(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            self.assertTrue(self.protocol.transport.written)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.startProtocol()
        d.cancel()

        return d

    def testUpdateReadstatStatusDefault(self):
        self.protocol.updateReadstatStatus()
        self.assertEqual(self.protocol.status, STATE_WARNING)

    def testUpdateReadstatStatusSync(self):
        statusOrig = self.protocol.status
        self.protocol.syncSource = True
        self.protocol.updateReadstatStatus()
        self.assertEqual(self.protocol.status, statusOrig)

    def testUpdateReadstatStatusAlarm(self):
        self.protocol.liAlarm = True
        self.protocol.updateReadstatStatus()
        self.assertEqual(self.protocol.status, STATE_WARNING)

    def testCheckCandidatesSync(self):
        self.protocol.peersToCheck = self.peersToCheck
        self.protocol.checkCandidates()
        self.assertTrue(self.protocol.syncSource)

    def testCheckCandidatesEmptySync(self):
        self.protocol.peersToCheck = {}
        self.protocol.checkCandidates()
        self.assertFalse(self.protocol.syncSource)

    def testCheckCandidatesMin(self):
        self.protocol.peersToCheck = self.peersToCheck
        self.protocol.checkCandidates()
        self.assertEqual(self.protocol.minPeerSource, 6)

    def testCheckCandidatesEmptyMin(self):
        self.protocol.peersToCheck = {}
        self.protocol.checkCandidates()
        self.assertEqual(self.protocol.minPeerSource, 4)

    def testSendReadStatRequestSent(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            self.assertTrue(self.protocol.transport.written)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.sendReadstatRequest()
        d.cancel()

        return d

    def testSendReadStatRequestCorrect(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            written_data = self.protocol.transport.written[-1][0]
            expected_data = '\x16\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
            self.assertEqual(written_data, expected_data)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.sendReadstatRequest()
        d.cancel()

        return d

    def testControlReadvarExchangeEmpty(self):
        def success(result):
            self.assertTrue(result)

        def failure(err):
            self.fail(err.getErrorMessage())

        d = Deferred()
        d.addCallback(success)
        d.addErrback(failure)
        self.protocol.d = d
        self.protocol.controlReadvarExchange()

        return d

    def testControlReadvarExchangeEmptyStatusSet(self):
        def final(result):
            self.assertEqual(self.protocol.status, STATE_UNKNOWN)
        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.controlReadvarExchange()
        d.cancel()

        return d

    def testControlReadvarExchangePop(self):
        def final(result):
            self.assertFalse(self.protocol.peersToCheck)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d

        self.protocol.peersToCheck = self.peersToCheck
        self.protocol.minPeerSource = 100  # wrong value (too high)
        self.protocol.controlReadvarExchange()
        d.cancel()

    def testControlReadvarExchangePeerSet(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            self.assertEqual(self.protocol.currentPeer, self.peer)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d

        self.protocol.peersToCheck = self.peersToCheck
        self.protocol.controlReadvarExchange()
        d.cancel()

        return d

    def testSendReadvarRequestSent(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            self.assertTrue(self.protocol.transport.written)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.currentPeer = self.peer
        self.protocol.sequenceCounter = 2
        self.protocol.sendReadvarRequest()
        d.cancel()

        return d

    def testSendReadvarRequestCorrect(self):
        def final(err):
            # err is a Failure instance because of d.cancel()
            if self.protocol.timeoutCall.active():
                self.protocol.timeoutCall.cancel()
            written_data = self.protocol.transport.written[-1][0]
            expected_data = '\x16\x02\x00\x02\x00\x00g\xf3\x00\x00\x00\x06offset\x00\x00\x00\x00\x00\x00'
            self.assertEqual(written_data, expected_data)

        d = Deferred()
        d.addBoth(final)
        self.protocol.d = d
        self.protocol.currentPeer = self.peer
        self.protocol.sequenceCounter = 2
        self.protocol.sendReadvarRequest()
        d.cancel()

        return d

    def testGetResult(self):
        expected = {
            "offset": 0.33,
            "offsetResult": 1,
            "status": 2,
            "syncSource": True,
            "liAlarm": False,
            "warning": 5,
            "critical": 6
        }

        self.protocol.offset = 0.33
        self.protocol.offsetResult = 1
        self.protocol.status = 2
        self.protocol.syncSource = True
        self.protocol.liAlarm = False
        self.protocol.warning = 5
        self.protocol.critical = 6

        data = self.protocol.getResult()
        self.assertDictEqual(data, expected)


def test_suite():
    """
    Return test suite for this module.
    """
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestNtpProtocolDynamic))
    suite.addTest(makeSuite(TestNtpProtocolStatic))
    return suite

if __name__ == "__main__":
    from zope.testrunner.runner import Runner
    runner = Runner(found_suites=[test_suite()])
    runner.run()
