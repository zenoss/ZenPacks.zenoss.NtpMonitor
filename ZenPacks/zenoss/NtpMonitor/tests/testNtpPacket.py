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
import unittest

__doc__= """

 o-----.
 |     |\
 |     '-|
 |       |
 |    ntp|
 '-------'
 
NtpPacket's header structure (version 2):

* leap (2 bits)
  Indicates the leap indicator
  Shows whether one second is added to or deleted from the last minute of 
  the current day.
  
  LI	Description
   0	No warning.
   1	Last minute has 61 seconds.
   2	Last minute has 59 seconds.
   3	Alarm condition, clock not synchronized.
   
* version (3 bits)
  Indicates the NTP version number.
  Note: currently only version 2 of NtpProtocol is implemented here
  
* mode (3 bits)
  Indicates the NTP operation mode.
  Note: for checking peers only 0x06 (NTP control message is used)
  

Look at RFC #1119 for more info: https://tools.ietf.org/html/rfc1119
"""

class TestNtpPacket(unittest.TestCase):
    """
    Test NtpPacket class.
    """

    peer = 26611
    peers = {26611: 38490}
    getvar = "offset"
    readstatData = '\x16\x81\x00\x01\x06\x18\x00\x00\x00\x00\x00\x04g\xf3\x96Z'
    readvarData = '\x16\x82\x00\x02\x96Zg\xf3\x00\x00\x00\x0eoffset=2.063\r\n\x00\x00'


    def setUp(self):
        super(TestNtpPacket, self).setUp()

    def testReadstatRequest(self):
        expected = '\x16\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
        result = NtpPacket(version=2, opcode=1, sequence=1).toDataReadstat()
        self.assertEqual(result, expected)

    def testReadstatRequestWrongVersion(self):
        packet = NtpPacket(version=3, opcode=1, sequence=1)
        self.assertRaises(NtpException, packet.toDataReadstat)

    def testReadvarRequest(self):
        packet = NtpPacket(version=2, opcode=2, sequence=2)
        packet.assoc = self.peer
        packet.data = 'offset'
        packet.count = len(packet.data)
        expected = '\x16\x02\x00\x02\x00\x00g\xf3\x00\x00\x00\x06offset\x00\x00\x00\x00\x00\x00'
        result = packet.toDataReadvar()
        self.assertEqual(result, expected)

    def testReadvarRequestWrongVersion(self):
        packet = NtpPacket(version=3, opcode=2, sequence=2)
        self.assertRaises(NtpException, packet.toDataReadvar)

    def testFromDataLeap(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.leap, 0)

    def testFromDataVersion(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.version, 2)

    def testFromDataMode(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.mode, 6)

    def testFromDataSequence(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.sequence, 2)

    def testFromDataStatus(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.status, 38490)

    def testFromDataAssoc(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.assoc, self.peer)

    def testFromDataOffset(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.offset, 0)

    def testFromDataCount(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.count, 14)

    def testFromDataPeerData(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.peerData, 'offset=2.063\r\n\x00\x00')

    def testPeers(self):
        packet = NtpPacket.fromData(self.readstatData)
        self.assertDictEqual(packet.peers, self.peers)

    def testErrorReadstat(self):
        packet = NtpPacket.fromData(self.readstatData)
        self.assertFalse(packet.hasError)

    def testErrorReadvar(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertFalse(packet.hasError)

    def testAlarm(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertFalse(packet.hasAlarm)

    def testWrongSize(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertFalse(packet.hasWrongSize)

    def testMorePackets(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertFalse(packet.hasMorePackets)

    def testPeerOffsetGetter(self):
        packet = NtpPacket.fromData(self.readvarData)
        self.assertEqual(packet.getPeerOffset(), 0.002063)

    def testPeerToRequestSetter(self):
        packet = NtpPacket(version=2, opcode=2, sequence=2)
        packet.setPeerToRequest(self.peer)
        self.assertEqual(packet.assoc, self.peer)

    def testDataToRequestSetterData(self):
        packet = NtpPacket(version=2, opcode=2, sequence=2)
        packet.setDataToRequest(self.getvar)
        self.assertEqual(packet.data, self.getvar)
        self.data = requestDetails
        self.count = len(requestDetails)

    def testDataToRequestSetterDataSize(self):
        size = len(self.getvar)
        packet = NtpPacket(version=2, opcode=2, sequence=2)
        packet.setDataToRequest(self.getvar)
        self.assertEqual(packet.count, size)


def test_suite():
    """
    Return test suite for this module.
    """
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestNtpPacket))
    return suite

if __name__ == "__main__":
    from zope.testrunner.runner import Runner
    runner = Runner(found_suites=[test_suite()])
    runner.run()
