##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

"""
Contains logic for NTP protocol.
"""

import struct
import logging
from twisted.internet.defer import succeed, fail
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from Products.ZenUtils import IpUtil


log = logging.getLogger("zen.NtpMonitor")

LEAP_MAP = {
    0: "NO WARNING",
    1: "EXTRA SEC",  # last minute "has" 61 seconds
    2: "MISSING SEC",  # last minute "has" 59 seconds
    3: "ALARM"  # clock not synchronized
}

STATUS_MAP = {
    0: "NTP OK:",
    1: "NTP UNKNOWN:",
    2: "NTP WARNING:",
    3: "NTP CRITICAL:"
}

# STATE_OK < STATE_UNKNOWN < STATE_WARNING < STATE_CRITICAL
STATE_OK = 0
STATE_UNKNOWN = 1
STATE_WARNING = 2
STATE_CRITICAL = 3


class NtpException(Exception):
    """
    Exception raised by NTP related classes.
    """
    pass


class NtpController(object):
    """
    Controls the process of executing NTP protocol.
    """
    def __init__(self):
        self.port = None

    def start(self, protocol):
        """
        Execute NTP protocol
        :param protocol: instance of NtpProtocol
        """
        if IpUtil.get_ip_version(protocol.host) == 6:
            self.port = reactor.listenUDP(0, protocol, interface='::')
        else:
            self.port = reactor.listenUDP(0, protocol)

    def success(self, data):
        self.port.stopListening()
        return succeed(data)

    def failure(self, err):
        self.port.stopListening()
        return fail(err)


class NtpPacket(object):
    """
    Represents NTP packet. Contains methods for converting
    data to/from binary format and checking flags.
    """

    _BASE_FIELDS = "!B B 5H"
    _DATA = "!{0}s"
    _PADDING = "!{0}B"

    MAX_CM_SIZE = 468

    def __init__(self, version=2, opcode=1, sequence=1):
        """
        Initialize NtpPacket.
        :param version: version number of NTP protocol
        :param opcode: type of the REQUEST (0x01 READSTAT, 0x02 READVAR)
        :param sequence: ordinal of packet during exchange
        """
        self.leap = 0
        self.version = version
        self.opcode = opcode
        self.sequence = sequence
        self.status = 0
        self.mode = 6  # 0x06 - NTP control message
        self.assoc = 0
        self.offset = 0
        self.count = 0
        self.errorBit = 0
        self.data = None
        self.peerData = None

    def toDataReadstat(self):
        """
        Returns this instance as a READSTAT request in binary form.
        :return: binary format of NTP READSTAT packet.
        :rtype: str
        """
        if self.version == 2:
            try:
                # pack: 2 x 1 byte, 5 x 2 bytes
                packed = struct.pack(
                    NtpPacket._BASE_FIELDS,
                    # masks for first byte:
                    # - leap: 11000000
                    # - version: 00111000
                    # - mode: 00000111
                    (
                        (self.leap << 6 & 0xc0) |
                        (self.version << 3 & 0x38) |
                        (self.mode & 0x07)
                    ),
                    self.opcode,
                    self.sequence,
                    self.status,
                    self.assoc,
                    self.offset,
                    self.count
                )
            except struct.error:
                raise NtpException("Internal packet parsing error")
            return packed
        else:
            raise NtpException(
                "Version %i of NTP protocol is not implemented" % self.version
            )

    def toDataReadvar(self):
        """
        Returns this instance as a READVAR request in binary form.
        :return: binary format of NTP READVAR packet.
        :rtype: str
        """
        if self.version == 2:
            try:
                # unpack: 2 x 1 byte, 5 x 2 bytes, self.count x 1 byte
                packed = struct.pack(
                    NtpPacket._BASE_FIELDS,
                    (
                        (self.leap << 6 & 0xc0) |
                        (self.version << 3 & 0x38) |
                        (self.mode & 0x07)
                    ),
                    self.opcode,
                    self.sequence,
                    self.status,
                    self.assoc,
                    self.offset,
                    self.count
                )
                packed += struct.pack(
                    NtpPacket._DATA.format(self.count), self.data
                )
                padding = ''
                if self.count % 12 != 0:
                    toPad = 12 - (self.count - 12 * int(self.count / 12))
                    for _ in range(0, toPad):
                        padding += struct.pack("!B", 0)
                packed += padding
            except struct.error:
                raise NtpException("Invalid packet received from NTP server")
            return packed
        else:
            raise NtpException(
                "Version %i of NTP protocol is not implemented" % self.version
            )

    @classmethod
    def fromData(cls, data):
        """
        Creates NtpPacket, extracts values from binary data to packet's fields and return NtpPacket instance.
        :param data: binary data
        :return: NtpPacket with extracted data
        :rtype: NtpPacket
        """
        try:
            unpacked = struct.unpack(
                NtpPacket._BASE_FIELDS,
                data[0:struct.calcsize(NtpPacket._BASE_FIELDS)]
            )
        except struct.error:
            raise NtpException("Invalid packet received from NTP server")

        packet = cls()
        packet.leap = unpacked[0] >> 6 & 0x03
        packet.version = unpacked[0] >> 3 & 0x07
        packet.mode = unpacked[0] & 0x07
        packet.opcode = unpacked[1]
        packet.sequence = unpacked[2]
        packet.status = unpacked[3]
        packet.assoc = unpacked[4]
        packet.offset = unpacked[5]
        packet.count = unpacked[6]
        if packet.count >= 4:
            packet.peerData = data[12:]

        return packet

    @property
    def peers(self):
        """
        Extract data about peers from NTP packet's data field.
        Pair of 2 bytes per one peer.
        """
        peers = {}
        if self.peerData:
            try:
                unpacked = struct.unpack('!{0}H'.format(self.count / 2), self.peerData)
            except struct.error:
                log.debug("Error during extracting data from NTP packet")
                raise NtpException("Invalid packet received from NTP server")
            for peer in range(0, len(unpacked) / 2, 2):
                peers[unpacked[peer]] = unpacked[peer + 1]
        return peers

    @property
    def hasError(self):
        """
        Check if error bit is set inside packet.
        """
        return bool((self.opcode >> 6) & 0x01)

    @property
    def hasAlarm(self):
        """
        Check if alarm bit is set in leap indicator.
        """
        return bool(self.leap == 3)

    @property
    def hasWrongSize(self):
        """
        Check if packet exceeds max specified size.
        """
        return bool(self.count > self.MAX_CM_SIZE)

    @property
    def hasMorePackets(self):
        """
        Check if packet has 'more packets' bit set.
        Server has more data prepared if this flag is active.
        """
        return bool((self.opcode >> 5) & 0x01)

    @property
    def isResponse(self):
        """
        Check if packet has response bit set (0x02).
        """
        return bool((self.opcode >> 1) & 0x01)

    def getPeerOffset(self):
        if self.peerData:
            peerData = self.peerData[:self.count].strip().replace(" ", "")
            peerDataDict = {
                key: value for key, value
                in [d.split("=") for d in peerData.split(",")]
            }
            tmpOffset = peerDataDict.get("offset", None)
            if tmpOffset:
                return float(tmpOffset) / 1000

    def setPeerToRequest(self, peer):
        """
        Set peer for which data will be requested.
        :param peer: peer to set
        """
        self.assoc = peer

    def setDataToRequest(self, requestDetails):
        """
        Set string that specifies variables to request about.
        Empty string for all possible values.
        :param requestDetails: requested variables separated by commma
        """
        self.data = requestDetails
        self.count = len(requestDetails)


class NtpProtocol(DatagramProtocol):
    """
    Logic for NTP protocol.
    """
    port = 123
    timeout = 60.0
    warning = 60.0
    critical = 120.0

    def __init__(self, host=None, port=None, timeout=None, warning=None,
                 critical=None, version=2):
        """
        Initialize NtpProtocol class.
        :param host: targeted host
        :param port: exposed server's port, 123 by default
        :param timeout: timeout for socket's calls, 60 seconds by default
        :param warning: value causes warning status, 60 seconds by default
        :param critical: value causes critical status, 120 seconds by default
        :param version: version number of NTP protocol
        """
        self.host = host
        if port:
            self.parsePort(port)
        if timeout:
            self.parseTimeout(timeout)
        self.parseThresholds(warning, critical)
        self.version = version
        self.peersToCheck = {}
        self.readstat = True
        self.sequenceCounter = 1
        self.getvar = "offset"
        self.minPeerSource = 4  # peer included
        self.currentPeer = None
        self.status = STATE_OK
        self.offsetResult = STATE_UNKNOWN
        self.offset = 0
        self.syncSource = False
        self.liAlarm = False
        self.d = None
        self.timeoutCall = None
        self.dataQueue = ""
        self.dataQueueCtr = 0

    def parsePort(self, port):
        try:
            self.port = int(port)
        except (ValueError, TypeError):
            log.debug("Wrong value for port is specified. Using default: %i",
                      self.port)

    def parseTimeout(self, timeout):
        try:
            self.timeout = float(timeout)
        except (ValueError, TypeError):
            log.debug("Unable to parse timeout's value. Using default: %.2fs",
                      self.timeout)

    def parseThresholds(self, warning, critical):
        """
        Set limits for received offset from provided values.
        """
        if warning:
            try:
                self.warning = float(warning)
            except (ValueError, TypeError):
                log.debug("Unable to parse warning's value. Using default: %.2fs",
                          self.warning)
        if critical:
            try:
                self.critical = float(critical)
            except (ValueError, TypeError):
                log.debug("Unable to parse critical's value. Using default: %.2fs",
                          self.critical)

    def updateOffset(self, tmpOffset):
        """
        Update final offset under certain conditions.
        :param tmpOffset: peer's offset value
        """

        offsetAbs = abs(self.offset)
        tmpOffsetAbs = abs(tmpOffset)

        if self.offsetResult == STATE_UNKNOWN or tmpOffsetAbs < offsetAbs:
            self.offset = tmpOffset
            self.offsetResult = STATE_OK

    def getProcessedOffset(self):
        """
        Compare offset to limits and return appropriate status.
        :return: state of status after processing
        :rtype: int
        """
        if self.offsetResult == STATE_UNKNOWN:
            return STATE_UNKNOWN
        if self.offset > self.critical:
            return STATE_CRITICAL
        elif self.offset > self.warning:
            return STATE_WARNING
        return STATE_OK

    def getMaxStatus(self):
        return max(self.status, self.offsetResult)

    def getClockStatus(self, peerStatus):
        """
        Return clock's status of NTP server.
        Possible values:
        * 0x06 PEER SYNCSOURCE
        * 0x04 PEER INCLUDED
        * 0x02 PEER TRUECHIMER
        :param peerStatus: received peer's status
        :return: clock's status
        :rtype: int
        """
        return (peerStatus >> 8) & 0x07

    def startProtocol(self):
        if not self.host:
            self.d.errback(NtpException("Host is not specified"))
            return
        self.transport.connect(self.host, self.port)
        log.debug("Protocol started for %s on port %d", self.host, self.port)
        self.sendReadstatRequest()

    def timeoutHandler(self):
        log.info("Timeout. No response from NTP server after %.2fs",
                 self.timeout)
        self.d.errback(NtpException("Timeout. No response from NTP server"))

    def datagramReceived(self, data, addr):
        log.debug("Datagram received from %s", addr)
        if self.timeoutCall.active():
            log.debug("Timeout was in active state, disabling")
            self.timeoutCall.cancel()
        if self.readstat:
            self.processReadstatResponse(data, addr)
        else:
            self.processReadvarResponse(data, addr)

    def connectionRefused(self):
        self.d.errback(NtpException("Connection refused"))

    def updateReadstatStatus(self):
        if not self.syncSource:
            self.status = STATE_WARNING
        if self.liAlarm:
            self.status = STATE_WARNING

    def checkCandidates(self):
        """
        Check if NTP server sent proper candidates to ask for NTP's offset.
        """
        peerCandidates = 0
        log.debug("Processing READSTAT responses for %d peers",
                  len(self.peersToCheck))
        for peer, peerStatus in self.peersToCheck.iteritems():
            clockSelect = self.getClockStatus(peerStatus)
            if clockSelect == 6:  # 0x06 PEER SYNCSOURCE
                self.minPeerSource = 6
                self.syncSource = True
                log.debug("Synchronization source found, peer: %d", peer)
                peerCandidates += 1
            elif clockSelect == 4:  # 0x04 PEER INCLUDED
                peerCandidates += 1
        log.debug("%d candidate peers available", peerCandidates)
        self.updateReadstatStatus()

    def sendReadstatRequest(self):
        packet = NtpPacket(self.version, sequence=self.sequenceCounter)
        try:
            data = packet.toDataReadstat()
        except NtpException as ntpEx:
            self.d.errback(ntpEx)
            return
        self.transport.write(data)
        self.timeoutCall = reactor.callLater(
            self.timeout, self.timeoutHandler
        )
        log.debug("READSTAT request was sent to host %s", self.host)

    def controlReadvarExchange(self):
        """
        Controls process of READVAR exchange.
        """
        if self.peersToCheck:
            peer, peerStatus = self.peersToCheck.popitem()
            clockSelect = self.getClockStatus(peerStatus)
            if clockSelect >= self.minPeerSource:
                self.currentPeer = peer
                self.sendReadvarRequest()
        else:
            self.status = self.getProcessedOffset()
            self.status = self.getMaxStatus()
            data = self.getResult()
            self.d.callback(data)

    def processReadstatResponse(self, data, addr):
        log.debug("READSTAT response was received from %s", addr)
        try:
            packet = NtpPacket.fromData(data)
        except NtpException as ntpEx:
            self.d.errback(ntpEx)
            return
        if packet.hasWrongSize:
            log.debug("Invalid READSTAT packet (MAX_CM_SIZE) "
                      "was received from host %s", self.host)
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if packet.sequence != self.sequenceCounter:
            log.debug("Wrong sequence number was set in packet")
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if packet.hasError:
            log.debug("Error bit was set in packet")
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if LEAP_MAP.get(packet.leap, None):
            if packet.hasAlarm:
                log.info("Leap indicator: alarm bit is set")
                self.liAlarm = True
        else:
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        try:
            self.peersToCheck.update(packet.peers)
        except NtpException as ntpEx:
            self.d.errback(ntpEx)
            return
        if not packet.hasMorePackets:
            self.readstat = False
            self.sequenceCounter += 1
            self.checkCandidates()
            self.controlReadvarExchange()

    def sendReadvarRequest(self):
        log.debug("Getting offset for peer %d", self.currentPeer)
        packet = NtpPacket(
            version=self.version, sequence=self.sequenceCounter, opcode=2
        )
        packet.setPeerToRequest(self.currentPeer)
        packet.setDataToRequest(self.getvar)
        try:
            data = packet.toDataReadvar()
        except NtpException as ntpEx:
            self.d.errback(ntpEx)
            return
        self.transport.write(data)
        self.timeoutCall = reactor.callLater(
            self.timeout, self.timeoutHandler
        )

    def processReadvarResponse(self, data, addr):
        log.debug("READVAR response was received from %s", addr)
        try:
            packet = NtpPacket.fromData(data)
        except NtpException as ntpEx:
            self.d.errback(ntpEx)
            return
        if packet.hasWrongSize:
            log.debug("Invalid READVAR packet (MAX_CM_SIZE) "
                      "was received from host %s", self.host)
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if packet.sequence != self.sequenceCounter:
            log.debug("Wrong sequence number was set in packet")
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if packet.hasError:
            if self.getvar:
                log.debug("Error bit set in packet, trying to get "
                          "all possible values")
                self.getvar = ""
                self.sendReadvarRequest()
                return
            else:
                log.debug("Error bit was set in packet")
                self.d.errback(
                    NtpException("Invalid packet received from NTP server")
                )
                return
        if not packet.isResponse:
            self.d.errback(
                NtpException("Invalid packet received from NTP server")
            )
            return
        if packet.hasMorePackets:
            self.dataQueue += packet.peerData
            self.dataQueueCtr += packet.count
        else:
            packet.peerData = self.dataQueue + packet.peerData
            packet.count += self.dataQueueCtr
            self.dataQueue = ""
            self.dataQueueCtr = 0
            tmpOffset = packet.getPeerOffset()
            if tmpOffset:
                log.debug("Offset for peer %d: %f", self.currentPeer, tmpOffset)
                self.updateOffset(tmpOffset)
            self.controlReadvarExchange()

    def getResult(self):
        """
        Return result of executing NTP protocol.
        :return: final values after exchange
        :rtype: dict
        """
        result = {
            "offset": self.offset,
            "offsetResult": self.offsetResult,
            "status": self.status,
            "syncSource": self.syncSource,
            "liAlarm": self.liAlarm,
            "warning": self.warning,
            "critical": self.critical
        }
        return result
