##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import socket
import struct
import logging
from twisted.internet.defer import returnValue, inlineCallbacks
from Products.ZenUtils import IpUtil


log = logging.getLogger("zen.NtpMonitor")

LEAP_TABLE = {
    0: "NO WARNING",
    1: "EXTRA SEC",  # last minute "has" 61 seconds
    2: "MISSING SEC",  # last minute "has" 59 seconds
    3: "ALARM"  # clock not synchronized
}

STATUS_TABLE = {
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

# max size of control message
MAX_CM_SIZE = 468


class NTPException(Exception):
    """
    Exception raised by NTP related classes.
    """
    pass


class NTPPacket(object):
    """
    Class which represents NTP packet. Contains methods for converting
    data to/from binary format.
    """

    _BASE_FIELDS = "!B B 5H"
    _DATA = "!{0}s"
    _PADDING = "!{0}B"

    def __init__(self, version=2, opcode=1, sequence=1):
        """
        Initialize NTPPacket.
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
        self.error_bit = 0  # 1 if packet was received with error bit
        self.data = None

    def to_data_readstat(self):
        """
        Converts data required by READSTAT request into binary format.
        :return: binary format of NTP READSTAT packet.
        :rtype: str
        """
        if self.version == 2:
            try:
                # pack: 2 x 1 byte, 5 x 2 bytes
                packed = struct.pack(
                    NTPPacket._BASE_FIELDS,
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
                raise NTPException("NTPPacket's fields parsing error.")
            return packed
        else:
            raise NTPException("Version %i of NTP protocol is not implemented." % self.version)

    def to_data_readvar(self):
        """
        Converts data required by READVAR request into binary format.
        :return: binary format of NTP READVAR packet.
        :rtype: str
        """
        if self.version == 2:
            try:
                # unpack: 2 x 1 byte, 5 x 2 bytes, len(self.data) x 1 byte
                packed = struct.pack(
                    NTPPacket._BASE_FIELDS,
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
                # add data
                packed += struct.pack(NTPPacket._DATA.format(len(self.data)), self.data)
                # padding with 0 if self.count is not multiple of 12
                padding = ''
                if self.count % 12 != 0:
                    to_pad = 12 - (self.count - 12 * int(self.count/12))
                    for _ in range(0, to_pad):
                        padding += struct.pack("!B", 0)
                packed += padding
            except struct.error:
                raise NTPException("NTPPacket's fields parsing error.")
            return packed
        else:
            raise NTPException("Version %i of NTP protocol is not implemented." % self.version)

    def from_data(self, data):
        """
        Extract values from binary data to NTPPacket's fields.
        :param data: binary data
        """
        try:
            unpacked = struct.unpack(
                NTPPacket._BASE_FIELDS,
                data[0:struct.calcsize(NTPPacket._BASE_FIELDS)]
            )
        except struct.error:
            log.debug("Error during extracting data from NTP packet.")
            raise NTPException("Invalid packet received from NTP server")
        self.leap = unpacked[0] >> 6 & 0x03
        self.version = unpacked[0] >> 3 & 0x07
        self.mode = unpacked[0] & 0x07
        self.opcode = unpacked[1]
        self.sequence = unpacked[2]
        self.status = unpacked[3]
        self.assoc = unpacked[4]
        self.offset = unpacked[5]
        self.count = unpacked[6]

    def extract_peers(self, data):
        """
        Extract data about peers from NTP packet's data field.
        Pair of 2 bytes per one peer.
        :param data: binary data
        """
        peers = {}
        if self.count >= 4:
            try:
                # count is a number of bytes in DATA field
                unpacked = struct.unpack('!{0}H'.format(self.count/2), data)
            except struct.error:
                log.debug("Error during extracting data from NTP packet.")
                raise NTPException("Invalid packet received from NTP server")
            for peer in range(0, len(unpacked)/2, 2):
                peers[unpacked[peer]] = unpacked[peer+1]
        return peers

    def check_error_bit(self):
        self.error_bit = self.opcode >> 6 & 0x01
        if self.error_bit:
            log.debug("Error bit set in packet")
            return True
        return False


class NTPPeerChecker(object):
    """
    Contains logic for checking NTP peers.
    """

    port = 123
    timeout = 60.0
    warning = 60
    critical = 120

    def __init__(self, version=2, host=None, port=None, timeout=None, warning=None, critical=None):
        """
        Initialize NTPPeerChecker class.
        :param version: version number of NTP protocol
        :param host: target host
        :param port: exposed port, 123 by default
        :param timeout: timeout for full exchange, 60 seconds by default
        :param warning: value causes warning status, 60 seconds by default
        :param critical: value causes critical status, 120 seconds by default
        """
        if not host:
            raise NTPException("Host is not specified. Unable to create NTPPeerChecker instance.")
        self.host = host
        if port:
            try:
                self.port = int(port)
            except ValueError:
                log.debug("Wrong value for port is specified. Using default: %i.", self.port)
        self.version = version
        if timeout:
            try:
                self.timeout = float(timeout)
            except ValueError:
                log.debug("Unable to parse Timeout set to default value: %ds.", self.timeout)
        self.parse_thresholds(warning, critical)
        # socket section
        self.socket = None
        self.sockaddr = None
        # flags and settings
        self.sequence_counter = 0
        self.li_alarm = False  # set to True if alarm bit is set
        self.min_peer_source = 4  # peer included
        self.status = STATE_OK
        self.offset_result = STATE_UNKNOWN
        self.offset = 0
        self.sync_source = False  # set to True if synchronization source was found

    def parse_thresholds(self, warning, critical):
        """
        Set limits for offset from provided values.
        """
        if warning:
            try:
                self.warning = float(warning)
            except ValueError:
                pass
        if critical:
            try:
                self.critical = float(critical)
            except ValueError:
                pass

    def setup_socket(self):
        """
        Create socket and set timeout.
        """
        if self.socket is None:
            try:
                if IpUtil.get_ip_version(self.host) == 4:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif IpUtil.get_ip_version(self.host) == 6:
                    self.socket = socket.socket(
                        socket.AF_INET6, socket.SOCK_DGRAM)
            except socket.error:
                raise NTPException("Error during opening socket.")

        self.sockaddr = socket.getaddrinfo(self.host, self.port)[0][4]
        log.debug("Socket address (sockaddr): %s", self.sockaddr)

        self.socket.settimeout(self.timeout)
        log.debug("Timeout for socket is set to %ds", self.timeout)

    def send_packet(self, data):
        self.socket.sendto(data, (self.host, self.port))

    def process_offset(self):
        """
        Compare offset to limits and return appropriate status.
        :return: state of status after processing
        """
        if self.offset_result == STATE_UNKNOWN:
            return STATE_UNKNOWN
        if self.offset > self.critical:
            return STATE_CRITICAL
        elif self.offset > self.warning:
            return STATE_WARNING
        return STATE_OK

    def max_status(self):
        return max(self.status, self.offset_result)

    def update_readstat_status(self):
        if not self.sync_source:
            self.status = STATE_WARNING
        if self.li_alarm:
            self.status = STATE_WARNING

    def check_packet_source(self, src_addr):
        if src_addr[0] != self.sockaddr[0]:
            log.debug("Invalid packet. Server address doesn't match.")
            return False
        return True

    def is_response(self, opcode):
        """
        Check if received packet has response bit set (0x02).
        """
        return opcode >> 1 & 0x01

    def more_packets(self, opcode):
        """
        Check if server has more packets to send.
        """
        return opcode >> 5 & 0x01

    def result_to_dict(self):
        result = {
            "offset": self.offset,
            "offset_result": self.offset_result,
            "status": self.status,
            "sync_source": self.sync_source,
            "li_alarm": self.li_alarm
            "warning": self.warning,
            "critical": self.critical
        }
        return result

    @inlineCallbacks
    def readstat_exchange(self):
        peers_to_check = {}
        self.sequence_counter += 1
        packet = NTPPacket(self.version, sequence=self.sequence_counter)
        more_packets = True
        while more_packets:
            self.send_packet(packet.to_data_readstat())
            log.debug("READSTAT request was sent to host %s", self.host)
            response_data, src_addr = self.socket.recvfrom(256)
            log.debug("READSTAT response was received from host %s", self.host)
            more_packets = False
            if self.check_packet_source(src_addr):
                response_packet = NTPPacket(self.version)
                response_packet.from_data(response_data)
                if response_packet.count > MAX_CM_SIZE:
                    log.debug(
                        "Invalid READSTAT packet (MAX_CM_SIZE) was received from host %s.",
                        self.host
                    )
                    raise NTPException("Invalid packet received from NTP server")
                if response_packet.check_error_bit():
                    raise NTPException("Invalid packet received from NTP server")
                if response_packet.sequence != self.sequence_counter:
                    log.debug("Wrong sequence number")
                    raise NTPException("Invalid packet received from NTP server")
                if LEAP_TABLE.get(response_packet.leap, None):
                    # check if alarm bit is set
                    if response_packet.leap == 3:
                        self.li_alarm = True
                        log.info("Leap indicator: alarm bit is set")
                else:
                    raise NTPException("Invalid packet received from NTP server")
                if not self.more_packets(response_packet.opcode):
                    more_packets = False
                # extract peers
                peers_to_check.update(response_packet.extract_peers(response_data[12:]))
        result = yield peers_to_check
        returnValue(result)

    @inlineCallbacks
    def readvar_exchange(self, peers_to_check):
        for peer, peer_status in peers_to_check.iteritems():
            # query if status is >= min_peer_source
            clock_select = peer_status >> 8 & 0x07
            if clock_select >= self.min_peer_source:
                log.debug("Getting offset for peer %d", peer)
                self.sequence_counter += 1
                readvar_packet = NTPPacket(
                    version=self.version, sequence=self.sequence_counter, opcode=2
                )
                readvar_packet.assoc = peer
                readvar_packet.data = "offset"
                readvar_packet.count = len(readvar_packet.data)
                self.send_packet(readvar_packet.to_data_readvar())
                readvar_data, src_addr = self.socket.recvfrom(256)
                if not self.check_packet_source(src_addr):
                    raise NTPException("Invalid packet received from NTP server")
                readvar_packet.from_data(readvar_data)
                if not self.is_response(readvar_packet.opcode):
                    raise NTPException("Invalid packet received from NTP server")
                if readvar_packet.check_error_bit():
                    log.debug("Error bit set in packet, trying to get all possible values")
                    self.sequence_counter += 1
                    readvar_packet.sequence = self.sequence_counter
                    readvar_packet.data = ""
                    readvar_packet.count = len(readvar_packet.data)
                    self.send_packet(readvar_packet.to_data_readvar())
                    readvar_data, src_addr = self.socket.recvfrom(256)
                    if not self.check_packet_source(src_addr):
                        raise NTPException("Invalid packet received from NTP server")
                    readvar_packet.from_data(readvar_data)
                    if readvar_packet.check_error_bit() \
                            or not self.is_response(readvar_packet.opcode):
                        raise NTPException("Invalid packet received from NTP server")
                if readvar_packet.count != 0:
                    # get data field (ASCII) and strip whitespaces, newlines symbols etc.
                    peer_data = readvar_data[12:(readvar_packet.count+12)].strip().replace(" ", "")
                    peer_data_dict = {
                        key: value for key, value in [d.split("=") for d in peer_data.split(",")]
                    }
                    # extract offset
                    tmp_offset = peer_data_dict.get("offset", None)
                    if tmp_offset:
                        tmp_offset = float(tmp_offset) / 1000
                        log.debug("Offset for peer %d: %f", peer, tmp_offset)
                        if self.offset_result == STATE_UNKNOWN \
                                or abs(tmp_offset) < abs(self.offset):
                            self.offset = tmp_offset
                            self.offset_result = STATE_OK
        self.status = self.process_offset()
        self.status = self.max_status()
        result = yield self.result_to_dict()
        returnValue(result)
