from Packet import *
import Utils

class IPv6PacketAnalyzer:

  PROTO_UDP = 17
  PROTO_TCP = 6
  PROTO_ICMP = 58

  UNSPECIFIED_ADDRESS = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

  IPV6_DISPATCH = 0x41

  def matchPacket(self, packet):
    return packet.level == PacketAnalyzer.NETWORK_LEVEL and packet[0] == IPv6PacketAnalyzer.IPV6_DISPATCH
  
  def analyzePacket(self, packet, verbose=[]):

    # if packet has less than 40 bytes it is not interesting ...
    if packet.get_size() < 40: return PacketAnalyzer.ANALYSIS_FAILED

    # need to decompress while analyzing - add that later...
    verbose.append("IPv6\n")

    pos = 1

    version = 6
    trafficClass = 0
    flowLabel = 0
    length = packet.getInt(pos + 4, 2)
    proto = packet.getInt(pos + 6, 1)
    ttl = packet.getInt(pos + 7, 1)
    srcAddress = [0x00]*16
    destAddress = [0x00]*16

    packet.copy(pos + 8, srcAddress, 0, 16)
    packet.copy(pos + 24, destAddress, 0, 16)

    protoStr = "" + str(proto)
    if proto == IPv6PacketAnalyzer.PROTO_ICMP:
      protoStr = "ICMPv6"
    elif proto == IPv6PacketAnalyzer.PROTO_UDP:
      protoStr = "UDP"
    elif proto == IPv6PacketAnalyzer.PROTO_TCP:
      protoStr = "TCP"

    # consume dispatch + IP header
    packet.pos += 41

    verbose.append("\nIPv6 ")
    verbose.append(str(protoStr))
    verbose.append("TC = ")
    verbose.append(str(trafficClass))
    verbose.append(" FL: ")
    verbose.append(str(flowLabel))
    verbose.append("\n")
    verbose.append("From ")
    verbose.append(Utils.human_readable_address(srcAddress,2))
    verbose.append("  to ")
    verbose.append(Utils.human_readable_address(destAddress,2))

    packet.lastDispatch = proto & 0xff
    packet.level = PacketAnalyzer.APPLICATION_LEVEL
    return PacketAnalyzer.ANALYSIS_OK_CONTINUE