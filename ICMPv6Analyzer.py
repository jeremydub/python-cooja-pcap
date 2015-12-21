from Packet import *

class ICMPv6Analyzer:

  ICMPv6_DISPATCH = 58

  ECHO_REQUEST = 128
  ECHO_REPLY = 129
  GROUP_QUERY = 130
  GROUP_REPORT = 131
  GROUP_REDUCTION = 132
  ROUTER_SOLICITATION = 133
  ROUTER_ADVERTISEMENT = 134
  NEIGHBOR_SOLICITATION = 135
  NEIGHBOR_ADVERTISEMENT = 136

  RPL_CODE_DIS = 0 
  RPL_CODE_DIO = 1 
  RPL_CODE_DAO = 2
  RPL_CODE_DAO_ACK = 3

  FLAG_ROUTER = 0x80
  FLAG_SOLICITED = 0x40
  FLAG_OVERRIDE = 0x20

  ON_LINK = 0x80
  AUTOCONFIG = 0x40

  SOURCE_LINKADDR = 1
  TARGET_LINKADDR = 2
  PREFIX_INFO = 3
  MTU_INFO = 5

  TYPE_NAME = [
    "Echo Request", "Echo Reply", \
    "Group Query", "Group Report", "Group Reduction", \
    "Router Solicitation", "Router Advertisement", \
    "Neighbor Solicitation", "Neighbor Advertisement", "Redirect", \
    "Router Renumber", "Node Information Query", "Node Information Response"]

  BRIEF_TYPE_NAME=[
    "ECHO REQ", "ECHO RPLY", \
    "GRP QUERY", "GRP REPORT", "GRP REDUCTION", \
    "RS", "RA", \
    "NS", "NA", "REDIRECT", \
    "ROUTER RENUMBER", "NODE INFO QUERY", "NODE INFO RESP"]

  def matchPacket(self, packet):
    return packet.level == PacketAnalyzer.APPLICATION_LEVEL and packet.lastDispatch == ICMPv6Analyzer.ICMPv6_DISPATCH

  def analyzePacket(self, packet, verbose=[]):
    type = packet[0] & 0xff
    code = packet[1] & 0xff

    verbose.append("ICMPv6")
    if type >= 128 and (type - 128) < len(ICMPv6Analyzer.TYPE_NAME):
      verbose.append("\nType: ")
      verbose.append(str(TYPE_NAME[type - 128]))
      verbose.append(", Code:")
      verbose.append(str(code))
    elif type == 155:
      verbose.append("\nType: RPL Code: ")
      # switch
      if code == ICMPv6Analyzer.RPL_CODE_DIS:
        verbose.append("DIS")
      elif code == ICMPv6Analyzer.RPL_CODE_DIO:
        verbose.append("DIO\n")

        instanceID = packet[4] & 0xff
        version = packet[5] & 0xff
        rank = ((packet[6] & 0xff) << 8) + (packet[7] & 0xff)
        mop = (packet[8] >> 3) & 0x07
        dtsn = packet[9] & 0xFF

        verbose.append("InstanceID: ")
        verbose.append(str(instanceID))
        verbose.append(", Version: ")
        verbose.append(str(version))
        verbose.append(", Rank: ")
        verbose.append(str(rank))
        verbose.append(", MOP: ")
        verbose.append(str(mop))
        verbose.append(", DTSN: ")
        verbose.append(str(dtsn))
        packet.consumeBytesStart(8)
      elif code == ICMPv6Analyzer.RPL_CODE_DAO:
        verbose.append("DAO")
      elif code == ICMPv6Analyzer.RPL_CODE_DAO_ACK:
        verbose.append("DAO ACK")
      else:
        verbose.append(str(code))

    # remove type, code, crc
    packet.consumeBytesStart(4)
    return PacketAnalyzer.ANALYSIS_OK_FINAL