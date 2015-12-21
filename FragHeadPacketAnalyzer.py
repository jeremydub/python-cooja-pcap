from Packet import *

class FragHeadPacketAnalyzer:
  
  SICSLOWPAN_DISPATCH_FRAG1 = 0xc0 # 1100 0xxx
  SICSLOWPAN_DISPATCH_FRAGN = 0xe0 # 1110 0xxx

  def matchPacket(self, packet):
    return packet.level == PacketAnalyzer.NETWORK_LEVEL and \
           (packet[0] & 0xD8) == FragHeadPacketAnalyzer.SICSLOWPAN_DISPATCH_FRAG1
  
  def analyzePacket(self, packet, verbose=[]):
    hdr_size = 0
    
    verbose.append("Frag Header ")

    if (packet[0] & 0xF8) == FragHeadPacketAnalyzer.SICSLOWPAN_DISPATCH_FRAG1 :
      hdr_size = 4
      verbose.append("first\n")
    elif (packet[0] & 0xF8) == FragHeadPacketAnalyzer.SICSLOWPAN_DISPATCH_FRAGN:
      hdr_size = 5
      verbose.append("nth\n")
    
    datagram_size = ((packet[0] & 0x07) << 8) + packet[1]
    datagram_tag = packet.getInt(2, 2)
    
    verbose.append("size = ")
    verbose.append(str(datagram_size))
    verbose.append(", tag = ")
    verbose.append(str(datagram_tag).zfill(4))
    
    if hdr_size == 5:
      verbose.append(", offset = ")
      verbose.append(str(packet[4] * 8))
    
    packet.pos += hdr_size

    return PacketAnalyzer.ANALYSIS_OK_CONTINUE