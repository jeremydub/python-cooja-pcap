from Packet import *
import Utils

class IPHCPacketAnalyzer:

  SICSLOWPAN_UDP_4_BIT_PORT_MIN = 0xF0B0
  SICSLOWPAN_UDP_4_BIT_PORT_MAX = 0xF0BF   #F0B0 + 15
  SICSLOWPAN_UDP_8_BIT_PORT_MIN = 0xF000
  SICSLOWPAN_UDP_8_BIT_PORT_MAX = 0xF0FF   #F000 + 255

  SICSLOWPAN_DISPATCH_IPV6                    = 0x41 #01000001 = 65
  SICSLOWPAN_DISPATCH_HC1                     = 0x42 #01000010 = 66
  SICSLOWPAN_DISPATCH_IPHC                    = 0x60 #011xxxxx = ...

  EXT_HDR_HOP_BY_HOP  = 0
  EXT_HDR_ROUTING     = 43
  EXT_HDR_FRAGMENT    = 44

  """
  Values of fields within the IPHC encoding first byte
  (C stands for compressed and I for inline)
  """
  SICSLOWPAN_IPHC_FL_C                        = 0x10
  SICSLOWPAN_IPHC_TC_C                        = 0x08
  SICSLOWPAN_IPHC_NH_C                        = 0x04
  SICSLOWPAN_IPHC_TTL_1                       = 0x01
  SICSLOWPAN_IPHC_TTL_64                      = 0x02
  SICSLOWPAN_IPHC_TTL_255                     = 0x03
  SICSLOWPAN_IPHC_TTL_I                       = 0x00

  """
  Values of fields within the IPHC encoding second byte
  """
  SICSLOWPAN_IPHC_CID                         = 0x80

  SICSLOWPAN_IPHC_SAC                         = 0x40
  SICSLOWPAN_IPHC_SAM_00                      = 0x00
  SICSLOWPAN_IPHC_SAM_01                      = 0x10
  SICSLOWPAN_IPHC_SAM_10                      = 0x20
  SICSLOWPAN_IPHC_SAM_11                      = 0x30

  SICSLOWPAN_IPHC_M                           = 0x08
  SICSLOWPAN_IPHC_DAC                         = 0x04
  SICSLOWPAN_IPHC_DAM_00                      = 0x00
  SICSLOWPAN_IPHC_DAM_01                      = 0x01
  SICSLOWPAN_IPHC_DAM_10                      = 0x02
  SICSLOWPAN_IPHC_DAM_11                      = 0x03

  SICSLOWPAN_NDC_UDP_MASK                     = 0xf8
  SICSLOWPAN_NHC_UDP_ID =                       0xf0
  SICSLOWPAN_NHC_UDP_00 = 0xf0
  SICSLOWPAN_NHC_UDP_01 = 0xf1
  SICSLOWPAN_NHC_UDP_10 = 0xf2
  SICSLOWPAN_NHC_UDP_11 = 0xf3

  PROTO_UDP = 17
  PROTO_TCP = 6
  PROTO_ICMP = 58

  UNSPECIFIED_ADDRESS = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

  addrContexts = [[0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]]

  IPHC_DISPATCH = 0x60

  def matchPacket(self, packet):
    """
    packet must be on network level && have a IPHC dispatch
    """
    return packet.level == PacketAnalyzer.NETWORK_LEVEL and (packet[0] & 0xe0) == IPHCPacketAnalyzer.IPHC_DISPATCH

  def analyzePacket(self, packet, verbose):

    # if packet has less than 3 bytes it is not interesting ...
    if packet.get_size() < 3 : return PacketAnalyzer.ANALYSIS_FAILED

    tf = (packet[0] >> 3) & 0x03
    nhc = (packet[0] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_NH_C) > 0
    hlim = (packet[0] & 0x03)
    
    #switch
    if hlim == 0x00:
      hlim = 0
    elif hlim == 0x01:
      hlim = 1
    elif hlim == 0x02:
      hlim = 64
    elif hlim == 0x03:
      hlim = 255
    
    cid = (packet[1] >> 7) & 0x01
    sac = (packet[1] >> 6) & 0x01
    sam = (packet[1] >> 4) & 0x03
    m = ((packet[1] >> 3) & 0x01) != 0
    dac = (packet[1] >> 2) & 0x01
    dam = packet[1] & 0x03
    sci = 0
    dci = 0

    error = None

    # need to decompress while analyzing - add that later...
    verbose.append("IPHC HC-06\n")
    verbose.append("TF = ")
    verbose.append(str(tf))
    verbose.append(", NH = ")
    verbose.append("compressed" if nhc else "inline")
    verbose.append(", HLIM = ")
    verbose.append( "inline" if hlim == 0 else str(hlim))
    verbose.append(", CID = ")
    verbose.append(str(cid))
    verbose.append(", SAC = ")
    verbose.append("stateless" if sac == 0 else "stateful")
    verbose.append(", SAM = ")
    verbose.append(str(sam))
    verbose.append(", MCast = ")
    verbose.append(str(m))
    verbose.append(", DAC = ")
    verbose.append("stateless" if dac == 0 else "stateful")
    verbose.append(", DAM = ")
    verbose.append(str(dam))
    if cid == 1:
      verbose.append("\nContexts: sci=")
      verbose.append(str(packet[2] >> 4))
      verbose.append(" dci=")
      verbose.append(str(packet[2] & 0x0f))
      sci = packet[2] >> 4
      dci = packet[2] & 0x0f    

    hc06_ptr = 2 + cid

    version = 6
    trafficClass = 0
    flowLabel = 0
    length = 0
    proto = 0
    ttl = 0
    srcAddress = [0x00]*16
    destAddress = [0x00]*16

    srcPort = 0
    destPort = 0

    try:
      # Traffic class and flow label
      if (packet[0] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_FL_C) == 0:
        # Flow label are carried inline
        if (packet[0] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TC_C) == 0:
          # Traffic class is carried inline
          flowLabel = packet.getInt(hc06_ptr + 1, 3)
          tmp = packet[hc06_ptr]
          hc06_ptr += 4
          # hc06 format of tc is ECN | DSCP , original is DSCP | ECN
          trafficClass = ((tmp >> 2) & 0x3f) | (tmp << 6) & (0x80 + 0x40)
          # ECN rolled down two steps + lowest DSCP bits at top two bits
        else:
          # highest flow label bits + ECN bits
          tmp = packet[hc06_ptr]
          trafficClass = (tmp >> 6) & 0x0f
          flowLabel = packet.getInt(hc06_ptr + 1, 2)
          hc06_ptr += 3
        
      else:
        # Version is always 6!
        # Version and flow label are compressed
        if (packet[0] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TC_C) == 0:
          # Traffic class is inline
          trafficClass = ((packet[hc06_ptr] >> 6) & 0x03)
          trafficClass |= (packet[hc06_ptr] << 2)
          hc06_ptr += 1

      # Next Header
      if (packet[0] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_NH_C) == 0:
        # Next header is carried inline
        proto = packet[hc06_ptr]
        hc06_ptr += 1

      # Hop limit
      # switch
      if packet[0] & 0x03 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TTL_1:
        ttl = 1
      elif packet[0] & 0x03 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TTL_64:
        ttl = 64
      elif packet[0] & 0x03 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TTL_255:
        ttl = 255
      elif packet[0] & 0x03 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_TTL_I:
        ttl = packet[hc06_ptr]
        hc06_ptr += 1

      # context based compression
      if (packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAC) > 0:
        # Source address
        context = None
        if (packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11) != IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_00:
          context = IPHCPacketAnalyzer.addrContexts[sci]

        # switch
        if packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_00:
          # copy the unspecificed address
          srcAddress = UNSPECIFIED_ADDRESS
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_01: # 64 bits
          # copy prefix from context
          srcAddress[:8] = context[:8]
          # copy IID from packet
          packet.copy(hc06_ptr, srcAddress, 8, 8)
          hc06_ptr += 8
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_10: # 16 bits
          # unicast address
          srcAddress[:8] = context[:8]
          # copy 6 NULL bytes then 2 last bytes of IID
          packet.copy(hc06_ptr, srcAddress, 14, 2)
          hc06_ptr += 2
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11: # 0-bits
          # copy prefix from context
          srcAddress[:8] = context[:8]
          # infer IID from L2 address
          srcAddress[16 - len(packet.llsender):]=packet.llsender
      
        # end context based compression
      else:
        # no compression and link local
        # switch
        if packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_00: # 128 bits
          # copy whole address from packet
          packet.copy(hc06_ptr, srcAddress, 0, 16)
          hc06_ptr += 16
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_01: # 64 bits
          srcAddress[0] = 0xfe
          srcAddress[1] = 0x80
          # copy IID from packet
          packet.copy(hc06_ptr, srcAddress, 8, 8)
          hc06_ptr += 8
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_10: # 16 bits
          srcAddress[0] = 0xfe
          srcAddress[1] = 0x80
          packet.copy(hc06_ptr, srcAddress, 14, 2)
          hc06_ptr += 2
        elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_SAM_11: # 0 bits
          # setup link-local address
          srcAddress[0] = 0xfe
          srcAddress[1] = 0x80
          # infer IID from L2 address
          srcAddress[16 - len(packet.llsender):]=packet.llsender

      # Destination address

      # multicast compression
      if (packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_M) != 0:
        # context based multicast compression
        if (packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAC) != 0:
          # TODO: implement this
          pass
        else:
          # non-context based multicast compression
          # switch
          if packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_00: # 128 bits
            # copy whole address from packet
            packet.copy(hc06_ptr, destAddress, 0, 16)
            hc06_ptr += 16
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_01: # 48 bits FFXX::00XX:XXXX:XXXX
            destAddress[0] = 0xff
            destAddress[1] = packet[hc06_ptr]
            packet.copy(hc06_ptr + 1, destAddress, 11, 5)
            hc06_ptr += 6
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_10: # 32 bits FFXX::00XX:XXXX
            destAddress[0] = 0xff
            destAddress[1] = packet[hc06_ptr]
            packet.copy(hc06_ptr + 1, destAddress, 13, 3)
            hc06_ptr += 4
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11: # 8 bits FF02::00XX
            destAddress[0] = 0xff
            destAddress[1] = 0x02
            destAddress[15] = packet[hc06_ptr]
            hc06_ptr+=1
      else:
        # no multicast
        # Context based
        if (packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAC) != 0:
          context = IPHCPacketAnalyzer.addrContexts[dci]

          # switch
          if packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_01: # 64 bits
            destAddress[:8] = context[:8]
            # copy IID from packet
            packet.copy(hc06_ptr, destAddress, 8, 8)
            hc06_ptr += 8
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_10: # 16 bits
            # unicast address
            destAddress[:8] = context[:8]
            # copy IID from packet
            packet.copy(hc06_ptr, destAddress, 14, 2)
            hc06_ptr += 2
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11: # 0 bits
            # unicast address
            destAddress[:8] = context[:8]
            # infer IID from L2 address
            destAddress[16 - len(packet.llreceiver):]=packet.llreceiver
          
        else:
          # not context based => link local M = 0, DAC = 0 - same as SAC
          # switch
          if packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_00: # 128 bits
            packet.copy(hc06_ptr, destAddress, 0, 16)
            hc06_ptr += 16
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_01: # 64 bits
            destAddress[0] = 0xfe
            destAddress[1] = 0x80
            packet.copy(hc06_ptr, destAddress, 8, 8)
            hc06_ptr += 8
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_10: # 16 bits
            destAddress[0] = 0xfe
            destAddress[1] = 0x80
            packet.copy(hc06_ptr, destAddress, 14, 2)
            hc06_ptr += 2
          elif packet[1] & IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11 == IPHCPacketAnalyzer.SICSLOWPAN_IPHC_DAM_11: # 0 bits
            destAddress[0] = 0xfe
            destAddress[1] = 0x80
            destAddress[16 - len(packet.llreceiver):]=packet.llreceiver

      # Next header processing - continued
      if nhc:
        # TODO: check if this is correct in hc-06
        # The next header is compressed, NHC is following
        if (packet[hc06_ptr] & IPHCPacketAnalyzer.SICSLOWPAN_NDC_UDP_MASK) == IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_ID:
          proto = PROTO_UDP
          # switch
          if packet[hc06_ptr] & IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_11 == IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_00:
            # 1 byte for NHC, 4 byte for ports, 2 bytes chksum
            srcPort = packet.getInt(hc06_ptr + 1, 2) & 0xFFFF
            destPort = packet.getInt(hc06_ptr + 3, 2) & 0xFFFF
            hc06_ptr += 7
          elif packet[hc06_ptr] & IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_11 == IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_01:
            # 1 byte for NHC, 3 byte for ports, 2 bytes chksum
            srcPort = packet.getInt(hc06_ptr + 1, 2)
            destPort = IPHCPacketAnalyzer.SICSLOWPAN_UDP_8_BIT_PORT_MIN + (packet[hc06_ptr + 3] & 0xFF)
            hc06_ptr += 6
          elif packet[hc06_ptr] & IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_11 == IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_10:
            # 1 byte for NHC, 3 byte for ports, 2 bytes chksum
            srcPort = IPHCPacketAnalyzer.SICSLOWPAN_UDP_8_BIT_PORT_MIN + (packet[hc06_ptr + 1] & 0xFF)
            destPort = packet.getInt(hc06_ptr + 2, 2)
            hc06_ptr += 6
          elif packet[hc06_ptr] & IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_11 == IPHCPacketAnalyzer.SICSLOWPAN_NHC_UDP_11:
            # 1 byte for NHC, 1 byte for ports, 2 bytes chksum
            srcPort = IPHCPacketAnalyzer.SICSLOWPAN_UDP_4_BIT_PORT_MIN + (packet[hc06_ptr + 1] >> 4)
            destPort = IPHCPacketAnalyzer.SICSLOWPAN_UDP_4_BIT_PORT_MIN + (packet[hc06_ptr + 1] & 0x0F)
            hc06_ptr += 4
          
      else:
        # Skip extension header
        # XXX TODO: Handle others, too?
        if proto == IPHCPacketAnalyzer.EXT_HDR_HOP_BY_HOP:
          proto = packet[hc06_ptr] & 0xFF

          # header length is length specified in field, rounded up to 64 bit
          hdr_len = ((packet[hc06_ptr + 1] / 8) + 1) * 8
          hc06_ptr += hdr_len

          # UDP hadling
          if proto == PROTO_UDP:
            srcPort = packet.getInt(hc06_ptr, 2) & 0xFFFF
            destPort = packet.getInt(hc06_ptr + 2, 2) & 0xFFFF
            hc06_ptr += 4

    except Exception as e:
      # some kind of unexpected error...
      error = " error during IPHC parsing: " + str(e)

    packet.pos += hc06_ptr

    protoStr = "" + str(proto)
    if proto == IPHCPacketAnalyzer.PROTO_ICMP:
      protoStr = "ICMPv6"
    elif proto == IPHCPacketAnalyzer.PROTO_UDP:
      protoStr = "UDP"
    elif proto == IPHCPacketAnalyzer.PROTO_TCP:
      protoStr = "TCP"
    else:
      protoStr = str(proto)
    
    # IPv6 Information
    verbose.append("\nIPv6 ")
    verbose.append(" TC = ")
    verbose.append(str(trafficClass))
    verbose.append(", FL = ")
    verbose.append(str(flowLabel))
    verbose.append("\n")
    verbose.append("From ")
    verbose.append(Utils.human_readable_address(srcAddress,2))
    verbose.append("  to ")
    verbose.append(Utils.human_readable_address(destAddress,2))
    if error != None:
      verbose.append(" ")
      verbose.append(error)

    # Application Layer Information
    if proto != IPHCPacketAnalyzer.PROTO_ICMP:
      verbose.append("\n")
      verbose.append(str(protoStr))
    
    if proto == IPHCPacketAnalyzer.PROTO_UDP:
      verbose.append("\nSrc Port: ")
      verbose.append(str(srcPort))
      verbose.append(", Dst Port: ")
      verbose.append(str(destPort))

    packet.lastDispatch = proto & 0xff
    if proto == IPHCPacketAnalyzer.PROTO_UDP or proto == IPHCPacketAnalyzer.PROTO_ICMP \
       or proto == IPHCPacketAnalyzer.PROTO_TCP:
      packet.level = PacketAnalyzer.APPLICATION_LEVEL
      return PacketAnalyzer.ANALYSIS_OK_CONTINUE
    else:
      packet.level = PacketAnalyzer.NETWORK_LEVEL
      return PacketAnalyzer.ANALYSIS_OK_CONTINUE