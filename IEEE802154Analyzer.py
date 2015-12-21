from Packet import *
import Utils

class IEEE802154Analyzer:

  #Addressing modes
  NO_ADDRESS = 0
  RSV_ADDRESS = 1
  SHORT_ADDRESS = 2
  LONG_ADDRESS = 3

  #Frame types
  BEACONFRAME = 0x00
  DATAFRAME = 0x01
  ACKFRAME = 0x02
  CMDFRAME = 0x03

  typeS = ["-", "D", "A", "C"]
  typeVerbose = ["BEACON", "DATA", "ACK", "CMD"]
  addrModeNames = ["None", "Reserved", "Short", "Long"]

  def matchPacket(self, packet):
    return packet.level == PacketAnalyzer.MAC_LEVEL

  def nextLevel(self,packet_bytes, level):
    """
    this protocol always have network level packets as payload
    """
    return PacketAnalyzer.NETWORK_LEVEL

  def analyzePacket(self,packet, verbose=[]):
    """
    create a 802.15.4 packet of the bytes and 'dispatch' to the next handler
    """
    pos = packet.pos

    # FCF field
    fcfType = int(packet.data[pos + 0] & 0x07)

    # booleans
    fcfSecurity = ((packet.data[pos + 0] >> 3) & 0x01) != 0
    fcfPending = ((packet.data[pos + 0] >> 4) & 0x01) != 0
    fcfAckRequested = ((packet.data[pos + 0] >> 5) & 0x01) != 0
    fcfIntraPAN = ((packet.data[pos + 0] >> 6) & 0x01) != 0

    fcfDestAddrMode = int((packet.data[pos + 1] >> 2) & 0x03)
    fcfFrameVersion = int((packet.data[pos + 1] >> 4) & 0x03)
    fcfSrcAddrMode = int((packet.data[pos + 1] >> 6) & 0x03)

    # Sequence number
    seqNumber = int(packet.data[pos + 2] & 0xff)

    # Addressing Fields
    destPanID = 0
    srcPanID = 0
    sourceAddress = None
    destAddress = None

    pos += 3

    if (fcfDestAddrMode > 0):
      destPanID = (packet.data[pos] & 0xff) + ((packet.data[pos + 1] & 0xff) << 8)
      pos += 2
      if fcfDestAddrMode == IEEE802154Analyzer.SHORT_ADDRESS:
        destAddress = [0x00]*2
        destAddress[1] = packet.data[pos]
        destAddress[0] = packet.data[pos + 1]
        pos += 2
      elif fcfDestAddrMode == IEEE802154Analyzer.LONG_ADDRESS:
        destAddress = [0x00]*8
        for i in range(8):
          destAddress[i] = packet.data[pos + 7 - i]
        pos += 8

    if fcfSrcAddrMode > 0:
      if fcfIntraPAN:
        srcPanID = destPanID
      else:
        srcPanID = int((packet.data[pos] & 0xff) + ((packet.data[pos + 1] & 0xff) << 8))
        pos += 2
      
      if fcfSrcAddrMode == IEEE802154Analyzer.SHORT_ADDRESS:
        sourceAddress = [0x00]*2
        sourceAddress[1] = packet.data[pos]
        sourceAddress[0] = packet.data[pos + 1]
        pos += 2
      elif fcfSrcAddrMode == IEEE802154Analyzer.LONG_ADDRESS:
        sourceAddress = [0x00]*8
        for i in range(8):
          sourceAddress[i] = packet.data[pos + 7 - i]
        pos += 8

    # update packet
    packet.pos = pos
    # remove CRC from the packet
    packet.consumeBytesEnd(2)

    if fcfType == IEEE802154Analyzer.ACKFRAME:
      # got ack - no more to do ...
      return PacketAnalyzer.ANALYSIS_OK_FINAL

    packet.level = PacketAnalyzer.NETWORK_LEVEL
    packet.llsender = sourceAddress
    packet.llreceiver = destAddress

    verbose.append("IEEE 802.15.4 ")
    verbose.append(IEEE802154Analyzer.typeVerbose[fcfType] if fcfType < len(IEEE802154Analyzer.typeVerbose) else "?")
    verbose.append(" #")
    verbose.append(str(seqNumber))

    if fcfType != IEEE802154Analyzer.ACKFRAME:
      verbose.append("\nFrom ")
      if srcPanID != 0:
        verbose.append("0x")
        verbose.append(hex(srcPanID >> 8)[2:])
        verbose.append(hex(srcPanID & 0xff)[2:])
        verbose.append('/')
      
      verbose.append(Utils.human_readable_address(sourceAddress,1))
      verbose.append(" to ")
      if destPanID != 0:
        verbose.append("0x")
        verbose.append(hex(destPanID >> 8)[2:])
        verbose.append(hex(destPanID & 0xff)[2:])
        verbose.append('/')
      verbose.append(Utils.human_readable_address(destAddress,1))

    verbose.append("\nSec = ")
    verbose.append(str(fcfSecurity))
    verbose.append(", Pend = ")
    verbose.append(str(fcfPending))
    verbose.append(", ACK = ")
    verbose.append(str(fcfAckRequested))
    verbose.append(", iPAN = ")
    verbose.append(str(fcfIntraPAN))
    verbose.append(", DestAddr = ")
    verbose.append(IEEE802154Analyzer.addrModeNames[fcfDestAddrMode])
    verbose.append(", Vers. = ")
    verbose.append(str(fcfFrameVersion))
    verbose.append(", SrcAddr = ")
    verbose.append(IEEE802154Analyzer.addrModeNames[fcfSrcAddrMode])

    return PacketAnalyzer.ANALYSIS_OK_CONTINUE