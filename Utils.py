import struct

from Packet import *
from FragHeadPacketAnalyzer import *
from IPHCPacketAnalyzer import *
from IPv6PacketAnalyzer import *
from ICMPv6Analyzer import *
import IEEE802154Analyzer

def human_readable_address(address_bytes, bytes_per_group=2):
  address=""
  size=len(address_bytes)
  for i in range(size):
    if i % bytes_per_group==0 and i > 0:
      address += ":"
    address += hex(address_bytes[i])[2:].zfill(2)
  return address

def analyse_packet(packet, verbose=[]):
  analyzers = [IEEE802154Analyzer.IEEE802154Analyzer(), FragHeadPacketAnalyzer(), IPHCPacketAnalyzer(), IPv6PacketAnalyzer(), ICMPv6Analyzer()]

  analyze = True
  while analyze:
    analyze = False
    for i in range(len(analyzers)):
      analyzer = analyzers[i]
      if analyzer.matchPacket(packet):
        res = analyzer.analyzePacket(packet, verbose)
        if packet.hasMoreData() and len(verbose) > 0:
          verbose.append("\n\n")
        if res != PacketAnalyzer.ANALYSIS_OK_CONTINUE:
          # this was the final or the analysis failed - no analyzable payload possible here...
          return len(verbose) > 0

        # continue another round if more bytes left
        analyze = packet.hasMoreData()
        break
  return len(verbose) > 0

def get_packets_from_pcap(filename):
  f=open(filename, 'rb')

  # get file size in bytes
  f.seek(0, 2)
  eof = f.tell()

  f.seek(0, 0)
  pos=0

  # skip pcap file header
  f.read(24)
  pos += 24

  time=None
  time2=None
  size=None

  packets=[]

  while pos < eof:
    # Read pcap packet header
    time=struct.unpack_from(">I", f.read(4))[0]
    time2=struct.unpack_from(">I", f.read(4))[0]
    size=struct.unpack_from(">I", f.read(4))[0]
    # Skip duplicated size
    f.read(4)
    # Read packet
    packet_bytes=bytearray(f.read(size))
    # create packet object
    packet = Packet(packet_bytes)
    packets.append(packet)
    pos += 16 + size
  f.close()

  for p in packets:
    analyse_packet(p)

  return packets