import copy

class PacketAnalyzer:
  ANALYSIS_FAILED = -1
  ANALYSIS_OK_CONTINUE = 1
  ANALYSIS_OK_FINAL = 2

  RADIO_LEVEL = 0
  MAC_LEVEL = 1
  NETWORK_LEVEL = 2
  APPLICATION_LEVEL = 3

class Packet :

  def __init__(self, data, level=PacketAnalyzer.MAC_LEVEL):

    if type(data) == str:
      self.data=bytearray.fromhex(data)
    elif type(data) == bytearray:
      self.data=data
    else:
      raise TypeError("Data type must be either str or bytearray")

    self.level = level
    self.size = len(data)
    self.pos=0
    self.lastDispatch = 0

  def consumeBytesStart(self, n_bytes):
    self.pos += n_bytes

  def consumeBytesEnd(self, n_bytes):
    self.size -= n_bytes

  def hasMoreData(self):
    return self.size > self.pos

  def get_size(self):
    return self.size - self.pos

  def get(self,index):
    if (index >= self.size) :
      return 0
    elif index < 0:
      return self.get((self.size+index)%self.size)
    else:
      return self.data[self.pos + index]

  def __getitem__(self, index):
    return self.get(index)

  def getInt(self, index, size):
    value = 0
    for i in range(size):
      value = (value << 8) + (self.get(index + i) & 0xFF)
    return value

  def getPayload(self):
    return copy.copy(self.data[self.pos:])

  def copy(self, srcpos, arr, pos, length):
    for i in range(length):
      arr[pos + i] = self.get(srcpos + i)

  def getLLSender(self):
    return self.llsender

  def getLLReceiver(self):
    return self.llreceiver

  def __eq__(self, other):
    if type(other) == Packet:
      return self.data == other.data
    else:
      return False