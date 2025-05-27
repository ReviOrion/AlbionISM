class SegmentedPacket:
    def __init__(self, hw_Length = 0, bytes_written = 0, gh_Payload = bytearray(0)):
        self.hw_Length = hw_Length
        self.bytes_written = bytes_written
        self.gh_Payload = gh_Payload