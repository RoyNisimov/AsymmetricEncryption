
class BytesAndInts:

    def __init__(self):
        pass

    @staticmethod
    def int2Byte(i: int) -> bytes:
        return i.to_bytes(i.bit_length(), "little").rstrip(b'\x00')

    @staticmethod
    def byte2Int(b: bytes) -> int:
        return int.from_bytes(b, "little")
