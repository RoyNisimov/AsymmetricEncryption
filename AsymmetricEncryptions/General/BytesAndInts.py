
class BytesAndInts:
    """A class to convert bytes and ints easily"""

    def __init__(self):
        pass

    @staticmethod
    def int2Byte(i: int) -> bytes:
        """
        Turns int into bytes using the to_bytes with byteorder=little
        :param i: the int to convert
        :return: bytes
        """
        if not isinstance(i, int): raise TypeError("I must be an int!")
        if i < 0:
            raise ValueError("i can't be a negative number!")

        return i.to_bytes(i.bit_length(), "little").rstrip(b'\x00')

    @staticmethod
    def byte2Int(b: bytes) -> int:
        """
        Turns bytes into int using the from_bytes with byteorder=little
        :param b: the byte to convert
        :return: int
        """
        if not isinstance(b, bytes): raise TypeError("I must be a byte!")
        return int.from_bytes(b, "little")
