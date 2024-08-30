from unittest import TestCase
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts


class TestBytesAndInts(TestCase):

    # ------------------------- int2byte Start ---------------------
    def test_int2byte(self) -> None:
        # When i >= 0
        self.assertEqual(BytesAndInts.int2Byte(478560413032), b"hello")
        self.assertEqual(BytesAndInts.int2Byte(48), b"0")
        self.assertEqual(BytesAndInts.int2Byte(0), b"")

    def test_int2byte_value(self) -> None:
        # When i < 0
        self.assertRaises(ValueError, BytesAndInts.int2Byte, -1)
        self.assertRaises(ValueError, BytesAndInts.int2Byte, -2)
    # ------------------------- int2byte End ---------------------

    # ------------------------- byte2int Start ---------------------
    def test_byte2int(self):
        # When b is bytes
        self.assertEqual(BytesAndInts.byte2Int(b"hello"), 478560413032)
        self.assertEqual(BytesAndInts.byte2Int(b"0"), 48)
        self.assertEqual(BytesAndInts.byte2Int(b""), 0)
    # ------------------------- byte2int End ---------------------
