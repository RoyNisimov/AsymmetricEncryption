from unittest import TestCase
from AsymmetricEncryptions.General.XOR import XOR

class TestXOR(TestCase):

    def test_repeated_key_xor(self):
        self.assertEqual(XOR.repeated_key_xor(b"1", b"1"), b"\x00")
        self.assertEqual(XOR.repeated_key_xor(b"2", b"1"), b'\x03')
        self.assertEqual(XOR.repeated_key_xor(b"\x00", b"1"), b'1')
        self.assertEqual(XOR.repeated_key_xor(XOR.repeated_key_xor(b"msg", b"key"), b"key"), b'msg')

    def test_repeated_key_xor_with_scrypt_kdf(self):
        self.assertEqual(XOR.repeated_key_xor_with_scrypt_kdf(XOR.repeated_key_xor_with_scrypt_kdf(b"msg", b"key"), b"key"), b'msg')




