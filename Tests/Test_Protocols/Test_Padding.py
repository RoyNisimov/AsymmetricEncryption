from __future__ import annotations
from AsymmetricEncryptions.Protocols.Padding import PKCS7
from unittest import TestCase

class TestPKCS7(TestCase):

    def test_pad(self):
        msg = b"PKCS7"
        block_size = 32
        padded = PKCS7(block_size).pad(msg)
        self.assertEqual(b'PKCS7\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b', padded)

    def test_unpad(self):
        unpadded = PKCS7(32).unpad(b'PKCS7\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b')
        self.assertEqual(unpadded, b"PKCS7")