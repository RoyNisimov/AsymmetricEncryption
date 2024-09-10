from __future__ import annotations
from AsymmetricEncryptions.Protocols.OAEP import OAEP
from unittest import TestCase

class TestOAEP(TestCase):

    def test_OAEP(self):
        msg = b"OAEP"
        padded = OAEP.oaep_pad(msg)
        unpadded = OAEP.oaep_unpad(padded)
        self.assertEqual(msg, unpadded)
        self.assertNotEqual(msg, padded)

    def test_ErrOAEP(self):
        msg = b"OAEP" * 8 + b"a"
        self.assertRaises(ValueError, OAEP.oaep_pad, msg)











