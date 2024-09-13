from __future__ import annotations
from unittest import TestCase
from AsymmetricEncryptions import EllipticCurveNISTP256, ECDH, ECKey

class TestECDH(TestCase):

    def test_ecdh(self):
        curve = EllipticCurveNISTP256.get_curve()
        keyA = ECKey.new(curve=curve)
        ecdh = ECDH(keyA)
        A = keyA.public_key
        keyB = ECKey.new(curve=curve)
        B = keyB.public_key
        shared_key_alice = ecdh.Stage1(B)
        shared_key_bob = ECDH.Stage2(keyB, A)
        self.assertEqual(shared_key_alice, shared_key_bob)

