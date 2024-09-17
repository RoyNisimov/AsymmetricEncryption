from __future__ import annotations
from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECIES, ECKey, ECPoint, EllipticCurveNISTP256
from secrets import token_bytes

class TestECIES(TestCase):


    def test_encrypt(self):
        curve = EllipticCurveNISTP256.get_curve()
        priv = ECKey.new(curve)
        pub = priv.public_key
        m = token_bytes(16)
        e = ECIES.encrypt(m, pub)
        d = ECIES.decrypt(e, priv)
        self.assertEqual(m, d)
    
    def test_export(self):
        curve = EllipticCurveNISTP256.get_curve()
        priv = ECKey.new(curve)
        priv.export("TestFiles\\ECKeyTestFileUnprotected.key", b"")
        loaded_priv = ECKey.load("TestFiles\\ECKeyTestFileUnprotected.key", b"")
        self.assertEqual(priv, loaded_priv)
        priv: ECKey = ECKey.new(curve)
        priv.export("TestFiles\\ECKeyTestFileProtected.key", b"Pass")
        loaded_priv = ECKey.load("TestFiles\\ECKeyTestFileProtected.key", b"Pass")
        self.assertEqual(priv, loaded_priv)
