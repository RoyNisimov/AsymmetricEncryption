from __future__ import annotations
from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECCurve, EllipticCurveNISTP256, ECPoint

class TestECCurve(TestCase):

    def test_g(self):
        self.assertEqual(EllipticCurveNISTP256.get_curve().g(), ECPoint(EllipticCurveNISTP256.get_curve(), EllipticCurveNISTP256.g_x, EllipticCurveNISTP256.g_y))

    def test_f(self):
        curve = EllipticCurveNISTP256.get_curve()
        self.assertEqual(curve.f(3), 41058363725152142129326129780047268409114441015993725554835256314039467401309)

    def test_f_value(self):
        curve = EllipticCurveNISTP256.get_curve()
        self.assertRaises(ValueError, curve.f, -1)

