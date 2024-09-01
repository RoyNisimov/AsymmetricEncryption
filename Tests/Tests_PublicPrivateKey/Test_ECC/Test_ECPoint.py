from __future__ import annotations
from unittest import TestCase
from AsymmetricEncryptions import ECPoint, EllipticCurveNISTP256

class TestECPoint(TestCase):

    def test_copy(self):
        curve = EllipticCurveNISTP256.get_curve()
        p1: ECPoint = curve.g() * 2
        p1_copy = p1.copy()
        self.assertEqual(p1_copy, p1)

    def test_add(self):
        curve = EllipticCurveNISTP256.get_curve()
        p1: ECPoint = curve.g() * 2
        p2: ECPoint = curve.g() + curve.g()
        self.assertEqual(p1, p2)


