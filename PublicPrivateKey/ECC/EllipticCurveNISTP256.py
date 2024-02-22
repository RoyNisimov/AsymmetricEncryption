from __future__ import annotations
from AsymmetricEncryption.PublicPrivateKey.ECC import ECPoint


class EllipticCurveNISTP256:
    p: int = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    n: int = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    a: int = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b: int = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    g_x: int = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    g_y: int = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

    def g(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=EllipticCurveNISTP256.g_x, y=EllipticCurveNISTP256.g_x)

    def infinity(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=None, y=None)

    def __init__(self):
        self.p = EllipticCurveNISTP256.p
        self.n = EllipticCurveNISTP256.n
        self.a = EllipticCurveNISTP256.a
        self.b = EllipticCurveNISTP256.b
        self.G = self.g()

    def __eq__(self, other) -> bool:
        return isinstance(other, EllipticCurveNISTP256)
