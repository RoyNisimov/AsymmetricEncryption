from __future__ import annotations
import secrets
from AsymmetricEncryption.PublicPrivateKey.ECC import ECPoint


class EllipticCurveNISTP256:
    p: int = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    n: int = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    a: int = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    b: int = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    g_x: int = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    g_y: int = 36134250956749795798585127919587881956611106672985015071877198253568414405109

    def g(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=EllipticCurveNISTP256.g_x, y=EllipticCurveNISTP256.g_x)

    def infinity(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=None, y=None)

    def __init__(self):
        self.p = EllipticCurveNISTP256.p
        self.n = EllipticCurveNISTP256.n
        self.a = EllipticCurveNISTP256.a

    def __eq__(self, other) -> bool:
        return isinstance(other, EllipticCurveNISTP256)