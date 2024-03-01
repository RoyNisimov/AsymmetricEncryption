from __future__ import annotations
from . import ECCurve
import hashlib
import json

class ECPoint:
    """A point on the ECC NIST-P-256 curve"""
    # https://github.com/cgossi/fundamental_cryptography_with_python/blob/main/implementing_p_256_ecdhe.py
    def __init__(self, curve: ECCurve.ECCurve, x: int, y: int) -> None:
        self.curve: ECCurve.ECCurve = curve
        self.x: int = x
        self.y: int = y

    def copy(self) -> ECPoint:
        return ECPoint(self.curve, self.x, self.y)

    def is_inf(self) -> bool:
        return self == self.curve.infinity()

    def __str__(self):
        return f"({self.x}, {self.y})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECPoint): return False
        return self.x == other.x and self.y == other.y

    # Point multiplication
    def __mul__(self, s):
        bits = [s & (1 << i) for i in range(s.bit_length() - 1, -1, -1)]
        res = self.curve.infinity()
        for bit in bits:
            res = res + res
            if bit:
                res = res + self
        return res

    def __bytes__(self) -> bytes:
        return hashlib.sha256(str(self).encode()).digest()

    def __imul__(self, other):
        return self.__mul__(other)

    # Point addition
    def __add__(self, other):
        if self.is_inf():
            return other.copy()
        if other.is_inf():
            return self.copy()
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = self.curve.p
        if x1 % p == x2 % p and y1 % p == (-y2) % p:
            return self.curve.infinity()
        if self != other:
            s = (y2 - y1) * pow(x2 - x1, -1, p) % p
        else:
            # Point doubling
            s = (3 * pow(x1, 2) + self.curve.a) * pow(2 * y1, -1, p) % p
        x3 = (pow(s, 2) - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return ECPoint(curve=self.curve, x=x3, y=y3)

    def export(self) -> str:
        d: dict = {"curve": self.curve.export(), "x": self.x, "y": self.y}
        return json.dumps(d)

    @staticmethod
    def load(s: str) -> ECPoint:
        d: dict = json.loads(s)
        d['curve'] = ECCurve.load(d['curve'])
        return ECPoint(**d)
