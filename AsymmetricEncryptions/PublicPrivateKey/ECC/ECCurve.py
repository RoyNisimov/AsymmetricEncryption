from __future__ import annotations
from . import ECPoint
import json

class ECCurve:

    def g(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=self.G.x, y=self.G.y)

    def set_g(self, G: ECPoint.ECPoint) -> None:
        self.G = G

    def infinity(self) -> ECPoint.ECPoint:
        return ECPoint.ECPoint(curve=self, x=None, y=None)

    def __init__(self, a: int, b: int, n: int, p: int, g: ECPoint.ECPoint = None):
        self.p = p
        self.n = n
        self.a = a
        self.b = b
        self.G = g

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECCurve): return False
        return self.p == other.p and self.n == other.n and self.a == other.a and self.b == other.b and self.G == other.G

    def f(self, x: int):
        return (pow(x, 3, self.p) + self.a * x + self.b) % self.p

    def export(self) -> str:
        d: dict = {"a": self.a, "b": self.b, "n": self.n, "p": self.p, "g_x": self.G.x, "g_y": self.G.y}
        return json.dumps(d)

    @staticmethod
    def load(s: str):
        d: dict = json.loads(s)
        x, y = d["g_x"], d["g_y"]
        del d["g_x"]
        del d["g_y"]
        c: ECCurve = ECCurve(**d)
        c.set_g(ECPoint.ECPoint(c, x, y))
        return c
