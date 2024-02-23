from __future__ import annotations
from AsymmetricEncryption.AsymmetricEncryptions.General import PrimeNumberGen
import secrets

class DLIESKey:

    def __init__(self, g: int, n: int, y: int, x: int = None):
        self.g: int = g
        self.n: int = n
        self.y: int = y
        self.x: int = x
        self.has_private: bool = False
        if x:
            self.has_private = True
            self.public: DLIESKey = DLIESKey(g, n, y)

    @staticmethod
    def new(nBit: int) -> DLIESKey:
        n: int = PrimeNumberGen.generate(nBit)
        g: int = secrets.randbelow(n)
        x: int = secrets.randbelow(n)
        y: int = pow(g, x, n)
        return DLIESKey(g, n, y, x)
