from __future__ import annotations
from math import gcd

from AsymmetricEncryption.General import PrimeNumberGen
from AsymmetricEncryption.Exceptions import NeededValueIsNull
class RSA_KEY:
    def __init__(self, p: int or None=None, q: int or None=None, n: int=None, e: int=None, d: int or None=None, tot_n:int or None=None) -> None:
        if not e or not n:
            raise NeededValueIsNull("e or n needed to create key")
        self.p = p
        self.q = q
        self.n = n
        self.tot_n = tot_n
        self.e = e
        self.d = d
        self.has_private = False
        if d:
            self.has_private = True
            self.public = RSA_KEY(None, None, n, e, None, None)

    @staticmethod
    def new(bit_number: int) -> RSA_KEY:
        p: int = PrimeNumberGen.generate(bit_number)
        q: int = PrimeNumberGen.generate(bit_number)
        n: int = p * q
        tot_n: int = (p - 1) * (q - 1)
        e: int = PrimeNumberGen.generate(bit_number)
        while gcd(e, tot_n) != 1:
            e: int = PrimeNumberGen.generate(bit_number)
        d: int = pow(e, -1, tot_n)
        return RSA_KEY(p, q, n, e, d, tot_n)

    def __str__(self) -> str:
        r: str = ""
        if self.has_private:
            r += f"""
Private Key:

p = {self.p}
q = {self.q}
n = {self.n}
tot_n = {self.tot_n}
e = {self.e}
d = {self.d}

"""
        r += f"""
Public Key:

n = {self.n}
e = {self.e}
"""
        return r