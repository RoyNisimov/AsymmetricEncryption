from __future__ import annotations
from math import gcd
from AsymmetricEncryptions.General import PrimeNumberGen, XOR, Exportation
from AsymmetricEncryptions.Exceptions import NeededValueIsNull
from AsymmetricEncryptions.Interfaces import IKey, IExport
import hashlib



class RSAKey(IKey, IExport):
    def __init__(self, p: int or None = None, q: int or None = None, n: int = None, e: int = None, d: int or None = None, tot_n: int or None = None, size=2048) -> None:
        if not e or not n:
            raise NeededValueIsNull("e or n needed to create key")
        self.p = p
        self.q = q
        self.n = n
        self.tot_n = tot_n
        self.e = e
        self.d = d
        self.has_private = False
        self.size = size
        if d:
            self.has_private = True
            self.public = RSAKey(None, None, n, e, None, None)

    def get_pub(self) -> RSAKey:
        return RSAKey(None, None, self.n, self.e, None, None, size=self.size)

    @staticmethod
    def new(bit_number: int) -> RSAKey:
        if not isinstance(bit_number, int):
            raise TypeError("bit_number must be an integer")
        if bit_number < 0:
            raise ValueError("Bit number must be unsigned!")
        if not bit_number % 2 == 0:
            raise ValueError("Bit number must be a power of two!")
        from AsymmetricEncryptions.General.PowerOf2 import isPowerOfTwo
        if not isPowerOfTwo(bit_number):
            raise ValueError("Bit number must be a power of two!")
        p: int = PrimeNumberGen.generate(bit_number)
        q: int = PrimeNumberGen.generate(bit_number)
        n: int = p * q
        tot_n: int = (p - 1) * (q - 1)
        e: int = PrimeNumberGen.generate(bit_number)
        while gcd(e, tot_n) != 1:
            e: int = PrimeNumberGen.generate(bit_number)
        d: int = pow(e, -1, tot_n)
        return RSAKey(p, q, n, e, d, tot_n, size=bit_number)


    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        data_dict: dict = {"p": self.p, "q": self.q, "n": self.n, "tot_n": self.tot_n, "e": self.e, "d": self.d}
        Exportation.Exportation.export(file_name=file_name, pwd=pwd, data_dict=data_dict, exportation_func=enc_func)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> RSAKey:
        return RSAKey(**Exportation.Exportation.load(file_name=file_name, pwd=pwd, dec_func=dec_func))

    def __eq__(self, other: RSAKey) -> bool:
        if not isinstance(other, RSAKey): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()

    def get_hash_hex(self):
        return hashlib.sha256(str(self).encode()).hexdigest()

    def __str__(self) -> str:
        r: str = "-" * 100 + '\n'
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
        return r + "-" * 100 + '\n'
