from __future__ import annotations
from math import gcd
import json
from AsymmetricEncryption.General import PrimeNumberGen, XOR
from AsymmetricEncryption.Exceptions import NeededValueIsNull
import hmac
import hashlib

class RSAKey:
    def __init__(self, p: int or None = None, q: int or None = None, n: int = None, e: int = None, d: int or None = None, tot_n: int or None = None) -> None:
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
            self.public = RSAKey(None, None, n, e, None, None)

    @staticmethod
    def new(bit_number: int) -> RSAKey:
        p: int = PrimeNumberGen.generate(bit_number)
        q: int = PrimeNumberGen.generate(bit_number)
        n: int = p * q
        tot_n: int = (p - 1) * (q - 1)
        e: int = PrimeNumberGen.generate(bit_number)
        while gcd(e, tot_n) != 1:
            e: int = PrimeNumberGen.generate(bit_number)
        d: int = pow(e, -1, tot_n)
        return RSAKey(p, q, n, e, d, tot_n)


    def export(self, file_name: str, pwd: bytes = b"\x00") -> None:
        data_dict: dict = {"p": self.p, "q": self.q, "n": self.n, "tot_n": self.tot_n, "e": self.e, "d": self.d}
        jData: bytes = json.dumps(data_dict).encode("utf-8")
        write_data: bytes = XOR.repeated_key_xor(jData, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        with open(file_name, "wb") as f:
            f.write(mac.digest() + write_data)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00") -> RSAKey:
        with open(file_name, "rb") as f:
            dMac: bytes = f.read(64)
            read_data: bytes = f.read()
        jData: bytes = XOR.repeated_key_xor(read_data, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        assert mac.digest() == dMac
        return RSAKey(**json.loads(jData.decode()))

    def __eq__(self, other: RSAKey) -> bool:
        if not isinstance(other, RSAKey): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()


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
