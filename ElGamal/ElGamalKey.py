from __future__ import annotations
from math import gcd
import json
import secrets
from AsymmetricEncryption.General import PrimeNumberGen, XOR
from AsymmetricEncryption.Exceptions import NeededValueIsNull
import hmac
import hashlib

class ElGamalKey:

    def __init__(self, p: int, g: int, y: int, x: int or None = None) -> None:
        self.p: int = p
        self.g: int = g
        self.y: int = y
        self.x: int = x
        self.has_private: bool = False
        if x:
            self.has_private = True
            self.public: ElGamalKey = ElGamalKey(p=p, g=g, y=y, x=None)

    @staticmethod
    def new(nBit) -> ElGamalKey:
        p: int = PrimeNumberGen.generate(nBit)
        g: int = secrets.randbelow(p)
        x: int = secrets.randbelow(p)
        y: int = pow(g, x, p)
        return ElGamalKey(p=p, g=g, y=y, x=x)


    def export(self, file_name: str, pwd: bytes = b"\x00") -> None:
        data_dict: dict = {"p": self.p, "g": self.g, "y": self.y, "x": self.x}
        jData: bytes = json.dumps(data_dict).encode("utf-8")
        write_data: bytes = XOR.repeated_key_xor(jData, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        with open(file_name, "wb") as f:
            f.write(mac.digest() + write_data)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00") -> ElGamalKey:
        with open(file_name, "rb") as f:
            dMac: bytes = f.read(64)
            read_data: bytes = f.read()
        jData: bytes = XOR.repeated_key_xor(read_data, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        assert mac.digest() == dMac
        return ElGamalKey(**json.loads(jData.decode()))

