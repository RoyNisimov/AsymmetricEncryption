from __future__ import annotations
from math import gcd
import json
import secrets
from AsymmetricEncryption.General import PrimeNumberGen, XOR
from AsymmetricEncryption.Exceptions import NeededValueIsNull
import hmac
import hashlib

class DSAKey:
    # H is Sha256 |H| is 256 bits or 32 bytes
    # L (Key length) is going to be 1024
    # N = 160
    # q (N bit prime)
    # p (L bit prime), p - 1 mod q == 0
    # h (2 <= h < p - 2), usually 2
    # g = pow(h, (p-1) / q, p), if g == 1 -> reselect h
    # shared parameters are (p, q, g)
    p = 89884656743115796742429711405763364460177151692783429800884652449310979263752253529349195459823881715145796498046459238345428121561386626945679753956400077352882071663925459750500807018254028771490434021315691357123734637046894876123496168716251735252662742462099334802433058472377674408598573487858308054417
    q = 1193447034984784682329306571139467195163334221569

    def __init__(self, g: int, p: int, q: int, y: int, x: int or None = None):
        if not y: raise NeededValueIsNull("Y can't be null")
        self.g = g
        self.y = y
        self.x = x
        self.has_private = False
        if x:
            self.has_private = True
            self.public = DSAKey(g=g, p=DSAKey.p, q=DSAKey.q,y=y, x=None)

    @staticmethod
    def new() -> DSAKey:
        # DSA Params
        h: int = secrets.randbelow(DSAKey.p - 2)
        g: int = pow(h, int((DSAKey.p-1) // DSAKey.q), DSAKey.p)
        while g == 1:
            h: int = secrets.randbelow(DSAKey.p - 2)
            g: int = pow(h, int((DSAKey.p - 1) // DSAKey.q), DSAKey.p)
        x: int = secrets.randbelow(DSAKey.q - 1)
        y: int = pow(g, x, DSAKey.p)
        return DSAKey(g=g, p=DSAKey.p, q=DSAKey.q,y=y, x=x)

    def __str__(self) -> str:
        r: str = ""
        if self.has_private:
            r += f"""
Private Key:

p = {self.p}
q = {self.q}
g = {self.g}
y = {self.y}
x = {self.x}

"""
        r += f"""
Public Key:
p = {self.p}
q = {self.q}
g = {self.g}
y = {self.y}

"""
        return r

    def export(self, file_name: str, pwd: bytes = b"\x00") -> None:
        data_dict: dict = {"p": self.p, "q": self.q, "g": self.g, "x": self.x, "y": self.y}
        jData: bytes = json.dumps(data_dict).encode("utf-8")
        write_data: bytes = XOR.repeated_key_xor(jData, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        with open(file_name, "wb") as f:
            f.write(mac.digest() + write_data)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00") -> DSAKey:
        with open(file_name, "rb") as f:
            dMac: bytes = f.read(64)
            read_data: bytes = f.read()
        jData: bytes = XOR.repeated_key_xor(read_data, pwd)
        mac: hmac = hmac.new(key=pwd, msg=jData, digestmod="sha512")
        assert mac.digest() == dMac
        return DSAKey(**json.loads(jData.decode()))

    def __eq__(self, other: DSAKey) -> bool:
        if not isinstance(other, DSAKey): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()
