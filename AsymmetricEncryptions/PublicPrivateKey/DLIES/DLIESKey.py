from __future__ import annotations
from AsymmetricEncryptions.General import PrimeNumberGen, Exportation, XOR
import secrets
from hashlib import sha256

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

    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        data_dict: dict = {"g": self.g, "n": self.n, "x": self.x, "y": self.y}
        Exportation.export(file_name=file_name, pwd=pwd, data_dict=data_dict, exportation_func=enc_func)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> DLIESKey:
        return DLIESKey(**Exportation.load(file_name=file_name, pwd=pwd, dec_func=dec_func))

    def __eq__(self, other: DLIESKey) -> bool:
        if not isinstance(other, DLIESKey): return False
        return sha256(f"{self}".encode()).hexdigest() == sha256(f"{other}".encode()).hexdigest()


    @staticmethod
    def build(g: int, n: int, x: int = None) -> DLIESKey:
        if x is None:
            x = secrets.randbelow(n-1)
        y: int = pow(g, x, n)
        return DLIESKey(g, n, y, x)

    def __str__(self) -> str:
        r: str = ""
        if self.has_private:
            r += f"""
    Private Key:

    g = {self.g}
    n = {self.n}
    x = {self.x}
    y = {self.y}



    """
            r += f"""
    Public Key:

    g = {self.g}
    n = {self.n}
    y = {self.y}

    """
            return r