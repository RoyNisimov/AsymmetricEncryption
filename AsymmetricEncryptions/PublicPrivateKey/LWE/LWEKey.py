from __future__ import annotations
import secrets
from AsymmetricEncryptions.General import PrimeNumberGen, Exportation, XOR
import hashlib

class LWEKey:
    """
    Learning With Errors key object
    """

    def __init__(self, A: list[int], B: list[int], q: int, e: list[int] = None, s: int = None) -> None:
        self.A: list[int] = A
        self.B: list[int] = B
        self.q: int = q
        self.e: list[int] = e
        self.s: int = s
        self.is_private: bool = False
        self.public = None
        if s:
            self.is_private = True
            self.public = LWEKey(A, B, q)

    @staticmethod
    def new(nBit: int = 128) -> LWEKey:
        """
        Generates a new Learning With Errors key
        """
        s: int = secrets.randbits(nBit)
        q: int = PrimeNumberGen.generate(nBit)
        s = s % q
        n: int = 20
        A: list[int] = [secrets.randbelow(q) for _ in range(n)]
        error_margin: int = 4
        e: list[int] = [secrets.randbelow(error_margin) for _ in range(n)]
        B: list[int] = [((A[i] * s) + e[i]) % q for i in range(n)]
        return LWEKey(A, B, q, e, s)

    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        data_dict: dict = {"A": self.A, "B": self.B, "q": self.q, "e": self.e, "s": self.s}
        Exportation.export(file_name=file_name, pwd=pwd, data_dict=data_dict, exportation_func=enc_func)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> LWEKey:
        return LWEKey(**Exportation.load(file_name=file_name, pwd=pwd, dec_func=dec_func))

    def __eq__(self, other: LWEKey) -> bool:
        if not isinstance(other, LWEKey): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()

    def __str__(self) -> str:
        r: str = ""
        if self.is_private:
            r += f"""
Private Key:

A = {self.A}
B = {self.B}
q = {self.q}
e = {self.e}
s = {self.s}


"""
        r += f"""
Public Key:

A = {self.A}
B = {self.B}
q = {self.q}

"""
        return r