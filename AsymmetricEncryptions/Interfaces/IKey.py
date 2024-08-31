from __future__ import annotations
from AsymmetricEncryptions.General.XOR import XOR

class IKey:

    @staticmethod
    def new(nBit: int):
        raise NotImplementedError("Function should be implemented inside of class")

    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        raise NotImplementedError("Function should be implemented inside of class")

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> IKey:
        raise NotImplementedError("Function should be implemented inside of class")


