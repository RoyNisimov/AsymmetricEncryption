from __future__ import annotations
from AsymmetricEncryptions.General.XOR import XOR
from abc import ABC, abstractmethod

class IKey(ABC):

    @staticmethod
    @abstractmethod
    def new(nBit: int):
        raise NotImplementedError("Function should be implemented inside of class")

    @abstractmethod
    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        raise NotImplementedError("Function should be implemented inside of class")

    @staticmethod
    @abstractmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> IKey:
        raise NotImplementedError("Function should be implemented inside of class")


