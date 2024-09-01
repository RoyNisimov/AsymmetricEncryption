from __future__ import annotations
from abc import ABC, abstractmethod
from .IExport import IExport
class IEncryptAndDecrypt(ABC):

    @staticmethod
    @abstractmethod
    def generate_key_pair(nBit: int):
        raise NotImplementedError("Function should be implemented inside of class")

    @abstractmethod
    def encrypt(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")

    @abstractmethod
    def decrypt(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")




