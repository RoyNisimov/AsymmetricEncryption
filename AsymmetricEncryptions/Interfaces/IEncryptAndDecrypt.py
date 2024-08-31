from __future__ import annotations

class IEncryptAndDecrypt:

    @staticmethod
    def generate_key_pair(nBit: int):
        raise NotImplementedError("Function should be implemented inside of class")

    def encrypt(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")

    def decrypt(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")




