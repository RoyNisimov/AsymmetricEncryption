from __future__ import annotations

class ISignAndVerify:

    @staticmethod
    def generate_key_pair(nBit: int):
        raise NotImplementedError("Function should be implemented inside of class")

    def sign(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")

    def verify(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")




