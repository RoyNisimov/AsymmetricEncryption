from __future__ import annotations
from .RSA_KEY import RSA_KEY

class RSA:
    def __init__(self, key: RSA_KEY) -> None:
        self.key = key

    @staticmethod
    def generate_key_pair(nBit) -> (RSA_KEY, RSA_KEY):
        # RSA_KEY.new returns a pair of priv and pub
        Priv: RSA_KEY = RSA_KEY.new(nBit)
        Pub: RSA_KEY = Priv.public
        return Priv, Pub
