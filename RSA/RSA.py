from __future__ import annotations
from .RSA_KEY import RSA_KEY
from AsymmetricEncryption.General import BytesAndInts

class RSA:
    def __init__(self, key: RSA_KEY) -> None:
        self.key = key

    @staticmethod
    def generate_key_pair(nBit) -> (RSA_KEY, RSA_KEY):
        # RSA_KEY.new returns a pair of priv and pub
        Priv: RSA_KEY = RSA_KEY.new(nBit)
        Pub: RSA_KEY = Priv.public
        return Priv, Pub


    def encrypt(self, msg: bytes) -> bytes:
        int_msg: int = BytesAndInts.byte2Int(msg)
        cipher: int = pow(int_msg, self.key.e, self.key.n)
        return BytesAndInts.int2Byte(cipher)

    def decrypt(self, cipher: bytes) -> bytes:
        assert self.key.has_private
        int_cipher: int = BytesAndInts.byte2Int(cipher)
        m: int = pow(int_cipher, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(m)

    def sign(self, msg: bytes) -> bytes:
        assert self.key.has_private
        int_msg: int = BytesAndInts.byte2Int(msg)
        s: int = pow(int_msg, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(s)

    def verify(self, s, og_msg: bytes) -> None:
        int_s: int = BytesAndInts.byte2Int(s)
        cipher: int = pow(int_s, self.key.e, self.key.n)
        assert cipher == BytesAndInts.byte2Int(og_msg)