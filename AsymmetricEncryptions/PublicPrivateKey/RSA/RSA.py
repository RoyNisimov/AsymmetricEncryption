from __future__ import annotations
from AsymmetricEncryption.PublicPrivateKey.RSA.RSAKey import RSAKey
from AsymmetricEncryption.General import BytesAndInts

class RSA:
    def __init__(self, key: RSAKey) -> None:
        self.key = key

    @staticmethod
    def generate_key_pair(nBit) -> RSAKey and RSAKey:
        # RSAKey.new returns a pair of priv and pub
        Priv: RSAKey = RSAKey.new(nBit)
        Pub: RSAKey = Priv.public
        return Priv, Pub


    def encrypt(self, msg: bytes, assertion=True) -> bytes:
        int_msg: int = BytesAndInts.byte2Int(msg)
        if assertion: assert int_msg < self.key.n
        cipher: int = pow(int_msg, self.key.e, self.key.n)
        return BytesAndInts.int2Byte(cipher)

    def decrypt(self, cipher: bytes) -> bytes:
        assert self.key.has_private
        int_cipher: int = BytesAndInts.byte2Int(cipher)
        m: int = pow(int_cipher, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(m)

    def sign(self, msg: bytes, assertion=True) -> bytes:
        assert self.key.has_private
        int_msg: int = BytesAndInts.byte2Int(msg)
        if assertion: assert int_msg < self.key.n
        s: int = pow(int_msg, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(s)

    def verify(self, s, og_msg: bytes) -> None:
        int_s: int = BytesAndInts.byte2Int(s)
        cipher: int = pow(int_s, self.key.e, self.key.n)
        assert cipher == BytesAndInts.byte2Int(og_msg
                                               )