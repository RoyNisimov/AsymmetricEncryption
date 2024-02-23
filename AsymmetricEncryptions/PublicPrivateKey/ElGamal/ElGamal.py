from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.ElGamal.ElGamalKey import ElGamalKey
from AsymmetricEncryptions.General import BytesAndInts
import secrets
from math import gcd
class ElGamal:

    def __init__(self, key: ElGamalKey) -> None:
        self.key = key

    @staticmethod
    def generate_key_pair(nBit) -> ElGamalKey and ElGamalKey:
        # ElGamalKey.new returns a pair of priv and pub
        Priv: ElGamalKey = ElGamalKey.new(nBit)
        Pub: ElGamalKey = Priv.public
        return Priv, Pub

    def encrypt(self, msg: bytes, assertion=True) -> tuple[bytes, bytes]:
        m: bytes = BytesAndInts.byte2Int(msg)
        if assertion: assert m < self.key.p
        b: int = secrets.randbelow(self.key.p)
        c1: int = pow(self.key.g, b, self.key.p)
        c2: int = (m * pow(self.key.y, b, self.key.p)) % self.key.p
        return BytesAndInts.int2Byte(c1), BytesAndInts.int2Byte(c2)

    def decrypt(self, cipher: tuple[bytes, bytes]):
        assert self.key.x
        c1: int = BytesAndInts.byte2Int(cipher[0])
        c2: int = BytesAndInts.byte2Int(cipher[1])
        a: int = pow(c1, self.key.x, self.key.p)
        m = (c2 * pow(a, self.key.p - 2, self.key.p)) % self.key.p
        return BytesAndInts.int2Byte(m)


    def sign(self, msg: bytes, assertion=True) -> tuple[bytes, bytes, bytes]:
        m: bytes = BytesAndInts.byte2Int(msg)
        if assertion: assert m < self.key.p
        k: int = secrets.randbelow(self.key.p)
        while gcd(k, self.key.p - 1) != 1: k = secrets.SystemRandom().randint(2, self.key.p - 2)
        s1: int = pow(self.key.g, k, self.key.p)
        phi_n: int = self.key.p - 1
        inv: int = pow(k, -1, phi_n)
        s2: int = (inv * (m - s1 * self.key.x)) % phi_n
        if s2 == 0: self.sign(msg, assertion)
        return BytesAndInts.int2Byte(s1), BytesAndInts.int2Byte(s2),  BytesAndInts.int2Byte(m)

    def verify(self, signature: tuple[bytes, bytes, bytes]):
        s1: int = BytesAndInts.byte2Int(signature[0])
        s2: int = BytesAndInts.byte2Int(signature[1])
        m: int = BytesAndInts.byte2Int(signature[2])
        V = pow(self.key.y, s1, self.key.p) * pow(s1, s2, self.key.p)
        V = V % self.key.p
        W = pow(self.key.g, m, self.key.p)
        print(W)
        print(V)
        return V == W
