from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.DSA import DSAKey
from AsymmetricEncryptions.General import BytesAndInts
from AsymmetricEncryptions.Interfaces import ISignAndVerify
from AsymmetricEncryptions.Exceptions import MACError
import secrets
import hashlib
class DSA(ISignAndVerify):
    """Digital Signature Algorithm"""
    def __init__(self, key: DSAKey) -> None:
        self.key = key

    def sign(self, message: bytes) -> tuple[int, int]:
        """
        Signs a message.
        :param message: Message to sign
        :return: Signature.
        """
        assert self.key.has_private
        m: int = BytesAndInts.byte2Int(message)
        k: int = secrets.randbelow(self.key.q - 1)
        r: int = pow(self.key.g, k, self.key.p) % self.key.q
        if r == 0: self.sign(message)
        s: int = (pow(k, -1, self.key.q) * ((self.H(m) + self.key.x * r) % self.key.q)) % self.key.q
        if s == 0: self.sign(message)
        return r, s

    def verify(self, sig: tuple[int, int], message: bytes) -> None:
        """
        Verifies a signed message.
        :param sig: The signature.
        :param message: The original message
        :return: None, will throw an assertion error if it failed to verify.
        """
        r: int = sig[0]
        s: int = sig[1]
        assert 0 < r < self.key.q and 0 < s < self.key.q
        m: int = BytesAndInts.byte2Int(message)
        w: int = pow(s, -1, self.key.q)
        u1: int = (self.H(m) * w) % self.key.q
        u2: int = (r * w) % self.key.q
        v = ((pow(self.key.g, u1, self.key.p) * pow(self.key.y, u2, self.key.p)) % self.key.p) % self.key.q
        if not v == r: raise MACError("Signatures don't match!")

    @staticmethod
    def H(m: int) -> int:
        # H = sha256
        b: bytes = BytesAndInts.int2Byte(m)
        return BytesAndInts.byte2Int(hashlib.sha256(b, usedforsecurity=True).digest())


    @staticmethod
    def generate_key_pair(nBit: int = 1024, use_precalculated: bool = True) -> DSAKey and DSAKey:
        # DSAKey.new returns a pair of priv and pub
        Priv: DSAKey = DSAKey.new(nBit=nBit, use_precalculated=use_precalculated)
        Pub: DSAKey = Priv.public
        return Priv, Pub
