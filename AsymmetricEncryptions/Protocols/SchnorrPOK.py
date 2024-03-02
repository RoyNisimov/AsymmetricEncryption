from __future__ import annotations
from hashlib import sha256
import secrets
from AsymmetricEncryptions.PublicPrivateKey.DLIES import DLIESKey
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts

# Schnorr Proof Of Knowledge (non-interactive)
class POK:

    def __init__(self, key: DLIESKey):
        self.key: DLIESKey = key

    def prove(self, msg: bytes) -> tuple[int, int, DLIESKey]:
        """
        Proves that you know a message without reveling what it is.
        @param msg: The message
        @return: Proof, tuple[int, int, DLIESKey]
        """
        new_key: DLIESKey = DLIESKey.build(self.key.g, self.key.n, BytesAndInts.byte2Int(msg))
        r: int = secrets.randbelow(new_key.n - 1)
        t: int = pow(new_key.g, r, new_key.n)
        c: int = POK.H([new_key.g, new_key.y, t])
        s: int = r + (new_key.x * c)
        return t, s, new_key.public

    @staticmethod
    def H(l: list[int]) -> int:
        nl: bytes = b"".join([BytesAndInts.int2Byte(i) for i in l])
        return BytesAndInts.byte2Int(sha256(nl).digest())

    @staticmethod
    def verify(proof: tuple[int, int, DLIESKey]) -> bool:
        """
        Verifies a proof
        @param proof: The proof
        @return: bool
        """
        t, s, key = proof
        c: int = POK.H([key.g, key.y, t])
        return pow(key.g, s, key.n) == (pow(key.y, c, key.n) * t) % key.n

