from __future__ import annotations
from AsymmetricEncryptions.Protocols import KDF
from AsymmetricEncryptions.General import BytesAndInts
from secrets import randbits
from hashlib import sha256

class PRF:

    def __init__(self, seed: bytes = None):
        if seed is None: seed = BytesAndInts.int2Byte(randbits(2048))[:256]
        self.seed: bytes = seed
        self.starting_seed: bytes = seed

    def digest(self, n: int = 16) -> int:
        c = sha256(self.seed).digest()
        self.seed = c[:256]
        while len(c) < n:
            c += sha256(self.seed).digest()
            self.seed = c[:256]
        return BytesAndInts.byte2Int(c[:n])

if __name__ == "__main__":
    p = PRF()
    c = p.digest(16)
    print(c)
    c = p.digest(32)
    print(c)
    p = PRF(p.starting_seed)
    c = p.digest(16)
    print(c)
    c = p.digest(33)
    print(c)