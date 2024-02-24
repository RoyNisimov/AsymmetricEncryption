from __future__ import annotations
# Fiat–Shamir Zero Knowledge Proof
from AsymmetricEncryptions.General import PrimeNumberGen, BytesAndInts
import secrets
import hashlib

class FiatShamirZeroKnowledgeProof:
    """
    Example:
    ```
    from AsymmetricEncryptions.Protocols import FiatShamirZeroKnowledgeProof
    m = b'test'
    fs = FiatShamirZeroKnowledgeProof.new()
    y = fs.AliceStage1(m)
    # send y to bob
    v, t = fs.AliceStage2()
    # keep v send t
    c = fs.BobStage1()
    # Bob sends c as a challenge
    r = fs.AliceStage3(v, c, m)
    # Alice sends r to bob
    ver = fs.BobStage2(y, r, c, t)
    print(ver)
    ```
    """
    def __init__(self, g: int, n: int):
        self.g: int = g
        self.n: int = n

    @staticmethod
    def new() -> FiatShamirZeroKnowledgeProof:
        """
        :return: Generates a FiatShamirZeroKnowledgeProof object
        """
        n: int = PrimeNumberGen.generate(1024)
        g: int = secrets.randbelow(n)
        return FiatShamirZeroKnowledgeProof(g, n)

    def AliceStage1(self, msg: bytes) -> int:
        """
        :param msg: The message to be proven
        :return: y, the other person needs to keep it
        """
        x: int = BytesAndInts.byte2Int(hashlib.sha256(msg).digest()) % self.n
        y: int = pow(self.g, x, self.n)
        return y
        # Bob keeps y

    def AliceStage2(self) -> int and int:
        v: int = secrets.randbelow(self.n)
        t: int = pow(self.g, v, self.n)
        return v, t
        # Alice keeps v
        # Bob keeps t

    def BobStage1(self) -> int:
        c: int = secrets.randbelow(self.n)
        return c

    def AliceStage3(self, v: int, c: int, msg: bytes) -> int:
        x: int = BytesAndInts.byte2Int(hashlib.sha256(msg).digest()) % self.n
        r: int = (v - (c * x))
        return r

    def BobStage2(self, y: int, r: int, c: int,t: int) -> bool:
        x: int = pow(self.g, r, self.n) * pow(y, c, self.n)
        x %= self.n
        return x == t


