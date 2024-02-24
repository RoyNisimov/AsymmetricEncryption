from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA, RSAKey
from AsymmetricEncryptions.General import BytesAndInts
import secrets
# 1 out of 2 Oblivious Transfer https://en.wikipedia.org/wiki/Oblivious_transfer


class ObliviousTransfer:
    """
    Oblivious Transfer.
    The methods with static method on them are ment to be used by the other person.
    (In the example below Alice wants to send Bob only one of the messages)
    Example:
    ```
    # Alice
    otProt = ObliviousTransfer(b"test A", b"test B")
    sendBob = otProt.Stage1and2and3()
    # Bob
    b = int(input("Choice 0 or 1: ")) % 2
    AlicePubKey = sendBob[0]
    sendAlice, keepPrivate = ObliviousTransfer.Stage4and5(sendBob, b)
    # Alice
    sendBob = otProt.Stage6and7(sendAlice)
    # Bob
    m = ObliviousTransfer.Stage8(sendBob, keepPrivate, b, AlicePubKey)
    print(m)
    ```
    """
    def __init__(self, m0: bytes, m1: bytes) -> None:
        # stage one
        self.m0: int = BytesAndInts.byte2Int(m0)
        self.m1: int = BytesAndInts.byte2Int(m1)
        self.priv = RSA.generate_key_pair(1024)
        self.pub: RSAKey = self.priv[1]
        self.priv: RSAKey = self.priv[0]
        self.x0: int = None
        self.x1: int = None

    def Stage1and2and3(self) -> tuple[RSAKey, int, int]:
        pub: RSAKey = self.priv.public
        x0: int = secrets.randbelow(pub.n)
        x1: int = secrets.randbelow(pub.n)
        self.x0 = x0
        self.x1 = x1
        return pub, x0, x1
        # send pub, x0, x1 to the other person

    @staticmethod
    def Stage4and5(pubX0X1: tuple[RSAKey, int, int], b: int) -> int and int:
        pub: RSAKey = pubX0X1[0]
        x0: int = pubX0X1[1]
        x1: int = pubX0X1[2]
        assert b in [0, 1]
        xs: tuple[int, int] = (x0, x1)
        k: int = secrets.randbelow(pub.n)
        v: int = (xs[b] + pow(k, pub.e, pub.n)) % pub.n
        return v, k
        # send only v! keep k private

    def Stage6and7(self, v: int) -> tuple[int, int]:
        assert self.x0 and self.x1
        k0: int = pow((v - self.x0), self.priv.d, self.priv.n)
        k1: int = pow((v - self.x1), self.priv.d, self.priv.n)
        mp0: int = (self.m0 + k0) % self.priv.n
        mp1: int = (self.m1 + k1) % self.priv.n
        return mp0, mp1
        # send both

    @staticmethod
    def Stage8(mps: tuple[int, int], k: int, b: int, pub: RSAKey) -> bytes:
        mb: int = (mps[b] - k) % pub.n
        return BytesAndInts.int2Byte(mb)


if __name__ == '__main__':
    # Alice
    otProt = ObliviousTransfer(b"test A", b"test B")
    sendBob = otProt.Stage1and2and3()
    # Bob
    b = int(input("Choice 0 or 1: ")) % 2
    AlicePubKey = sendBob[0]
    sendAlice, keepPrivate = ObliviousTransfer.Stage4and5(sendBob, b)
    # Alice
    sendBob = otProt.Stage6and7(sendAlice)
    # Bob
    m = ObliviousTransfer.Stage8(sendBob, keepPrivate, b, AlicePubKey)
    print(m)
