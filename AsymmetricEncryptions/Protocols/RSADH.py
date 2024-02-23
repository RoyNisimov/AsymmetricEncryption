from __future__ import annotations
from AsymmetricEncryptions.General import PrimeNumberGen, BytesAndInts
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSAKey, RSA
import secrets
class DiffieHellman:

    def __init__(self, priv_key: RSAKey, p: int, g: int) -> None:
        self.key: RSAKey = priv_key
        self.p: int = p
        self.g: int = g

    def get_gp(self) -> tuple[int, int]: return self.g, self.p

    @staticmethod
    def new(priv_key: RSAKey, nBitP: int) -> DiffieHellman:
        p: int = PrimeNumberGen.generate(nBitP)
        g: int = secrets.randbelow(p)
        return DiffieHellman(priv_key, p, g)

    def Stage1(self) -> int:
        return pow(self.g, self.key.d, self.p)

    @staticmethod
    def Stage2(gp: tuple[int, int], Key: RSAKey, A: int) -> int and bytes:
        shared_key: int = pow(A, Key.d, gp[1])
        B: int = pow(gp[0], Key.d, gp[1])
        return B, BytesAndInts.int2Byte(shared_key)

    def Stage3(self, B) -> bytes:
        shared_key: int = pow(B, self.key.d, self.p)
        return BytesAndInts.int2Byte(shared_key)
        # shared key is g**(a*b) % p

if __name__ == '__main__':
    Apriv, Apub = RSA.generate_key_pair(2048)
    Bpriv, Bpub = RSA.generate_key_pair(2048)
    DH = DiffieHellman.new(Apriv, 2048)
    # Alice
    A = DH.Stage1()
    gp = DH.get_gp()
    # send A and gp to Bob

    # Bob
    B, Bob_shared = DiffieHellman.Stage2(gp, Bpriv, A)
    print(Bob_shared)
    # send B to Alice

    # Alice
    Alice_shared = DH.Stage3(B)
    print(Alice_shared)
    print(Alice_shared == Bob_shared)



