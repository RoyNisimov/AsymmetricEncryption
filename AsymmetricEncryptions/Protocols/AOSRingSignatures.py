# An implementation of AOS ring signatures
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, ECPoint, ECCurve
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts
from hashlib import sha256
from secrets import randbelow, SystemRandom
from warnings import warn

class AOS:

    def __init__(self, keys: list[ECKey], signer: ECKey):
        self.keys = keys
        self.signer_key = signer

    def sign(self, m: bytes):
        curve = self.signer_key.curve
        keys = self.keys.copy()
        SystemRandom().shuffle(keys)
        j = randbelow(len(keys) + 1)
        keys.insert(j, self.signer_key)
        n = len(keys)
        s = [None] * n

        def H(M:bytes):
            return BytesAndInts.byte2Int(sha256(M + m).digest())

        alpha = randbelow(curve.n-1)
        g = curve.g()
        Q = g * alpha
        e = H(str(Q).encode())
        e0 = b""
        for i in range(j+1, n+j):
            indexI = i % n
            s[indexI] = randbelow(curve.n-1)
            e = H(str((g*s[indexI]) + (keys[indexI].public_key * e)).encode())
            if (indexI+1) % n == 0:
                e0 = e
        s[j] = (alpha - (e*keys[j].private_key)) % curve.n
        sigma = (e0, s)
        rk = keys.copy()
        rk[j] = rk[j].get_public_key()
        return sigma, rk.copy()

    @staticmethod
    def verify(rk: list[ECKey], m: bytes, sigma: tuple[int, list[int]]):
        s = sigma[1]
        e = e_0 = sigma[0]
        n = len(rk)
        if n != len(s):
            warn("Might be missing a key")
            return False
        curve = rk[0].curve

        def H(M: bytes) -> int:
            return BytesAndInts.byte2Int(sha256(M + m).digest())

        for indexI in range(n):
            e = H(str((curve.g()*s[indexI]) + (rk[indexI].public_key * e)).encode())

        return e == e_0
