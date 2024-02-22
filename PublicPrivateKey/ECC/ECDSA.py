from __future__ import annotations
from AsymmetricEncryption.PublicPrivateKey.ECC import ECKey, EllipticCurveNISTP256, ECPoint
from AsymmetricEncryption.General import BytesAndInts, PrimeNumberGen
import hashlib
import secrets
class ECDSA:

    def __init__(self, privKey: ECKey) -> None:
        raise NotImplementedError("Code doesn't work for some odd reason")
        self.privKey: ECKey = privKey

    def sign(self, msg: bytes) -> tuple[int, int]:
        params = EllipticCurveNISTP256()
        e: int = BytesAndInts.byte2Int(hashlib.sha256(msg).digest())
        k: int = BytesAndInts.byte2Int(hashlib.sha256(msg + str(self.privKey).encode()).digest()) % params.n
        curve_point: ECPoint = params.g() * k
        r: int = curve_point.x % params.n
        inv_k: int = pow(k, -1, params.n)
        s: int = (inv_k * (e + (r * self.privKey.private_key))) % params.n
        if s == 0: self.sign(msg)
        return r, s

    @staticmethod
    def verify(pubKey: ECPoint, signature: tuple[int, int], msg: bytes) -> bool:
        params = EllipticCurveNISTP256()
        r, s = signature
        if pubKey.is_inf(): return False
        if not 1 < r < params.n or not 1 < s < params.n: return False
        e: int = BytesAndInts.byte2Int(hashlib.sha256(msg).digest())
        w = pow(s, -1, params.n)
        u1: int = (e * w) % params.n
        u2: int = (r * w) % params.n
        point: ECPoint = (params.g() * u1) + (pubKey * u2)
        if point.is_inf(): return False
        return r == point.x % params.n

if __name__ == '__main__':
    AliceKey = ECKey()
    A = AliceKey.public_key
    ecdsa = ECDSA(AliceKey)
    msg = b'test'
    signature = ecdsa.sign(msg)
    v = ECDSA.verify(A, signature, msg)
    print(v)

