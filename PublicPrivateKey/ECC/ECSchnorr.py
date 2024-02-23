from __future__ import annotations
from AsymmetricEncryption.PublicPrivateKey.ECC import EllipticCurveNISTP256, ECPoint, ECKey
from AsymmetricEncryption.General import BytesAndInts
import secrets
from hashlib import sha256

class ECSchnorr:

    def __init__(self, key: ECKey):
        self.key: ECKey = key

    def sign(self, msg: bytes) -> tuple[int, ECPoint]:
        G: ECPoint = EllipticCurveNISTP256().g()
        r: int = secrets.randbelow(EllipticCurveNISTP256.p)
        R: ECPoint = G * r
        c: int = BytesAndInts.byte2Int(sha256(bytes(R) + msg).digest())
        s: int = (c * self.key.private_key) + r
        return s, R

    @staticmethod
    def verify(signature: tuple[int, ECPoint], msg: bytes, pubkey: ECPoint) -> bool:
        G: ECPoint = EllipticCurveNISTP256().g()
        s, R = signature
        c: int = BytesAndInts.byte2Int(sha256(bytes(R) + msg).digest())
        return G * s == (pubkey * c) + R

if __name__ == '__main__':
    key = ECKey()
    signer = ECSchnorr(key)
    msg = b"test"
    signature = signer.sign(msg)
    verify = ECSchnorr.verify(signature, msg, key.public_key)
    print(verify)
