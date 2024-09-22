from __future__ import annotations
from . import ECPoint, ECKey, EllipticCurveNISTP256
from AsymmetricEncryptions.General import BytesAndInts
import secrets
from hashlib import sha256

class ECSchnorr:
    """Schnorr's signature scheme implemented with ECC."""
    def __init__(self, key: ECKey):
        self.key: ECKey = key
        self.nonces = set()

    def sign(self, msg: bytes) -> tuple[int, ECPoint]:
        """
        Signs a message
        :param msg: the message
        :return: signature
        """
        G: ECPoint = self.key.public_key.curve.G
        r: int = secrets.randbelow(self.key.public_key.curve.p)
        h_r = sha256(BytesAndInts.int2Byte(r)).digest()
        while h_r in self.nonces:
            r: int = secrets.randbelow(self.key.public_key.curve.p)
            h_r = sha256(BytesAndInts.int2Byte(r)).digest()
        self.nonces.add(h_r)
        R: ECPoint = G * r
        c: int = BytesAndInts.byte2Int(sha256(bytes(R) + msg).digest())
        s: int = (c * self.key.private_key) + r
        return s, R

    @staticmethod
    def verify(signature: tuple[int, ECPoint], msg: bytes, pubkey: ECPoint) -> bool:
        """
        Verifies a signature.
        :param signature: The signature.
        :param msg: The message.
        :param pubkey: the public key.
        :return: True if it passes, else: False.
        """
        G: ECPoint = pubkey.curve.G
        s, R = signature
        c: int = BytesAndInts.byte2Int(sha256(bytes(R) + msg).digest())
        return G * s == (pubkey * c) + R

if __name__ == '__main__':
    key = ECKey.new(EllipticCurveNISTP256.get_curve())
    signer = ECSchnorr(key)
    msg = b"test"
    signature = signer.sign(msg)
    verify = ECSchnorr.verify(signature, msg, key.public_key)
    print(verify)
