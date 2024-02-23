from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.ECC import EllipticCurveNISTP256, ECPoint, ECKey
from AsymmetricEncryptions.General import XOR
import secrets

class ECIES:

    def __init__(self):
        pass



    @staticmethod
    def encrypt(msg: bytes, pub_key: ECPoint, encryption_function=XOR.repeated_key_xor) -> tuple[bytes, ECPoint]:
        r: int = secrets.randbelow(EllipticCurveNISTP256.p)
        G: ECPoint = EllipticCurveNISTP256().g()
        R: ECPoint = G * r
        S: ECPoint = pub_key * r
        symmetric_key: bytes = bytes(S)
        encrypted: bytes = encryption_function(msg, symmetric_key)
        return encrypted, R

    @staticmethod
    def decrypt(encrypted_msg, private_key: ECKey, decryption_function=XOR.repeated_key_xor) -> bytes:
        encrypted, R = encrypted_msg
        S: ECPoint = R * private_key.private_key
        symmetric_key: bytes = bytes(S)
        msg: bytes = decryption_function(encrypted, symmetric_key)
        return msg

if __name__ == '__main__':
    keyPair = ECKey()
    msg = b"test"
    c = ECIES.encrypt(msg, keyPair.public_key)
    print(c)
    d = ECIES.decrypt(c, keyPair)
    print(d)
    assert d == msg
