from __future__ import annotations
from . import ECPoint, ECKey
from .EllipticCurveNISTP256 import EllipticCurveNISTP256
from AsymmetricEncryptions.General import XOR
from AsymmetricEncryptions.Protocols import KDF
import secrets

class ECIES:
    """Elliptic Curve Integrated Encryption Scheme.
    This is how encryption really works in ECC.
    """

    def __init__(self):
        pass



    @staticmethod
    def encrypt(msg: bytes, pub_key: ECPoint, encryption_function=XOR.repeated_key_xor) -> tuple[bytes, ECPoint]:
        """
        Encrypts a message with a public ECC key (As an ECPoint)
        :param msg: The message.
        :param pub_key: The public key as an ECPoint (If in ECKey you can just do .public_key)
        :param encryption_function: The symmetric encryption function used (XOR is used here if no changes are made)
        :return: The ciphertext as a tuple
        """
        r: int = secrets.randbelow(EllipticCurveNISTP256().p)
        G: ECPoint = EllipticCurveNISTP256().g()
        R: ECPoint = G * r
        S: ECPoint = pub_key * r
        symmetric_key: bytes = bytes(S)
        symmetric_key: bytes = KDF.derive_key(symmetric_key)
        encrypted: bytes = encryption_function(msg, symmetric_key)
        return encrypted, R

    @staticmethod
    def decrypt(encrypted_msg, private_key: ECKey, decryption_function=XOR.repeated_key_xor) -> bytes:
        """
        Decrypts ciphertext.
        :param encrypted_msg: The ciphertext.
        :param private_key: The private key.
        :param decryption_function: The symmetric decryption function
        :return: message
        """
        encrypted, R = encrypted_msg
        S: ECPoint = R * private_key.private_key
        symmetric_key: bytes = bytes(S)
        symmetric_key: bytes = KDF.derive_key(symmetric_key)
        msg: bytes = decryption_function(encrypted, symmetric_key)
        return msg

if __name__ == '__main__':
    keyPair = ECKey.new()
    msg = b"test"
    c = ECIES.encrypt(msg, keyPair.public_key)
    print(c)
    d = ECIES.decrypt(c, keyPair)
    print(d)
    assert d == msg
