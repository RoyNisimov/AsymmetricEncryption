from __future__ import annotations
from . import ECPoint, ECKey
from AsymmetricEncryptions.General import XOR
from AsymmetricEncryptions.Protocols import KDF, PKCS7
import secrets

class ECIES:
    """Elliptic Curve Integrated Encryption Scheme.
    This is how encryption really works in ECC.
    """

    def __init__(self):
        pass



    @staticmethod
    def encrypt(msg: bytes, pub_key: ECPoint, encryption_function=XOR.repeated_key_xor, block_size: int=32) -> tuple[bytes, ECPoint]:
        """
        Encrypts a message with a public ECC key (As an ECPoint)
        @param msg: The message.
        @param pub_key: The public key as an ECPoint (If in ECKey you can just do .public_key)
        @param encryption_function: The symmetric encryption function used (XOR is used here if no changes are made)
        @return: The ciphertext as a tuple
        @param block_size: The symmetric block_size
        """
        msg: bytes = PKCS7(block_size).pad(msg)
        r: int = secrets.randbelow(pub_key.curve.p)
        G: ECPoint = pub_key.curve.g()
        R: ECPoint = G * r
        S: ECPoint = pub_key * r
        symmetric_key: bytes = bytes(S)
        symmetric_key: bytes = KDF.derive_key(symmetric_key)
        encrypted: bytes = encryption_function(msg, symmetric_key)
        return encrypted, R

    @staticmethod
    def decrypt(encrypted_msg, private_key: ECKey, decryption_function=XOR.repeated_key_xor, block_size=32) -> bytes:
        """
        Decrypts ciphertext.
        @param encrypted_msg: The ciphertext.
        @param private_key: The private key.
        @param decryption_function: The symmetric decryption function
        @return: message
        @param block_size: The symmetric decryption block size
        """
        encrypted, R = encrypted_msg
        S: ECPoint = R * private_key.private_key
        symmetric_key: bytes = bytes(S)
        symmetric_key: bytes = KDF.derive_key(symmetric_key)
        msg: bytes = decryption_function(encrypted, symmetric_key)
        msg: bytes = PKCS7(block_size).unpad(msg)
        return msg

if __name__ == '__main__':
    keyPair = ECKey.new()
    msg = b"test"
    c = ECIES.encrypt(msg, keyPair.public_key)
    print(c)
    d = ECIES.decrypt(c, keyPair)
    print(d)
    assert d == msg
