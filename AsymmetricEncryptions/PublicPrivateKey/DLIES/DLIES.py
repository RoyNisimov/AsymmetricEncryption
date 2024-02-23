from AsymmetricEncryptions.General import XOR, BytesAndInts
from .DLIESKey import DLIESKey
import secrets

class DLIES:

    def __init__(self) -> None:
        pass

    @staticmethod
    def encrypt(pub_key: DLIESKey, msg: bytes, encryption_func=XOR.repeated_key_xor) -> tuple[bytes, int]:
        r: int = secrets.randbelow(pub_key.n)
        R: int = pow(pub_key.g, r, pub_key.n)
        S: int = pow(pub_key.y, r, pub_key.n)
        S_bytes: bytes = BytesAndInts.int2Byte(S)
        encrypted = encryption_func(msg, S_bytes)
        return encrypted, R

    @staticmethod
    def decrypt(private_key: DLIESKey, ciphertxt: tuple[bytes, int], decryption_function=XOR.repeated_key_xor) -> bytes:
        encrypted, R = ciphertxt
        assert private_key.x and private_key.has_private
        S: int = pow(R, private_key.x, private_key.n)
        S_bytes: bytes = BytesAndInts.int2Byte(S)
        return decryption_function(encrypted, S_bytes)
