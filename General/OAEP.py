import hashlib
import secrets
from AsymmetricEncryption.General import XOR
class OAEP:
    # Using Sha256 as the hash algorithm
    @staticmethod
    def oaep_pad(message: bytes) -> bytes:
        nonce: bytes = secrets.token_bytes(32)
        mm: bytes = message + b"\x00" * (32 - len(message))
        G: bytes = XOR.repeated_key_xor(mm, hashlib.sha256(nonce).digest())
        H: bytes = XOR.repeated_key_xor(nonce, hashlib.sha256(G).digest())
        return G + H

    @staticmethod
    def oaep_unpad(message) -> bytes:
        oaep_step2: bytes = message + b'\x00' * (64 - len(message))
        G: bytes = oaep_step2[:32]
        H: bytes = oaep_step2[32:64]
        nonce = XOR.repeated_key_xor(H, hashlib.sha256(G).digest())[:32]
        mm = XOR.repeated_key_xor(G, hashlib.sha256(nonce).digest())
        return mm.rstrip(b'\x00')