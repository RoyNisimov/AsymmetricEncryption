from __future__ import annotations
import hashlib

class KDF:

    def __init__(self):
        pass

    @staticmethod
    def derive_key(passphrase: bytes) -> bytes:
        count: int = 0
        cur: bytes = b'\x00'
        while b'\x00' in cur:
            cur = hashlib.scrypt(passphrase, salt=hashlib.sha256(passphrase + bytes(count)).digest(), r=16, n=2048, p=1)
            count += 1
        return cur



