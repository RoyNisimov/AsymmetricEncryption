from AsymmetricEncryptions.Protocols.Feistel import Feistel
from hashlib import sha256


class FeistelSha256:

    @staticmethod
    def fSHA(msg, key):
        return sha256(msg + key).digest()

    @staticmethod
    def get_feistel() -> Feistel:
        return Feistel(FeistelSha256.fSHA)

    @staticmethod
    def wrapper_encrypt(msg: bytes, key: bytes) -> bytes:
        return FeistelSha256.get_feistel().encrypt(msg, key)

    @staticmethod
    def wrapper_decrypt(ciphertxt: bytes, key: bytes) -> bytes:
        return FeistelSha256.get_feistel().decrypt(ciphertxt, key)