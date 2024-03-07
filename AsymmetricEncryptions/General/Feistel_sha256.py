from AsymmetricEncryptions.Protocols.Feistel import Feistel
from hashlib import sha256


class FeistelSha256:

    @staticmethod
    def fSHA(msg, key):
        return sha256(msg + key).digest()

    @staticmethod
    def get_feistel() -> Feistel:
        return Feistel(FeistelSha256.fSHA)
