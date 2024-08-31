from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.RSA.RSAKey import RSAKey
from AsymmetricEncryptions.General import BytesAndInts
from AsymmetricEncryptions.Exceptions import MACError
from AsymmetricEncryptions.Interfaces import IEncryptAndDecrypt, ISignAndVerify
from hashlib import sha256

class RSA(IEncryptAndDecrypt, ISignAndVerify):
    """Rivest-Shamir-Adleman"""
    def __init__(self, key: RSAKey) -> None:
        self.key = key

    @staticmethod
    def generate_key_pair(nBit) -> [RSAKey, RSAKey]:
        """
        RSAKey.new returns a pair of priv and pub
        :param nBit: Key length (2048+ is recommended )
        :return: Private key, public key
        """
        if not isinstance(nBit, int):
            raise TypeError("nBit must be an integer")
        Priv: RSAKey = RSAKey.new(nBit)
        Pub: RSAKey = Priv.public
        return Priv, Pub


    def encrypt(self, msg: bytes, assertion=True) -> bytes:
        """
        Encrypts a message
        :param msg: The plaintext
        :param assertion: If assertion is true then it will assert if the message is smaller than allowed. (e.g. m < p)
        :return: Ciphertext
        """
        int_msg: int = BytesAndInts.byte2Int(msg)
        if assertion: assert int_msg < self.key.n
        cipher: int = pow(int_msg, self.key.e, self.key.n)
        return BytesAndInts.int2Byte(cipher)


    def decrypt(self, cipher: bytes) -> bytes:
        """
        Decrypts (Only possible if key is private)
        :param cipher: the ciphertext
        :return: message
        """
        assert self.key.has_private
        int_cipher: int = BytesAndInts.byte2Int(cipher)
        m: int = pow(int_cipher, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(m)

    def sign(self, msg: bytes, assertion=True) -> bytes:
        """
        Signs a message
        :param msg: The plaintext
        :param assertion: if true then will check if m is allowed
        :return: signature
        """
        assert self.key.has_private
        msg = sha256(msg).digest()
        int_msg: int = BytesAndInts.byte2Int(msg)
        if assertion: assert int_msg < self.key.n
        s: int = pow(int_msg, self.key.d, self.key.n)
        return BytesAndInts.int2Byte(s)

    def verify(self, signature: bytes, og_msg: bytes) -> None:
        """
        Verifies a signature.
        :param signature: The signature.
        :param og_msg: The original message.
        :return: None, will throw an assertion error if fails
        """
        og_msg = sha256(og_msg).digest()
        int_s: int = BytesAndInts.byte2Int(signature)
        cipher: int = pow(int_s, self.key.e, self.key.n)
        if not cipher == BytesAndInts.byte2Int(og_msg):
            raise MACError("Sig is wrong!")
