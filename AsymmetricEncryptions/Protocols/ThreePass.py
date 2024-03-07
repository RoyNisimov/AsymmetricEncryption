from __future__ import annotations
from typing import Callable
from AsymmetricEncryptions.General import XOR
from AsymmetricEncryptions.Exceptions import UnsafeEncryptionFunction
from .KDF import KDF
import warnings

class ThreePassProtocol:

    """without any additional authentication the protocol is susceptible to a man-in-the-middle attack if the opponent has the ability to create false messages, or to intercept and replace the genuine transmitted messages."""

    def __init__(self, key: bytes, *, warningsBool=True) -> None:
        self.wb = warningsBool
        if warningsBool: warnings.warn("WARNING: Three pass is considered unsafe without authentication and can't be used with XOR!")
        self.key: bytes = KDF.derive_key(key)

    def stage1(self, msg: bytes, encryption_function: Callable[[bytes, bytes], bytes] = None) -> bytes:
        """
        Alice encrypts her message.
        :param msg: The message.
        :param encryption_function: the symmetric encryption function used
        :return: bytes, send to Bob
        """
        assert encryption_function
        if encryption_function is XOR.repeated_key_xor:
            raise UnsafeEncryptionFunction("XOR", "XOR is very unsafe with three pass")
        if self.wb: warnings.warn("WARNING: Three pass is considered un-safe without authentication!")
        return encryption_function(msg, self.key)

    @staticmethod
    def stage2(key: bytes, ciphertext: bytes, encryption_function: Callable[[bytes, bytes], bytes] = None) -> bytes:
        """
        Bob gets a cipher text, and hopefully authentication as well
        :param key: Bob's key
        :param ciphertext: The ciphertext that Alice gave me.
        :param encryption_function: the symmetric encryption function used (can be different from Alice's)
        :return: send ciphertext and auth as well
        """
        assert encryption_function
        if encryption_function is XOR.repeated_key_xor:
            raise UnsafeEncryptionFunction("XOR", "XOR is very unsafe with three pass")
        key: bytes = KDF.derive_key(key)
        return encryption_function(ciphertext, key)

    def stage3(self, ciphertext, decryption_function: Callable[[bytes, bytes], bytes] = None) -> bytes:
        """
        Alice hopefully gets an authentication and a ciphertext
        :param ciphertext: The ciphertext Bob sent.
        :param decryption_function: The symmetric decryption function.
        :return: ciphertext and sign it as well.
        """
        assert decryption_function
        if decryption_function is XOR.repeated_key_xor:
            raise UnsafeEncryptionFunction("XOR", "XOR is very unsafe with three pass")
        if self.wb: warnings.warn("WARNING: Three pass is considered un-safe without authentication!")
        return decryption_function(ciphertext, self.key)

    @staticmethod
    def stage4(ciphertext: bytes, key: bytes, decryption_function: Callable[[bytes, bytes], bytes] = None) -> bytes:
        """
        Bob hopefully gets an authentication and a ciphertext
        :param ciphertext: The ciphertext Alice sent.
        :param key: Bob's key
        :param decryption_function: The symmetric decryption function.
        :return: The message
        """
        assert decryption_function
        if decryption_function is XOR.repeated_key_xor:
            raise UnsafeEncryptionFunction("XOR", "XOR is very unsafe with three pass")
        key: bytes = KDF.derive_key(key)
        return decryption_function(ciphertext, key)




