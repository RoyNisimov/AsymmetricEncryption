from __future__ import annotations
from typing import Callable
from AsymmetricEncryptions.General import XOR
from AsymmetricEncryptions.Protocols import KDF, PKCS7

class Feistel:

    def __init__(self, encryption_function: Callable[[bytes, bytes], bytes], block_size: int = 64, key_size: int = 32):
        """
        A basic Feistel network.
        @param key_size: the key size.
        @param encryption_function: The symmetric encryption function.
        @param block_size: The function's block size.
        """
        self.key_size = key_size
        assert block_size <= 256
        self.encryption_function = encryption_function
        self.block_size = block_size

    def expand_key(self, key: bytes, rounds: int) -> list[bytes]:
        """
        Expands a key.
        @param key: The key.
        @param rounds: The size of the keys
        @return: list[bytes]
        """
        current: bytes = KDF.derive_key(key)[:self.key_size]
        l: list[bytes] = [current]
        for _ in range(rounds - 1):
            l.append(KDF.derive_key(current)[:self.key_size])
        return l


    def encrypt(self, msg: bytes, key: bytes, *, rounds: int = 16, keys: list[bytes] = None) -> bytes:
        """
        Encrypts a message.
        @param msg: the message.
        @param key: the secret key.
        @param rounds: how many rounds (r > 4)
        @param keys: the round keys (No need to touch)
        @return: bytes, cipher text.
        """
        msg = PKCS7(self.block_size).pad(msg)
        if not keys:
            keys: list[bytes] = self.expand_key(key, rounds)
        msgs = [msg[i:i+self.block_size] for i in range(0, len(msg), self.block_size)]

        def e(msg, keys):
            half_point: int = int(self.block_size // 2)
            left: bytes = msg[0:half_point]
            right: bytes = msg[half_point:]
            for i in range(rounds):
                left = XOR.repeated_key_xor(left, self.encryption_function(right, keys[i % len(keys)]))
                tmp: bytes = left
                left = right
                right = tmp
            return right + left
        c = b""
        for m in msgs:
            c += e(m, keys)
        return c

    def decrypt(self, cipher: bytes, key: bytes, *, rounds: int = 16) -> bytes:
        """
        Decrypts a message.
        @param cipher: the cipher text.
        @param key: the private key.
        @param rounds: how many rounds the cipher text was encrypted with.
        @return: bytes, the message
        """
        keys: list[bytes] = self.expand_key(key, rounds)[::-1]
        return PKCS7(self.block_size).unpad(self.encrypt(cipher, key, rounds=rounds, keys=keys))
