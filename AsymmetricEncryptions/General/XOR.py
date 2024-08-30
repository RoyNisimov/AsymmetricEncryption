from hashlib import scrypt, sha256
class XOR:
    @staticmethod
    def repeated_key_xor(plain_text: bytes, key: bytes) -> bytes:
        """
        Encrypts using OTP
        :param plain_text: The plain text
        :param key: The encryption/decryption key
        :return: ciphertext
        """
        pt = plain_text
        len_key = len(key)
        encoded = []
        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)

    @staticmethod
    def repeated_key_xor_with_scrypt_kdf(plain_text: bytes, key: bytes) -> bytes:
        """
        Encrypts using OTP
        :param plain_text: The plain text
        :param key: The encryption/decryption key
        :return: ciphertext
        """
        key = scrypt(key, salt=sha256(key).digest(), r = 16, n = 32, p=1, dklen=32)
        return XOR.repeated_key_xor(plain_text, key)