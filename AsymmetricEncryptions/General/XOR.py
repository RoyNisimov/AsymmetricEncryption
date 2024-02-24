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
