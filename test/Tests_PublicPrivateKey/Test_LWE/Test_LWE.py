from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.LWE import LWEKey, LWE
import secrets
class TestLWE(TestCase):
    def test_encrypt(self):
        key_pair = LWEKey.new(1024)
        m = secrets.token_bytes(4)
        cipher = LWE(key_pair)
        ciphertxt = LWE.encrypt_message(key_pair.public, m)
        plaintext = cipher.decrypt_message(ciphertxt)
        self.assertEqual(plaintext, m)

