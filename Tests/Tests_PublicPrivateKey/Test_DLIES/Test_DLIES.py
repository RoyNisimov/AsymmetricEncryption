from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.DLIES import DLIES
from AsymmetricEncryptions import BytesAndInts, Exceptions
from secrets import token_bytes

class TestDLIES(TestCase):

    def test_generate_key_pair(self):
        priv, pub = DLIES.generate_key_pair(256)
        self.assertEqual(pub.y, pow(pub.g, priv.x, pub.n))

    def test_generate_key_pair_type(self):
        self.assertRaises(TypeError, DLIES.generate_key_pair, "test")
        self.assertRaises(TypeError, DLIES.generate_key_pair, b"test")

    def test_generate_key_pair_values(self):
        self.assertRaises(ValueError, DLIES.generate_key_pair, -2)
        self.assertRaises(ValueError, DLIES.generate_key_pair, 5)

    def test_encrypt(self):
        priv, pub = DLIES.generate_key_pair(256)
        c = DLIES.encrypt(pub, t := token_bytes(1))
        self.assertEqual(t, DLIES.decrypt(priv, c))

    def test_encrypt_type(self):
        priv, pub = DLIES.generate_key_pair(256)
        self.assertRaises(TypeError, DLIES.encrypt, pub, "test")
        self.assertRaises(TypeError, DLIES.encrypt, "test", "test")

    def test_decrypt(self):
        priv, pub = DLIES.generate_key_pair(256)
        c = DLIES.encrypt(pub, b"test")
        self.assertEqual(b"test", DLIES.decrypt(priv, c))


