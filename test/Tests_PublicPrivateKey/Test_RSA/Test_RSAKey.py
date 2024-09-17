from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSAKey

class TestRSAKey(TestCase):
    def test_new(self):
        priv = RSAKey.new(256)
        pub: RSAKey = priv.public
        self.assertEqual((pub.e * priv.d) % priv.tot_n, 1)

    def test_new_values(self):
        self.assertRaises(ValueError, RSAKey.new, -1)
        self.assertRaises(ValueError, RSAKey.new, 4209)

    def test_export_and_load(self):
        priv: RSAKey = RSAKey.new(256)
        priv.export("TestFiles\\RSAKeyTestFileUnprotected.key", b"")
        loaded_priv = RSAKey.load("TestFiles\\RSAKeyTestFileUnprotected.key", b"")
        self.assertEqual(priv, loaded_priv)
        priv: RSAKey = RSAKey.new(256)
        priv.export("TestFiles\\RSAKeyTestFileProtected.key", b"Pass")
        loaded_priv = RSAKey.load("TestFiles\\RSAKeyTestFileProtected.key", b"Pass")
        self.assertEqual(priv, loaded_priv)



