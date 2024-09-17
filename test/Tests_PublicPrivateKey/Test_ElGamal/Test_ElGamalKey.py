from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamalKey

class TestElGamalKey(TestCase):
    def test_new(self):
        priv = ElGamalKey.new(256)
        pub: ElGamalKey = priv.public
        self.assertEqual(pub.y, pow(priv.g, priv.x, priv.p))

    def test_new_values(self):
        self.assertRaises(ValueError, ElGamalKey.new, -1)
        self.assertRaises(ValueError, ElGamalKey.new, 4209)

    def test_export_and_load(self):
        priv: ElGamalKey = ElGamalKey.new(256)
        priv.export("TestFiles\\ElGamalKeyTestFileUnprotected.key", b"")
        loaded_priv = ElGamalKey.load("TestFiles\\ElGamalKeyTestFileUnprotected.key", b"")
        self.assertEqual(priv, loaded_priv)
        priv.export("TestFiles\\ElGamalKeyTestFileProtected.key", b"Pass")
        loaded_priv = ElGamalKey.load("TestFiles\\ElGamalKeyTestFileProtected.key", b"Pass")
        self.assertEqual(priv, loaded_priv)



