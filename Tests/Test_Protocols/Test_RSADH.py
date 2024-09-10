from AsymmetricEncryptions.Protocols.RSADH import DiffieHellman
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA
from unittest import TestCase

class TestRSADH(TestCase):

    def test_DiffieHellman(self):
        Apriv, Apub = RSA.generate_key_pair(256)
        Bpriv, Bpub = RSA.generate_key_pair(256)
        DH = DiffieHellman.new(Apriv, 256)
        A = DH.Stage1()
        gp = DH.get_gp()
        B, Bob_shared = DiffieHellman.Stage2(gp, Bpriv, A)
        Alice_shared = DH.Stage3(B)
        self.assertEqual(Alice_shared,Bob_shared)


