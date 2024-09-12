from AsymmetricEncryptions.Protocols.SchnorrPOK import POK
from AsymmetricEncryptions.PublicPrivateKey import DLIES
from unittest import TestCase

class TestPOK(TestCase):

    def test_proof(self):
        priv, pub = DLIES.generate_key_pair(1024)
        m = b"test"
        prover = POK(priv)
        proof = prover.prove(m)
        self.assertEqual(POK.verify(proof), True)