from __future__ import annotations
from unittest import TestCase
from unittest.mock import patch, Mock
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECIES, ECKey, ECPoint, EllipticCurveNISTP256

class TestECIES(TestCase):

    @patch("AsymmetricEncryptions.PublicPrivateKey.ECC.ECIES.random_wrapper_for_test_mock")
    def test_encrypt(self, r: Mock):
        r.return_value = 3
        priv = ECKey.load("..\\..\\..\\TestFiles\\Test_KEY_PRIV_ECC.key", b"Key")
        pub = priv.public_key
        Msg = b"Test"
        e = ECIES.encrypt(Msg, pub)
        e_should_be = b'l\xbfM\x91\xba\xbf\x98\xf8\x8fk\xf0f\xa5\xe0j\x9f\x92t\x9f\xe0\x98\xe1\xf5\x8b\xc9\x86\x91A&\xf2O4'
        e_point = (42877656971275811310262564894490210024759287182177196162425349131675946712428, 61154801112014214504178281461992570017247172004704277041681093927569603776562)
        e_point = ECPoint(EllipticCurveNISTP256.get_curve(), e_point[0], e_point[1])
        self.assertEqual(e, (e_should_be, e_point))

