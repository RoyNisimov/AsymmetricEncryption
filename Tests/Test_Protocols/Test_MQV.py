from AsymmetricEncryptions.PublicPrivateKey.ECC import ECMQV, ECKey, EllipticCurveNISTP256

from unittest import TestCase

class TestMQV(TestCase):

    def test_MQV(self):
        a = ECKey.new(EllipticCurveNISTP256.get_curve())
        b = ECKey.new(EllipticCurveNISTP256.get_curve())

        x = ECMQV.Stage1n2(EllipticCurveNISTP256.get_curve())
        y = ECMQV.Stage1n2(EllipticCurveNISTP256.get_curve())

        Sa = ECMQV.Stage3n4(a, x)
        Sb = ECMQV.Stage3n4(b, y)

        keyA = ECMQV.Stage5(b.get_public_key(), Sa, y.get_public_key())
        keyB = ECMQV.Stage5(a.get_public_key(), Sb, x.get_public_key())
        self.assertEqual(keyA, keyB)