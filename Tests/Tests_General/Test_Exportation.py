from unittest import TestCase
from AsymmetricEncryptions.General.Exportation import Exportation

class TestExportation(TestCase):

    def test_export(self):
        d = {"test": 123456789, "e": 69}
        e = Exportation.export("testdict.txt", d, b"", isTesting=True)
        nd = Exportation.load("testdict.txt", b"", isTesting=True, dataIfTesting=e)
        self.assertEqual(d, nd)