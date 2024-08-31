import secrets
from unittest import TestCase
from unittest.mock import patch, Mock
from AsymmetricEncryptions.General.Exportation import Exportation

class TestExportation(TestCase):

    @patch("AsymmetricEncryptions.General.Exportation.sha_wrapper")
    def test_export(self, mock_randomness):
        mock_randomness.return_value = b" "
        d = {"test": 123456789, "e": 69}
        self.assertEqual(b'3MCFp+lsJbLhsVPcCxAR1bzqBPbaabQWbyN8+s3qyatLgrCv020yik/0odPzGqNiee5Vj7+SdQT7Dcow8qHqA9LuGHzBSqUryeLfG/PCCdIGv/ZIMvrRdZac3XY6QU3I4DT0TEwo1mxi6FHRXVIFphPcFQ6B58mJg3OVtyNEHS8g', Exportation.export("testdict.txt", d, b"", isTesting=True))



    def test_export_and_load(self):
        d = {"test": 123456789, "e": 69}
        e = Exportation.export("testdict.txt", d, b"", isTesting=True)
        nd = Exportation.load("testdict.txt", b"", isTesting=True, dataIfTesting=e)
        self.assertEqual(d, nd)