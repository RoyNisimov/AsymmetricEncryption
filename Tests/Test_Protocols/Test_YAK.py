from AsymmetricEncryptions.Protocols.YAK import YAK
from AsymmetricEncryptions.PublicPrivateKey import DLIESKey
from unittest import TestCase

class TestYAK(TestCase):

    def test_YAK(self):
        yakAlice = YAK.new(256)
        gq = yakAlice.get_gq()
        yakBob = YAK(*gq)
        g, q = gq
        AlicePriv = DLIESKey.build(g, q)
        AlicePub = AlicePriv.public
        BobPriv = DLIESKey.build(g, q)
        BobPub = BobPriv.public
        x, AliceSend = yakAlice.stage_1()
        y, BobSend = yakBob.stage_1()
        sharedAlice = yakAlice.stage_2(x, AlicePriv, BobSend, BobPub)
        sharedBob = yakBob.stage_2(y, BobPriv, AliceSend, AlicePub)
        self.assertEqual(sharedAlice, sharedBob)