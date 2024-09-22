from unittest import TestCase
# This isn't really secure since I didn't implement the nonce thing fully as well as the ticket lifetime, but this is a showcase
from AsymmetricEncryptions.Protocols.Kerberos import KDC, KerberosService, KerberosClient
# Make sure the symmetric encryption function is AES (Make a wrapper function, use other library like PyCryptodom or Cryptography)

class TestKerberos(TestCase):
    def test_kerberos(self):
        clients = {"Alice": b"Alice", "Bob": b"Bob"}
        services = {"S": b"Secret", "CRM": b"Super secret passwOrd"}

        serviceS = KerberosService(b"Secret")
        CRM = KerberosService(b"Super secret passwOrd")

        kdc = KDC(clients, services, b"secret password")
        clientAlice = KerberosClient("Alice", b"Alice")

        approach = clientAlice.approach_AS("S")

        msgA, TGT = kdc.AS_response(approach[0])

        approach_TGS, Kc_tgs = clientAlice.approach_TGS(msgA, TGT)

        ticket, msgF = kdc.TGS_response(*approach_TGS)

        approach_service, Kc_s = clientAlice.approach_service(ticket, msgF, Kc_tgs)

        serviceS.confirm(*approach_service)

        clientBob = KerberosClient("Bob", b"Bob")

        approach = clientBob.approach_AS("CRM")

        msgA, TGT = kdc.AS_response(approach[0])

        approach_TGS, Kc_tgs = clientBob.approach_TGS(msgA, TGT)

        ticket, msgF = kdc.TGS_response(*approach_TGS)

        approach_service, Kc_s = clientBob.approach_service(ticket, msgF, Kc_tgs)

        CRM.confirm(*approach_service)
        self.assertEqual(None, None)
        try:
            clientCarol = KerberosClient("Bob", b"Carol")

            approach = clientCarol.approach_AS("CRM")

            msgA, TGT = kdc.AS_response(approach[0])

            approach_TGS, Kc_tgs = clientCarol.approach_TGS(msgA, TGT)

            ticket, msgF = kdc.TGS_response(*approach_TGS)

            approach_service, Kc_s = clientCarol.approach_service(ticket, msgF, Kc_tgs)
        except Exception:
            self.assertEqual(None, None)
        else:
            self.assertEqual(True, False)
