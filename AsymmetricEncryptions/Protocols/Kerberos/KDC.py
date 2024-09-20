# Key Distribution Center
from datetime import datetime

from AsymmetricEncryptions.General.Feistel_sha256 import FeistelSha256
from AsymmetricEncryptions.Protocols import KDF
from AsymmetricEncryptions.Protocols.Kerberos import AS, TGS
from hashlib import sha256
import hmac
from build.lib.AsymmetricEncryptions import MACError
from AsymmetricEncryptions.General.XOR import XOR


class KDC:

    def __init__(self, clients: dict[str, bytes], services: dict[str, bytes], master_passwd: bytes, symmetric_enc_func=FeistelSha256.get_feistel().encrypt, symmetric_dec_func=FeistelSha256.get_feistel().decrypt, ticket_life_time=datetime(1, 1, 1, 1, minute=1)):
        self.clients = clients
        self.services = services
        self.master_passwd = KDF.derive_key(master_passwd)
        self.enc = self.add_hmac(symmetric_enc_func)
        self.dec = self.dec_with_hmac(symmetric_dec_func)
        self.KTGS = KDF.derive_key(self.master_passwd)
        self.ticket_life_time = ticket_life_time
        self.auth_server = AS(clients, self.enc, self.KTGS, ticket_life_time)
        self.ticket_granting_server = TGS(services, self.enc, self.dec, self.KTGS)

    @staticmethod
    def add_hmac(enc) -> callable:
        def wrapper(m, k):
            if isinstance(m, str): m = m.encode()
            c = enc(m, k)
            mac = hmac.new(k, c, sha256).digest()
            return mac + c
        return wrapper

    @staticmethod
    def dec_with_hmac(dec):
        def wrapper(c, k):
            if isinstance(c, str): c = c.encode()
            ciphertxt = c[32:]
            mac = c[:32]
            new_mac = hmac.new(k, ciphertxt, sha256).digest()
            if not hmac.compare_digest(mac, new_mac): raise MACError("")
            m = dec(ciphertxt, k)
            return m
        return wrapper


    def AS_response(self, approach: str):
        return self.auth_server.reply(approach)

    def TGS_response(self, TGT: bytes, msgD: bytes):
        return self.ticket_granting_server.grant_ticket(TGT, msgD)







