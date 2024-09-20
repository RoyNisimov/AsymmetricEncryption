import json
from base64 import b64decode
from datetime import datetime

from .KDC import KDC
from AsymmetricEncryptions.General.XOR import XOR
from AsymmetricEncryptions.Protocols.KDF import KDF

class KerberosService:
    def __init__(self, Ks: bytes, symmetric_enc_func=XOR.repeated_key_xor_with_scrypt_kdf, symmetric_dec_func=XOR.repeated_key_xor_with_scrypt_kdf):
        self.enc = KDC.add_hmac(symmetric_enc_func)
        self.dec = KDC.dec_with_hmac(symmetric_dec_func)
        self.ks = KDF.derive_key(Ks)
        self.clients = {}

    def confirm(self, ticket: bytes, msgG: bytes):
        msgE = self.dec(ticket, self.ks)
        ticket = json.loads(msgE)
        Kc_s = b64decode(ticket["Kc_s"].encode())
        client_id = ticket["client_id"]
        if client_id in self.clients: return None
        msgG = self.dec(msgG, Kc_s).decode()
        msgG = json.loads(msgG)
        if msgG["client_id"] != client_id: return None
        self.clients[client_id] = Kc_s
        msgH = json.dumps({"timestamp": datetime.now().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")}).encode()
        return self.enc(msgH, Kc_s)
