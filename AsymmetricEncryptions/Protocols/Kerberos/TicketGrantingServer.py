import json
import secrets
from AsymmetricEncryptions.Protocols import KDF
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

class TGS:
    # Ticket Granting Server
    def __init__(self, services: dict[str, bytes], symmetric_enc_func, symmetric_dec_func, KTGS: bytes):
        self.services = services
        self.dec = symmetric_dec_func
        self.enc = symmetric_enc_func
        self.KTGS = KTGS

    def grant_ticket(self, TGT: bytes, msgD: bytes):
        d_TGT = self.dec(TGT, self.KTGS)
        try:
            TGT = json.loads(d_TGT)
        except Exception:
            return None
        Kc_TGS = b64decode(TGT["Kc_TGS"].encode())
        lifetime = datetime.strptime(TGT["lifetime"], "%Y-%m-%d %H:%M:%S").replace(microsecond=0)
        assert datetime.now() < lifetime, "Life time has passed"
        verify_msgD = self.dec(msgD, Kc_TGS)
        msgD_dict = json.loads(verify_msgD)
        assert msgD_dict["client_id"] == TGT["client_id"]
        Kc_s = b64encode(KDF.derive_key(secrets.token_bytes(32))).decode()
        msgE = {"Kc_s": Kc_s, "client_id": TGT["client_id"], "lifetime": TGT["lifetime"]}
        msgE = json.dumps(msgE)
        Ks = KDF.derive_key(self.services[TGT["service_id"]])
        msgE = self.enc(msgE, Ks)
        msgF = self.enc(Kc_s, Kc_TGS)
        return msgE, msgF