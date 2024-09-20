import json
import secrets

from AsymmetricEncryptions.Protocols import KDF
from base64 import b64encode
from datetime import datetime, timedelta

class AS:
    # Authentication server
    def __init__(self, clients: dict[str, bytes], enc_func: callable, KTGS: bytes, ticket_life_time: datetime):
        self.KTGS = KTGS
        self.clients = clients
        self.enc = enc_func
        self.ticket_life_time = ticket_life_time

    def reply(self, approach_request: str):
        try:
            d = json.loads(approach_request)
        except Exception:
            return None

        if not d["client_id"] in self.clients: return None
        clients_key: bytes = KDF.derive_key(self.clients[d["client_id"]])
        Kc_TGS: bytes = KDF.derive_key(secrets.token_bytes(32))
        Kc_TGS = b64encode(Kc_TGS).decode()
        now = datetime.now()
        # year can't be 0 so I do -1
        time_change = timedelta(days=self.ticket_life_time.day + ((self.ticket_life_time.year - 1) * 365), minutes=self.ticket_life_time.minute, hours=self.ticket_life_time.hour)

        life_time = now + time_change
        life_time = life_time.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
        msgA_unenc = {"nonce": d["nonce"], "lifetime": life_time, "Kc_TGS": Kc_TGS, "service_id": d["service_id"]}
        msgA_json = json.dumps(msgA_unenc)
        msgA: bytes = self.enc(msgA_json, clients_key)
        msgB_unenc = {"client_id": d["client_id"], "Kc_TGS": Kc_TGS, "lifetime": life_time, "service_id": d["service_id"], "nonce": d["nonce"]}
        msgB_json = json.dumps(msgB_unenc)
        TGT: bytes = self.enc(msgB_json, self.KTGS)
        return msgA, TGT



