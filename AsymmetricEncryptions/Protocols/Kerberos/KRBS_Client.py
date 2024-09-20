from datetime import datetime
from secrets import token_bytes
from AsymmetricEncryptions.Protocols import KDF
import json
from .KDC import KDC
from base64 import b64decode

class KerberosClient:
    from AsymmetricEncryptions.General.Feistel_sha256 import FeistelSha256

    def __init__(self, c_id: str, passwd: bytes, dec_func: callable = FeistelSha256.get_feistel().decrypt, symmetric_enc_func: callable = FeistelSha256.get_feistel().encrypt):
        self.id = c_id
        self.passwd = passwd
        self.key = KDF.derive_key(passwd)
        self.dec = KDC.dec_with_hmac(dec_func)
        self.enc = KDC.add_hmac(symmetric_enc_func)



    def approach_AS(self, service_id: str) -> str and int:
        from AsymmetricEncryptions.General import BytesAndInts
        nonce = BytesAndInts.byte2Int(token_bytes(32))
        d = {"service_id": service_id, "client_id": self.id, "nonce": nonce}
        return json.dumps(d), nonce

    def approach_TGS(self, msgA: bytes, TGT: bytes) -> (bytes, bytes) and bytes:
        # get Kc-tgs
        msgA_dec = self.dec(msgA, self.key)
        msgA_dict = json.loads(msgA_dec)
        Kc_tgs: bytes = b64decode(msgA_dict["Kc_TGS"])
        msgD_dict = {"client_id": self.id, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        msgD_json = json.dumps(msgD_dict)
        msgD = self.enc(msgD_json, Kc_tgs)
        return (TGT, msgD), Kc_tgs

    def approach_service(self, ticket: bytes, msgF: bytes, Kc_tgs):
        Kc_s = b64decode(self.dec(msgF, Kc_tgs))
        msgG_dict = {"client_id": self.id, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        msgG_json = json.dumps(msgG_dict)
        msgG = self.enc(msgG_json, Kc_s)
        return (ticket, msgG), Kc_s


