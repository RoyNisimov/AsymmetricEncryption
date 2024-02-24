from AsymmetricEncryptions.Protocols.KDF import KDF
from AsymmetricEncryptions.General import XOR
import json
from secrets import compare_digest
import hmac
import base64
class Exportation:

    @staticmethod
    def export(file_name: str, data_dict: dict, pwd: bytes, *, exportation_func=XOR.repeated_key_xor) -> None:
        key: bytes = KDF.derive_key(pwd)
        jData: bytes = json.dumps(data_dict).encode("utf-8")
        write_data: bytes = exportation_func(jData, key)
        mac: hmac = hmac.new(key=key, msg=jData, digestmod="sha512")
        final_data: bytes = mac.digest() + write_data
        final_data = base64.b64encode(final_data)
        with open(file_name, "wb") as f:
            f.write(final_data)

    @staticmethod
    def load(file_name: str, pwd: bytes, *, dec_func=XOR.repeated_key_xor) -> dict:
        key: bytes = KDF.derive_key(pwd)
        with open(file_name, "rb") as f:
            final_data: bytes = f.read()
        final_data = base64.b64decode(final_data)
        dMac: bytes = final_data[:64]
        read_data: bytes = final_data[64:]
        jData: bytes = dec_func(read_data, key)
        mac: hmac = hmac.new(key=key, msg=jData, digestmod="sha512")
        assert compare_digest(mac.digest(), dMac)
        return json.loads(jData.decode())
