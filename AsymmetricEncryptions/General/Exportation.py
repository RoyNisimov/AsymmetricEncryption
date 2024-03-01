from AsymmetricEncryptions.Protocols import KDF, PKCS7
from AsymmetricEncryptions.General import XOR
import json
from secrets import compare_digest, token_bytes
import hmac
import base64
from hashlib import sha256

class Exportation:
    """
    Handles the exportation of keys. Nothing in here is done by regulations though.
    """


    @staticmethod
    def export(file_name: str, data_dict: dict, pwd: bytes, *, exportation_func=XOR.repeated_key_xor, block_size: int = 32) -> None:
        """
        Encrypts and exports data that can be converted to json.
        @param file_name: The file that will be exported into
        @param data_dict: The data that will be exported
        @param pwd: The passphrase that will be used in the KDF and then encryption part of the export
        @param exportation_func: The encryption function used (I'm using XOR or OTP)
        @return: None
        @param block_size: The symmetric encryption block size
        """
        key: bytes = KDF.derive_key(pwd)
        jData: bytes = json.dumps(data_dict).encode("utf-8")
        randomness: bytes = sha256(token_bytes(32)).digest()
        xored: bytes = XOR.repeated_key_xor(jData, randomness)
        xored: bytes = PKCS7(block_size).pad(xored)
        write_data: bytes = exportation_func(xored, key)
        mac: hmac = hmac.new(key=key, msg=jData, digestmod="sha512")
        final_data: bytes = mac.digest() + write_data + randomness
        final_data = base64.b64encode(final_data)
        with open(file_name, "wb") as f:
            f.write(final_data)

    @staticmethod
    def load(file_name: str, pwd: bytes, *, dec_func=XOR.repeated_key_xor, block_size: int = 32) -> dict:
        """
        Loads data from an encrypted file
        @param file_name: The encrypted file name
        @param pwd: The passphrase used as a key
        @param dec_func: The opposite of the encryption function
        @return: The data as a dict
        @param block_size: The symmetric decryption block size
        """
        key: bytes = KDF.derive_key(pwd)
        with open(file_name, "rb") as f:
            final_data: bytes = f.read()
        final_data = base64.b64decode(final_data)
        dMac: bytes = final_data[:64]
        read_data: bytes = final_data[64:-32]
        randomness: bytes = final_data[-32:]
        jData: bytes = dec_func(read_data, key)
        jData: bytes = PKCS7(block_size).unpad(jData)
        jData = XOR.repeated_key_xor(jData, randomness)
        mac: hmac = hmac.new(key=key, msg=jData, digestmod="sha512")
        assert compare_digest(mac.digest(), dMac)
        return json.loads(jData.decode())
