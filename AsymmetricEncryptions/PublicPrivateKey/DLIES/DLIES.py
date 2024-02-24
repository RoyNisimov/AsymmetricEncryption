from AsymmetricEncryptions.General import XOR, BytesAndInts
from AsymmetricEncryptions.Protocols import KDF
from .DLIESKey import DLIESKey
import secrets

class DLIES:
    """
    Discrete Logarithm Integrated Encryption Scheme.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate_key_pair(nBits: int) -> tuple[DLIESKey, DLIESKey]:
        """
        Generates a DLIES key pair
        :param nBits: How large the modulus be.
        :return: Private key, Public Key
        """
        priv: DLIESKey = DLIESKey.new(nBits)
        return priv, priv.public

    @staticmethod
    def encrypt(pub_key: DLIESKey, msg: bytes, encryption_func=XOR.repeated_key_xor) -> tuple[bytes, int]:
        """
        Encrypts the message.
        :param pub_key: Public key
        :param msg: The plaintext
        :param encryption_func: The symmetric encryption function
        :return: Encrypted Message, Decrypt helper as a tuple, don't split.
        """
        r: int = secrets.randbelow(pub_key.n)
        R: int = pow(pub_key.g, r, pub_key.n)
        S: int = pow(pub_key.y, r, pub_key.n)
        S_bytes: bytes = BytesAndInts.int2Byte(S)
        key: bytes = KDF.derive_key(S_bytes)
        encrypted = encryption_func(msg, key)
        return encrypted, R

    @staticmethod
    def decrypt(private_key: DLIESKey, ciphertxt: tuple[bytes, int], decryption_function=XOR.repeated_key_xor) -> bytes:
        """
        Decrypts a ciphertext.
        :param private_key: The private key.
        :param ciphertxt: The ciphertext containing (encrypted, R)
        :param decryption_function: The symmetric decryption function
        :return: The message
        """
        encrypted, R = ciphertxt
        assert private_key.x and private_key.has_private
        S: int = pow(R, private_key.x, private_key.n)
        S_bytes: bytes = BytesAndInts.int2Byte(S)
        key: bytes = KDF.derive_key(S_bytes)
        return decryption_function(encrypted, key)
