from AsymmetricEncryptions.General import XOR, BytesAndInts
from AsymmetricEncryptions.Protocols import KDF
from AsymmetricEncryptions.Interfaces import IEncryptAndDecrypt
from .DLIESKey import DLIESKey
import secrets
from hashlib import sha256

class DLIES(IEncryptAndDecrypt):
    """
    Discrete Logarithm Integrated Encryption Scheme.
    """

    def __init__(self, private_key: DLIESKey, public_key: DLIESKey, nonces: set = None) -> None:
        self.nonces = set()
        if nonces is not None:
            self.nonces = nonces
        self.private_key = private_key
        self.public_key = public_key

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
        if not isinstance(msg, bytes) or not isinstance(pub_key, DLIESKey): raise TypeError("Values must be: pub: DLIESKey, msg: Bytes, encryption_func: function")
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



    def sign(self, message: bytes):
        """Schnorr signature
        @param message: Message to be signed
        """
        assert self.private_key.has_private
        r = secrets.randbelow(self.private_key.n-1)
        h_r = sha256(BytesAndInts.int2Byte(r)).digest()
        while h_r in self.nonces:
            r = secrets.randbelow(self.private_key.n - 1)
            h_r = sha256(BytesAndInts.int2Byte(r)).digest()
        self.nonces.add(h_r)
        R: int = pow(self.private_key.g, r, self.private_key.n)
        c: int = BytesAndInts.byte2Int(f"{R}{self.public_key.y}".encode() + message)
        s: int = c * self.private_key.x + r
        return s, R

    @staticmethod
    def verify(public_key: DLIESKey, signature: tuple[int, int], message: bytes):
        """Verification of Schnorr signature
        @param public_key: the signers public key
        @param signature: the signature
        @param message: the message
        """
        s, R = signature
        c: int = BytesAndInts.byte2Int(f"{R}{public_key.y}".encode() + message)
        return pow(public_key.g, s, public_key.n) == (pow(public_key.y, c, public_key.n) * R) % public_key.n