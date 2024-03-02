from __future__ import annotations

from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamalKey, ElGamal
from AsymmetricEncryptions.Protocols import KDF, PKCS7
from AsymmetricEncryptions.General import BytesAndInts, XOR
import secrets
from hashlib import sha256

# A KEM for RSA

class UHElGamal:
    """
    A safe ElGamal encryption class
    """
    def __init__(self, private_key: ElGamalKey):
        """
        Private key for signing
        """
        self.private_key: ElGamalKey = private_key

    def encrypt(self, public_key: ElGamalKey, msg: bytes, *, encryption_function=XOR.repeated_key_xor, padding_block_size: int = 32) -> list[tuple[tuple[bytes], bytes], tuple[bytes, bytes, bytes]]:
        """
        Encrypts a message using ElGamal with a symmetric encryption method. (Uses the OTP without change, please use a better symmetric encryption algorithm such as AES-256)
        @rtype: The ciphertext as a tuple
        @param public_key: The public ElGamal key
        @param msg: The message you want to encrypt
        @param encryption_function: The symmetric encryption method, please also install PyCryptodome and use AES with here. The signature of the function must be (bytes, bytes) -> bytes
        @param padding_block_size: The padding block size, int
        """
        # pre reqs
        ciphertxt: list = []
        cipher: ElGamal = ElGamal(public_key)
        # Padding
        msg = PKCS7(padding_block_size).pad(msg)
        # Generates a random nonce
        r: bytes = BytesAndInts.int2Byte(secrets.randbelow(public_key.p-1))
        # encrypts r
        ciphertxt_r: bytes = cipher.encrypt(r)
        # Generates a key from the nonce
        key: bytes = KDF.derive_key(r)
        # symmetrically encrypts a message
        ciphertxt_msg: bytes = encryption_function(msg, key)
        # cipher text without a signature
        ciphertxt.append((ciphertxt_r, ciphertxt_msg))
        # Signer
        signer: ElGamal = ElGamal(self.private_key)
        # signing a hash
        signature = signer.sign(sha256(str(ciphertxt[0]).encode()).digest())
        ciphertxt.append(signature)
        return ciphertxt.copy()

    def decrypt(self, ciphertext: list[tuple[bytes, bytes], bytes], public_key: ElGamalKey, *, decryption_function=XOR.repeated_key_xor, padding_block_size: int = 32) -> bytes:
        """
        Decrypts a signed cipher text
        @rtype: bytes, message
        @param ciphertext: The cipher text.
        @param public_key: The sender's public key, for signature verification
        @param decryption_function: The symmetric decryption function
        @param padding_block_size: The padding block size, int
        """
        assert len(ciphertext) == 2
        # verifying the signature
        verifier: ElGamal = ElGamal(public_key)
        needed_signature: bytes = sha256(str(ciphertext[0]).encode()).digest()
        signature: tuple[bytes, bytes, bytes] = ciphertext[1]
        verifier.verify(signature, og_message=needed_signature)
        # decrypting
        cipher: ElGamal = ElGamal(self.private_key)
        ciphertext_r, ciphertext_msg = ciphertext[0]
        r: bytes = cipher.decrypt(ciphertext_r)
        key: bytes = KDF.derive_key(r)
        message: bytes = decryption_function(ciphertext_msg, key)
        message: bytes = PKCS7(padding_block_size).unpad(message)
        return message

