from AsymmetricEncryptions.Unhazardous.PublicKey.UHRSA import UHRSA
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA

key_size = 2048
AlicesPriv, AlicesPub = RSA.generate_key_pair(key_size)
BobsPriv, BobsPub = RSA.generate_key_pair(key_size)
msg = b"test"
cipherAlice = UHRSA(AlicesPriv)
ct = cipherAlice.encrypt(BobsPub, msg)
cipherBob = UHRSA(BobsPriv)
pt = cipherBob.decrypt(ct, AlicesPub)
assert pt == msg
print(ct)
print(pt)
