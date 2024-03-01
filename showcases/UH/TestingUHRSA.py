from AsymmetricEncryptions.Unhazardous.UHRSA import UHRSA
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSAKey, RSA

AlicesPriv, AlicesPub = RSA.generate_key_pair(2048)
BobsPriv, BobsPub = RSA.generate_key_pair(2048)
msg = b"test"
cipherAlice = UHRSA(AlicesPriv)
ct = cipherAlice.encrypt(BobsPub, msg)
cipherBob = UHRSA(BobsPriv)
pt = cipherBob.decrypt(ct, AlicesPub)
assert pt == msg
print(ct)
print(pt)
