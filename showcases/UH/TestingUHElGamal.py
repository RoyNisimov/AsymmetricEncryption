from AsymmetricEncryptions.Unhazardous.PublicKey.UHElGamal import UHElGamal
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamal

AlicesPriv, AlicesPub = ElGamal.generate_key_pair(2048)
BobsPriv, BobsPub = ElGamal.generate_key_pair(2048)
msg = b"test"
cipherAlice = UHElGamal(AlicesPriv)
ct = cipherAlice.encrypt(BobsPub, msg)
cipherBob = UHElGamal(BobsPriv)
pt = cipherBob.decrypt(ct, AlicesPub)
assert pt == msg
print(ct)
print(pt)
