from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, ECDH, ECSchnorr, ECIES, EllipticCurveNISTP256

# key pair gen
key_pair = ECKey.new(EllipticCurveNISTP256.get_curve())
priv = key_pair.private_key  # int
pub = key_pair.public_key  # ECPoint

# ECDH

keyA = ECKey.new(EllipticCurveNISTP256.get_curve())
ecdh = ECDH(keyA)
A = keyA.public_key

keyB = ECKey.new(EllipticCurveNISTP256.get_curve())
B = keyB.public_key

shared_key_alice = ecdh.Stage1(B)

shared_key_bob = ECDH.Stage2(keyB, A)

print(shared_key_alice)
print(shared_key_bob)

assert shared_key_alice == shared_key_bob

# ECIES
keyPair = ECKey.new(EllipticCurveNISTP256.get_curve())
msg = b"test"
c = ECIES.encrypt(msg, keyPair.public_key)
print(c)
d = ECIES.decrypt(c, keyPair)
print(d)
assert d == msg

# Schnorr signing
key = ECKey.new(EllipticCurveNISTP256.get_curve())
signer = ECSchnorr(key)
msg = b"test"
signature = signer.sign(msg)
verify = ECSchnorr.verify(signature, msg, key.public_key)
print(verify)

# export
key = ECKey.new(EllipticCurveNISTP256.get_curve())
key.export("key.key", b"password") # there's also an encryption function variable (XOR right now)
new_key = ECKey.load("key.key", b"password")
assert new_key == key