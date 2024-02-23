from AsymmetricEncryptions.PublicPrivateKey import DLIESKey, DLIES

key = DLIESKey.new(1024)
msg = b"test"

c = DLIES.encrypt(key.public, msg)
d = DLIES.decrypt(key, c)

print(c)
print(d)


