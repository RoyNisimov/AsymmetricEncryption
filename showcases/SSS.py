from AsymmetricEncryptions.Protocols.SSS import SSS

secret = b"test"
sss = SSS()
shares = sss.make_random_shares(secret, 3, 5)
recover = sss.recover_secret(shares[:3])
print(recover)