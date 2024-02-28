from AsymmetricEncryptions.PublicPrivateKey.LWE import LWEKey, LWE

if __name__ == '__main__':
    key_pair = LWEKey.new(128)
    m = b"test"
    cipher = LWE(key_pair)
    ct = LWE.encrypt_message(key_pair.public, m)
    nm = cipher.decrypt_message(ct)
    print(nm)
    assert nm == m

