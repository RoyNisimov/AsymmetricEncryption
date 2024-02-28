from AsymmetricEncryptions.PublicPrivateKey.LWE import LWEKey, LWE

if __name__ == '__main__':
    # generation
    key_pair = LWEKey.new(128)
    # encryption
    m = b"test"
    cipher = LWE(key_pair)
    ciphertxt = LWE.encrypt_message(key_pair.public, m)
    plaintext = cipher.decrypt_message(ciphertxt)
    print(plaintext)
    assert plaintext == m

    # exportation
    key_pair.export("test.txt", b"super secret")
    new_key = LWEKey.load("test.txt", b"super secret")
    assert new_key == key_pair