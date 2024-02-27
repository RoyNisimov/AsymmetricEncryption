from AsymmetricEncryptions.Protocols.OT1O2 import ObliviousTransfer

if __name__ == '__main__':
    # Alice
    otProt = ObliviousTransfer(b"test A", b"test B")
    sendBob = otProt.Stage1and2and3()
    # Bob
    b = int(input("Choice 0 or 1: ")) % 2
    AlicePubKey = sendBob[0]
    sendAlice, keepPrivate = ObliviousTransfer.Stage4and5(sendBob, b)
    # Alice
    sendBob = otProt.Stage6and7(sendAlice)
    # Bob
    m = ObliviousTransfer.Stage8(sendBob, keepPrivate, b, AlicePubKey)
    print(m)