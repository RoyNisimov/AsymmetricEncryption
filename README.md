# WARNING
This is probably hazards because I don't know best practices.
I write this only for fun and learning.
Do not use it on real things.
Checkout Pycryptodome [here](https://github.com/Legrandin/pycryptodome) and [here](https://pycryptodome.readthedocs.io/en/latest/)


# Asymmetric-Encryption
Asymmetric encryption uses two keys, one public, one private.
You can encrypt with the public key and only decrypt with the private key.
You can also sign with them.

# Table of contents

---
| Algorithm    | Code            | Math behind it  |
|---------------|-----------------|-----------------|
| [RSA](#rsa)   | [Code](#code)   | [Math](#math)   |
---

# Math symbols
- Pow : **
- Modulo / Mod : %


# General
- [Prime Number Generator](https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/)


---

# RSA
RSA stands for Rivest–Shamir–Adleman, the three people who invented it (Ron Rivest, Adi Shamir, and Leonard Adleman).

RSA is considered one of the best asymmetric crypto systems.
Used for authentication and Diffie-Hellman exchanges.

Problems:
If m >= n then the encryption wouldn't work

- [code here](#code)
- [math here](#math)
## Math
```
==============================================
                   Generate
----------------------------------------------
let p and q be prime numbers
let n = p * q
let tot(n) = (p - 1) * (q - 1)
let e be prime number such that 2 < e < tot_n -1 and gcd(e, tot_n) == 1
let d = e**-1 % tot_n
        |
        ⌄
It took me ages to figure out what that means.
Bassicly if you do e * d and then mod it by tot_n you get 1.
e and d must be inteager primes.
For example:
p = 5 // Prime should be a lot larger this is for example. 
q = 7 // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
n = 35 // p * q, 5 * 7 = 35
tot_n = 24 // (p - 1) * (q - 1), (5 - 1) * (7 - 1) = 4 * 6 = 24
e = 5 // greatest common denemenator between tot_n and e is 1
(e * d) % tot_n = 1
d = 5 // 5 * 5 = 25, 25 % 24 is 1


Public: e, n
Private: p, q, tot_n, d
==============================================
                   Encryption
----------------------------------------------
c = m**e % n
==============================================
                   Decryption
----------------------------------------------
m = c**d % n
==============================================
                   Signature
----------------------------------------------
s = m**d % n
==============================================
                    Verify 
----------------------------------------------
v = s**e % n
m == v
==============================================
```
## Code
**WARNING:** This is the bare bones RSA with OAEP (If you pad it with OAEP)
```python
from AsymmetricEncryption import RSA
from AsymmetricEncryption.General.OAEP import OAEP

message: bytes = b"RSA test"

# pad
message = OAEP.oaep_pad(message)
print(message)
# Key generation
priv, pub = RSA.generate_key_pair(1024)
print(priv)
print(pub)
# Encryption (Assume we don't have the private key)
cipher = RSA(pub)
encrypted_msg: bytes = cipher.encrypt(message)

# decryption (we must have the private key (d))
cipher = RSA(priv)
msg: bytes = cipher.decrypt(encrypted_msg)
# make sure to use OAEP.oaep_unpad on msg

# Test
print(OAEP.oaep_unpad(msg))
print(message)
print(msg)
print(msg == message)  # True

# Sign
cipher = RSA(priv)
s: bytes = cipher.sign(msg)
cipher.verify(s, msg)
# Verify (Will throw and error if it isn't auth)


```
# OAEP





