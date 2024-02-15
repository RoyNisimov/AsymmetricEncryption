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
| Algorithm           | Code                  | Math behind it        |
|---------------------|-----------------------|-----------------------|
| [RSA](#rsa)         | [Code](#rsa-code)     | [Math](#rsa-math)     |
| [ElGamal](#elgamal) | [Code](#elgamal-code) | [Math](#elgamal-math) |
| [OAEP](#oaep)       | [Code](#oaep-code)    | [Math](#oaep-math)    |
---

# Math symbols
- Pow : **
- Modulo / Mod : %
- XOR: ^
- Append: ||


# General
- [Prime Number Generator](https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/)
- [Repeating key xor \ OTP (one-time-pad): symmetric](https://www.geeksforgeeks.org/encrypt-using-xor-cipher-with-repeating-key/)
- [OAEP](#oaep) [here](https://www.youtube.com/watch?v=ZwPGE5GgG_E) and [here](https://www.youtube.com/watch?v=bU4so01qMP4)

---

# RSA
RSA stands for Rivest–Shamir–Adleman, the three people who invented it (Ron Rivest, Adi Shamir, and Leonard Adleman).

RSA is considered one of the best asymmetric crypto systems.
Used for authentication and Diffie-Hellman exchanges.

Problems:
If m >= n then the encryption wouldn't work

- [code here](#rsa-code)
- [math here](#rsa-math)
## RSA Math
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
## RSA Code
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
**WARNING:** The exportation process is dumping it to JSON, then XOR it with the pwd.
The HMAC is then put before it.


You can export and load keys like this:
```python
from AsymmetricEncryption.RSA import RSA, RSAKey
priv, pub = RSA.generate_key_pair(1024)
priv.export(file_name="file_name.txt", pwd=b"test")
RSAKey.load(file_name="file_name.txt", pwd=b"test")
# load will throw an assertion error if the HMACs aren't the same
```
# ElGamal
ElGamal was invented in 1985 by [Taher Elgamal](https://en.wikipedia.org/wiki/Taher_Elgamal).
Read more [here](https://en.wikipedia.org/wiki/ElGamal_encryption)



- [code here](#elgamal-code)
- [math here](#elgamal-math)
## ElGamal Math
```
                        The math of ElGamal
------------------------------------------------------------------------

                          Key Generation
------------------------------------------------------------------------
Let p = large prime number
Let g = 1 < g < p-1
Let x = 1 < x < p-1
Let y = g**x % p

Public = {p,g,y}
Private = {x}

                            Encryption
------------------------------------------------------------------------

m = message < p
Let b = 2 < b < p-1
C1 = g**b % p
C2 = (m * y**b) % p

                            Decryption
------------------------------------------------------------------------

XM = C1**x % p
m = (C2 * XM**(p-2)) % p

                             Signing
------------------------------------------------------------------------
m = message
k = 0 < k < p
s1 = g**k % p
phi = p - 1
mod_inv = k ** -1 % phi // pow(k, -1, phi) or mod_inv*k % phi == 1
s2 = (mod_inv * (m - x * s1)) % phi

Send {m, s1, s2}
Keep k private

                             Verifying
------------------------------------------------------------------------
V = y**s1 * s1**s2 % p
W = g**m % p
If V == W then the message was signed by the private key



                              Example
------------------------------------------------------------------------

Let p = 23
Let g = 6
Let x = 8
Let y = 6**8 % 23 = 18

m = 4
Let b = 3
C1 = 6**3 % 23 = 9
C2 = (4 * 18**3) % 23 = 6

XM = 9**8 % 23 = 13
m = (6 * 13**21) % 23 = 4

Sign 
m = 5
k = 3
s1 = g**k % m = 9
phi_n = p-1 = 22
inv = k**-1 % phi_n = 15
s2 = (inv * (m - x * s1)) % phi_n = 7

Verify
V = (18**9 * 9**7) % 23 = 2
W = 6**5 % 23 = 2

The message is authentic
```
## ElGamal Code
**WARNING:** This is the bare bones RSA with OAEP (If you pad it with OAEP)
```python
from AsymmetricEncryption.ElGamal import ElGamal
from AsymmetricEncryption.General.OAEP import OAEP

message: bytes = b"ElGamal test"

# pad
message = OAEP.oaep_pad(message)
print(message)
# Key generation
priv, pub = ElGamal.generate_key_pair(1024)
print(priv)
print(pub)
# Encryption (Assume we don't have the private key)
cipher = ElGamal(pub)
c1, c2 = cipher.encrypt(message)

# decryption (we must have the private key (d))
cipher = ElGamal(priv)
msg: bytes = cipher.decrypt(c1, c2)
# make sure to use OAEP.oaep_unpad on msg

# Test
print(OAEP.oaep_unpad(msg))
print(message)
print(msg)
print(msg == message)  # True

# Sign
cipher = ElGamal(priv)
s1, s2, m = cipher.sign(msg)
cipher.verify(s1, s2, m)
# Verify (Will throw and error if it isn't auth)
```
**WARNING:** The exportation process is dumping it to JSON, then XOR it with the pwd.
The HMAC is then put before it.


You can export and load keys like this:
```python
from AsymmetricEncryption.ElGamal import ElGamalKey, ElGamal
priv, pub = ElGamal.generate_key_pair(1024)
priv.export(file_name="file_name.txt", pwd=b"test")
ElGamalKey.load(file_name="file_name.txt", pwd=b"test")
# load will throw an assertion error if the HMACs aren't the same
```



# OAEP
```
O-ptimal
A-symmetric
E-ncryption
P-adding
```
[Here](https://www.youtube.com/watch?v=ZwPGE5GgG_E) and [Here](https://www.youtube.com/watch?v=bU4so01qMP4)
## OAEP Math
![image](https://miro.medium.com/v2/resize:fit:1358/1*ppgvPx2BA-Il2w9aZhRrWw.png)
```
G(x) |
     | -> hash functions outputing g and h bits
H(H) |

Pad
================================
r -> random nonce of g bits
m = m || 0**(g-len(m))
x = m ^ G(r)
y = H(X) ^ r
p =  x || y
remember that x and y are g and h bits long
--------------------------------
Unpad
================================
x = p[:g]
y = p[g:]
r = H(X) ^ y
m = x ^ G(r)
```

## OAEP Code
```python 
from AsymmetricEncryption.General import OAEP
msg = b"OAEP"
padded = OAEP.oaep_pad(msg)
print(padded)
unpadded = OAEP.oaep_unpad(padded)
print(unpadded)
print(unpadded == msg) # True if the msg is small 
```








