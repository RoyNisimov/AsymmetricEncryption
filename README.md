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
| [DSA](#dsa)         | [Code](#dsa-code)     | [Math](#dsa-math)     |
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
**WARNING:** This is the bare bones ElGamal with OAEP (If you pad it with OAEP)
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
encrypted_msg = cipher.encrypt(message)

# decryption (we must have the private key (d))
cipher = ElGamal(priv)
msg: bytes = cipher.decrypt(encrypted_msg)
# make sure to use OAEP.oaep_unpad on msg

# Test
print(OAEP.oaep_unpad(msg))
print(message)
print(msg)
print(msg == message)  # True

# Sign
cipher = ElGamal(priv)
signature = cipher.sign(msg)
cipher.verify(signature)
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

# DSA
The Digital Signature Algorithm (DSA) is a public-key cryptosystem and Federal Information Processing Standard for digital signatures, based on the mathematical concept of modular exponentiation and the discrete logarithm problem. DSA is a variant of the Schnorr and ElGamal signature schemes.

All the math was taken straight from Wikipedia. Read more [here](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)

**DSA is a signature only algorithm, no encryption and key exchange**

- [code here](#dsa-code)
- [math here](#dsa-math)
## DSA Math
```
                           The math of DSA
------------------------------------------------------------------------
The math is very complex.
Good luck.
        
                            Key generation
------------------------------------------------------------------------
Key generation has two phases. 
The first phase is a choice of algorithm parameters which may be shared between different users of the system.
The second phase computes a single key pair for one user.

First phase (paramaters)
------------------------------
1. Choose an aproved hash function (I chose Sha256) H that outputs |H| bits (256)
2. Choose a key length L (1024 without any change).
(2048 or 3072 is considered safer for life long until 2030)
3. Choose modulus N such that N < L and 0 < N <= |H|
Tricky part:
4. Choose N-bit prime q
5. Choose L-bit prime p such that (p -1) % q == 0
End of tricky part.
6. Choose 0 < h < p - 2
7. Compute g = h**((p-1)//q) % p
{p, q, g} may be shared.

Second phase (Actuall key gen)
-------------------------------
1. Choose private key x such that 0 < x < q -1
2. Compute public key y, y = g**x % p

                            Signing
------------------------------------------------------------------------
m = message as an int
1. Choose an integer k randomly from {1... q-1}
2. Compute r = (g**k % p) % q
3. Compute s = ((k**-1 % q) * (H(m) + x * r)) % q
4. If s == 0 or r == 0: start over with a different k
Sig = (r, s)
                            Verifying
------------------------------------------------------------------------
m = message as an int
1. Verify that 0 < r < q, 0 < s < q
2. Compute W = s**-1 % q
3. Compute U1 = (H(m) * w) % q
4. Compute U2 = (r * w) % q
5. Compute V = (((g**u1 % p) * (y**u2 % p)) % p) % q
The signature is valid if and only if V == r
------------------------------------------------------------------------

```


## DSA Code
**WARNING:** I made this with some questionable decisions, this algorithm is complex, please use [PyCryptodome implementation](https://pycryptodome.readthedocs.io/en/latest/src/public_key/dsa.html) or use [RSA](#rsa) instead.
```python
from AsymmetricEncryption.DSA import DSA

message: bytes = b"DSA test"

# Key generation, Will take longer if the nBit is large and is not 1024, 2048, or 3072
# An extra bool (use_precalculated) is equal to true, this is to save time, you can turn it off though.
priv, pub = DSA.generate_key_pair(1024)
print(priv)
print(pub)

# Sign
cipher = DSA(priv)
sig = cipher.sign(message)
cipher.verify(sig, message)
# Verify (Will throw and error if it isn't auth)
```
**WARNING:** The exportation process is dumping it to JSON, then XOR it with the pwd.
The HMAC is then put before it.


You can export and load keys like this:
```python
from AsymmetricEncryption.DSA import DSA, DSAKey
priv, pub = DSA.generate_key_pair()
priv.export(file_name="file_name.txt", pwd=b"test")
DSAKey.load(file_name="file_name.txt", pwd=b"test")
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








