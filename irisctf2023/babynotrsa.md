# babynotrsa (Crypto)
> Everyone knows [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), but everyone also knows that RSA is slow. Why not just use a faster operation than exponentiation?

This is a baby challenge claiming to implement a faster RSA using a faster operation. The intent was to a have a baby challenge that required people to learn how basic operations over a finite ring work.

The challenge generates a normal RSA modulus `n=pq` for 1024-bit p and q primes. An encryptionn key is randomly picked below n, and the flag is encrypted as `flag * e` instead of `flag ^ e`.

```py
from Crypto.Util.number import getStrongPrime

# We get 2 1024-bit primes
p = getStrongPrime(1024)
q = getStrongPrime(1024)

# We calculate the modulus
n = p*q

# We generate our encryption key
import secrets
e = secrets.randbelow(n) # <-- technically breaks the scheme if e in {p, q, 0, 1}

# We take our input
flag = b"irisctf{REDACTED_REDACTED_REDACTED}"
assert len(flag) == 35
# and convert it to a number
flag = int.from_bytes(flag, byteorder='big')

# We encrypt our input
encrypted = (flag * e) % n # <-- the encryption is multiplication
```

You can just divide the encrypted flag by the key as follows:
- Calculate `d = -e mod n` - [Wikipedia](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) shows how to do it, or in Python Cryptodome's `Util.number.inverse` function can do it 
- Multiply encrypted flag by `d`, which is `1/e`. Then `encrypted * d = flag * e * (1 / e) = flag`

More advanced solvers would probably just do it in Sage, which has abstractions for easily working in rings, like so:
```py
R = Zmod(n)
flag = R(encrypted) / e
```

```
irisctf{discrete_divide_isn't_hard}
```
