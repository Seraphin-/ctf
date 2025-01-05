# AYES (Crypto, easy)

> Something is a bit off with my AES implementation. Get it?
> 
> AES implementation is directly from [here](https://github.com/boppreh/aes).

## Challenge
This was the "easy" challenge I made, though it got less than the challenge I marked as medium. It provides an AES scheme and oracle to request up to $2^{12}$ single block encryptions of plaintext. In order to get the flag, you need to provide a string which encrypts to the key.

At the start of a session, the challenge prompts for a bit index which corresponds to a single bit in the AES S-box to flip. Otherwise, the implementation of AES is normal.

## Solution
The intended solution revolves around the AES S-box not being an one-to-one function if a bit is flipped. Since the S-Box has 256 entries, any bit flip (regardless of the chosen index) results in 2 input values mapping to the same output value.

Let's consider what happens in AES and what the implications of this are. The first step in AES is expanding the AES key to round keys $\texttt{ExpandRoundKey}(K) = \\{ RK_0, ..., RK_{10} \\}$, but our bit flip has no interaction with this step so there's nothing to exploit. Next, the AES initial AES round key ($RK_0$) is xor-ed once with the initial input state $P$. This is the input to the first AES round; and the first step there is applying the S-box to this state. This is the first place the challenge's bit flip matters and what we'll attack. We'll call the byte index (S-box input) where a bit was flipped $B_f$ s.t. $\texttt{S-box}[B_f]=B_f'$, and the other byte index mapping to the output $B_o$ s.t. $\texttt{S-box}[B_o]=B_f'$.

The contents of the state are now $state = \texttt{SubBytes}(K \oplus P)$. However, since our S-box is no longer one-to-one, the output of this is not unique. Specifically, when $K \oplus P$ contains $B_f$ or $B_o$ at position $i$, it produces the same output. The rest of the algorithm continues normally, but from this point the encryption output between $P$ and $P ^ B_o = P ^ B_f$ is the same! This means we can construct an oracle that tells us if $P \oplus RK_0 \in \{B_o, B_f\}$.

Let $P$ be any arbitrary input block. For each position $i$, we can find two guesses for $RK_0[i] = \\{G, G \oplus B_f \\}$ by querying $P \oplus bit$ for $bit \in {0, ..., 255}$ and noting which calls to the encryption oracle produce the same encrypted text (we can also stop with an index once we see a repeat). Doing this for all positions gives us $2^{16}$ possible values for $RK_0$ in $256*16$ queries. But isn't what we need is the complete key, not $RK_0$? Well, the first round key is helpfully identical to the AES key $K$!

We can test each possible guess for $K = RK_0$ by computing whether it produces the same encryption for an input as the server; if it was correct, we can simply decrypt the key to produce the input to get the flag. If the value of the key cannot be decrypted correctly (due to encryption no longer being correctly defined, we can try a new session).

Solve:

```py
# Picked 28 bit 7 since it makes it easy to invert lol

import itertools
from pwn import *
import aes
r = remote("ayes.chal.irisc.tf", 10100)
r.sendlineafter(b"> ", str(28*8+0))

bit = 28 * 8
bits = list(bin(int.from_bytes(bytes(aes.s_box), "big"))[2:].rjust(256 * 8, '0'))
bits[bit] = "1" if bits[bit] == "0" else "0"
aes.s_box = int(''.join(bits), 2).to_bytes(256, "big")
aes.inv_s_box = list(aes.inv_s_box)
aes.inv_s_box[28] = 28

# known val
r.recvuntil(b"> ")
known_pt = b"\xff" * 16
r.sendline(bytes(known_pt).hex())
known = bytes.fromhex(r.recvline().decode()[:-1])

b = [0] * 16
seen = {}
key = []
for i in range(16):
    for bit in range(256):
        c = list(b)
        c[i] = bit
        r.recvuntil(b"> ")
        r.sendline(bytes(c).hex())
        d = r.recvline()
        if d in seen:
            print(d, "!!!", i, bit)
            break
        seen[d] = bit
    # one of these
    key.append(((196 ^ bit) & 0xff, (196 ^ seen[d]) & 0xff))
    seen = {}

print(key)
# brute force real key
for choice in itertools.product([0, 1], repeat=len(key)):
    assembled = bytes([k[bit] for k, bit in zip(key, choice)])
    a = aes.AES(assembled)
    if a.encrypt_block(known_pt) == known:
        print(assembled)
        r.sendline(a.decrypt_block(assembled).hex())
        r.interactive()
        exit()
```

Flag: `irisctf{the_first_round_really_is_the_key}`
