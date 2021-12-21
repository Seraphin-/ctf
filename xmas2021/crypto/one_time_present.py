# One Time Present (crypto 494)
# X-MAS{bu7_1_7h0u6h7_7h47_0n3_71m3_P4dS_4r3_supP0S3d_70_b3_s3CUR3_Jv903eRJV98}

# The challenge gives us a binary which encrypts the flag repeatedly using a "fresh" one time pad key every time we query it. It seems to perform some checks on the key/ciphertext, so I completely guessed that it won't encrypt a byte to the plaintext.
# It seems like I was right?

# We solve the challenge by repeatedly quering for ciphertexts until we can identify which byte does not show up in ciphertexts.

from pwn import *
import json

#r = process(["./chall"])
r = remote("challs.xmas.htsp.ro", 1037)
r.recvuntil(b"Awaiting your input: ")
flag = []
bb = []
for _ in range(77):
    bb.append(set())
while not all(len(b) == 255 for b in bb):
    r.sendline("")
    t = r.recvuntil(b"Awaiting your input: ").decode().split("\n")[0]
    for i, byte in enumerate(bytes.fromhex(t)):
        if byte not in bb[i]:
            bb[i].add(byte)
            with open("progress.json", "w") as f:
                f.write(json.dumps([list(b) for b in bb]))

ab = set(range(256))
for b in bb:
    s = list(ab - b)
    flag.append(s[0])

print(bytes(flag))

