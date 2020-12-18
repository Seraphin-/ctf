# Lost List (Crypto 396, 48 solves)

## Recon
We open the provided pcap to see the log of a single hex command being sent to the server.
The result of the command looks like the output of `ls`.

## Solving
The first thing to do is simply decode the hex string. There's a sixteen byte string followed by what appears to be 16 bytes of encrypted data. The first string says it's an IV, and along with the block size of 16 it's pretty easy to assume it's AES-128-CBC. In particular, "IV" usually refers to CBC, nonce is used for a lot of other modes/block ciphers.

## The attack
At this point we know the plaintext (which is `ls`, padded to block size) and the IV ("Santa's1337IV420"). The ciphertext is *only one block long*.

We have no idea what the key is, but this information is sufficient to forge any message we want! Consider [the way CBC works](https://en.wikipedia.org/wiki/File:CBC_decryption.svg).

The first block of plaintext is the result of IV xor the actual AES decryption of the ciphertext, let's call it I. Notice that since we know the plaintext P, we can find `I=IV xor P`. With this, we can simply xor I with another value to produce any plaintext we want! This is completely independent of the ciphertext itself. Let's call our modified IV IV' and the target plaintext P'. Then, `IV' = P' xor I = P' xor P xor IV`. That's it!

We still have one problem, which is that the known plaintext is 2 bytes but the blocksize is 16 bytes. What are the rest of the bytes? We can try null bytes, but we'll find out this doesn't work.
The normal way to pad AES is [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS%235_and_PKCS%237). In this system, `ls` is padded to `ls + "\x0e" * 14`. Using this plaintext to produce IV' as above allows us to run commands!

## Shell escape
At this point, trying to `cat key.py` produces a "Command not found", which is obviously bullshit. So we need to try something else. `help` produces a normal output, so we look around with `ls /bin` to see which binaries we can try. It turns out `awk` is avaliable, so we can use `awk '//' \*` to read everything in the current directory.

At the end of the output, we find our flag (along with the server code and key):
```
X-MAS{s33ms_1ik3_y0u_4r3_0n_7h3_1is7_700_h0_h0_h0}
```

Solution script:
```python
from pwn import *

iv = bytes.fromhex("53616e74612773313333374956343230")
plaintext = b"ls" + b"\x0e" * 14
ciphertext = "ab0c288b0ae26eaf8adbcf00bddf35fa"

def rewrite(iv, plaintext, target):
    newiv = bytearray(iv)
    assert len(target) <= 16
    target += bytes([16-len(target)]) * (16-len(target)) # pad
    for i in range(16):
        newiv[i] = target[i] ^ plaintext[i] ^ iv[i]
    return newiv

r = remote("challs.xmas.htsp.ro", 1002)
# Alternatively "awk '//' *" for everything :)
payload = rewrite(iv, plaintext, b"awk '//' nice").hex() + ciphertext
r.sendlineafter("~$ ", payload)

flag = r.recvuntil("}").decode().split("\n")[-1]
log.success("Flag: " + flag)
```
