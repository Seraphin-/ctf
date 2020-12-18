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
