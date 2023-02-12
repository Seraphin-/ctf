from pwn import *

r = remote("lac.tf", 31190)
while True:
    r.recvuntil(b"c =  ")
    c = Integer(r.recvline().decode())
    counts = 0
    while c % 6 == 0:
        counts += 1
        c //= 6
    r.sendline(str(counts % 2).encode())
