# provably secure 1 (crypto)
# dice{yeah_I_lost_like_10_points_on_that_proof_lmao}
# seen check doesn't work, so you can just decrypt

from pwn import *

r = remote("mc.ax", 31493)
a="00000000000000000000000000000000"
b="11111111111111111111111111111111"
r.recvuntil(b"Actions:")
while True:
    r.recvuntil(b"Action")
    r.sendline(b"1")
    r.sendline(a.encode() + b"\n" + b.encode())
    p = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1]
    r.sendline(b"2")
    r.sendline(p)
    p = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1]
    if p.decode() == a: 
        r.sendline(b"0\n0")
    else:
        r.sendline(b"0\n1")
