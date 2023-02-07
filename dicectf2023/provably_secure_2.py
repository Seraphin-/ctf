# provably secure 2 (crypto)
# dice{my_professor_would_not_be_proud_of_me}
# recover msg with some xor combinations

from pwn import *

r = remote("mc.ax", 31497)
a="00000000000000000000000000000000"
b="11111111111111111111111111111111"
aa = bytes.fromhex(a)
r.recvuntil(b"Actions:")
while True:
    r.recvuntil(b"Action")
    cts = []
    for _ in range(3):
        r.sendline(b"1")
        r.sendline(a.encode() + b"\n" + b.encode())
        p = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1]
        cts.append(p)

    # c2[0] + c3[1]
    r.sendline(b"2")
    r.sendline(cts[1][:512] + cts[2][512:])
    d1 = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1].decode()
    # c2[0] + c1[1]
    r.sendline(b"2")
    r.sendline(cts[1][:512] + cts[0][512:])
    d2 = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1].decode()
    # c3[0] + c1[1]
    r.sendline(b"2")
    r.sendline(cts[2][:512] + cts[0][512:])
    d3 = r.recvuntil(b"\nAction",drop=True).split(b": ")[-1].decode()

    p = xor(xor(bytes.fromhex(d1), bytes.fromhex(d2)), bytes.fromhex(d3))
    print(p)

    if p == aa: 
        r.sendline(b"0\n0")
    else:
        r.sendline(b"0\n1")
