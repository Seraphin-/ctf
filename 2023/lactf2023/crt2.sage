from pwn import *

r = remote('lac.tf', 31111)
p = Integer(r.recvline().decode())
q = Integer(r.recvline().decode())
r.sendline(b"1")
r.recvuntil(b'Type your modulus here: ')
r.sendline(str(p).encode())
a = Integer(r.recvline().decode().strip())
r.sendline(b"1")
r.recvuntil(b'Type your modulus here: ')
r.sendline(str(q).encode())
b = Integer(r.recvline().decode().strip())
r.sendline(b"2")
for i in range(31):
    try:
        m = CRT_list([a,b,i%2,i%3,i%5],[p,q,2,3,5])
    except ValueError:
        continue 
    r.recvuntil(b"Type")
    r.sendline(str(m).encode())
