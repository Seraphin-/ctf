import numpy as np
from pwn import *
n=20

def stov(s):
    return np.array([ord(c)-32 for c in s])
def vtos(v):
    return ''.join([chr(v[i]+32) for i in range(n)])

def encrypt(s):
    return vtos(np.matmul(A, stov(s))%95)

#r = process(['python3', './hill_easy.py'])
r = remote("lac.tf", 31140)
A=[]
b=bytearray(b' '*20)
for i in range(10):
    r.recvuntil(b"your guess: ")
    bm = bytearray(b)
    bm[i*2] = 33
    r.send(bm)
    bm = bytearray(b)
    bm[i*2+1] = 33
    r.sendline(bm)
    r.recvline()
    s1 = r.recvline().decode()[:20]
    s2 = r.recvline().decode()[:20]
    A.append(stov(s1))
    A.append(stov(s2))

A = np.array(A).T
print(A)

r.recvline()
r.recvline()
r.recvline()
r.recvline()
target = r.recvline().decode()[:-1]
r.sendline(encrypt(target[:20]))
r.sendline(encrypt(target[20:]))
r.interactive()
