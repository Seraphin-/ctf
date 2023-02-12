from pwn import *
import numpy as np

n = 20
def stov(s):
    return np.array([ord(c)-32 for c in s])
def vtos(v):
    return ''.join([chr(v[i]+32) for i in range(n)])

def encrypt(s):
    return vtos(np.matmul(A, stov(s))%95)

r = remote("lac.tf", 31141)
b = bytearray(b'@'*13)

r.recvuntil(b"reads:\n")
flag1 = stov(r.recvline().decode()[:20])

r.recvuntil(b"your guess: ")
r.sendline(b"lactf{" + b + b"}")
basis = stov(r.recvline().decode()[:20])
A = []
for i in range(13):
    bm = bytearray(b)
    bm[i] = ord('`')
    r.recvuntil(b"your guess: ")
    r.sendline(b"lactf{" + bm + b"}")
    l = r.recvline().decode()[:20]
    print("l", l)
    A.append(((basis - stov(l)))%95)

from sage.all import matrix, Zmod, vector, ZZ
F = Zmod(95)

A = np.array(A).T
print(A)
AA = matrix(F, A)
V = vector(F, basis)
print(AA, V)
c = AA.solve_right(V)
print("C", c)
Vf = vector(F, flag1)
cI = vector(F, [i+65-2 for i in c])
print("CI", cI)
AcI = AA*(cI)
AcI %= 95
print("ACI", AcI)
Vff = Vf - AcI
print("V-ACI", Vff)

r.recvuntil(b"Encrypt me:\n")
query = r.recvline().decode()[:20]
q = stov(query)[6:-1]
print(q)
Vq = AA * vector(F,q) + Vff
print(Vq)
r.sendline(vtos(Vq.change_ring(ZZ)))

r.interactive()
