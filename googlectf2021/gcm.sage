from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import base64
G.<x> = GF(2**128, modulus=x^128+x^7+x^2+x+1)

def i2e(ii):
    res = 0
    for i in range(128):
        res += (ii & 1) * (x ^ (127 - i))
        ii >>= 1
    return res

def e2i(e):
    res = 0
    integer = e.integer_representation()
    for i in range(128):
        res = (res << 1) + (integer & 1)
        integer >>= 1
    return res

def e2ib(e):
    res = 0
    integer = e.list()
    for i in range(128):
        res = (res << 1) + (integer[i] == 1)
    return res

def bxor(a,b):
    return i2e(e2i(a).__xor__(e2i(b)))

def enc(K):
    N = b""
    AD = b""
    M = b"\x00"*16
    Ek = AES.new(K, AES.MODE_ECB).encrypt
    H = i2e(bytes_to_long(Ek(b'\x00'*16)))
    print("H", e2i(H))
    P = i2e(bytes_to_long(Ek(b'\x00'*15+b'\x01')))
    L = i2e(len(M)*8)
    T = (L * H) + P
    print(e2i(L*H))
    m = i2e(1); a = i2e(0)
    b = i2e(1);
    #for i in range(a):
    #    T = T ^^ (0)
    #for i in range(m):
    C = i2e(bytes_to_long(Ek(long_to_bytes(2).rjust(16,b"\x00")))) + i2e(bytes_to_long(M))
    T = T + (C * H**(2))
    print(e2i(T))
    return N.encode("hex"), long_to_bytes(e2i(C)).encode("hex"), long_to_bytes(e2i(T)).encode("hex")

def interpolate(pairs):
    x_values, y_values = zip(*pairs)
    k = len(x_values)
    def _basis(j):
        p = [(x - x_values[m])/(x_values[j] - x_values[m]) for m in range(k) if m != j]
        return reduce(operator.mul, p)
    assert len(x_values) != 0 and (len(x_values) == len(y_values)), 'x and y cannot be empty and must have the same length'
    k = len(x_values)
    return sum(_basis(j)*y_values[j] for j in range(k))

def multi_collide_gcm(K,N,T):
    T = i2e(bytes_to_long(T))
    L = i2e((len(K)-1)*128)
    pairs = []; C = b""
    for i in range(len(K)):
        #print("Processing --- " + K[i].encode("hex"))
        Ek = AES.new(K[i], AES.MODE_ECB).encrypt
        H = bytes_to_long(Ek(b"\x00"*16))
        P = bytes_to_long(Ek(N+b'\x00'*3+b'\x01'))
        H = i2e(H); P = i2e(P)
        y = (((L*H)+P)+T)*(H**-2)
        pairs.append((H,y))
    f = G['x'].lagrange_polynomial(pairs)
    #f = interpolate(pairs)
    v = f.coefficients(sparse=False)
    #v = [e2i(e) for e in f]
    for i in range(len(K)):
        C += long_to_bytes(e2i(v[len(K)-i-1])).ljust(16,b"\x00")
    return C

import binascii
keyset = []
with open("keys", "r") as f:
    for line in f:
        keyset.append(binascii.unhexlify(line.rstrip()))

while True:
    a,b = Integer(input("start: ")), Integer(input("end: "))
    res = multi_collide_gcm(keyset[a:b],b"\x00"*12,b"\x00"*16)
    with open("cache2/%d_%d" % (a,b), "wb") as f:
        f.write(base64.b64encode(res))
    print("Done")
