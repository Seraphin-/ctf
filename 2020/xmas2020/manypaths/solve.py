# Many Paths (Programming 167, 86)

from numpy.core.numeric import concatenate, isscalar, binary_repr, identity, asanyarray, dot
from numpy.core.numerictypes import issubdtype
from numpy.core import fromstring
from pwn import *
import time

# Use this: https://stackoverflow.com/questions/14237593/all-paths-of-given-length-between-two-given-nodes-in-a-graph
# Implementation stolen from: https://stackoverflow.com/questions/8514565/numpy-matrix-power-exponent-with-modulo
# This one even provides the binary decompositon
def matrix_power(M, n, mod_val):
    # Implementation shadows numpy's matrix_power, but with modulo included
    M = asanyarray(M)
    if len(M.shape) != 2 or M.shape[0] != M.shape[1]:
        raise ValueError("input  must be a square array")
    if not issubdtype(type(n), int):
        raise TypeError("exponent must be an integer")

    from numpy.linalg import inv

    if n==0:
        M = M.copy()
        M[:] = identity(M.shape[0])
        return M
    elif n<0:
        M = inv(M)
        n *= -1

    result = M % mod_val
    if n <= 3:
        for _ in range(n-1):
            result = dot(result, M) % mod_val
        return result

    # binary decompositon to reduce the number of matrix
    # multiplications for n > 3
    beta = binary_repr(n)
    Z, q, t = M, 0, len(beta)
    while beta[t-q-1] == '0':
        Z = dot(Z, Z) % mod_val
        q += 1
    result = Z
    for k in range(q+1, t):
        Z = dot(Z, Z) % mod_val
        if beta[t-k-1] == '1':
            result = dot(result, Z) % mod_val
    return result % mod_val

t1 = time.time()
r = remote('challs.xmas.htsp.ro', 6053)
p = log.progress("Solving")
for i in range(40):
    p.status("#%.2d/40 %.2d/45s" % (i+1, int(time.time() - t1)))
    s = r.recvuntil("/40\n")
    N = int(r.recvline()[4:-1])
    r.recvuntil("adjacency matrix:\n")
    raw_matrix = ','.join(r.recvuntil("f")[:-2].decode().split("\n"))
    matrix = fromstring(raw_matrix, dtype=int, sep=',').reshape(N, N)
    # forbidden = eval(r.recvuntil("\n")[])
    r.recvuntil("\n") # Why do we care? It's zeroed anyway
    L = int(r.recvline()[4:-1])
    # We would zero transitions to forbidden node (Nth column), but they did it for us
    matrix = matrix_power(matrix, L, 666013)
    r.sendline(str(matrix[0][N-1]))
p.success("Done.")

flag = r.recvuntil("}").decode().split("\n")[-1].split(": ")[-1]
log.success(flag)

# Flag: X-MAS{n0b0dy_3xp3c73d_th3_m47r1x_3xp0n3n71a7i0n}
