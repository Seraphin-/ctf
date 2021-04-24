from math import ceil
from cipher_solver.simple import SimpleSolver

with open("./content.enc.txt") as f:
    CIPHERTEXT = f.read().rstrip()

def untranspose(x, l):
    # Oh god I'm so sorry
    ll = ceil(len(x) / l)
    A = [["_" for _ in range(l)] for _ in range(ll)]
    ni = 0
    for i in range(ll):
        for j in range(l):
            if i * l + j < len(x):
                A[i][j] = "X"
    for i in range(l):
        for j in range(ll):
            if A[j][i] == 'X':
                A[j][i] = x[ni]
                ni += 1
    r = ""
    for i in range(ll):
        for j in range(l):
            if A[i][j] != "_":
                r += A[i][j]
    return r

for L in range(1, 100):
    ct = untranspose(CIPHERTEXT, L)
    assert len(ct) == len(CIPHERTEXT)
    s = SimpleSolver(ct)
    s.solve()
    pt = s.plaintext()
    if pt[0] != "Z":
        print(pt)

# CHTB{UNFORTUNATELYQUIPQIUPDOESNTSUPPORTTRANSPOSITIONS}
