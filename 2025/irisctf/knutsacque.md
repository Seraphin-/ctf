# knutsacque (Crypto, medium)

> Behold my original knut sacque scheme in 4D

## Challenge
The challenge computes the output of a knapsack sum problem on the flag; with the catch being that the sum is done over quaternions (4-dimensional vectors represented as $a\*1+b\*i+c\*j+d\*k$). The flag is split up into chunks for 4 bytes $[a, b, c, d]$ and mapped to quaternions. The problem coefficients are chosen randomly from $[0, 2^{64})$. The output is given as simply the coefficients and flag sum output.

## Solution
It is well known that knapsack problems can be solved using lattice reduction, so I won't cover this aspect of the solution. Here are some good resources for this:
- [Lattice Reduction Attack on the Knapsack](https://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf)
- [Practice lattice reductions for CTF challenges](https://ur4ndom.dev/static/files/latticetraining/practical_lattice_reductions.pdf)
- [A Gentle Tutorial for Lattice-Based Cryptanalysis](https://eprint.iacr.org/2023/032.pdf).

The density of the matrix is quite low, so it should be reasonable to use LLL. However, the LLL algorithm implemented in most mathematical software packages only supports coefficients in $Z$, but our coefficients are quaternions with integer coefficients (known sometimes as "Hurwitz" or more specifically "Lipschitz" quarternions). In general, LLL is possible to implement over norm-Euclidean fields, so it is possible to directly implement LLL on Hurwitz quaternions; but we will instead solve by embedding the quaternions into matrices with coeffients over $Z$ as this is much simpler.

As mentioned on Wikipedia, quaternions have a representation in matrices with elements in the complex field, and complex elements can also be represented as matrices in $R$. So we can construct our lattice over quaternions and use this injective homomorphism to create a matrix over $Z$ with similar properties and solve it using a standard LLL implementation. However, the structure out of the output matrix from LLL is not preserved, so in general only the runs of coefficients from the same quaternion base are preserved, so we'll have 4 chunks with different parts and just have to try all distinct orderings.

As a side note, Mathematica and [fpllh](https://www-fourier.univ-grenoble-alpes.fr/~pev/fplllh/) actually support LLL over gaussian integers. 🤔

Flag: `irisctf{wow_i_cant_believe_its_lll!}`

Solve code:
```py
FF.<i,j,k> = QuaternionAlgebra(-1,-1)

load("output.sage")

# Convert elements into field
a = [FF(x) for x in A]
s = FF(s)
n=len(a)

M = matrix(FF, n+1, n+1)

NN = 1024 # scaling
N = FF(NN)

# Diagonals
for i in range(n):
    M[i, i] = 1
    M[i, n] = N*a[i]

# Bottom row
M[n] = [0]*n + [N*s]

# Convert a matrix in C to a n*2 by n*2 matrix in Z
def toE(M):
    rows = []
    for row in M:
        nr = [e.real() for e in row] + [-e.imag() for e in row]
        rows.append(nr)
    for row in M:
        nr = [e.imag() for e in row] + [e.real() for e in row]
        rows.append(nr)
    return matrix(ZZ, rows)

# Convert a quaternion matrix to a n*2 by n*2 matrix in Z[i]
def toG(M):
    rows = []
    for row in M:
        nr = [e[0]+e[1]*I for e in row] + [e[2]+e[3]*I for e in row]
        rows.append(nr)
    for row in M:
        nr = [-e[2]+e[3]*I for e in row] + [e[0]-e[1]*I for e in row]
        rows.append(nr)
    return matrix(ZZ[I], rows)

Mg = toG(M)
Mp = toE(Mg)
# Reduction
MpL = Mp.LLL()

pos_slices = set()
for row in MpL:
    nl = len(row)//4
    # Slices corresponding to 16 submatrices

    for Ni in range(4): # Look for valid solutions
        Nli = Ni*nl
        if all(int(x) > 0 and int(x) < 128 for x in row[Nli:Nli+nl-1]):
            pos_slices.add(bytes(int(x) for x in row[Nli:Nli+nl-1]))
        if all(int(-x) > 0 and int(-x) < 128 for x in row[Nli:Nli+nl-1]):
            pos_slices.add(bytes(int(-x) for x in row[Nli:Nli+nl-1]))

import itertools

for sl in itertools.permutations(pos_slices, int(4)):
    flag = b"".join(b"".join(bytes([e[idx]]) for e in sl) for idx in range(len(sl[0])))
    if flag.startswith(b"irisctf{"):
        print(flag)

```
