from pwn import *
from powsolver import PoWSolver
import json
from Crypto.Util.number import inverse
# True "brute force" solution
# Keep doing it until we get a key we precomputed (maybe 17/65535)

precomputed = json.load(open("precomputed_primes"))
solver = PoWSolver()
p = log.progress("Attempting")
i = 1

while True:
    r = remote("challs.xmas.htsp.ro", 1000)
    p.status("%d: PoW" % i)
    message = r.recvuntil("\n\n").decode()[:-2]
    solver.parse(
            "Provide a hex string X such that {alg}(unhexlify(X))[{start:d}:] = {target}",
            message)
    sol = solver.solve()
    r.sendline(sol.hex())
    done = False
    for ii in range(1, 256):
        done = False
        p.status("%d: Sig #%d" % (i, ii))
        r.sendlineafter("exit\n\n", "1")
        m = int(r.recvuntil(".").decode().split(" ")[-1][:-1], 16)
        n = int(r.recvuntil("e: 65537").decode().split("\n")[-2].split(" ")[-1])
        for prime in precomputed:
            if n % prime == 0:
                done = True
                log.info("!!!")
                log.info("n %d" % n)
                log.info("m %d" % m)
                prime_q = n // prime
                phi = (prime - 1) * (prime_q - 1)
                d = inverse(65537, phi)
                pt = pow(m, d, n)
                r.sendlineafter("exit\n\n", "2")
                r.sendlineafter("got.\n\n", hex(pt)[2:])
                r.interactive()
                break
        if done: break
    if done:
        break
    i += 1

p.success("Done")
