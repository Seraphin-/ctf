# Help a Santa helper? (Crypto 240, 76 solves)

from pwn import *
from powsolver import PoWSolver

r = remote("challs.xmas.htsp.ro", 1004)
message = r.recvuntil("\n\n").decode()[:-2]
p = log.progress("PoW")
p.status("Solving...")

# PoW
solver = PoWSolver()
solver.parse(
    "Provide a hex string X such that {alg}(unhexlify(X))[{start:d}:] = {target}",
    message)
sol = solver.solve()
r.sendline(sol.hex())
p.success("Done")

# Let z be a zero block
# H(z) = a = z xor encrypt(z xor z) = encrypt(z)
# H(z+a) = a xor encrypt(H(z) xor a) = a xor encrypt(a xor a) = a xor encrypt(z) = z
# H(z+a+z) = z xor encrypt(H(z+a) xor z) = encrypt(H(z+a)) = encrypt(z) = a
# H(z) == H(z+a+z)
# ..and H(z+a) == H(z+a+z+a) == z follows

r.sendlineafter("exit\n\n", "1")
r.sendlineafter("hash.\n\n", "00")
hh = r.recvuntil("exit\n\n").decode().split("'")[1]
r.sendline("2")
r.sendlineafter("Give me a message.\n", "00")
r.sendlineafter("Give me a message.\n", "0" * 32 + hh + "00")

message = r.recvuntil("}\n").decode()
r.close()

log.success("Flag!")
log.info(message)

# Flag: X-MAS{C0l1i5ion_4t7ack5_4r3_c0o1!_4ls0_ch3ck_0u7_NSUCRYPTO_fda233}
