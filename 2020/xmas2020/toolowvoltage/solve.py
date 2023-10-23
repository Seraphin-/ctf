# Too low voltage (Crypto 435, 38 solves) 
# RSA-CRT fault attack (ref: https://crypto.stackexchange.com/questions/63710/fault-attack-on-rsa-crt)

from pwn import *
from powsolver import PoWSolver
from collections import defaultdict

r = remote("challs.xmas.htsp.ro", 1006)
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

# Snag N
rsa_N = r.recvuntil("e:10001\n").decode().split("\n")[-3].split(":")[1].rstrip()
r.recvuntil("exit\n\n")

p = log.progress("Fetching bad signature")
# Use up our requests, or until we get a second unique
sigs = defaultdict(int)
for i in range(1, 64):
    p.status("Attempt %d/63" % i)
    r.sendline("1")
    r.sendline("a")
    sig = r.recvuntil("Choose").decode().split("\n")[2].split(" ")[-1].rstrip()
    sigs[sig] += 1
    r.recvuntil("exit\n\n")
    if sum(sigs.values()) > 10 and len(sigs) > 1: break

if len(sigs) == 1:
    log.critical("Didn't get a bag sig :(")
    log.critical("Maybe retry?")
    exit()

p.success("Done")
sigs = min(sigs.items(), key=lambda x: x[1])
bad_sig = sigs[0]

# Get target
r.sendline("2")
target_sig = r.recvuntil("\n\n").decode().split("'")[1]
# Solve with sage script
p = log.progress("Forging signature")
p.status("Solving...")
solver = process(['sage', './solve.sage'])
solver.sendline(rsa_N)
solver.sendline(bad_sig)
solver.sendline("a")
solver.sendline(target_sig)
res = solver.recv(timeout=10).decode().split(":")[-1].rstrip()
p.success("Done")

# Send result
r.sendline(res)

# Get flag!
message = r.recvuntil("}\n").decode()
r.close()

log.success("Flag!")
log.info(message)
