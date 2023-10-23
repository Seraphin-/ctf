# Biggest Lowest (Programming 37, 281 solves)
# Solves in like 5 seconds

from pwn import *
import numpy as np
import ray
import time

r = remote('challs.xmas.htsp.ro', 6051)
ray.init(include_dashboard=False)

@ray.remote
def lowest(arr, k1):
    l = np.partition(arr, k1)[:k1]
    l.sort()
    return ", ".join(str(x) for x in l)

@ray.remote
def biggest(arr, k2):
    b = np.partition(arr, len(arr)-k2)[-k2:]
    b.sort()
    return ", ".join(str(x) for x in b[::-1])

p = log.progress("Solving")
t1 = time.time()
# tqdm doesn't like this challenge
for i in range(50):
    s = r.recvuntil("50\n")
    p.status("#%.2d/50 %.2d/90s" % (i+1, int(time.time() - t1)))
    rawarr = r.recvline()
    k1 = int(r.recvline()[5:-1])
    k2 = int(r.recvline()[5:-1])
    arr = np.fromstring(rawarr[9:-2].decode(), dtype=int, sep=", ")
    """lowest = np.partition(arr, k1)[:k1]
    biggest = np.partition(arr, len(arr)-k2)[-k2:]
    lowest.sort()
    biggest.sort()
    r.sendline(", ".join(str(x) for x in lowest) + "; " + ", ".join(str(x) for x in biggest[::-1]))"""
    r1 = lowest.remote(arr, k1)
    r2 = biggest.remote(arr, k2)
    l, b = ray.get([r1, r2])
    r.sendline(l + "; " + b)

flag = r.recvuntil("}").decode().split("\n")[-1][1:] # Leading space
log.success("Done.")
log.success(flag)

# Flag: X-MAS{th15_i5_4_h34p_pr0bl3m_bu7_17'5_n0t_4_pwn_ch41l}