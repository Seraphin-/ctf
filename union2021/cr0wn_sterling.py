# Cr0wn St3rling
# A bit of a meme challenge where the code's comments contain all kinds of bullshit.
# The key space is extremely small, but it runs slow enough that we can't brute force it immediately.
# With a profiler, we can see the bbp_pi function is what takes forever, but downloading a million hex digits of pi off the internet can make it instant :)
# This script is just lazily modified from the challenge

#!/usr/bin/env python3

flag = bytes.fromhex("76f64667220717784affa07cf6b8be52c7d8348d778a41615efa9e53f2566b27fd96eb984c08")
from Crypto.Util.number import isPrime
from itertools import product
from functools import lru_cache
from tqdm import tqdm
import math

@lru_cache(None)
def sieve_for_primes_to(n):
    # Copyright Eratosthenes, 204 BC
    size = n//2
    sieve = [1]*size
    limit = int(n**0.5)
    for i in range(1, limit):
        if sieve[i]:
            val = 2*i+1
            tmp = ((size-1) - i)//val
            sieve[i+val::val] = [0]*tmp
    return [2] + [i*2+1 for i, v in enumerate(sieve) if v and i > 0]

def is_quasi_prime(n, primes):
    # novel class of semi-prime numbers
    # https://arxiv.org/pdf/1903.08570.pdf
    p2 = 0
    for p1 in primes:
        if n % p1 == 0:
            p2 = n//p1
            break
    if isPrime(p2) and not p1 in [2, 3] and not p2 in [2, 3]:
        return True
    return False

@lru_cache(None)
def bbp_pi(n):
    # Bailey-Borwein-Plouffe Formula
    # sounds almost as cool as Blum-Blum-Shub
    # nth hex digit of pi
    @lru_cache(None)
    def S(j, n):
        s = 0.0
        k = 0
        while k <= n:
            r = 8*k+j
            s = (s + pow(16, n-k, r) / r) % 1.0
            k += 1
        t = 0.0
        k = n + 1
        while 1:
            newt = t + pow(16, n-k) / (8*k+j)
            if t == newt:
                break
            else:
                t = newt
            k += 1
        return s + t

    n -= 1
    x = (4*S(1, n) - 2*S(4, n) - S(5, n) - S(6, n)) % 1.0
    return "%02x" % int(x * 16**2)

@lru_cache(None)
def digital_root(n):
    # reveals Icositetragon modalities when applied to Fibonacci sequence
    return (n - 1) % 9 + 1 if n else 0

@lru_cache(None)
def fibonacci(n):
    # Nature's divine proportion gives high-speed oscillations of infinite
    # wave values of irrational numbers
    assert(n >= 0)
    if n < digital_root(2):
        return n
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)

@lru_cache(None)
def is_valid_music(music):
    # Leverage music's infinite variability
    assert(all(c in "ABCDEFG" for c in music))

@lru_cache(None)
def is_valid_number(D):
    # Checks if input symbolizes the digital root of oxygen
    assert(8==D)

@lru_cache(None)
def get_key(motif):
    is_valid_music(motif)
    is_valid_number(len(motif))
    # transpose music onto transcendental frequencies
    indexes = [(ord(c)-0x40)**i for i, c in enumerate(motif)]
    size = sum(indexes)
    if size >= 75000: # we will go larger when we have quantum
        return False, False
    return indexes, size

def get_q_grid(size):
    return [i for i in range(size) if is_quasi_prime(i, sieve_for_primes_to(math.floor(math.sqrt(size))+1))]
q_grid_f = get_q_grid(75000)

digits_file = open("data/pi-hex.1000000.txt", "r").read().lower()
digits_file = "3" + digits_file
def hpi(x):
    return digits_file[x:x+2]

bbp_pi_f = [hpi(x) for x in tqdm(q_grid_f)]

def solve(musical_key):
    # print("[+] Oscillating the key")
    key_indexes, size = get_key(musical_key)
    if size == False: return b""
    # print("[+] Generating quasi-prime grid")
    q_grid = [x for x in q_grid_f if x < size]
    if len(q_grid) == 0: return b""
    # print(f"indexes: {key_indexes}  size: {size}  len(q_grid): {len(q_grid)}")

    out = []
    for i, p in enumerate(flag):
        #print(f"[+] Entangling key and plaintext at position {i}")
        index = key_indexes[i % len(key_indexes)] * fibonacci(i)
        key_byte_hex = bbp_pi_f[index % len(q_grid)]
        #print(f"index: {index:10}  fib: {fibonacci(i):10}  q-prime: {q:10}  keybyte: {key_byte_hex:10}")
        out.append(p ^ int(key_byte_hex, 16))

    # print(f"[+] Encrypted: {bytes(out).hex()}")
    return bytes(out)

for perm in tqdm(product("ABCDEFG", repeat=8)):
    musical_key = ''.join(perm)
    s = solve(musical_key)
    if b"union{" in s and all(c < 0x7f for c in s):
        print(musical_key)
        print(s)
