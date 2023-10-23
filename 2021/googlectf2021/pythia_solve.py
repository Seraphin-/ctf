# pythia solve implementation by hand
# this solution is not always consistent
# special thanks to rbtree for helping explain after the ctf :)

# CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}

from pwn import *
import itertools
import string
import base64
from tqdm import tqdm
import os

all_passwords = list(''.join(p) for p in itertools.product(string.ascii_lowercase, repeat=3))
prefix = base64.b64encode(b"\x00"*12) + b","

#r = process(["python3", "./server.py"])
r = remote("pythia.2021.ctfcompetition.com", 1337)
p = process(["sage","./gcm.sage"])
r.recvuntil("Exit\n>>> ")

def check_server(ct):
    r.sendline("3")
    r.sendline(prefix + ct)
    res = r.recvuntil("Exit\n>>> ").decode()
    if "ERROR" in res:
        return False
    return True

def check_if_in(a, b):
    if b > len(all_passwords): b = len(all_passwords)-1
    log.info("Query: [%s-%s]" % (all_passwords[a], all_passwords[b]))
    cache_key = "cache/%d_%d" % (a,b)
    if not os.path.exists(cache_key):
        # Get a ct from sage
        p.sendline(str(a))
        p.sendline(str(b))
        p.recvuntil("Done")
    with open(cache_key, "rb") as f:
        ct = f.read().rstrip(b"\n")
    return check_server(ct)

def find_pass(sa=False):
    # Perform a too-lazy-so-decimal search
    idx = 0
    for i in range(1, 80):
        #if sa and i > 5:
        #    log.error("Giving up, first char unlucky :)")
        #    exit()
        if(check_if_in(idx+(i-1)*220, idx+i*220)):
            idx += (i-1)*220
            break
    log.info("IDX: %d" % idx)
    for i in range(1, 3):
        if(check_if_in(idx+(i-1)*110, idx+i*110)):
            idx += (i-1)*110
            break
    log.info("IDX: %d" % idx)
    for i in range(1, 4):
        if(check_if_in(idx+(i-1)*40, idx+i*40)):
            idx += (i-1)*40
            break
    log.info("IDX: %d" % idx)
    for i in range(1, 9):
        if(check_if_in(idx+(i-1)*5, idx+i*5)):
            idx += (i-1)*5
            break
    log.info("IDX: %d" % idx)
    for i in range(10):
        if(check_if_in(idx+i, idx+i+1)):
            idx += i
            break
    log.success("IDX: %d" % idx)
    return all_passwords[idx]

log.info("Starting password #1")
pass1 = find_pass(sa=True)
log.success("Password 1: %s" % pass1)
log.info("Starting password #2")
r.sendline("1\n1")
r.recvuntil("Exit\n>>>")
r.recv(timeout=5)
pass2 = find_pass()
log.success("Password 2: %s" % pass2)
log.info("Starting password #3")
r.sendline("1\n2")
r.recvuntil("Exit\n>>>")
r.recv(timeout=5)
pass3 = find_pass()
log.success("Password 3: %s" % pass3)
log.success("Password: %s%s%s" % (pass1, pass2, pass3))
r.sendline("2\n%s%s%s" % (pass1,pass2,pass3))
flag = r.recvuntil("}")
with open("flagf", "wb") as f:
    f.write(flag)
