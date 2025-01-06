from sphincs_util import *
from sign_graft import sign_graft

# Collect signatures
from pwn import *
import secrets
import hashlib
import json
import glob
import os
from tqdm import tqdm
from collections import defaultdict

# r = remote("0", 1337)
r = remote("sphincs5.chal.irisc.tf", 10103)

r.recvuntil(b"pk = ")
pk = bytes.fromhex(r.recvline().decode())

os.system("rm -rf sigs/*")

# keys that validate
valid_paths = []
with open("solve_graftkey", "wb") as f:
    f.write(pk)
    f.write(secrets.token_bytes(32)) # random private key
    f.write(pk) # private key copy of public key

for _ in tqdm(range(128)): # collect signatures
    r.sendlineafter(b"> ", b"1")
    r.recvuntil(b"sm = ")
    s1 = r.recvline().rstrip(b"\n")

    # local verify
    with open("ver", "wb") as f:
        f.write(bytes.fromhex(s1.decode()))
    rc = os.system("./chal_verify > /dev/null")

    path = f"sigs/sig{s1[:16].decode()}"
    if rc == 0:
        valid_paths.append(path)
    with open(path, "wb") as f:
        f.write(bytes.fromhex(s1.decode()))

# (this is split up to be ran seperately if failed when testing)
with open("solve_graftkey", "rb") as f:
    pub_seed = f.read(0x10)
    pub_key = pub_seed + f.read(0x10)
    pstate = hashlib.sha256()
    pstate.update(pub_seed + b"\x00"*(64-16))

candidate_sets=[]
wots_pks = {}
bestkeys = {}

# analyze keys for collisions and pick a good candidiate
for file in glob.glob("sigs/*"):
    print(file)
    with open(file, "rb") as f:
        sig = f.read()

    comps = extract_components_of_sig(sig)
    roots = dump_roots("solve_graftkey", file)

    for layer in range(SPX_D):
        wroot = chain_lengths(roots["layers"][layer]["root"])
        wpk_ly = []
        for i in range(SPX_WOTS_LEN):
            wpk = roots["layers"][layer]["wots_pks"][i]
            wsk = comps["sig"][layer]["wots"][i]
            addr = roots["layers"][layer]["addr"]
            if layer == 21: # target layer
                wpk_ly.append(wpk)
            if wpk not in wots_pks:
                wots_pks[wpk] = {wroot[i]}
            else:
                if wroot[i] not in wots_pks[wpk]:
                    wots_pks[wpk].add(wroot[i])
                    print("=== Collision")
                    print(layer, wpk, "signed", wots_pks[wpk])
                    print(addr)
            if layer == 21 and min(wots_pks[wpk]) == wroot[i]:
                bestkeys[wpk] = (wroot[i], wsk, addr)
        if layer == 21 and file in valid_paths:
            if wpk_ly not in candidate_sets:
                candidate_sets.append((wpk_ly, file)) # top part is chosen for grafting so make sure it's valid too

print("Checked", len(wots_pks))

# find a good candidate
best = [0, 9999999999]
for i, cf in enumerate(candidate_sets):
    cset, _ = cf
    cnt = [bestkeys[wpk][0] for wpk in cset]
    if sum(cnt) < best[1]:
        best[1] = sum(cnt)
        best[0] = i
    print(i, "can sign", cnt)

print("Best", best)

tg, example_file = candidate_sets[best[0]]
target_node = None
keys = []
bests = []
for i, t in enumerate(tg):
    print(t, bestkeys[t])

    # Check key
    s, sk, addr = bestkeys[t]
    target_node = addr[1], addr[0] # tree, leaf
    addr = bytearray(bytes.fromhex(addr[2]))
    addr[SPX_OFFSET_CHAIN_ADDR] = i
    w = bytes(sk)
    for k in range(s, 15):
        addr[SPX_OFFSET_HASH_ADDR] = k
        w = thash(w, pstate, addr[:SPX_SHA256_ADDR_BYTES])[:SPX_N]

    assert w == t # ensure that we actually signed it...
    keys.append({"s": s, "sk": sk.hex(), "addr": addr.hex()})
    bests.append(s)

with open("keys.json", "w") as f:
    f.write(json.dumps(keys))

# set up signature req
with open("req", "w") as f:
    f.write("give me the flag")

print("target node is", target_node)
# sign until we hit target node and is signable
while True:
    with open("solve_graftkey", "wb") as f:
        f.write(pub_key)
        f.write(secrets.token_bytes(32)) # random private key
        f.write(pub_key)

    out = subprocess.check_output(["./chal_sign", str(target_node[1])]).decode()
    details = out.split("at 21: tree = ")[-1].split("\n")[0].split(" ")
    tree = details[0].split(",")[0]
    leaf = details[-1]

    assert (int(tree),int(leaf)) == target_node # checked by signer

    # now see if it's signable by us
    print("good node, check sign")
    out = json.loads(subprocess.check_output("./chal_verify_dump_roots solve_graftkey flagsign2", shell=True).decode())

    root = bytes.fromhex(out[21*3])
    root_c = chain_lengths(root)
    print("root is", root)

    if not all(root_c[i] >= bests[i] for i in range(SPX_WOTS_LEN)):
        print("not signable")
        continue

    sign_graft("solve_graftkey", "flagsign2", example_file, root)

    # verify it looks good
    out = json.loads(subprocess.check_output("./chal_verify_dump_roots solve_graftkey newsig", shell=True).decode())
    print("new signature root:", out[-1], pub_key[SPX_N:].hex().upper())
    assert out[-1] == pub_key[SPX_N:].hex().upper()
    break

# send over new sig
with open("newsig", "rb") as f:
    ns = f.read().hex()

r.sendlineafter(b"> ", b"2")
r.sendlineafter(b": ", str(len(ns)).encode())
r.sendlineafter(b": ", ns)

# gg?
r.interactive()
