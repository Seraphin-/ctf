SPX_N = 16
SPX_D = 22
SPX_FORS_BYTES = 3696
SPX_WOTS_BYTES = 560
SPX_TREE_HEIGHT = 3
SPX_WOTS_W = 16
SPX_WOTS_LEN = 35
SPX_WOTS_LEN1 = 32
SPX_WOTS_LEN2 = 3
SPX_WOTS_LOGW = 4
SPX_OFFSET_HASH_ADDR = 21
SPX_SHA256_ADDR_BYTES = 22
SPX_OFFSET_CHAIN_ADDR = 17

import sys
import subprocess
import json
import hashlib

def extract_components_of_sig(sig):
    props = {}
    i = 0
    props["R"] = sig[i:i+SPX_N]
    i += SPX_N
    props["fors"] = sig[i:i+SPX_FORS_BYTES]
    i += SPX_FORS_BYTES
    props["sig"] = []
    for d in range(SPX_D):
        rsig = sig[i:i+SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N]
        ps = {"rsig": rsig}
        
        # wots sig parts
        ps["wots"] = []
        for w in range(SPX_WOTS_LEN):
            ps["wots"].append(sig[i:i+SPX_N])
            i += SPX_N
        # i += SPX_WOTS_BYTES

        # auth path
        path = []
        ps["path"] = path
        for w in range(SPX_TREE_HEIGHT):
            path.append(sig[i:i+SPX_N])
            i += SPX_N
        # i += SPX_TREE_HEIGHT*SPX_N
        props["sig"].append(ps)

    props["end"] = i # == SPX_BYTES
    props["msg"] = sig[i:]

    return props

def base_w(out_len, input):
    inp = 0
    out = 0
    total = 0
    bits = 0
    output = [0] * out_len
    for consumed in range(out_len):
        if bits == 0:
            total = input[inp]
            inp += 1
            bits += 8
        bits -= SPX_WOTS_LOGW
        output[out] = (total >> bits) & (SPX_WOTS_W - 1)
        out += 1
    return output

def wots_checksum(msg_base_w):
    csum = 0
    csum_bytes = [0] * ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) // 8)

    for i in range(SPX_WOTS_LEN1):
        csum += SPX_WOTS_W - 1 - msg_base_w[i]

    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    csum_bytes = csum.to_bytes(2, 'big')
    return base_w(SPX_WOTS_LEN2, csum_bytes);

def chain_lengths(msg):
    lengths = base_w(SPX_WOTS_LEN1, msg)
    lengths += wots_checksum(lengths)
    return lengths

def dump_roots(k, p):
    data = subprocess.check_output(["./chal_verify_dump_roots", k, p]).decode()
    data = json.loads(data)
    ret = []
    for i in range(SPX_D): # last is root public key
        data[i*3+1] = bytes.fromhex(data[i*3+1])
        wots = [data[i*3+1][z:z+SPX_N] for z in range(0, SPX_WOTS_LEN*SPX_N, SPX_N)]
        ret.append({"root": bytes.fromhex(data[i*3]), "wots_pks": wots, "addr": data[i*3+2]})
    return {"pk": data[SPX_D*3], "layers": ret}

def thash(buffer, pstate, addr):
    h = pstate.copy()
    h.update(addr + buffer)
    return h.digest()

if __name__ == "__main__":
    with open("solve_graftkey", "rb") as f:
        pub_seed = f.read(0x10)
        pstate = hashlib.sha256()
        pstate.update(pub_seed + b"\x00"*(64-16))

    with open(sys.argv[1], "rb") as f:
        sig = f.read()
    comps = extract_components_of_sig(sig)
    print(comps["msg"], comps["end"])

    roots = dump_roots("solve_graftkey", sys.argv[1])
    LT = 21

    w0a = bytearray(bytes.fromhex(roots["layers"][LT]["addr"][2]))
    #wroot = [int(x, 16) for x in roots["layers"][20]["root"].hex()]
    wroot = chain_lengths(roots["layers"][LT]["root"])
    for instance in range(SPX_WOTS_LEN):
        w0pk = roots["layers"][LT]["wots_pks"][instance]
        w0 = comps["sig"][LT]["wots"][instance]
        print(instance, w0, w0pk, w0a)
        w0a[SPX_OFFSET_CHAIN_ADDR] = instance
        s = wroot[instance]
        for k in range(s,15):
            w0a[SPX_OFFSET_HASH_ADDR] = k
            w0 = thash(w0, pstate, w0a[:SPX_SHA256_ADDR_BYTES])[:SPX_N]
        if w0 == w0pk:
            print("OK", s)
