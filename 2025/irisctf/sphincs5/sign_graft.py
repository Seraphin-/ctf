from sphincs_util import *
import json
import hashlib

def sign_graft(key_file, orig_sig_file, top_sig_file, root):
    print("signing", root.hex())

    # sign the new root
    with open(key_file, "rb") as f:
        pub_seed = f.read(0x10)
        pstate = hashlib.sha256()
        pstate.update(pub_seed + b"\x00"*(64-16))

    with open("keys.json") as f:
        w = json.load(f)

    wroot = chain_lengths(root)
    sig = b""
    for instance in range(SPX_WOTS_LEN):
        targ = wroot[instance]
        wi = w[instance]
        # sign up target
        addr = bytearray(bytes.fromhex(wi["addr"]))
        addr[SPX_OFFSET_CHAIN_ADDR] = instance
        sk = bytes.fromhex(wi["sk"])
        if targ > wi["s"]:
            for k in range(wi["s"], targ):
                addr[SPX_OFFSET_HASH_ADDR] = k
                sk = thash(sk, pstate, addr[:SPX_SHA256_ADDR_BYTES])[:SPX_N]
        elif targ < wi["s"]:
            raise ValueError(f"{targ} < {wi['s']}??")

        sig += sk

    #print("new part:", sig.hex())

    with open(orig_sig_file, "rb") as f:
        orig_sig = bytearray(f.read())
    with open(top_sig_file, "rb") as f:
        orig_sig2 = f.read()

    tmsg = b"give me the flag"

    # graft the signature together
    comp = extract_components_of_sig(sig)
    orig_sig = orig_sig[:comp["end"]]
    orig_sig += bytearray(tmsg)
    TARG=21
    i = SPX_N+SPX_FORS_BYTES+(SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N)*TARG # skip to target layer
    orig_sig[i:i+SPX_WOTS_BYTES] = bytearray(sig) # signature component
    orig_sig[i+SPX_WOTS_BYTES:i+SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N] = orig_sig2[i+SPX_WOTS_BYTES:i+SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N] # auth tree
    i += SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N
    orig_sig[i:comp["end"]] = orig_sig2[i:comp["end"]] # copy everything else too (just the flag though)

    with open("newsig", "wb") as f:
        f.write(orig_sig)
