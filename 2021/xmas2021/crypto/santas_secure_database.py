# Santa's Secure Database (crypto 498)
# X-MAS{7h3_0r4cl3_0f_64y_b335_15_pl3453d_50912jd1f}

# We have to guess (yes) that the server is performing CBC encryption and the "Invalid data" message means invalid padding.
# From there a standard CBC padding oracle attack applies - Google can explain it better than me

# Very messy code. Not sorry

import base64
import requests
import ray
ray.init()

@ray.remote
def decrypt(iv, inp, b):
    r = requests.post("http://challs.xmas.htsp.ro:1034/storage", json={"store":iv.hex()+inp.hex()})
    print(b, r.text)
    if "OK" not in r.text:
        return b, False
    return b, True

BLOCKSIZE = 16
ec = bytes.fromhex("754f546263d1c04dbc6e6960b4bed0937c368e6bfaf2a52d4bc944cc349103d1260c05b6e2f575dfe1fa65bf448b98c7bb454e54c04f4fbfeed6ec03941ec940946c21ea01d7a9def477c8efa2212f3c")
blocks = [ec[i:i+BLOCKSIZE] for i in range(0, len(ec), BLOCKSIZE)]
iv = blocks[0]
blocks = blocks[1:]
plaintext = b""
plaintext = b"X-MAS{7h3_0r4cl3_0f_64y_b335_15_pl3453d_50912jd1f}"
all_done = False
for block_num in range(0, len(blocks)):
    # We need to attack the bytes in reverse order
    print("Block", block_num)
    inp = blocks[block_num]
    plaintext_block = b""
    plaintext_r = b""
    if block_num-1 < 0: target_block = iv
    else: target_block = blocks[block_num-1]
    target_byte = BLOCKSIZE-1
    prev_b = 0
    incorrect = set()
    incorrect_for_block = 0
    while target_byte >= 0:
        padding_len = BLOCKSIZE - target_byte
        # if len(plaintext_block) > 0: print(plaintext_block, padding_len, padding_len ^ plaintext_block[-1])
        padding_enc = b"".join(bytes([padding_len ^ plaintext_block[i-target_byte-1]]) for i in range(target_byte+1, BLOCKSIZE))
        # print(padding_enc)
        done = False
        gets = []
        for b in range(0x100):
            if b in incorrect: continue
            tb_inp = target_block[:target_byte] + bytes([b]) + padding_enc
            gets.append(decrypt.remote(b"A" * BLOCKSIZE, tb_inp + inp, b))
        while True:
            ready = ray.wait(gets)[0]
            res = ray.get(ready)
            for o in ready: gets.remove(o)
            fl = list(filter(lambda x: x[1] == True, res))
            if len(fl) > 0:
                done = True
                break
            if len(gets) < 1: break
        for o in gets: ray.cancel(o, force=True)
        if not done:
            incorrect.add(prev_b) # Try again, must have hit the real padding :(
            plaintext_block = plaintext_block[:-1]
            incorrect_for_block += 1
            target_byte += 1
            continue
        else:
            incorrect = set()
        b = fl[0][0]

        prev_b = b
        plaintext_block = bytes([b ^ padding_len]) + plaintext_block
        plaintext_r = bytes([b ^ padding_len ^ target_block[target_byte]]) + plaintext_r
        print(plaintext_r)
        target_byte -= 1
    print("PT", plaintext_r)
    plaintext += plaintext_r

# Quick fix for last byte being errantly added as 01 for padded blocks
if plaintext[-1] == 1: plaintext = plaintext[:-1]
print(plaintext)
