# pow_erful (Crypto 390)
# Use bitcoin block headers to find hashed preimages with lots of zeroes
# uiuctf{bitcoin_to_the_moon}
# Requires blocks from https://gz.blockchair.com/bitcoin/blocks extracted into blocks/

from hashlib import sha256
import datetime
import pytz
import csv
import glob
from Crypto.Util.number import bytes_to_long

from pwn import *

# Definitely not based on the great Bit Flip 2 writeup here
# https://jsur.in/posts/2020-11-23-dragon-ctf-2020-bit-flip-writeups

def check_block(header, difficulty, target):
    if not header[:2] == target:
            return False
    hh = sha256(header).digest()
    h = bytes_to_long(hh)
    power = ((1 << difficulty) - 1).to_bytes(32, 'big')
    return all(a & b == 0 for a, b in zip(hh, power))

prev_block = "0000000000000000000000000000000000000000000000000000000000000000"

def get_block_data(block_data):
    global prev_block
    d = {}
    d['previousblockhash'] = prev_block
    prev_block = block_data[1]
    d['version'] = block_data[7]
    d['merkleroot'] = block_data[10]
    dt = datetime.datetime.strptime(block_data[2],"%Y-%m-%d %H:%M:%S")
    dt = pytz.utc.localize(dt)
    d['time'] = dt.timestamp()
    d['bits'] = block_data[12]
    d['nonce'] = block_data[11]
    return d

def get_block_header(block_data):
    header = int.to_bytes(int(block_data['version']), 4, 'little')
    header += bytes.fromhex(block_data['previousblockhash'])[::-1]
    header += bytes.fromhex(block_data['merkleroot'])[::-1]
    header += int.to_bytes(int(block_data['time']), 4, 'little')
    header += int.to_bytes(int(block_data['bits']), 4, 'little')
    header += int.to_bytes(int(block_data['nonce']), 4, 'little')
    return header

log.info("Processing...")
blocks = []
for path in sorted(glob.glob("./blocks/*.tsv")):
        with open(path, "r") as f:
                r = csv.reader(f, delimiter='\t', quotechar='\\')
                for row in r:
                        if row[0] == 'id': continue
                        blocks.append(sha256(get_block_header(get_block_data(row))).digest())
log.success("Done!")

def go(difficulty, target):
    global blocks
    for header in blocks:
        if check_block(header, difficulty, target):
            return header[2:]

#r = process(["python3","./pow_erful.py"])
r = remote("pow-erful.chal.uiuc.tf", 1337)
p = log.progress("Difficulty: ")
for difficulty in range(1,64):
    p.status(str(difficulty))
    r.recvuntil("You are on")
    r.recvuntil("sha256( ")
    target = r.recvuntil(" ||").split(b" ")[0].decode()
    target = bytes.fromhex(target)
    result = go(difficulty, target)
    r.sendlineafter("nonce = ", result.hex())
p.success()
r.interactive()
