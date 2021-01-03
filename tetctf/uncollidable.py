from pwn import *
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
import json

# The server is a kv store that uses a HMAC of the data as a key. We can choose the keys.
# HMAC is not really designed for this.
# The server will spit out the flag if we can cause HMAC collisions under the following conditions:
# MAC occured with two keys which are of different lengths (one >= 32 and one < 32)
# MAC occured with 10 different keys (different before padding...)
# The HMAC implementation itself is mostly fine though you should only hash the key if the length is > 32 (since it's just for size)

# Note that keys below 32 bytes are padded and keys longer/equal to that length are hashed with SHA256
# If we can find a 32 byte+ string that hashes to a value with a trailing null byte then we can pass that value as a second key which will be equivalent after padding.
# If we could find a hash that had many trailing null bytes, we would have that number of null bytes, then we would have that many unique keys as far as it's concerned.
# It may seem unreasonable to find a SHA256 hash which contains 10 trailing null bytes, but the bitcoin hivemind already did it for us :)

# TetCTF{HM4C_c4n_b3_m1sus3d-viettel:*100*718395803842748#}
# https://www.reddit.com/r/crypto/comments/guctw4/finding_sha256_partial_collisions_via_the_bitcoin/
inp_key_l = "a16a8141361ae9834ad171ec28961fc8a951ff1bfc3a9ce0dc2fcdbdfa2ccd35"
inp_key = sha256(bytes.fromhex(inp_key_l)).digest()
assert all(x == 0 for x in inp_key[-9:])
inp_key = inp_key.hex()

#r = process(["python3", "./uncollidable.py"])
r = remote("139.162.5.141", 5555)

p = log.progress("Storing")
p.status("1/10")

r.sendline(json.dumps({"action":"import_key","key_id":"o","key":inp_key_l}))
r.recvuntil("}\n")
r.sendline(json.dumps({"action":"store_data","key_id":"o","data":"aa"}))
for i in range(1, 10):
    p.status("%d/10" % (i+1))
    r.recvuntil("}\n")
    r.sendline(json.dumps({"action":"import_key","key_id":"%d" % i,"key":inp_key[:(-2*i)]}))
    r.recvuntil("}\n")
    r.sendline(json.dumps({"action":"store_data","key_id":"%d" % i,"data":"aa"}))

p.success("Done")
r.recvuntil("}\n")
r.sendline(json.dumps({"action":"report_bug"}))
res = json.loads(r.recvuntil("}\n"))
print(long_to_bytes(res['bounty']))
