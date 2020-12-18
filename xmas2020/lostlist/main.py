#!/usr/bin/python3
import os
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from key import key
import subprocess

def unpad(ct):
    return ct[:-(ct[-1])]

def decrypt(ct):
    return AES.new(key, AES.MODE_CBC, ct[:16]).decrypt(ct[16:])

blacklist = [b'tac', b'cat', b'less', b'more', b'head', b'tail', b'nl', b'grep', b'key']

for i in range(64):
    try:
        enc_cmd = long_to_bytes(int(input('santa@northpole ~$ '), 16))
        cmd = unpad(decrypt(enc_cmd))
    except:
        print('Command not found')
        continue

    test_cmd = cmd
    for i in [b'\\', b'`', b'$', b'(', b')', b'{', b'}', b'&', b'*', b"'", b'"']:
        test_cmd = test_cmd.replace(i, b'')

    if not any(i in test_cmd for i in blacklist):
        print(subprocess.check_output([b'/bin/bash', b'-c', cmd]).decode(), flush=True)
    else:
        print('Command not found')
