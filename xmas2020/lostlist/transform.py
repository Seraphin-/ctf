import sys
from Crypto.Cipher import AES

# Exact key from solving
key = b'\xd1\x1c\x07\xca\xfe\xba\xbe\xde\xad\xbe\xef\x42\xf0\x0d\xba\xbe'

iv = bytes.fromhex("53616e74612773313333374956343230")
ciphertext = "ab0c288b0ae26eaf8adbcf00bddf35fa"
assert len(iv) == 16
plaintext = b"ls" + b"\x0e" * 14
assert len(plaintext) == 16

newiv = bytearray(iv)
# We use an xor on IV attack
assert len(sys.argv[1]) <= 16
target = sys.argv[1].encode()
target += bytes([16-len(target)]) * (16-len(target))
print("Target:", target)
for i in range(16):
    newiv[i] = target[i] ^ plaintext[i] ^ iv[i]

a = AES.new(key, AES.MODE_CBC, iv=newiv)
print("Test:", a.decrypt(bytes.fromhex(ciphertext)))
print(newiv.hex() + ciphertext)
