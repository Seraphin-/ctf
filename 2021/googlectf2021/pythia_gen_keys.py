from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import string
import itertools

keys = []
for pos in itertools.product(string.ascii_lowercase, repeat=3):
    kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
    keys.append(kdf.derive((pos[0]+pos[1]+pos[2]).encode()).hex())

with open("keys", "w") as f:
    f.write("\n".join(keys))
