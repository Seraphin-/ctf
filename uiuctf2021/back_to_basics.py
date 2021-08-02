# back_to_basics (Crypto 50)
# Brute for key one by one, valid will product ascii text
# uiuctf{r4DixAL}

from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, to_binary
#from secret import flag, key

ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")

def base_n_encode(bytes_in, base):
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]
	return bytes_out

def encrypt(bytes_in, key):
	out = bytes_in
	for i in key:
            print(i)
            out = base_n_encode(out, ALPHABET.index(i))
	return out

def decrypt(bytes_in, key):
	out = bytes_in
	for i in key:
		out = base_n_decode(out, ALPHABET.index(i))
	return out

with open("./flag_enc", "rb") as f:
    enc = f.read()

while b"uiuctf" not in enc:
    for i in range(len(ALPHABET)):
        try:
            potential = base_n_decode(enc, i)
        except:
            potential = b"\xff"
            pass
        if all(p < 0x80 for p in potential):
            print(potential)
            enc = potential
            break
