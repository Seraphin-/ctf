# Snake ransomware (rev 499)

This challenge uses the obfuscation technique known as psychological warfare. Fortuantely, the code itself is pretty simple - most of the obfuscated code does just about nothing. I cleaned up the code using an IDE and was able to just striaght forwardly reverse the encryption process.

The encryption performs a bit of math on each char of the input, pads it with the 4th character of the plaintext, shuffles the characters, and then encodes the bits in each row of the ciphertext visually (with the "darkness" of the character representing the bit pattern).

The encryption is seeded using the current time in seconds, so the encryption seed of the flag can be determined by the timestamp embedded in the 7z file. Here's my shitty not-really-working decryptor that spits out just enough information to figure out the flag:

```py
import sys
import random
# copied straight off SO
def shuffle_under_seed(ls, seed):
  random.seed(seed)
  random.shuffle(ls)
  return ls

def unshuffle_list(shuffled_ls, seed):
  n = len(shuffled_ls)
  # Perm is [1, 2, ..., n]
  perm = [i for i in range(1, n + 1)]
  # Apply sigma to perm
  shuffled_perm = shuffle_under_seed(perm, seed)
  # Zip and unshuffle
  zipped_ls = list(zip(shuffled_ls, shuffled_perm))
  zipped_ls.sort(key=lambda x: x[1])
  return [a for (a, b) in zipped_ls]

with open(sys.argv[1], "r") as f:
    encrypted_string = f.read()

output_chars = "░▒▓█"

encrypted_string = encrypted_string.split("\n")
encrypted_string = encrypted_string[:len(encrypted_string)//2]
t = [""] * len(encrypted_string[0])
for s in encrypted_string:
    for i in range(len(s)):
        t[i] += s[i]
t = [e for e in unshuffle_list(t,1637854080)]
s = [""] * len(encrypted_string)
for e in t:
    for i in range(len(e)):
        s[i] += e[i]

# Show encryption visually
[print(c, end=" ") for c in "X-MAS{Th4_4t4rnA1_0rDe4l_ab293bf28e}"]
[print(x) for x in s]
max_bin_length = (len(encrypted_string) + 1) * 2
characters = [0] * len(encrypted_string[0])
for string in encrypted_string:
    for c in range(len(characters)):
        characters[c] <<= 2
        characters[c] += output_chars.index(string[c])

characters = [chr(c) for c in unshuffle_list(characters,1637854080)]
characters = characters[::2]
# Have fun
for c in characters:
    for mul in range(1, 6):
        x = round((ord(c) * mul - 1) ** (1 / 1.42)) // ord('}')
        if x > 0x7f:
            print(" ", end="")
        else: print(chr(x), end="")
    print()
#print(characters)
```

## Flag
```
X-MAS{Th4_4t4rni0_0rne4l_ab293bf28e}
```
