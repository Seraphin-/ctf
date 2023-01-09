# babymixup (Crypto)
> I encrypted a public string and the flag with AES. There's no known key recovery attacks against AES, so you can't decrypt the flag.

This challenge provides 2 pairs of encrypted messages using AES in CBC mode.

The first is of "Hello, this is a public message. This message contains no flags.". This message is encrypted mistakenly using the IV as a key and the key value instead of the IV.
```py

iv = os.urandom(16)
cipher = AES.new(iv,  AES.MODE_CBC, key) # <-- first param is actually used as the key
print("IV1 =", iv.hex())
print("CT1 =", cipher.encrypt(b"Hello, this is a public message. This message contains no flags.").hex())
```

The second is the flag, encrypted normally with a random IV.
```py
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv )
print("IV2 =", iv.hex())
print("CT2 =", cipher.encrypt(flag).hex())
```

CBC does not try to ensure the IV is secret, and it's easy to recover the IV from a known plaintext-ciphertext pair.

Denote the known message as PT. The "key", which was used as an IV, can be recovered from the encrypted text like so:
```
key = Decrypt(CT1[:16], IV1) xor PT1[:16]
```

Then you can decrypt the second ciphertext using the key and given IV like normal.
```py
cipher = AES.new(recovered_key, AES.MODE_CBC, IV2)
print(cipher.decrypt(encrypted_flag))
```

```
irisctf{the_iv_aint_secret_either_way_using_cbc}
```

This challenge was inspired by another CTF challenge that was mentioned to me that I misinterpreted as being this at first (it was something else). I figured it would make a good actual challenge.
