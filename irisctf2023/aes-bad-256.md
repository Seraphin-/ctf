# AES-BAD-256 (Crypto)

> I heard that some common block cipher modes have lots of footguns - using none (ECB) results in the legendary ECB Penguin, while others are vulnerable to bit flipping and padding attacks, so I made my own that would never fall to such a technique.

The challenge implements a cipher mode of operation, BAD, and uses it to encrypt messages. The description mentions some common problems with other modes that BAD "tries" to defeat.

## Scheme
The mode derives a permutation K of [0-15] from the AES key. The mode works on block sizes of 256 bytes (the square of the blocksize of the cipher).

The encryption in the mode is as follows:
Let `C` be cipher blocks numbered 0-15 describing the data actually input into AES. Let P be cipher blocks corresponding to input data.
Let `C_n` denote the block of `C` numbered `n` with byte indices `n` numbered 0-15, and `P_n` be the same with regards to `P`.
`C_n[i] = P_i[K(n)]`

```py
def encrypt(inp):
    inp = inp.ljust(MODE_BLOCK_SIZE, b"\x00")
    
    assert len(inp) % MODE_BLOCK_SIZE == 0

    data = b""
    for block in range(0, len(inp), MODE_BLOCK_SIZE):
        for i in range(AES_BLOCK_SIZE):
            data += bytes(inp[block+j*AES_BLOCK_SIZE+PERMUTATION[i]] for j in range(MODE_BLOCK_SIZE // AES_BLOCK_SIZE))
    
    return AES.encrypt(data)
```

In order to decrypt, the permutation is just reversed.

In effect, this means that the Nth block of the encrypted data corresponds to all the K[N]th bytes of plaintext in each block. This basically transposes the data and then shuffles the blocks.

## Challenge
The challenge provides an interface where you can request an "echo" command using a simple messaging protocol, and run an arbitary command. The commands are encrypted with the above mode.

The command scheme is as follows:
2 byte length + length bytes of JSON + padding

The command does not verify the contents of the padding and just verifies the length fits and the JSON is relatively valid. The JSON parsing is done in such a way that it allows invalid (non-ascii) bytes in names/values. The challenge would still be solvable without this, but this is to make it require less brute force.

The structure of an echo request is:
`{"type": "echo", "msg": input}` where input is any input. 

```
def make_echo(inp):
    data = json.dumps({"type": "echo", "msg": inp}).encode(errors="ignore")
    assert len(data) < 2**32 # <-- challenge typo! should be 2**16
    return len(data).to_bytes(length=2, byteorder="little") + data
```

When asked to run a command, the challenge will decrypt some input and decode the message. If the length or json cannot be parsed, it returns an error. If the json is missing the `type` field, it will return an error, and if the `type` is unrecognized it will say what the unrecognized type is.

The type field is lowercased before being parsed, but the only types it understands are `echo` and `flag`. If you manage to send a command with `type: flag`, the challenge will give you the flag.

## Attack
The scheme does not actually prevent the ECB penguin over enough data as it repeats after each 256 bytes. However, this is not useful for the solution, since it could only damage confidentiality, but the contents of the echo message are not secret.

The structure of the scheme instead serves to make the message more malleable. Although you cannot predictably control the contents of the decrypted data like with CBC, the transposition means that corrupting one block of plaintext will corrupt only one byte in each block of plaintext.

Becase the permutation is done before the encryption, changing a bit of plaintext will unpredictably set the corrupted bytes, but we can control the corruption since it's only 1 byte per block to forge a message.

In particular, here is the structure of a message:
```
LL{"type": "echo", "msg": "........"}\x00...
*...............*...............
```
The asterisk represents the start of a AES block. If the first byte of the length L is corrupted, then the same indice in the 2nd block - the closing quote in `"echo"` - will be corrupted. We can line the bytes we corrupt so that we can corrupt the "echo" message without breaking the JSON:

```
LL{"type": "echo", "msg": "....."}..............
*...............*...............*...............
............1234............1234............1234 
```
If we corrupt a block of plaintext and it corresponds to the 13-16th bytes of each block, the only other thing that gets corrupted is the message!

We can start with corrupting one character randomly in each block to determine which blocks correspod to the plaintext indices we want to attack. (The reason the challenge is very lax with parsing the message is so you can do this without having to brute force valid decoding bytes).
Then, we can randomly corrupt these blocks to change each byte in "echo" to "flag", as we assume is a 1/256 chance that a random AES decryption includes a certain byte at a certain index. Since the blocks are independent, we can brute force the first character until the server responds with "Fcho", then "FLho", and so on. I allowed uppercase just to prevent requiring even more brute force.

Once you assemble the type "flag", the message will be corrupted, but that's fine.

```
irisctf{bad_at_diffusion_mode}
```
