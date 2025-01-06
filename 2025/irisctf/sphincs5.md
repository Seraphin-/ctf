# SPHINCS5 (crypto, hard)

> My Super Stable SPHINCS+ Signature Service is Now Available!

I made this writeup without particularly proofreading it so feel free to harass me if you want clarifications.

## TL;DR
- When the diff path is hit, the treehash for the XMSS-MT signature is computed incorrectly. This means that the node next layer up in the hypertree signs the wrong message, causing the WOTS+ key to be used to sign more than 1 message, so the key can be compromised directly.
- Collect a few hundred signatures and check which ones reuse WOTS+ keys. Target the key at layer $d-1$ (the root hypertree which sings $d-2$) that has the lowest sum (i.e. can sign the most messages).
- Generate a random private key and sign the flag message (using the correct algorithm) randomly until it matches the `addr & 0xFFFF = 0x1337` condition, and the address points to the recovered WOTS+ key. If the root at $d-2$ isn't signable by the target WOTS+ key, just choose another private key.
- Take the part of the new signature form the start up to the target layer. Sign the root node at layer $d-2$ with the compromised WOTS+ key. Take the authentication path from a valid signature and then append the flag message from the new signature.

## Challenge
The challenge implements a signature service using the SPHINCS+ signature scheme that allows up to 256 random messages to be signed, and will give the flag if a valid signature with the text `give me the flag` is given. The challenge is based on the reference implementation for SPHINCS+, using the simple sha256 hash configuration.

## Solution
First, we can observe that the only meaningful addition between the reference code and the challenge is the following:
```c
/* 
 * Prevent dangerous reuse of WOTS signatures on same
 * auth path for top layers with fewer addresses
 */
if (layer >= SPX_D - 2 && h < tree_height - 1) {
    uint8_t bit = 0;
    randombytes(&bit, sizeof(bit));
    if(bit < 16) randombytes(&current[SPX_N], SPX_N);
}
```

The change claims to prevent "reuse of WOTS signatures", but as it turns out, the point of the treehash is to cause the same tree to always hash to the same value! We will see how this completely breaks the scheme.

Additionally, the challenge wants the `tree` address of the signature to end with `0x1337`; but as we will see it is relatively easy to ensure this constraint is satisfied when producing a signature, real or fake.

### Background
As SPHINCS+ is a complex scheme, I will try to only provide the knowledge needed to implement the attack.

The SPHINCS+ scheme has a multi-layered structure, but it is perhaps easiest to think of it simply as a signature chain. Each step of the scheme produces consists of a signature on some data plus the step's public key. This public key needs to be signed with the next signature up until the final signature in the chain. The final signature's public key is part of the public key for the whole SPHINCS+ scheme.

```
Message   -> Message Hash -> FORS signature -> XMSS-MT signature             -> [repeated until D XMSS-MT signatures] -> Final signature
Random Value ^                                 = WOTS+ signature + auth chain
```

The random value included in the message hash is supposed to be derived from the secret key, but there is no way for a verifier to check this, so it can be considered a nonce picked by the signer. There is one single FORS signature in the chain, but `SPX_D` XMSS-MT signatures in the chain that sign each other. The output of the final XMSS-MT signature is a public key which is also the end of the signature.

To verify the signature, a verifier needs to check the signature from each step is signed by the next step up until the end, when the public key of the final signature must match the SPHINCS+ public key.

An important property of SPHINCS+ is that all computations are branchless and the public key for each signature is actually generated in the process of verification as opposed to being included in the signature itself. If the signature is invalid, then one of the steps in the signature chain will produce the incorrect public key for the next step and the final output will not match the SPHINCS+ public key.

#### Message Hash
The message hash is the result of hashing the message and a random value $R$. This value is supposed to be picked using the private key and additional randomness, but we can treat it as a black box value that the attacker can modify, as the verifier has no way to know if the value of $R$ is from the real signer. Regardless, if the value of $R$ does not match the signature, the hash over $R$ will be a pseudorandom value and the rest of the signature verification will fail.

The message hash on message $M$ is treated as an blob $H(M, R) = HM || \texttt{addr}$. The first bytes are considered an opaque message hash. The remaining bytes are treated as an address which determines exactly which FORS and XMSS-MT private keys are used.

#### WOTS+
WOTS+ signatures are the backbone of SPHINCS+ as it's the deepest level of signature. WOTS+ is built around repeated hash applications. The idea is that if a hash function $H$ is preimage resistant, if you take any $SK=x$ and compute $PK=H(x)$, then  the private key holder can reveal $x$  as proof of knowing the secret. To actually sign a message $m$ where $m<n$, the signer starts with their private key being any bit string $x$, then computes $PK=H^n(x)$. Later, to sign a message, the signer computes $s=H^{m}(x)$ and the verifier checks that $H^{m-n}(x)=PK$. However, this alone is not sufficient, as this signature allows anyone to also compute a signature for any message between $m$ and $n$. To prevent this, we also must sign a checksum value $c$ which has the property that $c$ always decreases if $m$ increases. In SPHINCS+, the message is broken up into chunks of a parameter number of bits, and the checksum is the sum of maximum signable chunks minutes the sum of the message.

Each keypair can only be used for a _single message_ as signing multiple messages breaks the checksum and allows any messages with a higher value than seen previously to be signed.

#### FORS
It doesn't matter for this challenge so we can treat it as a black box that produces/verifies a signature by inputting the message address and hash and outputting a signature.

### XMSS-MT
XMSS-MT is the next abstraction up from WOTS+ in SPHINCS+. It is a Merkle tree of WOTS+ signatures, which allows a tree of depth $n$ to sign $2^n$ messages (one for each leaf node) instead of only a single message. This is achieved by assigning each node in the tree its own WOTS+ private key, deterministically computed from the WOTS+ key. The output of the signature is the hash of the tree, which is computed from the WOTS+ public keys.

Each instance of XMSS-MT can only sign $2^n$ messages before a leaf node (that is, a WOTS+ key) is necessarily reused.

#### SPHINCS+ hypertree

The SPHINCS+ hypertree links instances of XMSS-MT together to ensure each signature doesn't cause reuse of a WOTS+ private key. This is done by giving each XMSS-MT instance a different tweakable hash function instance based on the $adrs$ output from earlier. The tweakable hash function is effectively just the $addr$ bits corresponding to the layer hashed along with the normal value. The hypertree uses the FORS signature as the input to the first XMSS-MT instance, and the output of the final XMSS-MT instance is also the SPHINCS+ public key. The hypertree does not need to store any information in the signature as its operation is derived only from $adrs$ bits unlike the authentication path in XMSS-MT and the WOTS+ signatures.

### Vulnerability
Finally, we can look at the challenge. The diff causes some XMSS-MT trees to have an incorrect tree hash and therefore incorrect public key. This means that the next XMSS-MT instance will sign the wrong message (tree hash) with the leaf node that is supposed to sign a completely different tree hash! This leaf node now has a compromised WOTS+ public key, which means it can be used to sign any other message where each of the message components has a value greater than one signed before.

In the top XMSS-MT instance, there is only 1 tree with a few leaf nodes (8 for a depth of 3 in the challenge parameters). This means that it is easy to pick $R$ so $adrs$ corresponds to a specific leaf node with a compromised key. By using this compromised leaf node to sign any other previous signature with a corresponding $adrs$, we can forge a signature for any message. This attack is generally known as "tree grafting" as you attach an attacker-created tree below a compromised XMSS-MT leaf node. The attack was first discussed in the context of fault attacks, and some related papers can be found here:

- [Grafting Trees: a Fault Attack against the SPHINCS framework (2018)](https://eprint.iacr.org/2018/102.pdf)
- [Practical Fault Injection Attacks on SPHINCS (2018)](https://eprint.iacr.org/2018/674.pdf)

We'll now go through the steps of the complete attack. We'll only target the top XMSS-MT tree as the challenge diff can only corrupt the messages signed by this tree.

### Attack
First, we collect a bunch of signatures. We check which are verifiable with a local copy of the reference code and note down if it's not verifiable.

We now compute all the WOTS+ keys in the target layer for every signature, and store the partial private keys for the lowest known message chunk signed by each public key. Once we process all the messages, we check that at least one WOTS+ key has been compromised, and choose the compromised key with the lowest message value sum as our target.

We generate a random private key and $R$ then attempt to sign the flag message with this key up to our target, retrying until the $adrs$ portion of the message hash maps to our target compromised leaf node and `adrs & 0xFFFF == 0x1337`. Then, we check that the message (root at layer before the compromised leaf) is signable by our compromised key (in other words, the value of each message chunk is equal or higher to the lowest collected private key for the chunk). If it's not signable, we retry from the start.

Finally, we can forge the complete signature. We take our partial signature from the previous step and sign the new signature's XMSS-MT root at layer $target-1$ with our target private key. Then, we copy the remaining part of the signature from any valid signature that starts from the compromised leaf node. The resulting signature is valid!

Solution code is available in the [sphincs5/](sphincs5/) directory.

Flag: `irisctf{lost_in_the_forest}`

