# orz network (Crypto)
> On today's episode of "Why Is This Author So Obsessed With Algorithm Problems?".

The challenge description confused me a bit at first. We are given the connection logs of around 10k diffie hellman key exchange connections with different paramateres. The goal is to crack exactly 419 shared keys such that there is a path from computer 1 to every other 419 within 5 seconds.

The DH parameters are weak but many connections still take a full second or so to crack in sage, while a few are almost instant. As the readme mentions, this is a graph problem. We just need to generate a minimum spanning tree with the difficulty of the discrete logarithm as the weight.

The difficulty is directly tied to the modulus size, so I used the modulus directly as the weight and let networkx do the rest of the hard work. Once we generate the spanning tree, we iterative over edges with a DFS and crack each connection. `sympy` includes a discrete log function that is plenty fast.

See the solve script for details - it takes around half a second to crack the required keys for me.

```
python3 solve.py
[+] Opening connection to chall.ctf.bamboofox.tw on port 10369: Done
[+] PoW: Done
[+] Starting local process '/home/s/.pyenv/shims/python3': pid 5569
[*] Stopped process '/home/s/.pyenv/shims/python3' (pid 5569)
[+] Recieving data: Done
[+] Calculating tree and keys: 0.6761023998260498 seconds
[+] flag{orz_0TZ_0rz_Orz_OTZ_oTZ}
```
