# Santa's public key factory (Crypto 226, 78 solves)

The challenge is an RSA implementation that uses some clearly weak looking RNG. It picks 16 bits out of the 1024 key size on start and only randomizes those bits when generating primes.

Each possible key integer generated has a 1/65536 chance of being `2**(bits-1)`. It also has a 16/65536 chance of only having 1 additional bit set. We can easily precompute all adjacent primes to `2**1023+(1<<n)` for n in [32, 1022]. Yep, it's brute force time.

We keep fetching signatures until we get an `n` that contains one of our precomputed values as a factor. And sure enough, some thousand signatures later, we have the flag.

```
It seems you are a genius, we can't understand how you did it, but you did.
Here's your flag: X-MAS{M4yb3_50m3__m0re_r4nd0mn3s5_w0u1d_b3_n1ce_eb0b0506}
```

I figured we could determine the bits set from n with some thinking but thinking is hard and brute force is easy.
