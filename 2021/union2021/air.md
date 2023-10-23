# Cr0wnAir

Web challenge with a few (mostly simple) bugs stacked together.
The first goal is to check in and get a token. The json validator used is an old version, and we can bypass the restriction on sssr flags with something like:

```
{"firstName":"T","lastName":"A","passport":"123456789","ffp":"CA12345678","extras":{"a":{"sssr":"FQTU"},"constructor":{"name":"Array"}}}
```

The next goal is to be able to buy the flag by forging a token with a status of "gold". The version of JWT-simple used is vulnerable to key confusion which [jwt_tool](https://github.com/ticarpi/jwt_tool) can exploit. However, we need to recover the public key.

It is possible to recover the public key in RSA signatures with two different signatures. I modified a tool posted on github to work with non-pem signatures and guessed a modulus size of 2048. I then generated a PEM back out of the raw modulus and exponent, and forged a HS256 token out of it.

References:
https://gist.github.com/divergentdave/40ac9c7224b382166c905e76595bcf73
https://stackoverflow.com/questions/11541192/creating-a-rsa-public-key-from-its-modulus-and-exponent

```
union{I_<3_JS0N_4nD_th1ngs_wr4pp3d_in_JS0N}
```
