# epitaph

The challenge is a very simple VM implemented in flash. The input (the flag) is put into its memory, and the same region is compared to some magic bytes after it exits. The VM seems to implement some kind of block cipher, but I noticed the cipher had absolutely no diffusion.

It runs fast enough to brute force each byte one by one after reimplementing it in python...

```
union{rest_in_p3ac3_sh0ckw44v3_:(}
```
