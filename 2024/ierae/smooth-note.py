# today on "things i should have a template for and probably already do but forgot where it is"

from flask import Flask
import requests

CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVXYZ{}0123456789";

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

seen = set(CHARS)
known = "IERAE{"

@app.route("/leak/<g>")
def leak(g):
    global known, seen
    if g[:-1] != known: return ""
    if g[-1] in seen:
        seen.remove(g[-1])
    print(g[:-1], seen)
    if len(seen) == 1:
        known = g[:-1] + list(seen)[0]
        seen = set(CHARS)
    return ""

@app.route("/sol")
def s():
    sol = open("sol.html").read()
    return sol

@app.route("/chars")
def chars():
    return "".join(list(seen))

@app.route("/known")
def kn():
    global known
    return known
