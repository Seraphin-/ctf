import hashlib
import json
def hash(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    h_hash = hashlib.sha256(block_string).hexdigest()
    return h_hash

b = "0.cloud.chals.io:24797"
#b = "localhost:50002"
import requests
name = "aufiafafafaiohfoa"
chain = requests.get("http://" + b + "/chain").json()
pending = requests.get("http://" + b + "/pending_transactions").json()
chain["name"] = name

def c(prev):
    i = 1
    while True:
        i += 1
        if hashlib.sha256(f'{prev}{i}'.encode()).hexdigest()[:5] == '00000':
            print(i)
            return i

prev = chain["chain"][-1]
chain["length"] += 1
new = {"index": chain["length"], "previous_hash": hash(prev), "proof": c(prev["proof"]), "timestamp": prev["timestamp"] + 1, "transactions": pending}
chain["chain"].append(new)

print(chain)

print(requests.post("http://" + b + "/nodes/update", json=chain).text)
