import requests

state = bytes.fromhex("3132207c203080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004802000000000000207c203133")
print("New state:", state)
hh = "c28217c17f102d42d1b4a0ab33ec10a3"
x = requests.post('http://challs.xmas.htsp.ro:3003/api/buy.php', data={'state': state, 'hash': hh, 'item_id': 2})

print("Flag:", x.json()['item'])
