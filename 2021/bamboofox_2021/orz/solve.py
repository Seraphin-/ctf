from pwn import *
import networkx as nx
from collections import defaultdict
from sympy import discrete_log
import time

r = remote("chall.ctf.bamboofox.tw", 10369)

p = log.progress("PoW")
pow_string = r.recvuntil("Answer: ")
prefix = pow_string.decode().split(" + ")[0].split("(")[-1]

pow_s = process(['python3', '../pow_solver.py', prefix, '20'])
pow_solve = pow_s.recv(timeout=30).rstrip()
pow_s.close()

r.sendline(pow_solve)
r.sendlineafter(": ", "")
p.success("Done")

data = defaultdict(lambda: defaultdict(dict))
p = log.progress("Recieving data")

line = ""
use_next = False
last = [None, None]
while "whitespace characters: \n" not in line:
    line = r.recvline().decode()
    if use_next:
        use_next = False
        parsed = line.split(", ")
        data[last[0]][last[1]] = {
            'weight': int(parsed[0].split(" ")[-1]), # mod
            'base': int(parsed[1].split(" ")[-1]),
            'alice': int(parsed[2].split(" ")[-1]), # which prolly doesn't matter since smaller pk isn't faster for dlog
            'bob': int(parsed[3].split(" ")[-1]),
        }
    if "Secure connection established" in line:
        parsed = line.split("#")
        last[0] = int(parsed[1].split(" ")[0])
        last[1] = int(parsed[2].split(" ")[0])
        use_next = True

p.success("Done")
t = time.time()
p = log.progress("Calculating tree and keys")

graph = nx.from_dict_of_dicts(data)
tree = nx.minimum_spanning_tree(graph)

private_keys = []
for edge in nx.dfs_edges(tree, 1):
    dt = tree.edges[edge]
    pk = discrete_log(dt['weight'], dt['alice'], dt['base'])
    private_keys.append(str(pow(dt['bob'], pk, dt['weight'])))

assert len(private_keys) == 419
p.success("%s seconds" % (time.time() - t))

r.sendline(" ".join(private_keys))
flag = r.recvuntil("}").decode().split("\n")[-1]
log.success(flag)
