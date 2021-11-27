#!/usr/bin/env sage

# Binary Tree (re 224)

# pbctf{!!finding_the_shortest_path_in_self-modifying_code!!_e74c30e30bb22a478ac513c9017f1b2608abfee7}
# cost list was dumped by nope, I just wrote this

import re

nodes = {}
r = re.compile("(\d+):.*<-(\d+)\(\$(\d+)\), ->(\d+)\(\$(\d+)\).*")

exit_nodes = set()
with open("costlist.txt") as f:
    for line in f:
        if 'EXIT' in line:
            exit_nodes.add(int(line.split(':')[0]))
            continue
        v = [int(m) for m in r.match(line).groups()]
        nodes[v[0]] = v[1:]
        

TARGET = 18906

from sage.all import DiGraph
from tqdm import tqdm

G = DiGraph(weighted=True)

G.add_vertices(list(range(max(nodes)+1)))
for node in tqdm(nodes):
    G.add_edge((node, nodes[node][0], nodes[node][1]))
    G.add_edge((node, nodes[node][2], nodes[node][3]))

print("Generated graph")

from sage.graphs.path_enumeration import feng_k_shortest_simple_paths
exit_nodes = [19279] # cheating
for exit_node in exit_nodes:
    g = feng_k_shortest_simple_paths(G, 0, exit_node, by_weight=True, report_weight=True)
    l, path = next(g)
    print(l)
    if l > TARGET:
        continue
    break

path_str = ""
cur_node = 0
for p in path[1:]:
    if nodes[cur_node][0] == p:
        path_str += "1"
    else:
        path_str += "0"
    cur_node = p
print(path_str, len(path_str))
path = path_str

inp = b""
cur_b = ""
for i in range(len(path)):
    if i % 8 == 0 and i > 0:
        inp += bytes([int(cur_b[::-1], 2)])
        cur_b = ""
    cur_b += path[i]
inp += bytes([int(cur_b[::-1], 2)])
print(inp, len(inp))
assert len(inp) == 100

from pwn import *
p = process(["./binarytree.elf"])
p.send(inp)
print(p.recv())
p.close()
