# toobeetootee (Forensics 464)
# Credits to nope for digging most of this shit
# Requires https://github.com/AndrejIT/map_unexplore/blob/master/mt_block_parser.py
# uiuctf{BudG3t_c4ves_N_cl1fFs}

# tshark -T -e data > toobeetootee.hex

import struct

pthing_t = {
    0: "POINTEDTHING_NOTHING",
    1: "POINTEDTHING_NODE",
    2: "POINTEDTHING_OBJECT",
}

ic_t = [
	"INTERACT_START_DIGGING",     # 0: start digging (from undersurface) or use
	"INTERACT_STOP_DIGGING",      # 1: stop digging (all parameters ignored)
	"INTERACT_DIGGING_COMPLETED", # 2: digging completed
	"INTERACT_PLACE",             # 3: place block or item (to abovesurface)
	"INTERACT_USE",               # 4: use item
	"INTERACT_ACTIVATE"           # 5: rightclick air ("activate")
        ]

def uV3S16(b):
    return struct.unpack(">3h", b)

xs = [[],[],[],[]]
ys = [[],[],[],[]]
zs = [[],[],[],[]]
bad = []

with open("./toobeetootee.hex") as f:
    for line in f:
        line = line.rstrip()
        if line[22:26] == "0039":
            print("===================================")
            print(line)
            line = bytes.fromhex(line[22:])
            print("type", ic_t[line[2]])
            print(line[2])
            if line[2] != 3 and line[2] != 2:
                continue
            print("item", line[3:5])
            plen = struct.unpack(">i", line[5:9])[0]
            print("plen", plen)
            print("pointedThing", line[9:9+plen])
            pthing = line[9:9+plen]

            print("==", "version", pthing[0])
            print("==", "type", pthing_t[pthing[1]])
            if pthing[1] == 1:
                node_under = uV3S16(pthing[2:8])
                print("==", "u", node_under)
                node_above = uV3S16(pthing[8:14])
                print("==", "a", node_above)
                xs[line[2]].append(node_under[0])
                ys[line[2]].append(node_under[1])
                zs[line[2]].append(node_under[2])
                if line[2] == 3:
                    bad.append(node_above)

            print("position", line[9+plen:])

def getIntegerAsBlock(i):
    x = unsignedToSigned(i % 4096, 2048)
    i = int((i - x) / 4096)
    y = unsignedToSigned(i % 4096, 2048)
    i = int((i - y) / 4096)
    z = unsignedToSigned(i % 4096, 2048)
    return x,y,z

def unsignedToSigned(i, max_positive):
    if i < max_positive:
        return i
    else:
        return i - 2*max_positive

import sqlite3
import mt_block_parser
conn = sqlite3.connect("~/snap/minetest/current/worlds/world/map.sqlite")
cur = conn.cursor()
import pdb
for row in cur.execute("SELECT * FROM blocks"):
    temp = mt_block_parser.MtBlockParser(row[1])
    temp.nameIdMappingsParse()

    xx,yy,zz = getIntegerAsBlock(row[0])
    if xx != -23: continue

    temp.nodeDataParse()
    for pos in temp.arrayParam0:
        if temp.arrayParam0[pos] == 0:
            continue
        x = pos % 16 + (xx*16)
        y = (pos // 16) % 16 + (yy*16)
        z = (pos // 16 // 16) + (zz*16)
        
        if x == -357 and z >= -270 and z <= -120 and y >= 16 and y <= 24:
            if (x, y, z) in bad:
                print("Skipping", x, y, z)
                continue
            xs[0].append(x)
            ys[0].append(y)
            zs[0].append(z)

conn.close()

from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import numpy as np
fig = plt.figure()
#ax = fig.add_subplot(111, projection='3d')
ax = Axes3D(fig)

ax.set_box_aspect(aspect = (1,10,1))
ax.scatter(xs[0], zs[0], ys[0], c="b")
ax.scatter(xs[2], zs[2], ys[2], c="g")
#ax.scatter(xs[3], zs[3], ys[3], c="r")
ax.set_xlabel('X Label')
ax.set_zlabel('Y Label')
ax.set_ylabel('Z Label')
plt.show()
