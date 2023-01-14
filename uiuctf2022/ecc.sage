# ecc script that recovers a

from collections import namedtuple
Point = namedtuple("Point", "x y")

def point_addition(P, Q):
    Rx = (P.x*Q.x + D*P.y*Q.y) % p
    Ry = (P.x*Q.y + P.y*Q.x) % p
    return Point(Rx, Ry)

def matanh(P):
    t = GF(p)(sD*P.y/P.x)
    return (1+t)/(1-t)

p =62471552838526783778491264313097878073079117790686615043492079411583156507853 
D = -1
sD = GF(p)(D).sqrt()
G = Point(4603880836195915415499609181813839155074976164846557299963454168096659979337,
          34510208759284660042264570994647050969649037508662054358547659196695638877343)
a = Point(x=46585435492967888378295263037933777203199027198295712697342810710712585850566, y=49232075403052702050387790782794967611571247026847692455242150234019745608330)

t = matanh(G)
print(f"a = {log(matanh(a),t)}")
#print(f"b = {log(matanh(b),t)}")
