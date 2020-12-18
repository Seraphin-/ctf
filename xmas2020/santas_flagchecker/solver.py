from z3 import *
from pwnlib.util.packing import u32, u8

# Const arrays
arr4a60 = []
with open("arr_4a60", "rb") as f:
    while True:
        n = f.read(4)
        if len(n) < 4: break
        arr4a60.append(u32(n))

assert len(arr4a60) == 0x1e0
arr40c0 = []
with open("arr_40c0", "rb") as f:
    while True:
        n = f.read(1)
        if len(n) < 1: break
        arr40c0.append(u8(n))
assert len(arr40c0) == 0x3c

B = BitVecSort(32)
input_arr = Array("input_arr", B, B)

s = Solver()

for i in range(0x1e0):
    assert (i >> 3) < 60
    v4, ni = BitVecs("v4%d ni%d" % (i,i), 32)

    #s.add(v4 == Select(input_arr, i >> 3))
    s.add(v4 == input_arr[i>>3])
    #s.add(v5 == i & 7)
    #s.add(uVar4 == arr4a60[i] >> 0x37)
    #s.add(ni == ((v4 >> (i & 7)) & 1) << (((arr4a60[i] + ((arr4a60[i] >> 31) >> 29)) & 7) - ((arr4a60[i] >> 31) >> 29)))
    s.add(ni == ((v4 >> (i & 7)) & 1))
    s.add(((arr40c0[arr4a60[i] >> 3] >> (arr4a60[i] & 7)) & 1) == ni)
    #output = Store(output, arr4a60[i] >> 3, ni | Select(output, arr4a60[i] >> 3))

print(s)
s.check()
m = s.model()
for i in range(0x3C):
    s = int(str(m.eval(input_arr[i])))
    if s != 0: print(chr(s), end="")
print()
