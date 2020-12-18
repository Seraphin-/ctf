# Alternate solver knowing more
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

input_arr = [0] * 60

for i in range(0x1e0):
    input_arr[i >> 3] |= (arr40c0[arr4a60[i] >> 3] >> (arr4a60[i] & 7) & 1) << (i & 7)

print("".join([chr(x) for x in input_arr if x > 0]))
