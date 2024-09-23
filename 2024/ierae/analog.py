import numpy as np

ranges = [(-10, "011"), (-2.2, "111"), (-1.4, "110"), (-0.7, "010"), (0, "000"), (0.9, "100"), (1.6, "101"), (2.3, "001")]

cs = np.fromfile("analog_flag.encoded", dtype='F')
msg = ""
ay = []
for i in range(0, len(cs), 4):
    ms = []
    os = None
    for j in range(4):
        print(i, j, cs[i+j])
        magnitude = np.angle(cs[i+j])
        print(magnitude)
        ms.append(magnitude)
    val = 0
    a = np.median(ms)
    for r, v in ranges:
        if a < r:
            break
        val = v
    ay.append(a)
    msg += val[::-1]

msg2 = msg
msg = ""
for i in range(0, len(msg2), 8):
    msg += msg2[i:i+8][::-1]
print(bytes.fromhex(hex(int(msg, 2))[2:]))
