from nbt import nbt
import glob
from numpy import base_repr
import os

def b32_s(n):
	if n < 0: n = 256-n
	return base_repr(n & 63, 36).lower()

for r in glob.glob("*/*/*.dat"):
	nbtfile = nbt.NBTFile(r,'rb')
	# Entities hint the real location

	"""real_x = "Unknown"
	real_z = "Unknown"
	for b in nbtfile["Level"]["TileEntities"]:
		real_x = b['x'].value // 16
		if b['x'].value <= 0: real_x -= 1
		real_z = b['z'].value // 16
		if b['z'].value <= 0: real_z -= 1
		break
	for b in nbtfile["Level"]["Entities"]:

	nbtfile['Level']['xPos'].value = real_x
	nbtfile['Level']['zPos'].value = real_z"""
	# Actually, let's just parse
	rr = r.split("\\")
	real_x = int(rr[0], 36)
	real_z = int(rr[1], 36)
	# Let's use signs from the filename, though they're flipped
	rr = rr[2].split(".")
	x_pos = "-" in r[1]
	z_pos = "-" in r[2]	
	if not x_pos: real_x = 64-real_x & 63
	if not z_pos: real_z = 64-real_z & 63

	if real_x != "Unknown":
		if not os.path.isdir("..\\fixed_world\\%s" % b32_s(real_x)): os.mkdir("..\\fixed_world\\%s" % b32_s(real_x))
		if not os.path.isdir("..\\fixed_world\\%s\\%s" % (b32_s(real_x), b32_s(real_z))): os.mkdir("..\\fixed_world\\%s\\%s" % (b32_s(real_x), b32_s(real_z)))
		nbtfile.write_file("..\\fixed_world\\%s\\%s\\c.%s.%s.dat" % (b32_s(real_x), b32_s(real_z), base_repr(real_x, 36).lower(), base_repr(real_z, 36).lower()))