# Scrambled Carol (Crypto 47, 147 solves)

# This is a simple S-box, so frequency analysis helps us along
# Most common is 0x18 -> space?
# We assume most is lowercase. Lowercase ascii starts with 0x6 and 0x7 nibbles
# Earlier characters are more common, and 0x0 is a more common nibble, so we assume that is 0x6.
# At this point plenty is readable and we can figure out the rest by hand, seeing fragments of words like "garbage" and "flag".

# (We could have also used the fact that we knew it was a carol to guess, and I tried this, but it was easier to do the freq analysis in the end)

inp = open("output_chall.txt", "r").read().rstrip()

orig =  "0123456789abcdef"
known = "62e43cb901df578a"
output_data = ""

for i in inp:
	output_data += known[orig.index(i)]

output_data = [output_data[i:i+2] for i in range(0, len(output_data), 2)]
output_dc = ""
for i in output_data:
	if all(c in orig for c in i):
		output_dc += bytes.fromhex(i).decode()
	else: output_dc += "?"

print(" ".join(output_data))
print(output_dc)

# Flag: X-MAS{xmaswasneverasgoodasitisthisyear}