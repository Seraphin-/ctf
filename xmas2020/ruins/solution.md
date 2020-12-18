# Ruins of a long gone world (Forensics 491, 14 solves)

Better writeup coming soon?

We're given a corrupted Minecraft alpha world folder. level.dat has some bytes overwritten (data\x02 -> 0wn3d), and chunk locations/filenames are scrambled. We'll recover them based on the folder names and hope they don't wrap the modulus 64.

After fixing the chunk locations we can just open the world in an ancient version of MCedit and look around until we find the flag.

MCEdit alpha73: https://www.reddit.com/r/MCEdit/comments/3bmf9d/why_is_it_so_hard_to_find_a_version_of_mcedit/

Flag: `X-MAS{R3m0v3d_H3r0br1n3_1441cfef}`