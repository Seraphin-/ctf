# Ruins of a long gone world (Forensics 491, 14 solves)

We're given a corrupted Minecraft alpha world folder. This format is described [here](https://minecraft.gamepedia.com/Java_Edition_Alpha_level_format). To view and edit these files, a tool like [this python library](https://github.com/twoolie/NBT) is useful.

The first thing to do is install alpha from the launcher and create a world or download another alpha world. Comparing the provided level.dat, it has some bytes overwritten at the beginning (data\x02 -> 0wn3d). After fixing it we can open it in a NBT editor, along with the actual level files.

We quickly see that chunk locations and filenames are also scrambled. The positions (xz) in the levels are way past the farlands which seems wrong. Since the positions aren't relative offsets from the originals (I found out later they are xored with 0xdeafbeef) we'll recover them based on the folder names, which encode their position modulo 64, and hope they don't wrap the modulus.

After fixing the chunk locations using a python script we can just open the world in an ancient version of MCedit and look around until we find the flag. I couldn't get the world to load in Minecraft.

MCEdit alpha73: https://www.reddit.com/r/MCEdit/comments/3bmf9d/why_is_it_so_hard_to_find_a_version_of_mcedit/

Flag: `X-MAS{R3m0v3d_H3r0br1n3_1441cfef}`