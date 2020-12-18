# Reindeers 2.0 (Forensics 448, 34 solves)

The hint says "GO", so I looked up steg tools written in Go and found stegify. It outputs a binary blob that file claims is a DOS executable, but nothing happens if you run it in DOSbox. binwalk extracts a zip which contains some images, and checking the exif of download.png reveals the ROT13 flag.

Flag: `X-MAS{4hh_y0u_g0t_m3_in_th3_v3ry_3nd}`
