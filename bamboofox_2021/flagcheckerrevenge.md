# Flag Checker Revenge (Reverse)
I opened the binary in a dissasembler and saw there were a LOT of checker functions that seemed to have simple conditions. There was also a number comparison in `main` that appeared to be a length check.

Since the conditions seemed simple, I decided it was time for symbolic execution. I put it into angr and got the flag in a minute.

`flag{4ll_7h3_w4y_70_7h3_d33p357_v4l1d4710n}`
