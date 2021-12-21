# TinyVM (rev 495)
# After a bit of playing with the challenge binary, I noticed it appears to output a `1` when each character is correct. So it is time for brute force...

# X-MAS{th15_41Nt_VMPr0tEct_BUT_1t5_h0Ne5T_W0rK_9J9J0k09}

from pwn import *
from collections import defaultdict
import string
import ray
ray.init()

@ray.remote
def checkSubstring(test):
    p = process(["./tinyvm/chall"])
    p.sendline(test)
    try:
        j = len(p.recvuntil(b"0", timeout=2))-1
    except EOFError:
        j = len(test) # done
    p.close()
    return test[-1], j

known = "X-MAS{th15_41Nt_VMPr0tEct_BUT_1t5_h0Ne5T_W0rK_9J9J0k09" # Use this if you know any part of the string

log.info("Starting. Beware lots of error spam from ray!")

while True:
    log.success("Current flag: " + known)
    gets = []
    # Order these such that the characters we expect are first
    main = "0123456789-}" + string.ascii_uppercase + string.ascii_lowercase + string.punctuation
    for i in main + "".join(set(string.printable)-set(main)-set("\n")):
        gets.append(checkSubstring.remote(known+i))
    total = len(gets)
    # Get as results come, break on first True
    fl = []
    p = log.progress("Testing characters")
    p.status("Remaining %d/%d" % (total, total))
    while True:
        ready = ray.wait(gets)[0]
        res = ray.get(ready)
        for o in ready: gets.remove(o)
        p.status("Remaining %d/%d" % (len(gets), total))
        fl += list(filter(lambda x: x[1] == len(known)+1, res))
        if len(fl) > 0:
            break
        if len(gets) <= 1: break
    p.success("Done")
    for o in gets: ray.cancel(o, force=True)
    if len(fl) != 1:
        log.warning("Looks like the server is acting up.")
        exit()

    i = fl[0][0]
    known += i
    if known[-1] == "}": break

log.success("Flag: " + known)
# Time to solve from nothing: 
