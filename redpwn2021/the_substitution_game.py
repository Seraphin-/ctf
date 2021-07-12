from pwn import *

r = remote("mc.ax", 31996)

def submit_substitutions(substitutions):
    for s in substitutions[:-1]:
        r.sendline(" => ".join(s))
        r.sendline("y")
    r.sendline(" => ".join(substitutions[-1]))
    r.sendline("n")

# Level 1
r.sendlineafter("(y/n) ", "y")
submit_substitutions([("initial","target")])

# Level 2
r.recvuntil("Level passed!")
r.sendlineafter("(y/n) ", "y")
submit_substitutions([("hello","goodbye"),("ginkoid","ginky")])

# Level 3
r.recvuntil("Level passed!")
r.sendlineafter("(y/n) ", "y")
submit_substitutions([("aa","a"),("aaa","a")])

# Level 4
r.recvuntil("Level passed!")
r.sendlineafter("(y/n) ", "y")
submit_substitutions([("ginkoidginkoid","ginkoid"),("gginkoid","ginkoid"),("ginkoidg","ginkoid"),("gg","ginkoid")])

# Thx to jp person who solved this. Your solution is really cool
# Level 5
r.recvuntil("Level passed!")
r.sendlineafter("(y/n) ", "y")
substitutions = [("^yes$","palindrome"),("^no$","not_palindrome"),("t0","#"),("t1","##"),("#1","1#"),("#0","0#"),("#f","f"),("0##","f"),("1##",""),("1#","f"),("0#",""),("#",""),("tf$","no$"),("t$","yes$"),("^","^t")]
submit_substitutions(substitutions)

# Convert to unary and collapse
# Level 6
r.recvuntil("Level passed!")
r.sendlineafter("(y/n) ", "y")
substitutions = []
for c in range(5,0,-1):
    substitutions.append(("^" + "0" * c, "^"))
for c in range(5,0,-1):
    substitutions.append(("+" + "0" * c, "+"))
for c in range(5,0,-1):
    substitutions.append(("=" + "0" * c, "="))
for c in range(30,0,-1):
    substitutions.append(("|"*c + "0", "0" + "|"*(c*2)))
substitutions += [("111","0|0|0|"),("11","0|0|"),("1","0|"),("|0","0||")]
for c in range(5,0,-1):
    substitutions.append(("0"*c, ""))
for c in range(50,0,-1):
    substitutions.append(("|"*c+"+", "+"+"|"*c))
for c in range(50,0,-1):
    substitutions.append(("|"*c+"="+"|"*c, "="))
substitutions += [("^+=$","correct"),("=$","incorrect"),("^+incorrect","incorrect"),("^+=","incorrect")]
substitutions.append(("incorrect" + "$", "incorrect"))
for c in range(50,0,-1):
    substitutions.append(("incorrect" + "|"*c, "incorrect"))
    substitutions.append(("|"*c + "incorrect", "incorrect"))
submit_substitutions(substitutions)

r.interactive()
