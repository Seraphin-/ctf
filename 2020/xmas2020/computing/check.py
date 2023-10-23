from pwn import *

def queryTime(test):
    count = 1
    p = log.progress("Testing:")
    status = False
    while True:
        try:
            p.status("Trial %d/4" % count)
            if count > 4:
                status = True
                break
            r = remote('challs.xmas.htsp.ro', 5051)
            r.recvuntil("PASSWORD:\n")
            r.sendline(test)
            r.recvuntil("REJECTED.")
            break
        except EOFError:
            count += 1
            continue
        except PwnlibException:
            continue
    p.success("Done")
    return status

known = input("What to test: ")
r = queryTime(known)

if r: log.success("Looks good.")
else: log.failure("Nope!")
