# uiuctf{AES_@_h0m3_b3_l1ke3}

from pwn import *

server = remote("mom-can-we-have-aes.chal.uiuc.tf", 1337)
client = remote("mom-can-we-have-aes.chal.uiuc.tf", 1338)

client.recvline()
server.recvline()

server.send(client.recvline().replace(b"AES.MODE_CBC, AES.MODE_CTR, AES.MODE_OFB, AES.MODE_EAX, ", b""))
server.send(client.recvline())
client.send(server.recvline())
client.send(server.recvline())
client.send(server.recvline())
server.send(client.recvline())
server.send(client.recvline())
server.send(client.recvline())
server.close()
client.sendline(b"finish")
#Determine char
#aes256 => 32 bytes
import string
flagchars = string.printable.replace("\n", "").encode()

def check(known):
    t = b""
    for c in flagchars:
        t += b"\xff"*(32-len(known)-1) + known + bytes([c])
    t += b"\xff"*(32-len(known)-1) # trailing

    client.sendline(t.hex())
    r = bytes.fromhex(client.recvline().decode().rstrip())
    pos = r.find(r[32*len(flagchars):32*(len(flagchars)+1)])
    return known + bytes([flagchars[pos//32]])

known = b""
while len(known) == 0 or known[-1] != ord("}"):
    known = check(known)
    print(known)
