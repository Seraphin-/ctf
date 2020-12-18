# Bad GameBoy trade (Forensics 494, 12 solves)

We are given a pcap of a TCP connection of a "pokemon trade".
The pcap is quite massive and contains lots of empty data packets. The first thing is to identify the format of the data.

Since it's TCP, it can't be the actual link cable data and must be an intermediary connection of some kind. The title and short packet size alludes to it being [bgb's link protocol](https://bgb.bircd.org/bgblink.html). Looking at the first packet, it matches the initial handshake described. The packet structures are actually pretty simple themselves, so we can just dump the data and use Python to analyze it.

`tshark` can convert the packets into a trivial format so we can write a parser as a loop over files lines.
```
tshark -T fields -e tcp.dstport -e data -r capture.pcapng > parsed_capture
```

I like to write these kinds of TV parsers in python using a dict of handler functions. We can stub the handlers for sync3 and joypad data for now assuming we don't need it. The sync1 and sync2 packets look like what we're here for.

The bgb link protocol only transfers a single byte at a time, so we can write out the data into files to analyze it laterally. Upon dumping the file this way, the output looks like interesting data but there's no strings.
```
> xxd td1_raw
...
00001c80: c3bd c3bd c3bd c3bd c3bd c3bd 3fc2 94c3  ............?...
00001c90: aa42 c29c c3b8 56c2 b618 7bc3 bdc3 bdc3  .B....V...{.....
00001ca0: bdc3 bdc3 bdc3 bdc3 bdc3 bdc3 bdc2 80c2  ................
00001cb0: 8cc2 8050 0000 0000 0000 0006 c285 6ec2  ...P..........n.
00001cc0: 99c2 9808 6ac3 bfc2 8500 0b01 0015 15c3  ....j...........
00001cd0: bf42 505d 7a3c 6d00 0000 0037 0037 0032  .BP]z<m....7.7.2
00001ce0: 0037 0041 c2bc 2919 1419 1e01 000b 0005  .7.A..).........
00001cf0: 0006 0006 0005 6e00 1906 0015 1578 542d  ......n......xT-
00001d00: 2700 3c6d 0000 c2b3 0037 0037 0032 0037  '.<m.....7.7.2.7
00001d10: 0041 c2bc 291e 281e 0006 0019 000e 000e  .A..).(.........
00001d20: 0010 000c c299 0016 0600 1603 2d42 100e  ............-B..
00001d30: 003c 6d00 00c2 b300 3700 3700 3200 3700  .<m.....7.7.2.7.
00001d40: 41c2 bc29 1923 1e00 0600 1600 0c00 0c00  A..).#..........
00001d50: 0a00 0ec2 9800 c2be 4b00 1518 3c30 3076  ........K...<00v
00001d60: c284 3c6d 080b c3af 0037 0037 0032 0037  ..<m.....7.7.2.7
00001d70: 0041 c2bc 2914 140a 234b 00c2 be00 c287  .A..)...#K......
00001d80: 00c2 9800 c2b6 00c2 aa08 001c 0600 1518  ................
00001d90: 4bc2 8dc2 855c 333c 6d00 00c3 9800 3700  K....\3<m.....7.
00001da0: 3700 3200 3700 41c2 bc29 0f14 0a1e 0600  7.2.7.A..)......
00001db0: 1c00 0f00 1300 0800 0f6a 010e 6400 0101  .........j..d...
00001dc0: c2b4 252d 027d 3c6d 102c 1400 3700 3700  ..%-.}<m.,..7.7.
00001dd0: 3200 3700 41c2 bc29 1428 1914 6401 0e00  2.7.A..).(..d...
00001de0: c2bd 00c2 8300 5100 5fc2 80c2 8cc2 8050  ......Q._......P
...
```

Considering this is supposed to be a pokemon transfer, I figured the only way a flag would be sent would be as a pokemon nickname. Pokemon nicknames are send in an array and use a special encoding because the name bytes are equivalent to tile bytes. Armed with this information and [Bulabapedia](https://bulbapedia.bulbagarden.net/wiki/Character_encoding_in_Generation_I#English), we can construct a lookup table for printable tiles.

Since we're only interested in nicknames I decided to just skip copying non nicknamable characters into the output at all. After running all the data through this lookup table, we have the flag hanging out in the output.
The flag has PK and MN instead of {}, but it's still pretty easy to identify the leetspeak.

```
xxd td2
00000a20: 414d 4141 4d41 414d 4141 4d41 414d 4158  AMAAMAAMAAMAAMAX
00000a30: 2d4d 4153 7b4c 3030 6b21 2121 2d31 2d46  -MAS{L00k!!!-1-F
00000a40: 3075 6e64 2d37 6831 352d 6d33 772d 756e  0und-7h15-m3w-un
00000a50: 6433 722d 3768 332d 7472 7563 6b21 2121  d3r-7h3-truck!!!
00000a60: 2d30 3134 3561 6665 7d75 4137 3737 3737  -0145afe}uA77777
```

Dissector:
```python
from scapy.all import TCP, rdpcap
import sys
transfer_data_1 = open("td1", "w")
transfer_data_2 = open("td2", "w")

LT = {0x9a: "(", 0x9b: ")", 0x9c: ":", 0x9d: ";", 0x9e: "[", 0x9f: "]",
    0x60: "A", 0x61: "B", 0x62: "C", 0x63: "D", 0x64: "E", 0x65: "F", 0x66: "G",
    0x67: "H", 0x68: "I", 0x69: "V", 0x6a: "S", 0x6b: "L", 0x6c: "M",
    0x6d: ":", 0x6e: "?", 0x6f: "?",
    0x70: "'", 0x71: "'", 0x72: "\"", 0x73: "\"", 0x74: ".", 0x75: ".",
    0xe0: "'", 0xe1: "{", 0xe2: "}", 0xe3: "-", 0xe6: "?", 0xe7: "!", 0xe8: "."
    # { and } are usually PK MN but this works for the flag
}

def lookup(char):
    if char in LT:
        return LT[char]
    if char < 0x9A and char >= 0x80: return chr(char-0x80+65)
    if char < 0xba and char >= 0xa0: return chr(char-0xa0+97)
    if char > 0xf5: return chr(char-0xf6+0x30)
    return False

print("Starting")

def version(data, src, dst):
    print("Version check:", src, "=>", dst, "|", data)

def joypad(data, src, dst):
    pass # We don't want this probably

def save(data, src):
    data = lookup(data[1])
    # By just skipping it's easier to find the flag, though obviously data is lost
    if data == False: return # data = "`"
    if src == "1337": transfer_data_1.write(data)
    else: transfer_data_2.write(data)

def sync1(data, src, dst):
    # print(src, '=>', dst)
    # print("Send data (pri):", data[1])
    save(data, src)

def sync2(data, src, dst):
    # print(src, '=>', dst)
    # print("Send data (sub):", data[1])
    save(data, src)

def sync3(data, src, dst): pass

def status(data, src, dst):
    print("Status check:", src, "=>", dst)
    if data[1] & 1: print("statusflag_running")
    if data[1] & 2: print("statusflag_paused")
    if data[1] & 4: print("statusflag_supportreconnect")

handlers = {
    1: version,
    101: joypad,
    104: sync1,
    105: sync2,
    106: sync3,
    108: status,
}

# Takes the output of
# tshark -T fields -e tcp.dstport -e data -r capture.pcapng > parsed_capture
for line in open(sys.argv[1], "r"):
    dd = line.rstrip().split("\t")
    if len(dd) == 1: continue # Ignore empty TCP packets
    dst, data = dd
    data = bytes.fromhex(data)
    if dst == "1337": src = "50919"
    else: src = "1337"
    handlers[data[0]](data, src, dst)

# Just look in td1 and td2 now!

# X-MAS{L00k!!!-1-F0und-7h15-m3w-und3r-7h3-truck!!!-0145afe8}
# X-MAS{L00k!!!-1-F0und-7h15-m3w-und3r-7h3-truck!!!-0145afe}
# (depending on who you ask)
```
