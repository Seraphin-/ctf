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
