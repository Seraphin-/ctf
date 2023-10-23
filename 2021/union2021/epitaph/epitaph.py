import string
from pwn import log

sbox = []
for i in range(256):
    sbox.append(127 - i & 255 ^ 55)

FLAG_ARR = [255,238,46,22,7,209,30,68,133,2,125,35,7,245,28,18,131,77,172,159,26,194,92,66,70,117,36,59,31,153,51,27,215,215,70,178,111,172,106,39]

class Holder:
    def __getattribute__(self, name):
        return lambda *a: (int(name[1:], 16)-1, a)
O = Holder()

CODE = [O.O1(285,0),O.O2(272,264),O.O2(273,265),O.O2(274,266),O.O2(275,267),O.O2(276,268),O.O2(277,269),O.O2(278,270),O.O2(279,271),O.O2(280,272),O.O1(281,0),O.O1(282,0),O.O5(280,256,282),O.O3(283,0,280),O.O6(282),O.O2(284,282),O.O8(284,3),O.O5(283,272,284),O.O2(280,283),O.O9(280),O.O4(272,284,280),O.OA(282,8,12),O.O6(281),O.OA(281,32,11),O.O2(264,272),O.O7(286,285,264),O.O6(285),O.O2(265,273),O.O7(286,285,265),O.O6(285),O.O2(266,274),O.O7(286,285,266),O.O6(285),O.O2(267,275),O.O7(286,285,267),O.O6(285),O.O2(268,276),O.O7(286,285,268),O.O6(285),O.O2(269,277),O.O7(286,285,269),O.O6(285),O.O2(270,278),O.O7(286,285,270),O.O6(285),O.O2(271,279),O.O7(286,285,271),O.O6(285),O.OB(286,285),O.OA(284,9,1)];

# if debug: print(sbox)
debug = False

def VM(memory):
    if debug: print("Mem size", len(memory))
    if debug: print(CODE)
    loc4 = 0
    loc5 = 0
    loc6 = 0
    ip = 0
    num = -1
    while ip < len(CODE):
        op, args = CODE[ip]
        if debug: print("IP = %d ARGS = %s" % (ip, str(args)))
        ip += 1
        num += 1
        if op == 0:
            if debug: print("%.5d Memory write M[%d] => %d" % (num, args[0], args[1]))
            memory[args[0]] = args[1]
        elif op == 1:
            if debug: print("%.5d Memory move M[%d]=%d => M[%d]=%d" % (num, args[0], memory[args[0]], args[1], memory[args[1]]))
            memory[args[0]] = memory[args[1]]
        elif op == 2:
            if debug: print("%.5d Memory move M[%d] => M[%d+M[%d]]=%d" % (num, args[0], args[1], args[2], memory[args[1]+memory[args[2]]]))
            memory[args[0]] = memory[args[1] + memory[args[2]]]
        elif op == 3:
            if debug: print("%.5d Memory move M[%d+M[%d]] => M[%d]=%d" % (num, args[0], args[1], args[2], memory[args[2]]))
            memory[args[0] + memory[args[1]]] = memory[args[2]]
        elif op == 4:
            if debug: print("%.5d Memory move M[%d] => M[%d]+M[%d+M[%d]]=%d" % (num, args[0], args[0], args[1], args[2], memory[args[0]] + memory[args[1] + memory[args[2]]] & 255))
            memory[args[0]] = memory[args[0]] + memory[args[1] + memory[args[2]]]
            memory[args[0]] &= 255
        elif op == 5:
            if debug: print("%.5d Memory increment M[%d]=%d" % (num, args[0], memory[args[0]] + 1))
            memory[args[0]] += 1
            memory[args[0]] &= 255
        elif op == 6:
            loc = args[0] + memory[args[1]]
            if debug: print("%.5d Memory distant xor M[%d] ^ M[%d] = %d" % (num, loc, args[2], memory[loc] ^ memory[args[2]]))
            memory[loc] ^= memory[args[2]]
        elif op == 7:
            if debug: print("%.5d Memory and M[%d] & %d => %d" % (num, args[0], args[1], memory[args[0]] & args[1]))
            memory[args[0]] &= args[1]
        elif op == 8:
            if debug: print("%.5d Memory double and mod M[%d]=%d => %d" % (num, args[0], memory[args[0]], (memory[args[0]] * 2) % 255))
            memory[args[0]] = (((memory[args[0]]) << 1) | int(int(memory[args[0]]) >> 7)) & 255
        elif op == 9:
            if debug: print("%.5d LOOP if M[%d]=%d < %d then goto %d (%s)" % (num, args[0], memory[args[0]], args[1], args[2], str(memory[args[0]] < args[1])))
            if memory[args[0]] < args[1]:
                ip = args[2]
        elif op == 10:
            if debug: print("%.5d Break check %d+M[%d]=%d >= %d" % (num, args[0], args[1], args[0]+memory[args[1]], len(memory)))
            if args[0] + memory[args[1]] >= len(memory):
                return

def P(arr):
    loc6 = 0
    loc2 = list(arr)
    loc3 = 1
    while (len(arr) + loc3) % 8 != 0:
        loc3 += 1
    loc4 = 0
    while loc4 < loc3:
        loc6 = loc4
        loc4 += 1
        loc2.append(loc3)
    return loc2

def X(arr):
    loc5 = 0
    loc10 = 0
    loc11 = 0
    loc4 = "initiªl!"
    loc2 = [ord(x) for x in loc4]

    loc4 = "S3CRET__"
    loc7 = [ord(x) for x in loc4]

    loc3 = 286
    loc9 = []
    loc10 = loc3 + len(arr)
    for _ in range(loc10):
        loc9.append(0)
    for i in range(256):
        loc9[i] = sbox[i]

    loc9[256] = loc7[0]
    loc9[257] = loc7[1]
    loc9[258] = loc7[2]
    loc9[259] = loc7[3]
    loc9[260] = loc7[4]
    loc9[261] = loc7[5]
    loc9[262] = loc7[6]
    loc9[263] = loc7[7]
    loc9[264] = loc2[0]
    loc9[265] = loc2[1]
    loc9[266] = loc2[2]
    loc9[267] = loc2[3]
    loc9[268] = loc2[4]
    loc9[269] = loc2[5]
    loc9[270] = loc2[6]
    loc9[271] = loc2[7]
    for i in range(len(arr)):
        loc9[loc3 + i] = arr[i]

    VM(loc9)
    return loc9[loc3:]

flag = [ord(x) for x in "union{***************************}"]

p = log.progress("Flag")
for i in range(6, len(flag)):
    for c in range(0xff):
        flag[i] = c
        if X(P(flag))[i] == FLAG_ARR[i]: break
    p.status("%d/%d %s" % (i, len(flag), ''.join([chr(x) for x in flag])))

p.success(''.join([chr(x) for x in flag]))
