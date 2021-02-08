# i made this from a befunge interpreter i wrote a few years ago
# hence the variable names

import sys
import random
from colr import color
trace_record = [[], [], []]

INSTRUCTION_DESCRIPTIONS = {
    b'\x00': "Nothing",
    b'\x01': "Select register 0",
    b'\x02': "Select register 1",
    b'\x03': "Select register 2",
    b'\x04': "Select register 3",
    b'\x05': "Select register 4",
    b'\x06': "Select register 5",
    b'\x07': "Select register 6",
    b'\x08': "Select register 7",
    b'\x09': "selected ← r0",
    b'\x0A': "selected ← r1",
    b'\x0B': "selected ← r2",
    b'\x0C': "selected ← r3",
    b'\x0D': "selected ← r4",
    b'\x0E': "selected ← r5",
    b'\x0F': "selected ← r6",
    b'\x10': "selected ← r7",
    b'\x11': "selected += 1",
    b'\x12': "selected -= 1",
    b'\x13': "selected ← r6 + r7",
    b'\x14': "selected ← r6 - r7",
    b'\x15': "selected ← r6 * r7",
    b'\x16': "selected ← r6 / r7",
    b'\x17': "selected ← r6 % r7",
    b'\x18': "selected = ~selected",
    b'\x19': "selected = -selected",
    b'\x1A': "selected ← r6 & r7",
    b'\x1B': "selected ← r6 | r7",
    b'\x1C': "selected ← r6 ^ r7",
    b'\x1D': "selected ← r6 == r7",
    b'\x1E': "selected ← r6 < r7",
    b'\x1F': "r0 ← y, r1 ← x, r2 ← direction",
    b'\x20': "jump next instruction if selected & 1 else no-op",
    b'\x21': "selected ← (r1, r0)",
    b'\x22': "(r1, r0) ← selected",
    b'\x23': "x ← r1, y ← r0, direction ← r2",
    b'\x24': "selected ← getchar",
    b'\x25': "putchar(selected)",
    b'\x27': "move right",
    b'\x29': "move left",
    b'\x26': "move up",
    b'\x28': "move down",
}

class FungeSpace(object):
    def __init__(self):
        self.space = [0] * 70 * 70 #can use bytearray if no need to store values over 706 - spec unclear but some programs use

    def get(self, x, y):
        x %= 70
        y %= 70
        return self.space[y * 70 + x]

    def set(self, x, y, value, overwriteWithSpace=True):
        if overwriteWithSpace or (value != 0):
            self.space[y * 70 + x] = value

    def readScript(self, script):
        self.space = list(script)
        assert len(self.space) == 70 * 70

    def render(self, show_ip=False, ip=None):
        print('   ' + ''.join("%.2d" % x for x in range(70)))
        print('  *' + ('--' * 70) + '*')
        for y in range(70):
            print('%.2d|' % y,end='')
            for x in range(70):
                if show_ip and x == ip.x and y == ip.y: print(color("##", fore='000', back='fff'), end='')
                else:
                    val = "%.2X" % self.get(x, y)
                    if val == "00": val = color(val, fore='111')
                    elif self.get(x, y) < 0x11: val = color(val, fore='222')
                    elif val == "1E": val = color(val, fore='0f0') # gt check : blue
                    elif val == "1D": val = color(val, fore='7f7', back='fff') # equality : white bg
                    elif val == "20": val = color(val, fore='9f9', back='fff') # conditional move : white bg
                    elif val == "21" or val == "22": val = color(val, fore='f0f') # conditional move : white bg
                    elif val == "23": val = color(val, fore='909') # computed dir change
                    elif val == "24" or val == "25": val = color(val, fore='fff', back='00f') # i/o : blue bg
                    elif self.get(x, y) > 0x25:
                        if val == "26": val = "↑↑"
                        elif val == "27": val = "→→"
                        elif val == "28": val = "↓↓"
                        elif val == "29": val = "←←"
                        val = color(val, back='333')
                    print(val,end='')
            print('|\n',end='')
        print('  *' + ('--' * 70) + '*')

class BfInstructionPointer(object):
    def __init__(self):
        self.x = 0
        self.y = 0
        self.dx = 1
        self.dy = 0

    def clone(self):
        ret = BfInstructionPointer()
        ret.x, ret.y, ret.dx, ret.dy = self.x, self.y, self.dx, self.dy
        return ret

    def move(self):
        self.x = self.x + self.dx
        self.y = self.y + self.dy
        if self.x == 70:
        	self.x = 0
        if self.x == -1:
        	self.x = 69
        if self.y == 70:
        	self.y = 0
        if self.y == -1:
        	self.y = 69

    def setDelta(self, dx, dy):
        self.dx = dx
        self.dy = dy

    def get(self):
        return (self.x, self.y)

    def __repr__(self):
        return "BfIP @ (%d, %d) moving (%d, %d)" % (self.x, self.y, self.dx, self.dy)

class Befunge(object):
    def __init__(self, script, step=False, data_input=None, input_buffer=[]):
        self.step = step
        self.space = FungeSpace()
        self.space.readScript(script)
        self.ip = BfInstructionPointer()
        self.data_input = iter(data_input) if data_input is not None else None
        self.tick = 0
        self.blanks = 0
        self.buffer = input_buffer

        self.breakpoints_location = []
        self.breakpoints_instruction = []
        self.in_continue = False

        self.registers = [0] * 8
        self.unknowns = {"0x10110": {"cnt": 0, "str": b""}}
        self.selected = 0

        self.handlers = {
            b'\x01': lambda: self.select(0),
            b'\x02': lambda: self.select(1),
            b'\x03': lambda: self.select(2),
            b'\x04': lambda: self.select(3),
            b'\x05': lambda: self.select(4),
            b'\x06': lambda: self.select(5),
            b'\x07': lambda: self.select(6),
            b'\x08': lambda: self.select(7),
            b'\x09': lambda: self.set_selected(0),
            b'\x0A': lambda: self.set_selected(1),
            b'\x0B': lambda: self.set_selected(2),
            b'\x0C': lambda: self.set_selected(3),
            b'\x0D': lambda: self.set_selected(4),
            b'\x0E': lambda: self.set_selected(5),
            b'\x0F': lambda: self.set_selected(6),
            b'\x10': lambda: self.set_selected(7),
            b'\x11': lambda: self.set_selected_to(self.registers[self.selected] + 1),
            b'\x12': lambda: self.set_selected_to(self.registers[self.selected] - 1),
            b'\x13': lambda: self.set_selected_to(self.registers[6] + self.registers[7]),
            b'\x14': lambda: self.set_selected_to(self.registers[6] - self.registers[7]),
            b'\x15': lambda: self.set_selected_to(self.registers[6] * self.registers[7]),
            b'\x16': lambda: self.set_selected_to(self.registers[6] // self.registers[7]),
            b'\x17': lambda: self.set_selected_to(self.registers[6] % self.registers[7]),
            b'\x18': lambda: self.set_selected_to(~self.registers[self.selected]),
            b'\x19': lambda: self.set_selected_to(-self.registers[self.selected]),
            b'\x1A': lambda: self.set_selected_to(self.registers[6] & self.registers[7]),
            b'\x1B': lambda: self.set_selected_to(self.registers[6] | self.registers[7]),
            b'\x1C': lambda: self.set_selected_to(self.registers[6] ^ self.registers[7]),
            b'\x1D': lambda: self.set_selected_to(self.registers[6] == self.registers[7]), # self.step and print("Checked", self.registers[6], '==', self.registers[7])),
            b'\x1E': lambda: self.set_selected_to(self.registers[6] < self.registers[7]),
            b'\x1F': self.handleGetPos,
            b'\x20': self.handleConditional,
            b'\x21': self.handleGet,
            b'\x22': self.handlePut,
            b'\x23': self.handleUnknownWrite,
            b'\x24': self.handleInChar,
            b'\x25': self.handleOutChar,
            b'\x27': lambda: self.ip.setDelta(1, 0),
            b'\x29': lambda: self.ip.setDelta(-1, 0),
            b'\x26': lambda: self.ip.setDelta(0, -1),
            b'\x28': lambda: self.ip.setDelta(0, 1),
        }

    def run(self, trace=None):
        self.run = True
        while self.run:
            if trace is not None:
                test = trace.readline().rstrip()
                if test != repr(self.registers):
                    print("Trace mismatch")
                    print("Test", test)
                    print("Real", self.registers)
                    exit()
            self.interpret()
        if trace is not None:
            assert trace.readline() == ""
        print('Complete in %s ticks (%s blank)' % (self.tick, self.blanks))
        print('Registers', self.registers)
        print('Unknowns', self.unknowns)
        if input("Show (y/n)? ") == "y":
            self.space.render(show_ip=True,ip=self.ip)

    def render(self):
        self.space.render()

    def interpret(self):
        curSpace = bytes([self.space.get(*self.ip.get())]) #TODO try catch throw bad value
        trace_record[0].append(70-self.ip.get()[0])
        trace_record[1].append(self.ip.get()[1])
        trace_record[2].append(self.tick)

        if self.step:
            self.showInteractive(curSpace)

        if curSpace == b'\x00':
            self.blanks = self.blanks + 1
        elif curSpace not in self.handlers:
            self.run = False
        else:
            self.handlers[curSpace]()
            self.registers = [x % 256 for x in self.registers]
        self.tick = self.tick + 1
        self.ip.move()

    def showInteractive(self, curSpace):
        if self.in_continue and self.ip.get() not in self.breakpoints_location and hex(curSpace[0])[2:] not in self.breakpoints_instruction:
            return
        self.in_continue = False
        self.space.render(show_ip=True,ip=self.ip)
        print(color("Registers", back="333"),
                color(' '.join([("%.2x" % self.registers[x]) if x != self.selected else color("%.2x" % self.registers[x], fore='222') for x in range(8)]), back='444'),
                color("Current instruction", back='333'), "%.2x" % curSpace[0],
                "Buffered", len(self.buffer))
        print("Description:", INSTRUCTION_DESCRIPTIONS[curSpace] if curSpace in INSTRUCTION_DESCRIPTIONS else "Halts")
        action = input("interactive:")
        if len(action) == 0: return
        elif action[0] == "c": self.in_continue = True
        elif action[0:3] == "bl ":
            x, y = action[3:].split(" ")
            x, y = int(x), int(y)
            self.breakpoints_location.append((x, y))
        elif action[0:4] == "set ":
            x, y = action[4:].split(" ")
            x, y = int(x), int(y)
            self.ip.x, self.ip.y = x, y
        elif action[0:3] == "bi ":
            instruction = action[3:].lower()
            self.breakpoints_instruction.append(instruction)
        elif action == "dropin":
            import pdb; pdb.set_trace()

    def set_selected(self, target):
        self.registers[self.selected] = self.registers[target]

    def select(self, target):
        self.selected = target

    def set_selected_to(self, value):
        self.registers[self.selected] = value

    def handleGet(self):
        self.registers[self.selected] = self.space.get(self.registers[1], self.registers[0])

    def handlePut(self):
        self.space.set(self.registers[1], self.registers[0], self.registers[self.selected])

    def handleInChar(self):
        if self.data_input is not None:
            self.registers[self.selected] = next(self.data_input)
            return
        if len(self.buffer) == 0:
            inp = input("<INPUT> ")
            if len(inp) == 0: self.buffer = [ord("\n")]
            elif len(inp) == 4 and inp[:2] == "\\x": self.buffer = [int(inp[2:], 16)]
            else: self.buffer = list(inp.encode())
        else:
            # print("<INPUT> Buffered", bytes([self.buffer[0]]))
            pass
        
        self.registers[self.selected] = self.buffer.pop(0)

    def handleOutChar(self):
        #print("(PRINT) ", self.registers, self.selected)
        self.unknowns["0x10110"]['cnt'] += 1
        self.unknowns["0x10110"]['str'] += bytes([self.registers[self.selected]])
        print("(PRINT) '%s'" % chr(self.registers[self.selected]))
        #print(chr(self.registers[self.selected]), end='')

    def getDirAsNum(self):
        if self.ip.dx == 0 and self.ip.dy == -1: return 0
        if self.ip.dx == 1 and self.ip.dy == 0: return 1
        if self.ip.dx == 0 and self.ip.dy == 1: return 2
        if self.ip.dx == -1 and self.ip.dy == 0: return 3

    def setDirFromNum(self, v):
        if v == 0: self.ip.setDelta(0, -1)
        elif v == 1: self.ip.setDelta(1, 0)
        elif v == 2: self.ip.setDelta(0, 1)
        elif v == 3: self.ip.setDelta(-1, 0)

    def handleGetPos(self):
        self.registers[0] = self.ip.y
        self.registers[1] = self.ip.x
        self.registers[2] = self.getDirAsNum()

    def handleConditional(self): # flip dir?
        #if self.step:
            #print("(CONDITIONAL)")
            #print("Registers", self.registers)
        if not (self.registers[self.selected] & 1): return

        off_20F0 = [0x28, 0x29, 0x26, 0x27]

        v11 = self.getDirAsNum()
#        if v11 == 2:
#            self.ip.setDelta(-1, 0)
#        elif v11 == 0:
#            self.ip.setDelta(0, -1)
#        elif v11 == 1:
#            self.ip.setDelta(1, 0)
#        elif v11 == 3:
#            self.ip.setDelta(0, 1)
        self.ip.move()

        if self.space.get(*self.ip.get()) == off_20F0[v11]:
            print(self.space.get(*self.ip.get()), off_20F0[v11])
            self.run = False
            print("* May have exited from conditional?")

    def handleUnknownWrite(self):
        self.ip.y = self.registers[0]
        self.ip.x = self.registers[1]
        self.setDirFromNum(self.registers[2])

if __name__ == '__main__':
    print("Reading script from %s..." % sys.argv[1])
    print("Remember you can escape inputs with \\x?? like in python")
    print("Step mode:")
    print("  Breakpoint on location: 'bl x y'")
    print("  Breakpoint on instruction: 'bl ID'")
    print("  Type 'c' to continue to breakpoint or end")
    solution = list(b'&(\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04((((((((((((((((((((((()(&(\x04\x04\x01      \x02  \x04     \x01 (((((((((((((((((((((((\x11\x08&(\x04\x01\x00\x04\x04\x04\x04\x04\x04 \x04 \x04 \x04\x04\x04\x04 \x04((((((((((((((((((((((\x02\x11\x11&(\x04 \x04    \x04\x04 \x04   \x04  \x04 \x04((((((((((((((((((((((\x10\x11\x11&(\x04\x00\x03 \x04\x04  \x04 \x04\x04\x04\x04\x04\x04   \x04((((((((((((((((((((((\x01\x11\x11&(\x04\x04 \x04\x04\x04\x04  \x01      \x02\x04 \x04((((((((((((((((((((((\x0f\x11\x11&(\x04\x04\x00 \x03\x04\x04\x04\x04\x04 \x04\x04\x04\x04\x04 \x04 \x04((((((((((((((((((((((\x05\x11\x11&(\x04\x04\x04\x04 \x04\x04  \x04 \x04\x04   \x01\x02 \x04((((((((((((((((((((((!\x11\x11&(\x04\x01  \x00\x04\x04 \x04\x04    \x04\x04\x04  \x04(((((((((((((((((((((((\x11\x11&(\x04 \x04\x04\x04   \x04\x04\x04\x04\x04\x04\x04\x02 \x03 \x04(((((((((((((((((((((((\x11\x11&(\x04\x00\x03\x04\x04 \x04\x04      \x04 \x04\x04 \x04(((((((((((((((((((((((\x11\x11&(\x04\x04\x00   \x03\x04 \x04\x04\x04\x04\x04\x04 \x04\x04 \x04(((((((((((((((((((((((\x11\x11&(\x04 \x04 \x04\x04 \x04\x02  \x03\x04 \x04 \x04\x04 \x04(((((((((((((((((((((((\x11\x11&(\x04 \x04\x04\x04\x04 \x04 \x04\x04\x00   \x03\x04\x01\x00\x04(((((((((((((((((((((((\x11\x11&(\x04    \x04 \x04 \x04 \x04\x04\x04\x04\x04\x04 \x04\x04(((((((((((((((((((((((\x11\x11&(\x04\x04 \x04\x04\x04 \x04\x01 \x02\x04\x01    \x00\x04\x04(((((((((((((((((((((((\x11\x11&(\x04  \x04\x01 \x00\x04 \x04\x01 \x00\x04\x04\x04\x04\x04\x04\x04(((((((((((((((((((((((\x11\x11&(\x04 \x04\x04 \x04\x04\x04 \x04\x04\x04\x04\x04 \x04 \x04 \x04(((((((((((((((((((((((\x11\x11&(\x04\x01  \x00              \x04(((((((((((((((((((((((\x11\x11&(\x04 \x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04(((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11(&((((((((((((((((((((((((((((((((((((((((((((\x11\x07&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((\x11\x11&((((((((((((((((((((((((((((((((((((((((((((&)&))))))))))))))))))))))))))))))))))))))))))))))!')

    step = input("Step? (y/n):") == 'y'
    script = open(sys.argv[1], "rb")
    bf = Befunge(script.read(), step=step, data_input=solution)
    script.close()
    
    if input("Use trace? (y/n):") == 'y':
        bf.run(trace=open("memory_trace", "r"))
    else: bf.run()
