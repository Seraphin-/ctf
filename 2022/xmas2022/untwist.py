from z3 import *
from random import Random
from itertools import count
from time import time as Time
import logging

logging.basicConfig(format='STT> %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

SYMBOLIC_COUNTER = count()
symbolic_guess_l = []
gv = 0
class Untwister:
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    #This particular method was adapted from https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/
    def symbolic_untamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)

        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)

        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y == y4 ^ (LShR(y4, 18))
        ]

        solver.add(equations)
        return y1

    def symbolic_twist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        '''
            This method models MT19937 function as a Z3 program
        '''
        MT = [i for i in MT] #Just a shallow copy of the state

        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a) #Possible Z3 optimization here by declaring auxiliary symbolic variables
            MT[i] = MT[(i + m) % n] ^ xB

        return MT

    def get_symbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1001000??0?100?10??10010" where ? represents an unknown bit'

        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) <= 32, "One 32-bit number at a time please"
        guess = guess.zfill(32)
    
        self.symbolic_guess = BitVec(f'symbolic_guess_{name}', 32)
        symbolic_guess_l.append(self.symbolic_guess)
        guess = guess[::-1]

        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolic_guess) == bit)

        return self.symbolic_guess


    def submit(self, guess):
        '''
            You need 624 numbers to completely clone the state.
                You can input less than that though and this will give you the best guess for the state
        '''
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.symbolic_twist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0

        symbolic_guess = self.get_symbolic(guess)
        symbolic_guess = self.symbolic_untamper(self.solver, symbolic_guess)
        self.solver.add(self.MT[self.index] == symbolic_guess)
        self.index += 1

    def get_random(self):
        '''
            This will give you a random.Random() instance with the cloned state.
        '''
        logger.debug('Solving...')
        start = Time()
        self.solver.check()
        model = self.solver.model()
        end = Time()
        logger.debug(f'Solved! (in {round(end-start,3)}s)')

        #Compute best guess for state
        #print(symbolic_guess_l[620])
        #print(model[symbolic_guess_l[620]], len(symbolic_guess_l))
        #print([model[symbolic_guess_l[i]] for i in range(620, len(symbolic_guess_l))])
        gv = (model[symbolic_guess_l[683]].as_long() << 96) + (model[symbolic_guess_l[682]].as_long() << 64) + (model[symbolic_guess_l[681]].as_long() << 32) + model[symbolic_guess_l[680]].as_long()
        gv <<= 1920
        gv = str(gv)[:32]
        print(gv)
        state = list(map(lambda x: model[x].as_long(), self.MT))
        result_state = (3, tuple(state+[self.index]), None)
        r = Random()
        r.setstate(result_state)
        return r

def test():
    '''
        This test tries to clone Python random's internal state, given partial output from getrandbits
    '''

    r1 = Random()
    ut = Untwister()
    for _ in range(1337):
        random_num = r1.getrandbits(16)
        #Just send stuff like "?11????0011?0110??01110????01???"
            #Where ? represents unknown bits
        ut.submit(bin(random_num)[2:] + '?'*16)

    r2 = ut.get_random()
    for _ in range(624):
        assert r1.getrandbits(32) == r2.getrandbits(32)

    logger.debug('Test passed!')

if __name__ == '__main__':
    #import random
    ut = Untwister()

    from pwn import *
    
    #ut.submit(bin(random.getrandbits(640*31))[2:])
    """
    ints = []
    for i in range(31):
        #for j in range(20):
        #    ut.submit(bin(random.getrandbits(32))[2:])
        ints.append(random.getrandbits(640))
    """
    r = remote("challs.htsp.ro", 10003)
    data = r.recvuntil(b"> ").decode().split("\n")[:31]
    assert len(data) == 31
    ints = [int(x) for x in data]
    #"""
    for bits in ints:
        #print(bits)
        while bits > 0:
            #print(bin(bits & (2**32-1))[2:].rjust(32, "0"))
            ut.submit(bin(bits & (2**32-1))[2:].rjust(32, "0"))
            bits >>= 32

    words = ['mariah carey', 'holy night', 'let it snow', 'jingle bells', 'snow globe']
    #print(random.getstate())
    #bz = random.getrandbits(2048)
    #print((bz >> 2016))
    #print(2048, str(bz)[:32])
    for i in range(2048//32):
        ut.submit('?'*32)
    #for i in range(100):
    #    ut.submit(bin(random.getrandbits(32))[2:])
    #    ut.submit('?'*32)
    #    random.getrandbits(32)
    #"""
    def isHex(s):
        return all(c in "abcdef0123456789" for c in s)

    for i in range(0):
        r.sendline(b"1")
        data = r.recvuntil(b"> ").decode()
        print(data)
        for word in words:
            data = data.replace(word, '?')
        bits = data.split("\n")[:-6]
        bits = " ".join(w.rstrip() for w in bits).split(" ")
        for bit in bits[:10]:
            if isHex(bit):
                print(bit, bin(eval("0x" + bit.rjust(8, "0")))[2:].rjust(32, "0"))
                ut.submit(bin(eval("0x" + bit.rjust(8, "0")))[2:].rjust(32, "0"))
                #ut.submit(bin(u32(bytes.fromhex(bit.rjust(8, "0"))))[2:].rjust(32, "0"))
            else:
                print(bit)
                ut.submit('?' * 32)
    #"""
    #print(ut.get_random().getrandbits(32))
    #print(str(ut.get_random().getrandbits(2048))[:32])
    rand = ut.get_random()
    #print(rand.getstate())
    #print(rand.getrandbits(32))
    #print(rand.getstate())
    #print(random.getrandbits(32))
    #print([rand.getrandbits(32) for _ in range(624)])
    r.interactive()
