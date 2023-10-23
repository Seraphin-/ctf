# Santa's Flag Checker (rev 451, 33 solves)

This was quite hard for me to understand, but I managed to get through it and learn some z3 tricks too. The binary is a classic flagchecker that takes a flag and confirms it. The actual logic is implemented in the init and fini functions, and it also has some simple anti-debugging. The main function just reads in 61 bytes into a memory location and makes sure it contains "X-MAS".

The first thing to do is to patch out the anti-debugging. Scanning through the functions there are two that perform this: one which checks /proc/self, and one which tries ptrace. I just patched both to set the relevant byte at 0x521C to 0 if it fails instead of 1.

We can now debug the program along with static analysis. Regardless, a cursory decompilation shows two complex functions. The first, in the init function, seems to set up an array in memory based on the output of rand(). The second seems to be the actual flag checker and prints an encrypted string depending on whether the output of some operations on the input matches an array in memory.

Rather than reversing fully the first function, it's easier to dump it from memory. The decompiler shows it reads 0x1e0 values and places them as a 32bit int array in memory. We can dump this array with `dump binary memory arr_4a60 0x555555558a60 0x555555558a60+0x780` after setting a breakpoint after the function. The resulting integers are all pretty small.

The second function is more complicated and obfuscated with a lot of useless operations. The key insight is that the values read from memory in the first array are right shifted by more than 32 bits, so we can replace those with 0. In addition, it checks if the value is ever less than 0, but it can't be in practice so we ignore these.

The output of the second function is memcmp'd with 0x3C bytes at 0x5220, so we dump that with `dump binary memory arr_40c0 0x5555555580c0 0x5555555580c0+0x3c`.

Now we can translate the checking into some z3 constraints straight from the decompilation.
```python
B = BitVecSort(32)
input_arr = Array("input_arr", B, B)
s = Solver()
for i in range(0x1e0):
    v4, ni = BitVecs("v4%d ni%d" % (i,i), 32)
    s.add(v4 == input_arr[i>>3])
    s.add(ni == ((v4 >> (i & 7)) & 1))
    s.add(((arr40c0[arr4a60[i] >> 3] >> (arr4a60[i] & 7)) & 1) == ni)
s.check()
print(s.model())
```

This gives us the flag! But now that the constraints are written out it's a bit easier to see, especially if you print the constraints after being simplified by z3. The input bits are shuffled around to the output based on the array at 0x4a60. The array is length 0x1e0 because it's 60 << 3, and 8 entries are used per input - 1 for each bit. Here's a full solution not using z3:

```python
# Alternate solver knowing more
from pwnlib.util.packing import u32, u8

# Const arrays
arr4a60 = []
with open("arr_4a60", "rb") as f:
    while True:
        n = f.read(4)
        if len(n) < 4: break
        arr4a60.append(u32(n))
assert len(arr4a60) == 0x1e0

arr40c0 = []
with open("arr_40c0", "rb") as f:
    while True:
        n = f.read(1)
        if len(n) < 1: break
        arr40c0.append(u8(n))
assert len(arr40c0) == 0x3c

input_arr = [0] * 60

for i in range(0x1e0):
    input_arr[i >> 3] |= (arr40c0[arr4a60[i] >> 3] >> (arr4a60[i] & 7) & 1) << (i & 7)

print("".join([chr(x) for x in input_arr if x > 0]))
# X-MAS{S4n74_d035N7_l1K3_D3bU663r5_8a94aaf5}
```
