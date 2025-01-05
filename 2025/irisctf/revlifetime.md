# rev lifetime (Reverse Engineering, hard)

> rev
> lift
> repeat

## Challenge
The challenge implements a input checker which seems to have 100 "workers", which each ask for input; at the end the checker prints a potential flag based on the inputs.

## Solution
As this is a reverse engineering challenge, it's difficult for me to give a concrete solution path, but I'll describe how I tested solved it.

The first thing people will see is the challenge implements a VM with seemingly 100 programs, and the flag output is simply a hash of the inputs. The VM opcodes are pretty simple, but the VM programs are quite large. At this point, you're expected to write a lifter so that the VM code can also be decompiled - I used the Binary Ninja API to write a lifter. Some of the challenges with lifting the specific VM opcodes are:
- The VM is word-addressed memory.
- While the destination of all jumps is from a jump table, there are still instructions that use a dynamic jump index, and there's no clear call/ret.
- The registers are specifically all 24-bit.

Otherwise, the VM opcodes are intended to be very straightforward. However, as the nested binaries are large and contain lots of dead code, a hello world binary is provided which is similar but the nested program only prints "hello world" for comparison, which hopefully helps.

Once you manage to lift a VM binary correctly, you'll notice that it also actually implements the exact same VM but with different opcode IDs. This binary is much smaller and contains the actual "worker" and its input checker logic. Now, you need to dynamically disassemble each of the 100 nested programs and extract their checker components. This is (hopefully obviously) intended to be done automatically, and the nested binaries are almost identical besides opcode IDs and inputs. This means that you can use one binary as a reference to determine the opcodes of the other binaries and extract their checker components.

Each of the checker components is very simple and only performs addition/subtraction then comparisons on bytes of the input.

Flag: `iris{5ec8f67c8254e2c1c63c6ee526b1e399168b3e9b7051696ed5f2394049e5}`
