# antistatic

A baby reversing challenge.
The binary has symbols, but the `main` function seems to do nothing. All the logic is hidden in a fake \_\_libc\_gnu\_init. The actual flag checker just xors some memory with the symbol name GNU\_HASH with your input and compares the result. The anti-debugging is implemented by checking `/proc/self/cmdline`.
