# warden (misc, hard)

> `from os import system as win`
>
> This challenge is heavily inspired by the challenge "Diligent Auditor" by aplet123 from DiceCTF 2024.

## Challenge
The challenge provides a very restrictive pyjail. You are able to provide the function to be imported in a `from ... import ... as win` line, then a single-line argument to provide to the function. The argument must only use letter, digits, underscores, and whitespace. The challenge then installs an audit hook that instantly exists the challenge; a seccomp rule disallowing fork/execve, and deletes all globals, builtins, and locals. Finally, it calls your function.

## Solution
As the description mentions, this challenge is based on a previous CTF challenge, but the solution is completely different and irrelevant to this one, so I won't cover it.

The first part is what to import. Since the jail deletes builtins, most other imported functions won't even work anymore, with a notable exception being calls to python objects implemented in C. Furthermore, the function can't trip audit hooks; and most functions intended to be used and are interesting result in an audit call. There's no single great way to identify the right function besides scanning the whole builtin modules list, which is what I did when writing the challenge. It turns out the function `run_in_subinterp` from `_testcapi` (an internal testing module for C calls) does what we need - it spins up a new subinterpreter which removes all the audit hooks, and it doesn't trigger the seccomp while allowing us to do something interesting (execute the argument as python code).

Now that we have python execution outside of the audit hook's reach, we still are restricted in the argument to a limited character set. However, we need to execute a function in our code that somehow results in us winning, otherwise nothing will happen. In order to call a function, we'll use 2 tricks: the first is that `\r` is considered whitespace and a valid newline in python source code; yet can be read from `input()`. This allows us to execute multiple lines of python. The next is that we can trigger a function call implicitly by overriding `__getattr__` on an object. We will actually override this on our code's module itself by executing `from code import interact as __getattr__`. Finally, we trigger getattr by importing from ourself: `from __main__ import a`.

Our final payload is:
```py
from code import interact as __getattr__\rfrom __main__ import a
```

Flag: `irisctf{from_code_import_interact}`
