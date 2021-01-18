# ヽ(#`Д´)ﾉ (Web)
Another PHP pain challenge. Our input is verified to be less than 0xA characters and not contain any alphanumeric characters. It is then eval'd after being passed through print\_r. The catch is the length and character checks are done using `!strlen` and `!preg_match` instead of `cond!==false`.

We can pass in an array and it will always bypass these checks, the next thing is to construct input that is valid PHP after being passed in. The PHP parser doesn't really like the array output, and will first throw a syntax error. We can deal with this by adding a constant and closing parenthesis.

We then get an `illegal offset type` error. I was able to get around this by making the array indice a variable, which gives a `illegal offset type` warning (I have no idea). Now that our input is accepted as PHP we just add a `print \`cat /flag\*\`` to get our flag.

```
http://chall.ctf.bamboofox.tw:9487/?%E3%83%BD(%23`%D0%94%C2%B4)%EF%BE%89[$a]=print%20`cat%20/flag*`)?%3E
flag{!pee_echi_pee!}
```
