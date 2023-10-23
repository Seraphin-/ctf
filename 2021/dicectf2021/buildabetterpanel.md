# Build a Better Panel
This is almost exactly the same a "Build a Panel" but we can no longer provide the debug endpoint straight to the admin. The visiting page restriction indicates we need some kind of XSS on our panel page, since we can make the admin view it. If we have XSS we can use the exact same link as Build a Panel to gte the flag.

There is prototype pollution in the panel data, since the deep merge function is insufficiently safe. This is because `{}.__proto__ === {}.constructor.prototype`. The library conviniently used to display a Reddit post on the panel page has a gadget we can use to execute code. https://gist.github.com/keerok/52aa04c35aeb68a383727e978010a47a

However, the CSP forbids inline code - fortunately we don't actually need to run code, just make the admin visit a URL (the payload from Build a Panel) with cookies. The actual pollution attack sets properties on an iframe, so we can set the srcdoc to a script tag referencing the flag URL.

```
{"widgetName":"welcome back to build a panel!","widgetData":"{\"constructor\":{\"prototype\":{\"srcdoc\":\"<script src='https://build-a-better-panel.dicec.tf/admin/debug/add_widget?panelid=our banel&widgetname=flag%27,%20%27{%22type%22:%22%27%20||%20(SELECT%20*%20FROM%20flag%20LIMIT%201)%20||%20%27%22}%27);--&widgetdata=b'>\"}}}"}
```
