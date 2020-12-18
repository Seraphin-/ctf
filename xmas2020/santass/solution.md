# santass (Forensics 247, 75 solves)

We're given a packet dump of some http requests which either seem to return 404 or have their body removed. The only suspicious thing is the URLs for a few requests aren't words: `Z2d3a.jpg` `XJlc2.jpg` `hhcms.jpg`. I realized they were base64 and the result is our flag after wrapping it in X-MAS{}: `X-MAS{ggwireshark}`

(This problem got me good.)