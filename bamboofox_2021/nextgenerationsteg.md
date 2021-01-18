# Next Generation Steganography (Misc)
> Play my newest rhythm game map!

The challenge provides us with a K-Shoot Mania (KSM) chart and a readme that says the flag is hidden somewhere in the file. KSM is a rhythm game that more or less functions as a PC clone of Sound Voltex. We're also told the flag matches `[A-Z]+`.

The first thing to do is find documentation on the file format (I was already familiar with it so luckily I knew where to look, otherwise it might be pretty hard). [Here](https://github.com/m4saka/ksh/blob/master/ksh_format.md) is the official specification.

The first thing to do is try to locate something that could hold a string (and isn't obvious, like the title). There are two possibilities - the lasers' positions `[0-z]` and the legacy FX characters. Although the chart is in in the `1.71` format, the title hints to "generations", so we should try it anyway. (I only realized this after the final hint, which states this is a newer version of the chart).

Looking at the chart in the [editor](https://www.kshootmania.com/en/download.html), there is an area with a suspiciously large number of FX holds. If we convert these back into their old letters (e.g. `Gate;12` => `K`), we get the following message:

`FLAGISIBQDAIXJFBXSDJB`
