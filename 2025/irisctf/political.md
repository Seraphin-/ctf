# Political (web, easy)

> My new enterprise policy ensures you will remain flag-free.

## Challenge
The challenge presents a simple service which gives you the flag if you can get the admin to access a page, `giveflag?token=token` where the token is a random string given to each solver.

However, the admin bot has a Chrome enterprise policy installed which tries to block the admin from accessing the page. In particular, the policy is the following:
```json
{
	"URLBlocklist": ["*/giveflag", "*?token=*"]
}

```

[Google's documentation](https://support.google.com/chrome/a/answer/9942583?hl=en) mentions that this pattern matching is intended to be a bit more intelligent than just substring matches, so the `?token=*` rule blocks the parameter no matter where it is in the query string (queries such as `?a=1&token=` are also blocked).

## Solution
It turns out we can bypass the checking logic by URL-encoding the path and query. It is also possible to bypass the path check by prepending additional `/` to the path.

For example, this URL will not be blocked by the policy:
```
https://political-web.chal.irisc.tf/givefl%61g?tok%65n=...
```

Flag: `irisctf{flag_blocked_by_admin}`
