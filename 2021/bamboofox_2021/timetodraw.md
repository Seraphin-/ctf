# Time to Draw (Web)
There are 2 bugs. The first is the `userData` object doesn't contain a token when the user isn't admin. The second is here: `if (x && y && color) canvas[x][y] = color.toString();`

This is in the API call to `/api/draw`. Since we have complete control over x, y, and color we can set `x=__proto__` to override methods on the prototype of `canvas`, which is object - the same as userData. We can then set `y=token` and `color=hash(my ip + some token)`.

Now we can just visit `/flag?token=the token used earlier` to claim our flag.
