# Feeling Tagged (Web)
> Check out my *new* **note** service! It supports all the formatting you'll ever need.
> 
> Flag is in admin's cookies.

This challenge exposes a note service which tries to sanitize HTML via BeautifulSoup in Python. It has an admin bot and looks like an XSS challenge.

The user can submit any HTML for a note to display, but it has to go through a sanitization pass. The sanitization is done like so:
```py
@app.route("/page")
def page():
    contents = base64.urlsafe_b64decode(request.args.get('contents', '')).decode()
    
    tree = BeautifulSoup(contents)
    for element in tree.find_all():
        if element.name not in SAFE_TAGS or len(element.attrs) > 0:
            return "This HTML looks sus."

    return f"<!DOCTYPE html><html><body>{str(tree)}</body></html>"

```
BeautifulSoup parses the HTML and the challenge iterates over all the elements. If the element tag is not in `SAFE_TAGS` - which consists of only i, b, p, and br - it refuses to send it. It also refuses if any element has an attribute set.

The intended solution is to find any parser difference between the default HTML parser (html.parser on the server) and an the HTML5 spec parser. Comments are once place where XSS happens with these, so by trying various invalid markup I came up with this solution:
```
<!--><script>alert(1)</script>-->
```
The [HTML5 spec](https://html.spec.whatwg.org/multipage/syntax.html#comments) defines that `<!-->` is a closed comment, but the server thinks that it extends to the end (i.e. the contents of the comment are `><script>...</script>`) and leaves it intact even after being converted back to HTML. On the other hand, a browser will happily execute the script tag. With ss you can just leak the admin bot's cookie like normal.

```
irisctf{security_by_option}
```
