# babystretchy (Web)
> More byte mean more secure

This PHP challenge generates a random 64 hex character password on connect and passes it to `password_hash` after "stretching" it by repeating each character 64 times. It was intended to help new players get used to scripting even with web challenges and also require a bit of looking into how functions work.

The challenge starts by setting up the password hash like follows:
```php
$password = exec("openssl rand -hex 64");

$stretched_password = "";
for($a = 0; $a < strlen($password); $a++) {
    for($b = 0; $b < 64; $b++)
        $stretched_password .= $password[$a];
}

$h = password_hash($stretched_password, PASSWORD_DEFAULT);
```

If you can provide input that passes `password_verify`, it prints the flag. You have unlimited attempts (though the server has a timeout).
```php
while (FALSE !== ($line = fgets(STDIN))) {
    if(password_verify(trim($line), $h)) die(file_get_contents("flag"));
    echo "> ";
}
```

The attack is that `password_hash` silently truncates the password if it has more than 72 characters. This is documented in the [PHP](https://www.php.net/manual/en/function.password-hash.php) docs, but probably not well enough. This means that you only actually have to brute force `16 * 16` combinations of hex characters (1 byte's worth).

Simply try each combination and get the flag!

```
irisctf{truncation_silent_and_deadly}
```

Author's solution script:
```py
r = remote("remote-ip", remote-port)
r.recvuntil(b"!\n> ")

charset = "abcdef0123456789"
for a, b in itertools.product(charset, charset):
    r.sendline((a*64+b*64).encode())
    text = r.recvuntil([b"> ", "iris"])
    if b"iris" in text:
        print(text + r.recv(timeout=2))
```
