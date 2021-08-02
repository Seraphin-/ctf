<?php
$target = "8";

$a = 0;
while($a < 9999999999999999999999999999999999) {
    $a += 9;
    $b = 0;
    while($b < 9999999999999999999999999999999999) {
        $b += 9;
        if(substr(strval($a^$b), 0, 1) == $target) {
            var_dump($a);
            var_dump($b);
            var_dump((integer)($a^$b));
            die();
        }
        $b *= 10;
    }
    $a *= 10;
}
?>
