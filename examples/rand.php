<?php
$key = gmssl_rand_bytes(32);
print("gmssl_rand_bytes(32): ".bin2hex($key)."\n");
?>
