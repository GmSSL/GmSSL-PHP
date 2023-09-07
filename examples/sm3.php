<?php
$data = "abc";
$dgst = gmssl_sm3($data);
print("gmssl_sm3('abc'): ".bin2hex($dgst)."\n");
print("GMSSL_SM3_DIGEST_SIZE : ".GMSSL_SM3_DIGEST_SIZE."\n");
?>
