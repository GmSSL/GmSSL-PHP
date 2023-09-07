<?php
print("GMSSL_SM3_HMAC_MIN_KEY_SIZE = ".GMSSL_SM3_HMAC_MIN_KEY_SIZE."\n");
print("GMSSL_SM3_HMAC_SIZE = ".GMSSL_SM3_HMAC_SIZE."\n");

$msg = "abc";
$key = gmssl_rand_bytes(GMSSL_SM3_HMAC_MIN_KEY_SIZE + 16);
$mac = gmssl_sm3_hmac($key, $msg);

print("msg : $msg\n");
print("key : ".bin2hex($key)."\n");
print("mac = gmssl_sm3_hmac(key, msg) : ".bin2hex($mac)."\n");

?>
