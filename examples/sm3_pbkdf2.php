<?php
$password = "P@ssw0rd";
$salt = gmssl_rand_bytes(8);
$iter = 65536;
$keylen = GMSSL_SM4_KEY_SIZE;

$key = gmssl_sm3_pbkdf2($password, $salt, $iter, $keylen);

print("password : $password\n");
print("salt : ".bin2hex($salt)."\n");
print("iter : $iter\n");
print("keylen : $keylen\n");
print("key = sm2_pbkdf2(password, salt, iter, keylen) : ".bin2hex($key)."\n");


?>
