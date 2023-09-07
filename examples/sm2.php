<?php

$sm2_key = gmssl_sm2_key_generate();

$password = "P@ssw0rd";
$private_key_file = "sm2.pem";
$public_key_file = "sm2pub.pem";

gmssl_sm2_private_key_info_encrypt_to_pem($sm2_key, $private_key_file, $password);
print(file_get_contents($private_key_file));
print("\n");

gmssl_sm2_public_key_info_to_pem($sm2_key, $public_key_file);
print(file_get_contents($public_key_file));
print("\n");

$private_key = gmssl_sm2_private_key_info_decrypt_from_pem($private_key_file, $password);
$public_key = gmssl_sm2_public_key_info_from_pem($public_key_file);

$msg = "abc";
$signature = gmssl_sm2_sign($private_key, GMSSL_SM2_DEFAULT_ID, $msg);

print("GMSSL_SM2_DEFAULT_ID : ".GMSSL_SM2_DEFAULT_ID."\n");
print("msg : $msg\n");
print("signature : ".bin2hex($signature)."\n");

$ret = gmssl_sm2_verify($public_key, GMSSL_SM2_DEFAULT_ID, $msg, $signature);
print("verify result : ".$ret."\n");
print("\n");

$plaintext = "Hello world!";
print("GMSSL_SM2_MAX_PLAINTEXT_SIZE : ".GMSSL_SM2_MAX_PLAINTEXT_SIZE."\n");
print("plaintext : $plaintext\n");
$ciphertext = gmssl_sm2_encrypt($public_key, $plaintext);
$decrypted = gmssl_sm2_decrypt($private_key, $ciphertext);

print("ciphertext : ".bin2hex($ciphertext)."\n");
print("decrypted : $decrypted\n");
?>
