<?php
print("GMSSL_SM4_KEY_SIZE = ".GMSSL_SM4_KEY_SIZE."\n");
print("GMSSL_SM4_BLOCK_SIZE = ".GMSSL_SM4_BLOCK_SIZE."\n");
print("GMSSL_SM4_CTR_IV_SIZE = ".GMSSL_SM4_CTR_IV_SIZE."\n");

$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
$iv = gmssl_rand_bytes(GMSSL_SM4_CTR_IV_SIZE);
$plaintext = "abc";

$ciphertext = gmssl_sm4_ctr_encrypt($key, $iv, $plaintext);
$decrypted = gmssl_sm4_ctr_encrypt($key, $iv, $ciphertext);

print("key : ".bin2hex($key)."\n");
print("iv : ".bin2hex($iv)."\n");
print("plaintext : $plaintext\n");
print("ciphertext : ".bin2hex($ciphertext)."\n");
print("decrypted : $decrypted\n");
?>
