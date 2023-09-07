<?php
print("GMSSL_ZUC_KEY_SIZE = ".GMSSL_ZUC_KEY_SIZE."\n");
print("GMSSL_ZUC_IV_SIZE = ".GMSSL_ZUC_IV_SIZE."\n");
print("\n");

$key = gmssl_rand_bytes(GMSSL_ZUC_KEY_SIZE);
$iv = gmssl_rand_bytes(GMSSL_ZUC_IV_SIZE);
$plaintext = "abc";

$ciphertext = gmssl_zuc_encrypt($key, $iv, $plaintext);
$decrypted = gmssl_zuc_encrypt($key, $iv, $ciphertext);

print("key : ".bin2hex($key)."\n");
print("iv : ".bin2hex($iv)."\n");
print("plaintext : $plaintext\n");
print("ciphertext : ".bin2hex($ciphertext)."\n");
print("decrypted : $decrypted\n");
?>
