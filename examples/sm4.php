<?php
print("GMSSL_SM4_KEY_SIZE = ".GMSSL_SM4_KEY_SIZE."\n");
print("GMSSL_SM4_BLOCK_SIZE = ".GMSSL_SM4_BLOCK_SIZE."\n");

$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
$plaintext_block = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
$ciphertext_block = gmssl_sm4_encrypt($key, $plaintext_block);
$decrypted_block = gmssl_sm4_decrypt($key, $ciphertext_block);

print("key : ".bin2hex($key)."\n");
print("plaintext_block : ".bin2hex($plaintext_block)."\n");
print("ciphertext_block : ".bin2hex($ciphertext_block)."\n");
print("decrypted_block : ".bin2hex($decrypted_block)."\n");
?>
