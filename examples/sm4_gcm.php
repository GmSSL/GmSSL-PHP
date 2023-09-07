<?php
print("GMSSL_SM4_KEY_SIZE = ".GMSSL_SM4_KEY_SIZE."\n");
print("GMSSL_SM4_GCM_MIN_IV_SIZE = ".GMSSL_SM4_GCM_MIN_IV_SIZE."\n");
print("GMSSL_SM4_GCM_MAX_IV_SIZE = ".GMSSL_SM4_GCM_MAX_IV_SIZE."\n");
print("GMSSL_SM4_GCM_DEFAULT_IV_SIZE = ".GMSSL_SM4_GCM_DEFAULT_IV_SIZE."\n");
print("GMSSL_SM4_GCM_MAX_TAG_SIZE = ".GMSSL_SM4_GCM_MAX_TAG_SIZE."\n");
print("\n");

$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
$iv = gmssl_rand_bytes(GMSSL_SM4_GCM_DEFAULT_IV_SIZE);
$aad = "Associated Authenticated-only Data";
$taglen = GMSSL_SM4_GCM_MAX_TAG_SIZE;
$plaintext = "abc";

$ciphertext = gmssl_sm4_gcm_encrypt($key, $iv, $aad, $taglen, $plaintext);
$decrypted = gmssl_sm4_gcm_decrypt($key, $iv, $aad, $taglen, $ciphertext);

print("key : ".bin2hex($key)."\n");
print("iv : ".bin2hex($iv)."\n");
print("aad : $aad\n");
print("taglen : $taglen\n");
print("plaintext : $plaintext\n");
print("ciphertext : ".bin2hex($ciphertext)."\n");
print("decrypted : $decrypted\n");
?>
