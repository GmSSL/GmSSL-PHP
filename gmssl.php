<?php


print("gmssl_version_num(): ".gmssl_version_num()."\n");
print("gmssl_version_str(): ".gmssl_version_str()."\n");
print("gmssl_rand_bytes(32): ".bin2hex(gmssl_rand_bytes(32))."\n");
//print("gmssl_rand_bytes(1000): ".bin2hex(gmssl_rand_bytes(1000))."\n");
//print("gmssl_rand_bytes(0): ".bin2hex(gmssl_rand_bytes(0))."\n");


print("gmssl_sm3('abc'): ".bin2hex(gmssl_sm3("abc"))."\n");
print("gmssl_sm3_hmac('abc', '1234567812345678'): ".bin2hex(gmssl_sm3_hmac("1234567812345678", "abc"))."\n");



print(bin2hex(gmssl_sm4_cbc_encrypt("1234567812345678", "1234567812345678", "abc"))."\n");

$ciphertext = gmssl_sm4_cbc_encrypt("1234567812345678", "1234567812345678", "abc");
print(gmssl_sm4_cbc_decrypt("1234567812345678", "1234567812345678", $ciphertext)."\n");



$ciphertext = gmssl_zuc_encrypt("1234567812345678", "1234567812345678", "abc");
$plaintext = gmssl_zuc_encrypt("1234567812345678", "1234567812345678", $ciphertext);
print("ZUC ".$plaintext."\n");
print("ZUC ".$ciphertext."\n");




$ciphertext = gmssl_sm4_gcm_encrypt("1234567812345678", "123456781234", "aad", "message");


$plaintext = gmssl_sm4_gcm_decrypt("1234567812345678", "123456781234", "aad", $ciphertext);
print($plaintext."\n");


$sm2_key = gmssl_sm2_key_generate();


gmssl_sm2_private_key_info_encrypt_to_pem($sm2_key, "key.pem", "password");


$keypair = gmssl_sm2_private_key_info_decrypt_from_pem("key.pem", "password");

gmssl_sm2_public_key_info_to_pem($sm2_key, "pubkey.pem");


$pubkey = gmssl_sm2_public_key_info_from_pem("pubkey.pem");


$sig = gmssl_sm2_sign($keypair, "1234567812345678", "abc");

print("sig: ".bin2hex($sig)."\n");


$ret = gmssl_sm2_verify($pubkey, "1234567812345678", "abc", $sig);

print("verify ".$ret."\n");



$ct = gmssl_sm2_encrypt($pubkey, "hello");

print("ciphertext:".bin2hex($ct)."\n");

print(gmssl_sm2_decrypt($keypair, $ct)."\n");


$key = gmssl_sm3_pbkdf2(16, "password", "salt", 65536);

print("key_from_pass".bin2hex($key)."\n");



$sm9_sign_master = gmssl_sm9_sign_master_key_generate();
$sm9_sign_key = gmssl_sm9_sign_master_key_extract_key($sm9_sign_master, "Alice");



?>
