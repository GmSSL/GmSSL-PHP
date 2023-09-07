<?php
$master_key = gmssl_sm9_enc_master_key_generate();

$master_key_file = "sm9_enc_master.pem";
$password = "P@ssw0rd";
gmssl_sm9_enc_master_key_info_encrypt_to_pem($master_key, $master_key_file, $password);
print(file_get_contents($master_key_file));
print("\n");

$master_pub_key_file = "sm9_enc_master_pub.pem";
gmssl_sm9_enc_master_public_key_to_pem($master_key, $master_pub_key_file);
print(file_get_contents($master_pub_key_file));
print("\n");

$master = gmssl_sm9_enc_master_key_info_decrypt_from_pem($master_key_file, $password);
$master_pub = gmssl_sm9_enc_master_public_key_from_pem($master_pub_key_file);

$id = "Bob";
print("id : $id\n");

$enc_key = gmssl_sm9_enc_master_key_extract_key($master, $id);
$enc_key_file = "sm9_enc_key.pem";
gmssl_sm9_enc_key_info_encrypt_to_pem($enc_key, $enc_key_file, $password);
print(file_get_contents($enc_key_file));
print("\n");

$key = gmssl_sm9_enc_key_info_decrypt_from_pem($enc_key_file, $password);

$plaintext = "Plaintext";
$ciphertext = gmssl_sm9_encrypt($master_pub, $id, $plaintext);
print("plaintext : $plaintext\n");
print("ciphertext : ".bin2hex($ciphertext)."\n");

$decrypted = gmssl_sm9_decrypt($key, $id, $ciphertext);
print("decrypted : $decrypted\n");
?>
