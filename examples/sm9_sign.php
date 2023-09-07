<?php
$master_key = gmssl_sm9_sign_master_key_generate();

$master_key_file = "sm9_sign_master.pem";
$password = "P@ssw0rd";
gmssl_sm9_sign_master_key_info_encrypt_to_pem($master_key, $master_key_file, $password);
print(file_get_contents($master_key_file));
print("\n");

$master_pub_key_file = "sm9_sign_master_pub.pem";
gmssl_sm9_sign_master_public_key_to_pem($master_key, $master_pub_key_file);
print(file_get_contents($master_pub_key_file));
print("\n");

$master = gmssl_sm9_sign_master_key_info_decrypt_from_pem($master_key_file, $password);
$master_pub = gmssl_sm9_sign_master_public_key_from_pem($master_pub_key_file);

$id = "Alice";
print("id : $id\n");

$sign_key = gmssl_sm9_sign_master_key_extract_key($master, $id);
$sign_key_file = "sm9_sign_key.pem";
gmssl_sm9_sign_key_info_encrypt_to_pem($sign_key, $sign_key_file, $password);
print(file_get_contents($sign_key_file));
print("\n");

$key = gmssl_sm9_sign_key_info_decrypt_from_pem($sign_key_file, $password);

$msg = "Message";
$signature = gmssl_sm9_sign($key, $msg);
print("msg : $msg\n");
print("signature : ".bin2hex($signature)."\n");

$verify_ret = gmssl_sm9_verify($master_pub, $id, $msg, $signature);
print("verify result : $verify_ret\n");
?>
