--TEST--
Check if gmssl is loaded
--SKIPIF--
<?php
if (!extension_loaded('gmssl')) {
	echo 'skip';
}
?>
--FILE--
<?php
$sm9_enc_master_key = gmssl_sm9_enc_master_key_generate();
$pass = "123456";

$ret = gmssl_sm9_enc_master_key_info_encrypt_to_pem($sm9_enc_master_key, "sm9_enc_master_key.pem", $pass);
$sm9_enc_master_key = gmssl_sm9_enc_master_key_info_decrypt_from_pem("sm9_enc_master_key.pem", $pass);

$ret = gmssl_sm9_enc_master_public_key_to_pem($sm9_enc_master_key, "sm9_enc_master_pub.pem");
$sm9_enc_master_pub = gmssl_sm9_enc_master_public_key_from_pem("sm9_enc_master_pub.pem");

$sm9_enc_key = gmssl_sm9_enc_master_key_extract_key($sm9_enc_master_key, "Alice");
$ret = gmssl_sm9_enc_key_info_encrypt_to_pem($sm9_enc_key, "sm9_enc_key.pem", $pass);
$sm9_enc_key = gmssl_sm9_enc_key_info_decrypt_from_pem("sm9_enc_key.pem", $pass);

$ciphertext = gmssl_sm9_encrypt($sm9_enc_master_pub, "Alice", "abc");
$plaintext = gmssl_sm9_decrypt($sm9_enc_key, "Alice", $ciphertext);
print(strcmp($plaintext, "abc"));

?>
--EXPECT--
0
