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
$sm9_sign_master_key = gmssl_sm9_sign_master_key_generate();
$pass = "123456";

$ret = gmssl_sm9_sign_master_key_info_encrypt_to_pem($sm9_sign_master_key, "sm9_sign_master_key.pem", $pass);
$sm9_sign_master_key = gmssl_sm9_sign_master_key_info_decrypt_from_pem("sm9_sign_master_key.pem", $pass);

$ret = gmssl_sm9_sign_master_public_key_to_pem($sm9_sign_master_key, "sm9_sign_master_pub.pem");
$sm9_sign_master_pub = gmssl_sm9_sign_master_public_key_from_pem("sm9_sign_master_pub.pem");

$sm9_sign_key = gmssl_sm9_sign_master_key_extract_key($sm9_sign_master_key, "Alice");
$ret = gmssl_sm9_sign_key_info_encrypt_to_pem($sm9_sign_key, "sm9_sign_key.pem", $pass);
$sm9_sign_key = gmssl_sm9_sign_key_info_decrypt_from_pem("sm9_sign_key.pem", $pass);

$sig = gmssl_sm9_sign($sm9_sign_key, "abc");
$ret = gmssl_sm9_verify($sm9_sign_master_pub, "Alice", "abc", $sig);
print($ret."\n")
?>
--EXPECT--
1
