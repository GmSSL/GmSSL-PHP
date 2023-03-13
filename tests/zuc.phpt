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
$key = gmssl_rand_bytes(GMSSL_ZUC_KEY_SIZE);
$iv = gmssl_rand_bytes(GMSSL_ZUC_IV_SIZE);
$msg = gmssl_rand_bytes(33);
$ciphertext = gmssl_zuc_encrypt($key, $iv, $msg);
$plaintext = gmssl_zuc_encrypt($key, $iv, $ciphertext);
print(strcmp($msg, $plaintext));
?>
--EXPECT--
0
