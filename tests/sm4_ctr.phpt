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
$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
$iv = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
$msg = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
$ciphertext = gmssl_sm4_ctr_encrypt($key, $iv, $msg);
$plaintext = gmssl_sm4_ctr_encrypt($key, $iv, $ciphertext);
print(strcmp($msg, $plaintext));
?>
--EXPECT--
0
