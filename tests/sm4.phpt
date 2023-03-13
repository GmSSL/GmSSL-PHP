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
$msg = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
$ciphertext = gmssl_sm4_encrypt($key, $msg);
$plaintext = gmssl_sm4_decrypt($key, $ciphertext);
print(strcmp($msg, $plaintext));
?>
--EXPECT--
0
