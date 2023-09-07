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
$iv = gmssl_rand_bytes(GMSSL_SM4_GCM_DEFAULT_IV_SIZE);
$aad = "Auth-only-message";
$msg = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
$ciphertext = gmssl_sm4_gcm_encrypt($key, $iv, $aad, GMSSL_SM4_GCM_MAX_TAG_SIZE, $msg);
$plaintext = gmssl_sm4_gcm_decrypt($key, $iv, $aad, GMSSL_SM4_GCM_MAX_TAG_SIZE, $ciphertext);
print(strcmp($msg, $plaintext));
?>
--EXPECT--
0
