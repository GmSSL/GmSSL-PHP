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
print(GMSSL_SM3_DIGEST_SIZE."\n");
print(GMSSL_SM3_HMAC_MIN_KEY_SIZE."\n");
print(GMSSL_SM4_KEY_SIZE."\n");
print(GMSSL_SM4_BLOCK_SIZE."\n");
print(GMSSL_SM4_GCM_MIN_IV_SIZE."\n");
print(GMSSL_SM4_GCM_MAX_IV_SIZE."\n");
print(GMSSL_SM4_GCM_DEFAULT_IV_SIZE."\n");
print(GMSSL_SM4_GCM_MAX_TAG_SIZE."\n");
print(GMSSL_SM2_DEFAULT_ID."\n");
print(GMSSL_SM2_MAX_PLAINTEXT_SIZE."\n");
print(GMSSL_SM9_MAX_PLAINTEXT_SIZE."\n");
print(GMSSL_ZUC_KEY_SIZE."\n");
print(GMSSL_ZUC_IV_SIZE."\n");
?>
--EXPECT--
32
16
16
16
1
64
12
16
1234567812345678
255
255
16
16
