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
$sm2_key = gmssl_sm2_key_generate();
$pass = "123456";
gmssl_sm2_private_key_info_encrypt_to_pem($sm2_key, "sm2.pem", $pass);
$sign_key = gmssl_sm2_private_key_info_decrypt_from_pem("sm2.pem", $pass);
gmssl_sm2_public_key_info_to_pem($sm2_key, "sm2pub.pem");
$sm2_pub = gmssl_sm2_public_key_info_from_pem("sm2pub.pem");

$dgst = gmssl_rand_bytes(GMSSL_SM3_DIGEST_SIZE);
$sig = gmssl_sm2_sign($sign_key, GMSSL_SM2_DEFAULT_ID, $dgst);
print(gmssl_sm2_verify($sm2_pub, GMSSL_SM2_DEFAULT_ID, $dgst, $sig)."\n");

$msg = gmssl_rand_bytes(GMSSL_SM2_MAX_PLAINTEXT_SIZE);
$ciphertext = gmssl_sm2_encrypt($sm2_pub, $msg);
$plaintext = gmssl_sm2_decrypt($sm2_key, $ciphertext);
print(strcmp($msg, $plaintext)."\n");

?>
--EXPECT--
1
0
