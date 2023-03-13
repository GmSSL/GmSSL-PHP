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
print(bin2hex(gmssl_sm3_pbkdf2("password", "salt", 65536, GMSSL_SM4_KEY_SIZE)));
?>
--EXPECT--
244c631e1ae30ebf1c58d31a2988daf0
