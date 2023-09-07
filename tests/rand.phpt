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
var_dump(strlen(gmssl_rand_bytes(32)));
?>
--EXPECT--
int(32)
