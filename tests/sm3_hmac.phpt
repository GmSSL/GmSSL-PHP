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
print(bin2hex(gmssl_sm3_hmac("1234567812345678", "abc")));
?>
--EXPECT--
0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080
