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
$rootcacert=
"-----BEGIN CERTIFICATE-----\n".
"MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\n".
"EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\n".
"MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\n".
"UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n".
"MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\n".
"V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\n".
"W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\n".
"MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\n".
"53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\n".
"pDoiVhsLwg==\n".
"-----END CERTIFICATE-----\n";

file_put_contents("rootca.pem", $rootcacert);

$cert = gmssl_cert_from_pem("rootca.pem");
$serial = gmssl_cert_get_serial_number($cert);
print(bin2hex($serial)."\n");

print(gmssl_cert_verify_by_ca_cert($cert, $cert, GMSSL_SM2_DEFAULT_ID));
?>
--EXPECT--
69e2fec0170ac67b
1
