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

$certfile = "ROOTCA.pem";
file_put_contents($certfile, $rootcacert);

$cert = gmssl_cert_from_pem($certfile);
$label = "Certificate";
gmssl_cert_print($cert, $label);

$serial = gmssl_cert_get_serial_number($cert);
print("SerialNumber : ".bin2hex($serial)."\n");

$issuer = gmssl_cert_get_issuer($cert);
print("Issuer\n");
foreach ($issuer as $type=>$value) {
	print("\t$type : ");
	if ($type == "raw_data") {
		print(bin2hex($value)."\n");
	} else {
		print($value."\n");
	}
}

$subject = gmssl_cert_get_subject($cert);
print("Subject\n");
foreach ($subject as $type=>$value) {
	print("\t$type : ");
	if ($type == "raw_data") {
		print(bin2hex($value)."\n");
	} else {
		print($value."\n");
	}
}

$validity = gmssl_cert_get_validity($cert);
print("Validity\n");
foreach ($validity as $type=>$value) {
	print("\t$type : ".date("Y-m-d H:i:s e", $value)."\n");
}

$public_key = gmssl_cert_get_subject_public_key($cert);
$public_key_file = "sm2pub_from_cert.pem";
gmssl_sm2_public_key_info_to_pem($public_key, $public_key_file);
print(file_get_contents($public_key_file));
print("\n");

$verify_ret = gmssl_cert_verify_by_ca_cert($cert, $cert, GMSSL_SM2_DEFAULT_ID);
print("verify result : $verify_ret\n");
?>
