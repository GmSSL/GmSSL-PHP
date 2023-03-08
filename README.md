# GmSSL-PHP

## Introduction
The GmSSL extension is the binding to the GmSSL C library. GmSSL provides functions of Chinese SM2, SM3, SM4, SM9, ZUC crypto algorithms.

## Installation

To compile and install the GmSSL PHP extension, you need to install the GmSSL library (version >= 3.1.0). See the GmSSL INSTALL.md for more details.

```bash
$ cd GmSSL-PHP-master
$ phpize
$ ./configure
$ make
$ sudo make install
```

You can use `phpinfo()` to see if the GmSSL extension is correctly installed.

```php
<?php
phpinfo();
?>
```

## Predefined Constants

* `GMSSL_PHP_VERSION (string)`
* `GMSSL_LIBRARAY_VERSION (string)`
* `GMSSL_SM3_DIGEST_SIZE (int)`
* `GMSSL_SM3_HMAC_SIZE (int)`
* `GMSSL_SM4_KEY_SIZE (int)`
* `GMSSL_SM4_BLOCK_SIZE (int)`
* `GMSSL_SM4_GCM_MIN_IV_SIZE (int)`
* `GMSSL_SM4_GCM_MAX_IV_SIZE (int)`
* `GMSSL_SM4_GCM_DEFAULT_IV_SIZE (int)`
* `GMSSL_SM4_GCM_MAX_TAG_SIZE (int)`
* `GMSSL_SM2_DEFAULT_ID (string)`
* `GMSSL_SM2_MAX_SIGNATURE_SIZE (int)`
* `GMSSL_SM2_MAX_PLAINTEXT_SIZE (int)`
* `GMSSL_SM2_MAX_CIPHERTEXT_SIZE (int)`
* `GMSSL_SM9_SIGNATURE_SIZE (int)`
* `GMSSL_SM9_MAX_PLAINTEXT_SIZE (int)`
* `GMSSL_SM9_MAX_CIPHERTEXT_SIZE (int)`
* `GMSSL_ZUC_KEY_SIZE (int)`
* `GMSSL_ZUC_IV_SIZE (int)`

## GmSSL Functions

* `gmssl_version_num` - Get version number of the GmSSL C library
* `gmssl_version_str` - Get version string of the GmSSL C library
* `gmssl_rand_bytes` - Generate cryptographic secure random bytes
* `gmssl_sm3` - Calculate the SM3 digest of a message
* `gmssl_sm3_hmac` - Calculate the HMAC-SM3 MAC tag of a message
* `gmssl_sm3_pbkdf2` - Extract key material from a password by using KBKDF2-HMAC-SM3
* `gmssl_sm4_cbc_encrypt` - Encrypt message using SM4-CBC mode (with padding)
* `gmssl_sm4_cbc_decrypt` - Decrypt SM4-CBC (with padding) ciphertext
* `gmssl_sm4_ctr_encrypt` - Encrypt/decrypt message with SM4-CTR mode
* `gmssl_sm4_gcm_encrypt` - Encrypt message using SM4-GCM mode
* `gmssl_sm4_gcm_decrypt` - Decrypt SM4-GCM ciphertext
* `gmssl_zuc_encrypt` - Encrypt/decrypt message using ZUC stream cipher
* `gmssl_sm2_key_generate` - Generate SM2 Keypair
* `gmssl_sm2_private_key_info_encrypt_to_pem` - Export SM2 private key to password encrypted PEM file
* `gmssl_sm2_private_key_info_decrypt_from_pem` - Import SM2 private key from password encrypted PEM file
* `gmssl_sm2_public_key_info_to_pem` - Export SM2 public key to PEM file
* `gmssl_sm2_public_key_info_from_pem` - Import SM2 public key from PEM file
* `gmssl_sm2_sign` - Sign message (not digest) and generate SM2 signature
* `gmssl_sm2_verify` - Verify SM2 signature
* `gmssl_sm2_encrypt` - Encrypt short secret message with SM2 public key
* `gmssl_sm2_decrypt` - Decrypt SM2 ciphertext with SM2 private key
* `gmssl_sm9_sign_master_key_generate` - Generate SM9 signing master key
* `gmssl_sm9_sign_master_key_extract_key` - Extract the signing private key from SM9 master key with signer's ID
* `gmssl_sm9_sign_master_key_info_encrypt_to_pem` - Export SM9 signing master key to encrypted PEM file
* `gmssl_sm9_sign_master_key_info_decrypt_from_pem` - Import SM9 signing master key from encrypted PEM file
* `gmssl_sm9_sign_master_public_key_to_pem` - Export SM9 signing master public key to file
* `gmssl_sm9_sign_master_public_key_from_pem` - Import SM9 signing master public key from file
* `gmssl_sm9_sign_key_info_encrypt_to_pem` - Export user's SM9 signing key to encrypted PEM file
* `gmssl_sm9_sign_key_info_decrypt_from_pem` - Import user's SM9 signing key from encrypted PEM file
* `gmssl_sm9_sign` - Sign message with user's SM9 signing key
* `gmssl_sm9_verify` - Verify SM9 signature of message with signer's ID
* `gmssl_sm9_enc_master_key_generate` - Generate SM9 encryption master key
* `gmssl_sm9_enc_master_key_extract_key` - Extract the encryption private key from SM9 master key with user's ID
* `gmssl_sm9_enc_master_key_info_encrypt_to_pem` - Export SM9 encryption master key to encrypted PEM file
* `gmssl_sm9_enc_master_key_info_decrypt_from_pem` - Import SM9 encryption master key from encrypted PEM file
* `gmssl_sm9_enc_master_public_key_to_pem` - Export SM9 encryption master public key to file
* `gmssl_sm9_enc_master_public_key_from_pem` - Import SM9 encryption master public key from file
* `gmssl_sm9_enc_key_info_encrypt_to_pem` - Export user's SM9 encryption key to encrypted PEM file
* `gmssl_sm9_enc_key_info_decrypt_from_pem` - Import user's SM9 encryption key from encrypted PEM file
* `gmssl_sm9_encrypt` - Encrypt short message with recipient's ID
* `gmssl_sm9_decrypt` - Decrypt SM9 ciphertext with user's SM9 private key


