# GmSSL-PHP

## Introduction

The PHP GmSSL extension is the binding to the GmSSL C library, which provides functions of Chinese SM2, SM3, SM4, SM9, ZUC crypto algorithms.

## Installation

To compile and install the GmSSL PHP extension, you need to install the GmSSL library (version >= 3.1.0). See the GmSSL INSTALL.md for more details.

```bash
$ cd GmSSL-PHP-master
$ phpize
$ ./configure
$ make
$ sudo make install
```

The GmSSL PHP extension need to be enabled in the `php.ini`.

```
$ sudo vim `php-config --ini-path`/php.ini
```

Search "Dynamic Extensions" and dd a new line `extension=gmssl` at the end of this section.

You can print the constant value `GMSSL_PHP_VERSION` to see if the GmSSL extension is correctly installed.

```php
<?php
print(GMSSL_PHP_VERSION."\n");
?>
```

```bash
php gmssl.php
```


## GmSSL PHP API

### Predefined Constants

* **GMSSL_PHP_VERSION**(string)
* **GMSSL_LIBRARAY_VERSION** (string)
* **GMSSL_SM3_DIGEST_SIZE** (int)
* **GMSSL_SM3_HMAC_MIN_KEY_SIZE** (int)
* **GMSSL_SM4_KEY_SIZE** (int)
* **GMSSL_SM4_BLOCK_SIZE** (int)
* **GMSSL_SM4_GCM_MIN_IV_SIZE** (int)
* **GMSSL_SM4_GCM_MAX_IV_SIZE** (int)
* **GMSSL_SM4_GCM_DEFAULT_IV_SIZE** (int)
* **GMSSL_SM4_GCM_MAX_TAG_SIZE** (int)
* **GMSSL_SM2_DEFAULT_ID** (string)
* **GMSSL_SM2_MAX_PLAINTEXT_SIZE** (int)
* **GMSSL_SM9_MAX_PLAINTEXT_SIZE** (int)
* **GMSSL_ZUC_KEY_SIZE** (int)
* **GMSSL_ZUC_IV_SIZE** (int)

### Functions

* [gmssl_rand_bytes](#gmssl_rand_bytes) - Generate cryptographic secure random bytes
* [gmssl_sm3](#gmssl_sm3) - Calculate the SM3 digest of a message
* [gmssl_sm3_hmac](#gmssl_sm3_hmac) - Calculate the HMAC-SM3 MAC tag of a message
* [gmssl_sm3_pbkdf2](#gmssl_sm3_pbkdf2) - Extract key material from a password by using KBKDF2-HMAC-SM3
* [gmssl_sm4_encrypt](#gmssl_sm4_encrypt) - Encrypt a block of message using SM4 cipher.
* [gmssl_sm4_decrypt](#gmssl_sm4_decrypt) - Decrypt a block of ciphertext using SM4 cipher.
* [gmssl_sm4_cbc_encrypt](#gmssl_sm4_cbc_encrypt) - Encrypt message using SM4-CBC mode (with padding)
* [gmssl_sm4_cbc_decrypt](#gmssl_sm4_cbc_decrypt) - Decrypt SM4-CBC (with padding) ciphertext
* [gmssl_sm4_ctr_encrypt](#gmssl_sm4_ctr_encrypt) - Encrypt/decrypt message with SM4-CTR mode
* [gmssl_sm4_gcm_encrypt](#gmssl_sm4_gcm_encrypt) - Encrypt message using SM4-GCM mode
* [gmssl_sm4_gcm_decrypt](#gmssl_sm4_gcm_decrypt) - Decrypt SM4-GCM ciphertext
* [gmssl_zuc_encrypt](#gmssl_zuc_encrypt) - Encrypt/decrypt message using ZUC stream cipher
* [gmssl_sm2_key_generate](#gmssl_sm2_key_generate) - Generate SM2 Keypair
* [gmssl_sm2_compute_z](#gmssl_sm2_compute_z) - Compute SM2 Z value from public key and ID.
* [gmssl_sm2_private_key_info_encrypt_to_pem](#gmssl_sm2_private_key_info_encrypt_to_pem) - Export SM2 private key to password encrypted PEM file
* [gmssl_sm2_private_key_info_decrypt_from_pem](#gmssl_sm2_private_key_info_decrypt_from_pem) - Import SM2 private key from password encrypted PEM file
* [gmssl_sm2_public_key_info_to_pem](#gmssl_sm2_public_key_info_to_pem) - Export SM2 public key to PEM file
* [gmssl_sm2_public_key_info_from_pem](#gmssl_sm2_public_key_info_from_pem) - Import SM2 public key from PEM file
* [gmssl_sm2_sign](#gmssl_sm2_sign) - Sign message (not digest) and generate SM2 signature
* [gmssl_sm2_verify](#gmssl_sm2_verify) - Verify SM2 signature
* [gmssl_sm2_encrypt](#gmssl_sm2_encrypt) - Encrypt short secret message with SM2 public key
* [gmssl_sm2_decrypt](#gmssl_sm2_decrypt) - Decrypt SM2 ciphertext with SM2 private key
* [gmssl_sm9_sign_master_key_generate](#gmssl_sm9_sign_master_key_generate) - Generate SM9 signing master key
* [gmssl_sm9_sign_master_key_extract_key](#gmssl_sm9_sign_master_key_extract_key) - Extract the signing private key from SM9 master key with signer's ID
* [gmssl_sm9_sign_master_key_info_encrypt_to_pem](#gmssl_sm9_sign_master_key_info_encrypt_to_pem) - Export SM9 signing master key to encrypted PEM file
* [gmssl_sm9_sign_master_key_info_decrypt_from_pem](#gmssl_sm9_sign_master_key_info_decrypt_from_pem) - Import SM9 signing master key from encrypted PEM file
* [gmssl_sm9_sign_master_public_key_to_pem](#gmssl_sm9_sign_master_public_key_to_pem) - Export SM9 signing master public key to file
* [gmssl_sm9_sign_master_public_key_from_pem](#gmssl_sm9_sign_master_public_key_from_pem) - Import SM9 signing master public key from file
* [gmssl_sm9_sign_key_info_encrypt_to_pem](#gmssl_sm9_sign_key_info_encrypt_to_pem) - Export user's SM9 signing key to encrypted PEM file
* [gmssl_sm9_sign_key_info_decrypt_from_pem](#gmssl_sm9_sign_key_info_decrypt_from_pem) - Import user's SM9 signing key from encrypted PEM file
* [gmssl_sm9_sign](#gmssl_sm9_sign) - Sign message with user's SM9 signing key
* [gmssl_sm9_verify](#gmssl_sm9_verify) - Verify SM9 signature of message with signer's ID
* [gmssl_sm9_enc_master_key_generate](#gmssl_sm9_enc_master_key_generate) - Generate SM9 encryption master key
* [gmssl_sm9_enc_master_key_extract_key](#gmssl_sm9_enc_master_key_extract_key) - Extract the encryption private key from SM9 master key with user's ID
* [gmssl_sm9_enc_master_key_info_encrypt_to_pem](#gmssl_sm9_enc_master_key_info_encrypt_to_pem) - Export SM9 encryption master key to encrypted PEM file
* [gmssl_sm9_enc_master_key_info_decrypt_from_pem](#gmssl_sm9_enc_master_key_info_decrypt_from_pem) - Import SM9 encryption master key from encrypted PEM file
* [gmssl_sm9_enc_master_public_key_to_pem](#gmssl_sm9_enc_master_public_key_to_pem) - Export SM9 encryption master public key to file
* [gmssl_sm9_enc_master_public_key_from_pem](#gmssl_sm9_enc_master_public_key_from_pem) - Import SM9 encryption master public key from file
* [gmssl_sm9_enc_key_info_encrypt_to_pem](#gmssl_sm9_enc_key_info_encrypt_to_pem) - Export user's SM9 encryption key to encrypted PEM file
* [gmssl_sm9_enc_key_info_decrypt_from_pem](#gmssl_sm9_enc_key_info_decrypt_from_pem) - Import user's SM9 encryption key from encrypted PEM file
* [gmssl_sm9_encrypt](#gmssl_sm9_encrypt) - Encrypt short message with recipient's ID
* [gmssl_sm9_decrypt](#gmssl_sm9_decrypt) - Decrypt SM9 ciphertext with user's SM9 private key
* [gmssl_cert_from_pem](#gmssl_cert_from_pem) - Import X.509 certificate from PEM file
* [gmssl_cert_print](#gmssl_cert_print) - Print details of a X.509 certificate
* [gmssl_cert_get_serial_number](#gmssl_cert_get_serial_number) - Get the SerialNumber field of a certificate.
* [gmssl_cert_get_issuer](#gmssl_cert_get_issuer) - Get the Issuer field of a certificate
* [gmssl_cert_get_validity](#gmssl_cert_get_validity) - Get the Validity field of a certificate
* [gmssl_cert_get_subject](#gmssl_cert_get_subject) - Get the Subject field of a certificate
* [gmssl_cert_get_subject_public_key](#gmssl_cert_get_subject_public_key) - Get the subject public key of a SM2 certificate.
* [gmssl_cert_verify_by_ca_cert](#gmssl_cert_verify_by_ca_cert) - Verify a SM2 certificate by a CA certificate.


### **gmssl_rand_bytes**

Generate cryptographic secure random bytes.

```php
gmssl_rand_bytes(int $length): string
```

* Parameters
  * length - Number of bytes of the required random string. Must be a positive integer and should not be too long (such as over 1 MB).
* Return Values - Return a string of generated random binary raw data.
* Errors/Exceptions - Throws an Exception on failure.

### **gmssl_sm3**

Calculate the SM3 digest of a message.

```php
gmssl_sm3(string $message): string
```

* Parameters
	* message - String of the to be digested message.
* Return Values - Return a string of the bytes. The length of string should be GMSSL_SM3_DIGEST_SIZE.

### **gmssl_sm3_hmac**

Calculate the HMAC-SM3 MAC tag of a messag.

```php
gmssl_sm3_hmac(
	string $key,
	string $message
): string
```

* Parameters
  * key - a string of the binary raw key. The length should be at least GMSSL_SM3_HMAC_MIN_KEY_SIZE.
  * message - the message to be signed.
* Return Values - return a string of the MAC tag raw data. The length of string should be GMSSL_SM3_HMAC_SIZE.
* Errors/Exceptions - throws an Exception on failure.

### **gmssl_sm3_pbkdf2**

Extract key material from a password by using KBKDF2-HMAC-SM3

```php
gmssl_sm3_pbkdf2(
	string $password,
	string $salt,
	int $iter,
	string $outlen  
): string
```

* Parameters
  * password - Password from which the extracted key is generated.
  * salt - Unexpected salt of at least 8 bytes long for binary string, or longer for text string.
  * iter - The number of iterations to slow down brute force attacks. The numbers over 8000 are recommended.
  * outlen - Length of the output key.
* Return Values - Returns raw binary string or NULL on failure.
* Errors/Exceptions - throws an Exception on failure.

### **gmssl_sm4_encrypt**

Encrypt a block of message (16-bytes) using SM4 block cipher.

```php
gmssl_sm4_encrypt(
	string $key,
	string $data_block
): string
```

* Parameters
  * key - The encryption key string. The length should be GMSSL_SM4_KEY_SIZE (16).
  * data_block - To be encrypted message block. The length should be GMSSL_SM4_BLOCK_SIZE (16).
* Return Values - The encrypted ciphertext block with length GMSSL_SM4_BLOCK_SIZE (16).
* Errors/Exceptions - Throw exceptions on invalid **key** length or **data_block** length.

### **gmssl_sm4_decrypt**

Decrypt a block of message (16-bytes) using SM4 block cipher.

```php
gmssl_sm4_decrypt(
	string $key,
	string $cipher_block
): string
```

* Parameters
  * key - The decryption key string. The length should be GMSSL_SM4_KEY_SIZE (16).
  * cipher_block - To be decrypted ciphertext block. The length should be GMSSL_SM4_BLOCK_SIZE (16).
* Return Values - The encrypted ciphertext block with length GMSSL_SM4_BLOCK_SIZE (16).
* Errors/Exceptions - Throw exceptions on invalid **key** length or **cipher_block** length.

### **gmssl_sm4_cbc_encrypt**

Encrypt message using SM4-CBC mode (with padding)

```php
gmssl_sm4_cbc_encrypt(
	string $key,
	string $iv,
	string $data
): string
```

* Parameters
  * key - The encryption key. The length should be GMSSL_SM4_KEY_SIZE (16).
  * iv - Unpredictable random Initial Vector (IV), length should be GMSSL_SM4_BLOCK_SIZE (16).
  * data - To be encrypted plaintext string of any length.
* Return Values - Raw binary ciphertext, length always be multiple of GMSSL_SM4_BLOCK_SIZE.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.

### gmssl_sm4_cbc_decrypt

Decrypt SM4-CBC (with padding) ciphertext

```php
gmssl_sm4_cbc_decrypt(
	string $key,
	string $iv,
	string $ciphertext
): string
```

* Parameters
  * key - The decryption key. The length should be GMSSL_SM4_KEY_SIZE (16).
  * iv - Initial Vector (IV), length should be GMSSL_SM4_BLOCK_SIZE (16).
  * data - To be decrypted plaintext, length should be multiple of GMSSL_SM4_BLOCK_SIZE.
* Return Values - Decrypted plaintext.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.

### gmssl_sm4_ctr_encrypt

Encrypt/decrypt message with SM4-CTR mode.
The encryption and decryption is the same in CTR mode. So there is no **gmssl_sm4_ctr_decrypt**.

```php
gmssl_sm4_ctr_encrypt(
	string $key,
	string $iv,
	string $data
): string
```

* Parameters
  * key - The encryption key. The length should be GMSSL_SM4_KEY_SIZE (16).
  * iv - Unpredictable random Initial Vector (IV), length should be GMSSL_SM4_BLOCK_SIZE (16).
  * data - The plaintext or ciphertext of any length.
* Return Values - Encrypt/decrypt result.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.

### **gmssl_sm4_gcm_encrypt**

Encrypt message using SM4-GCM mode

```php
gmssl_sm4_gcm_encrypt(
	string $key,
	string $iv,
	string $aad,
	string $data
): string
```

* Parameters
  * key - The encryption key. The length should be GMSSL_SM4_KEY_SIZE (16).
  * iv - Initial Vector (IV), length should be between GMSSL_SM4_GCM_MIN_IV_SIZE and GMSSL_SM4_GCM_MAX_IV_SIZE. Use GMSSL_SM4_GCM_DEFAULT_IV_SIZE is recommened.
  * aad - AAD (Associated Authenticated Data) is the authenticated-only message (not encrypted).
  * data - To be encrypted plaintext of any length.
* Return Values - The output GCM ciphertext.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.


### **gmssl_sm4_gcm_decrypt**

Decrypt SM4-GCM ciphertext

```php
gmssl_sm4_gcm_decrypt(
	string $key,
	string $iv,
	string $aad,
	string $ciphertext
): string
```

* Parameters
  * key - The decryption key. The length should be GMSSL_SM4_KEY_SIZE (16).
  * iv - Initial Vector (IV), use the same value in gmssl_sm4_gcm_encrypt
  * aad - AAD (Associated Authenticated Data) is the authenticated-only message (not encrypted).
  * data - To be encrypted plaintext of any length.
* Return Values - The output GCM ciphertext.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.


### **gmssl_zuc_encrypt**

Encrypt/decrypt message using ZUC stream cipher

```php
gmssl_zuc_encrypt(
	string $key,
	string $iv,
	string $data
): string
```

* Parameters
  * key - The encryption key. The length should be GMSSL_ZUC_KEY_SIZE (16).
  * iv - Unpredictable random Initial Vector (IV), length should be GMSSL_ZUC_IV_SIZE (16).
  * data - The plaintext or ciphertext of any length.
* Return Values - Encrypt/decrypt result.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.


### **gmssl_sm2_key_generate**

Generate SM2 Keypair

```php
gmssl_sm2_key_generate(): string
```

* Parameters - None
* Return Values - SM2 private key (the same as SM2 key pair). The return string is 96 bytes. The first 64 bytes are the RAW public key. The last 32 bytes are the raw private key.
* Errors/Exceptions - Throw exceptions on GmSSL library inner errors.

### **gmssl_sm2_compute_z**

Compute SM2 Z value from SM2 public key and user's identity.

```php
gmssl_sm2_compute_z(
	string $public_key,
	string $id
): string
```

* Parameters
  * public_key - SM2 public key. Typically SM2 public key is imported by calling `gmssl_sm2_public_key_info_from_pem`. But SM2 private key is also acceptable for this function.
  * id - User's identity string. If no explicit identity scheme is specified, the default value GMSSL_SM2_DEFAULT_ID should be used.
* Return Values - The output Z value, a string of 32-byte raw data.
* Errors/Exceptions - Throw exceptions on invalid input or GmSSL library inner errors.

### **gmssl_sm2_private_key_info_encrypt_to_pem**

Export SM2 private key to password encrypted PEM file

```php
gmssl_sm2_private_key_info_encrypt_to_pem(
	string $keypair,
	string $file,
	string $passphrase
): bool
```

* Parameters
  * keypair - SM2 private key, should be 96-byte string generated from `gmssl_sm2_key_generate`.
  * file - The output PEM file path.
  * passphrase - The passphrase/password to encrypt the private key.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm2_private_key_info_decrypt_from_pem**

Import SM2 private key from password encrypted PEM file

```php
gmssl_sm2_private_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

* Parameters
  * file - The password encrypted SM2 private key PEM file.
  * passphrase - The passphrase/password to decrypt the private key.
* Return Values: SM2 private key, inner format is same as the output of `gmssl_sm2_key_generate`.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm2_public_key_info_to_pem**

Export SM2 public key to PEM file.

```php
gmssl_sm2_public_key_info_to_pem(
	string $public_key,
	string $file,
): bool
```

* Parameters
  * public_key - The SM2 public key to be exported. SM2 private key as input is also accepted and only the public key will be exported.
  * file - The output PEM file path.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm2_public_key_info_from_pem**

Import SM2 public key from PEM file.

```php
gmssl_sm2_public_key_info_from_pem(
	string $file,
): string
```

* Parameters
  * file - The public key PEM file.
* Return Values: SM2 public key, a 96-byte string with the last 32-byte private key all zeros.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm2_sign**

Sign message (not digest) and generate SM2 signature

```php
gmssl_sm2_sign(
	string $keypair,
	string $id,
	string $message
): string
```

* Parameters
  * keypair - Signer's SM2 private key, typically from `gmssl_sm2_key_generate`.
  * id - Signer's identity string. If no explicit identity scheme is specified, the default value GMSSL_SM2_DEFAULT_ID should be used.
  * messsage - To be signed message of any length.
* Return Values - The generated SM2 signature in DER encoding, the raw data bytes start with a `0x30` and the typical signature length is 70, 71 or 72 bytes.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm2_verify**

`gmssl_sm2_verify` - Verify SM2 signature

```php
gmssl_sm2_verify(
	string $public_key,
	string $id,
	string $message,
	string $signature
): bool
```

* Parameters
  * public_key - Signer's SM2 public key, typically from `gmssl_sm2_public_key_info_from_pem` or `gmssl_cert_get_subject_public_key`.
  * id - Signer's identity string. If no explicit identity scheme is specified, the default value GMSSL_SM2_DEFAULT_ID should be used.
  * messsage - The signed message.
  * signature - The SM2 signature in DER-encoding.
* Return Values - **ture** or **false**.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm2_encrypt**

Encrypt short secret message with SM2 public key.

```php
gmssl_sm2_encrypt(
	string $public_key,
	string $data
): string
```

* Parameters
  * public_key - Receiver's SM2 public key, typically from `gmssl_sm2_public_key_info_from_pem` or `gmssl_cert_get_subject_public_key`.
  * data - To be encrypted plaintext. SM2 encryption should be used to protect key materials. The length should not longer than GMSSL_SM2_MAX_PLAINTEXT_SIZE.
* Return Values - Ciphertext.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm2_decrypt**

Decrypt SM2 ciphertext with SM2 private key

```php
gmssl_sm2_decrypt(
	string $keypair,
	string $ciphertext
): string
```

* Parameters
  * keypair - Receiver's SM2 private key
  * data - Ciphertext.
* Return Values - Plaintext.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_sign_master_key_generate**

Generate SM9 signing master key

```php
gmssl_sm9_sign_master_key_generate(): string
```

### **gmssl_sm9_sign_master_key_extract_key**

Extract the signing private key from SM9 master key with signer's ID

```php
gmssl_sm9_sign_master_key_extract_key(
	string $masterKey,
	string $id
): string
```

### **gmssl_sm9_sign_master_key_info_encrypt_to_pem**

Export SM9 signing master key to encrypted PEM file

```php
gmssl_sm9_sign_master_key_info_encrypt_to_pem(
	string $masterKey,
	string $file,
	string $passphrase
): bool
```

### **gmssl_sm9_sign_master_key_info_decrypt_from_pem**

Import SM9 signing master key from encrypted PEM file

```php
gmssl_sm9_sign_master_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

### **gmssl_sm9_sign_master_public_key_to_pem**

Export SM9 signing master public key to file

```php
gmssl_sm9_sign_master_public_key_to_pem(
	string $masterKey,
	string $file,
): bool
```

### **gmssl_sm9_sign_master_public_key_from_pem**

Import SM9 signing master public key from file

```php
gmssl_sm9_sign_master_public_key_from_pem(
	string $file
): string
```

### **gmssl_sm9_sign_key_info_encrypt_to_pem**

Export user's SM9 signing key to encrypted PEM file

```php
gmssl_sm9_sign_key_info_encrypt_to_pem(
	string $signKey,
	string $file,
	string $passphrase
): bool
```

### **gmssl_sm9_sign_key_info_decrypt_from_pem**

Import user's SM9 signing key from encrypted PEM file

```php
gmssl_sm9_sign_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

### **gmssl_sm9_sign**

Sign message with user's SM9 signing key

```php
gmssl_sm9_sign(
	string $privateKey,
	string $message
): string
```

### **gmssl_sm9_verify**


Verify SM9 signature of message with signer's ID

```php
gmssl_sm9_verify(
	string $masterPublicKey,
	string $id,
	string $message,
	string $signature
): bool
```

### **gmssl_sm9_enc_master_key_generate**

Generate SM9 encryption master key

```php
gmssl_sm9_enc_master_key_generate(): string
```


### **gmssl_sm9_enc_master_key_extract_key**

Extract the encryption private key from SM9 master key with user's ID

```php
gmssl_sm9_enc_master_key_extract_key(
	string $masterKey,
	string $id
): string
```

###**gmssl_sm9_enc_master_key_info_encrypt_to_pem**

Export SM9 encryption master key to encrypted PEM file

```php
gmssl_sm9_enc_master_key_info_encrypt_to_pem(
	string $masterKey,
	string $file,
	string $passphrase
): bool
```

### **gmssl_sm9_enc_master_key_info_decrypt_from_pem**

Import SM9 encryption master key from encrypted PEM file

```php
gmssl_sm9_enc_master_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

### **gmssl_sm9_enc_master_public_key_to_pem**

Export SM9 encryption master public key to file

```php
gmssl_sm9_enc_master_public_key_to_pem(
	string $masterKey,
	string $file,
): bool
```

### **gmssl_sm9_enc_master_public_key_from_pem**

Import SM9 encryption master public key from file

```php
gmssl_sm9_enc_master_public_key_from_pem(
	string $file
): string
```

### **gmssl_sm9_enc_key_info_encrypt_to_pem**

Export user's SM9 encryption key to encrypted PEM file

```php
gmssl_sm9_enc_key_info_encrypt_to_pem(
	string $signKey,
	string $file,
	string $passphrase
): bool
```

### **gmssl_sm9_enc_key_info_decrypt_from_pem**

Import user's SM9 encryption key from encrypted PEM file

```php
gmssl_sm9_enc_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

### **gmssl_sm9_encrypt**

Encrypt short message with recipient's ID

```php
gmssl_sm9_encrypt(
	string $masterPublicKey,
	string $id,
	string $data
): string
```

### **gmssl_sm9_decrypt**

Decrypt SM9 ciphertext with user's SM9 private key

```php
gmssl_sm9_decrypt(
	string $privateKey,
	string $id,
	string $ciphertext
): string
```

### **gmssl_cert_from_pem**

Import X.509 certificate from PEM file.

```php
gmssl_cert_from_pem(string $path): string
```

### **gmssl_cert_print**

Print details of a X.509 certificate.

```php
gmssl_cert_print(
	string $cert,
	string $label
): bool
```

### **gmssl_cert_get_serial_number**

Get the SerialNumber field of a X.509 certificate.

```php
gmssl_cert_get_serial_number(string $cert): string
```

### **gmssl_cert_get_issuer**

Get the Issuer field of a X.509 certificate.

```php
gmssl_cert_get_issuer(string $cert): string
```

### **gmssl_cert_get_validity**

Get the Validity field of a X.509 certificate.

```php
gmssl_cert_get_validity(string $cert): array
```

### **gmssl_cert_get_subject**

Get the Subject field of a X.509 certificate.

```php
gmssl_cert_get_subject(string $cert): string
```

### **gmssl_cert_get_subject_public_key**

Get the SM2 public key from the SubjectPublicKeyInfo field of a X.509 certificate.

```php
gmssl_cert_get_subject_public_key(string $cert): string
```

### **gmssl_cert_verify_by_ca_cert**

Verify a X.509 certificate by a CA certificate.

```php
gmssl_cert_verify_by_ca_cert(
	string $cert,
	string $cacert,
	string $sm2_id
): bool
```














