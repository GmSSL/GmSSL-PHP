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

## Quick Start

You can start GmSSL extension with the following simple examples of SM3, SM4 and SM2 crypto algorithms.

### SM3 Examples

SM3 is a cryptographic hash function with 256-bit output hash value.
Compute the SM3 digest of the string "abc".

```php
<?php
	$hash = gmssl_sm3("abc");
	print(bin2hex($hash)."\n");
?>
```

### SM4 Examples

SM4 is a block cipher with 128-bit key length and 128-bit block size.
Use SM4 to encrypt a block of message (16 bytes).

```php
<?php
	$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
	$block = gmssl_rand_bytes(GMSSL_SM4_BLOCK_SIZE);
	$ciphertext = gmssl_sm4_encrypt($key, $block);
	$plaintext = gmssl_sm4_decrypt($key, $ciphertext);

	print(bin2hex($block)."\n");
	print(bin2hex($plaintext)."\n");
?>
```

The `gmssl_sm4_encrypt` and `gmssl_sm4_decrypt` functions export low-level API of SM4 block cipher.
For the encryption of typical message, You can use SM4 with some encryption modes, such as CBC, CTR and GCM mode.
The GCM mode is the recommended mode for non-expert users.

```php
<?php
	$key = gmssl_rand_bytes(GMSSL_SM4_KEY_SIZE);
	$iv = gmssl_rand_bytes(GMSSL_SM4_GCM_DEFAULT_ID_SIZE);
	$aad = "Encoding: Text";
	$message = "This is the secret text message.";

	$ciphertext = gmssl_sm4_gcm_encrypt($key, $iv, $aad, $message, GMSSL_SM4_GCM_MAX_TAG_SIZE);
	$plaintext = gmssl_sm4_gcm_decrypt($key, $iv, $aad, $ciphertext, GMSSL_SM4_GCM_MAX_TAG_SIZE);

	print(bin2hex($message)."\n");
	print(bin2hex($plaintext)."\n");
?>
```

### SM2 Examples

SM2 is the ellptic curve cryptogrphy standard of China. The standard includes the SM2 signature algorithm, the SM2 public key encryption algorithm and the recommended 256-bit SM2 domain parameters.
Here is the example of SM2 key generation, signature generation/verification, and the SM2 public key encryption/decryption.

```php
<?php
	$sm2_key = gmssl_sm2_key_generate();
	$pass = "123456";
	gmssl_sm2_private_key_info_encrypt_to_pem($sm2_key, $pass, "sm2.pem");
	gmssl_sm2_public_key_info_to_pem($sm2_key, "sm2pub.pem");
	$sm2_pub = gmssl_sm2_public_key_info_from_pem("sm2pub.pem");

	$sig = gmssl_sm2_sign($sign_key, GMSSL_SM2_DEFAULT_ID, "To be signed message");
	print(gmssl_sm2_verify($sm2_pub, GMSSL_SM2_DEFAULT_ID, "To be signed message", $sig)."\n");

	$ciphertext = gmssl_sm2_encrypt($sm2_pub, "Secret key materials");
	$plaintext = gmssl_sm2_decrypt($sm2_key, $ciphertext);
	print($plaintext."\n");
?>
```


## GmSSL PHP API

### Predefined Constants

* **GMSSL_PHP_VERSION**(string)
* **GMSSL_LIBRARAY_VERSION** (string)
* **GMSSL_SM3_DIGEST_SIZE** (int)
* **GMSSL_SM3_HMAC_SIZE** (int)
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

* Parameters - None
* Return Values - SM9 signing master key.
* Errors/Exceptions - Throw exceptions on GmSSL library inner errors.

### **gmssl_sm9_sign_master_key_extract_key**

Extract the signing private key from SM9 master key with signer's ID

```php
gmssl_sm9_sign_master_key_extract_key(
	string $master_key,
	string $id
): string
```

* Parameters
  * master_key - SM9 signing master key.
  * id - User's identity
* Return Values - User's sm9 signing private key extracted from the master key correponding to the given **id**
* Errors/Exceptions - Throw exceptions on invalid parameters or GmSSL library inner errors.

### **gmssl_sm9_sign_master_key_info_encrypt_to_pem**

Export SM9 signing master key to encrypted PEM file

```php
gmssl_sm9_sign_master_key_info_encrypt_to_pem(
	string $master_key,
	string $file,
	string $passphrase
): bool
```

* Parameters
  * master_key - SM9 signing master key
  * file - The output PEM file path.
  * passphrase - The passphrase/password to encrypt the private key.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_sign_master_key_info_decrypt_from_pem**

Import SM9 signing master key from encrypted PEM file

```php
gmssl_sm9_sign_master_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

* Parameters
  * file - The input password encrypted SM9 signing master key PEM file path.
  * passphrase - The passphrase/password to decrypt the PEM file.
* Return Values: SM9 signing master key
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_sign_master_public_key_to_pem**

Export SM9 signing master public key to file

```php
gmssl_sm9_sign_master_public_key_to_pem(
	string $master_key,
	string $file,
): bool
```

* Parameters
  * master_key - SM9 signing master key or master public key
  * file - The output SM9 signing master public key PEM file path.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_sign_master_public_key_from_pem**

Import SM9 signing master public key from file

```php
gmssl_sm9_sign_master_public_key_from_pem(
	string $file
): string
```

* Parameters
  * file - The SM9 signing master public key PEM file.
* Return Values: SM9 signing master public key.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_sign_key_info_encrypt_to_pem**

Export user's SM9 signing key to encrypted PEM file

```php
gmssl_sm9_sign_key_info_encrypt_to_pem(
	string $sign_key,
	string $file,
	string $passphrase
): bool
```

* Parameters
  * sign_key - SM9 signing private key
  * file - The output PEM file path.
  * passphrase - The passphrase/password to encrypt the private key.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_sign_key_info_decrypt_from_pem**

Import user's SM9 signing key from encrypted PEM file

```php
gmssl_sm9_sign_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

* Parameters
  * file - The input password encrypted SM9 signing private key PEM file path.
  * passphrase - The passphrase/password to decrypt the PEM file.
* Return Values: SM9 signing private key
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_sign**

Sign message with user's SM9 signing key

```php
gmssl_sm9_sign(
	string $sign_key,
	string $message
): string
```

* Parameters
  * sign_key - Signer's SM9 private key.
  * messsage - To be signed message of any length.
* Return Values - The generated SM9 signature in DER encoding, the raw data bytes start with a `0x30` byte.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_verify**


Verify SM9 signature of message with signer's ID

```php
gmssl_sm9_verify(
	string $master_public_key,
	string $id,
	string $message,
	string $signature
): bool
```

* Parameters
  * master_public_key - SM9 signing master public key.
  * id - Signer's identity string.
  * messsage - Signed message of any length.
  * signature - SM9 signature.
* Return Values - **ture** or **false**.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_enc_master_key_generate**

Generate SM9 encryption master key

```php
gmssl_sm9_enc_master_key_generate(): string
```

* Parameters - None
* Return Values - SM9 signing master key.
* Errors/Exceptions - Throw exceptions on GmSSL library inner errors.


### **gmssl_sm9_enc_master_key_extract_key**

Extract the encryption private key from SM9 master key with user's ID

```php
gmssl_sm9_enc_master_key_extract_key(
	string $master_key,
	string $id
): string
```

* Parameters
  * master_key - SM9 encryption master key.
  * id - User's identity
* Return Values - User's sm9 encryption private key extracted from the master key correponding to the given **id**
* Errors/Exceptions - Throw exceptions on invalid parameters or GmSSL library inner errors.


###**gmssl_sm9_enc_master_key_info_encrypt_to_pem**

Export SM9 encryption master key to encrypted PEM file

```php
gmssl_sm9_enc_master_key_info_encrypt_to_pem(
	string $master_key,
	string $file,
	string $passphrase
): bool
```

* Parameters
  * master_key - SM9 encryption master key
  * file - The output PEM file path.
  * passphrase - The passphrase/password to encrypt the private key.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_enc_master_key_info_decrypt_from_pem**

Import SM9 encryption master key from encrypted PEM file

```php
gmssl_sm9_enc_master_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

* Parameters
  * file - The input password encrypted SM9 encryption master key PEM file path.
  * passphrase - The passphrase/password to decrypt the PEM file.
* Return Values: SM9 encryption master key
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_enc_master_public_key_to_pem**

Export SM9 encryption master public key to file

```php
gmssl_sm9_enc_master_public_key_to_pem(
	string $master_key,
	string $file,
): bool
```

* Parameters
  * master_key - SM9 encryption master key or master public key
  * file - The output SM9 encryption master public key PEM file path.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_enc_master_public_key_from_pem**

Import SM9 encryption master public key from file

```php
gmssl_sm9_enc_master_public_key_from_pem(
	string $file
): string
```

* Parameters
  * file - The SM9 encryption master public key PEM file.
* Return Values: SM9 encryption master public key.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_enc_key_info_encrypt_to_pem**

Export user's SM9 encryption key to encrypted PEM file

```php
gmssl_sm9_enc_key_info_encrypt_to_pem(
	string $enc_key,
	string $file,
	string $passphrase
): bool
```

* Parameters
  * enc_key - SM9 encryption private key
  * file - The output PEM file path.
  * passphrase - The passphrase/password to encrypt the private key.
* Return Values: **true** on success or **false** on failure.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.


### **gmssl_sm9_enc_key_info_decrypt_from_pem**

Import user's SM9 encryption key from encrypted PEM file

```php
gmssl_sm9_enc_key_info_decrypt_from_pem(
	string $file,
	string $passphrase
): string
```

* Parameters
  * file - The input password encrypted SM9 encryption private key PEM file path.
  * passphrase - The passphrase/password to decrypt the PEM file.
* Return Values: SM9 encryption private key
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_encrypt**

Encrypt short message with recipient's ID

```php
gmssl_sm9_encrypt(
	string $master_public_key,
	string $id,
	string $data
): string
```

* Parameters
  * master_public_key - SM9 encryption master public key.
  * data - To be encrypted plaintext. SM9 encryption should be used to protect key materials. The length should not longer than GMSSL_SM9_MAX_PLAINTEXT_SIZE.
* Return Values - Ciphertext.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_sm9_decrypt**

Decrypt SM9 ciphertext with user's SM9 private key

```php
gmssl_sm9_decrypt(
	string $enc_key,
	string $id,
	string $ciphertext
): string
```

* Parameters
  * enc_key - Receiver's SM9 encryption/decryption private key
  * id - Receiver's identity
  * ciphertext - SM9 Ciphertext.
* Return Values - Plaintext.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_from_pem**

Import X.509 certificate from PEM file.

```php
gmssl_cert_from_pem(string $path): string
```

* Parameters
  * path - Certificate file path, the certificate should be a SM2 certficate in PEM format.
* Return Values - SM2 certificate. The raw data of the return value is the DER-encoding bytes of the certificate.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_print**

Print details of a X.509 certificate.

```php
gmssl_cert_print(
	string $cert,
	string $label
): bool
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
  * label - Label string that will be printed at the first line of the output.
* Return Values - **true** or **false**
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_get_serial_number**

Get the SerialNumber field of a X.509 certificate.

```php
gmssl_cert_get_serial_number(string $cert): string
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
* Return Values - SerialNumber field raw data (bytes).
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_get_issuer**

Get the Issuer field of a X.509 certificate.

```php
gmssl_cert_get_issuer(string $cert): array
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
* Return Values - Issuer field as an array. The element with key `raw_data` is the DER-encoding of the X.509 DN value (without Tag and Length).
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_get_validity**

Get the Validity field of a X.509 certificate.

```php
gmssl_cert_get_validity(string $cert): array
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
* Return Values - Validity field of the certificate as an array. The return array has two elements with key `notBefore` and `notAfter`, the value is an `int` value of the timestamp.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_get_subject**

Get the Subject field of a X.509 certificate.

```php
gmssl_cert_get_subject(string $cert): array
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
* Return Values - Subject field as an array. The element with key `raw_data` is the DER-encoding of the X.509 DN value (without Tag and Length).
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_get_subject_public_key**

Get the SM2 public key from the SubjectPublicKeyInfo field of a X.509 certificate.

```php
gmssl_cert_get_subject_public_key(string $cert): string
```

* Parameters
  * cert - SM2 certificate, typically from `gmssl_cert_from_pem`.
* Return Values - SM2 public key from the SubjectPublicKeyInfo field of the certificate. The return value format is the same as output of the `sm2_public_key_info_from_pem`.
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.

### **gmssl_cert_verify_by_ca_cert**

Verify a X.509 certificate by a CA certificate.

```php
gmssl_cert_verify_by_ca_cert(
	string $cert,
	string $cacert,
	string $sm2_id
): bool
```

* Parameters
  * cert - The verified SM2 certificate, to be verified if it is signed (issued) by the **cacert**.
  * cacert - The CA's SM2 certificate. The Issuer field of **cert** should be the same as the Subject field of the **cacert**.
  * sm2_id - The CA's signing SM2 ID, is not specified, GMSSL_SM2_DEFAULT_ID should be used.
* Return Values - **true** or **false**
* Errors/Exceptions - Throw exceptions on invalid parameters and GmSSL library inner errors.













