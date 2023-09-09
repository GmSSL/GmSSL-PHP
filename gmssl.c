/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Zhi Guan <guan@pku.edu.cn>                                  |
   +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_gmssl.h"
#include "zend_exceptions.h"

#include <gmssl/version.h>
#include <gmssl/rand.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>
#include <gmssl/zuc.h>
#include <gmssl/x509.h>
#include <gmssl/aead.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/error.h>


PHP_MINIT_FUNCTION(gmssl)
{
	REGISTER_STRING_CONSTANT("GMSSL_PHP_VERSION", PHP_GMSSL_VERSION, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("GMSSL_LIBRARY_VERSION", (char *)gmssl_version_str(), CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM3_DIGEST_SIZE", SM3_DIGEST_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM3_HMAC_SIZE", SM3_HMAC_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM3_HMAC_MIN_KEY_SIZE", 16, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_KEY_SIZE", SM4_KEY_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_BLOCK_SIZE", SM4_BLOCK_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_CBC_IV_SIZE", SM4_BLOCK_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_CTR_IV_SIZE", SM4_BLOCK_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_GCM_MIN_IV_SIZE", SM4_GCM_MIN_IV_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_GCM_MAX_IV_SIZE", SM4_GCM_MAX_IV_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_GCM_DEFAULT_IV_SIZE", SM4_GCM_IV_DEFAULT_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM4_GCM_MAX_TAG_SIZE", SM4_GCM_MAX_TAG_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("GMSSL_SM2_DEFAULT_ID", SM2_DEFAULT_ID, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM2_MAX_PLAINTEXT_SIZE", SM2_MAX_PLAINTEXT_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_SM9_MAX_PLAINTEXT_SIZE", SM9_MAX_PLAINTEXT_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_ZUC_KEY_SIZE", ZUC_KEY_SIZE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GMSSL_ZUC_IV_SIZE", ZUC_IV_SIZE, CONST_CS | CONST_PERSISTENT);
	return SUCCESS;
}

PHP_FUNCTION(gmssl_rand_bytes)
{
	zend_long size;
	zend_string *bytes;

	ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
		Z_PARAM_LONG(size)
	ZEND_PARSE_PARAMETERS_END();

	if (size < 1) {
		zend_throw_exception(zend_ce_error, "Length must be greater than 0", 0);
		return;
	}

	bytes = zend_string_alloc(size, 0);

	if (rand_bytes((uint8_t *)ZSTR_VAL(bytes), size) != 1) {
		zend_string_efree(bytes);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(bytes)[size] = 0;

	RETURN_STR(bytes);
}

PHP_FUNCTION(gmssl_sm3)
{
	zend_string *msg;
	uint8_t dgst[SM3_DIGEST_SIZE];

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(msg)
	ZEND_PARSE_PARAMETERS_END();

	sm3_digest((uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg), dgst);

	RETURN_STRINGL((char *)dgst, sizeof(dgst));
}

PHP_FUNCTION(gmssl_sm3_hmac)
{
	zend_string *key;
	zend_string *msg;
	uint8_t hmac[SM3_HMAC_SIZE];

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(key)
		Z_PARAM_STR(msg)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) < 16) {
		zend_throw_exception(zend_ce_error, "Key length must be at least 16", 0);
		return;
	}

	sm3_hmac((uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key), (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg), hmac);

	RETURN_STRINGL((char *)hmac, sizeof(hmac));
}

PHP_FUNCTION(gmssl_sm3_pbkdf2)
{
	zend_string *out;
	zend_string *pass;
	zend_string *salt;
	zend_long iter;
	zend_long outlen;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_STR(pass)
		Z_PARAM_STR(salt)
		Z_PARAM_LONG(iter)
		Z_PARAM_LONG(outlen)
	ZEND_PARSE_PARAMETERS_END();

	out = zend_string_alloc(outlen, 0);

	if (pbkdf2_hmac_sm3_genkey(ZSTR_VAL(pass), ZSTR_LEN(pass), (uint8_t *)ZSTR_VAL(salt), ZSTR_LEN(salt),
		iter, outlen, (uint8_t *)ZSTR_VAL(out)) != 1) {
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_encrypt)
{
	SM4_KEY sm4_key;
	zend_string *key;
	zend_string *in;
	zend_string *out;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(key)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4 key length must be 16", 0);
		return;
	}
	if (ZSTR_LEN(in) != SM4_BLOCK_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4 block size is 16", 0);
		return;
	}

	out = zend_string_alloc(SM4_BLOCK_SIZE, 0);

	sm4_set_encrypt_key(&sm4_key, (uint8_t *)ZSTR_VAL(key));

	sm4_encrypt(&sm4_key, (uint8_t *)ZSTR_VAL(in), (uint8_t *)ZSTR_VAL(out));

	ZSTR_VAL(out)[SM4_BLOCK_SIZE] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_decrypt)
{
	SM4_KEY sm4_key;
	zend_string *key;
	zend_string *in;
	zend_string *out;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(key)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4 key length must be 16", 0);
		return;
	}
	if (ZSTR_LEN(in) != SM4_BLOCK_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4 block size is 16", 0);
		return;
	}

	out = zend_string_alloc(SM4_BLOCK_SIZE, 0);

	sm4_set_decrypt_key(&sm4_key, (uint8_t *)ZSTR_VAL(key));

	sm4_encrypt(&sm4_key, (uint8_t *)ZSTR_VAL(in), (uint8_t *)ZSTR_VAL(out));

	ZSTR_VAL(out)[SM4_BLOCK_SIZE] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_cbc_encrypt)
{
	SM4_KEY sm4_key;
	zend_string *key;
	zend_string *iv;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) != SM4_BLOCK_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC IV length must be at 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in) + SM4_BLOCK_SIZE - ZSTR_LEN(in) % SM4_BLOCK_SIZE, 0);

	sm4_set_encrypt_key(&sm4_key, (uint8_t *)ZSTR_VAL(key));

	if (sm4_cbc_padding_encrypt(&sm4_key, (uint8_t *)ZSTR_VAL(iv),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "ligmssl inner error", 0);
		return;
	}
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_cbc_decrypt)
{
	SM4_KEY sm4_key;
	zend_string *key;
	zend_string *iv;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) != SM4_BLOCK_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC IV length must be at 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in), 0);

	sm4_set_decrypt_key(&sm4_key, (uint8_t *)ZSTR_VAL(key));

	if (sm4_cbc_padding_decrypt(&sm4_key, (uint8_t *)ZSTR_VAL(iv),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {

		gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "decryption failure", 0);
		return;
	}
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_ctr_encrypt)
{
	SM4_KEY sm4_key;
	uint8_t ctr[16];
	zend_string *key;
	zend_string *iv;
	zend_string *in;
	zend_string *out;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) != SM4_BLOCK_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-CBC IV length must be at 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in), 0);

	sm4_set_encrypt_key(&sm4_key, (uint8_t *)ZSTR_VAL(key));
	memcpy(ctr, ZSTR_VAL(iv), ZSTR_LEN(iv));

	sm4_ctr_encrypt(&sm4_key, ctr, (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out));

	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	ZSTR_VAL(out)[ZSTR_LEN(in)] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_gcm_encrypt)
{
	SM4_GCM_CTX gcm_ctx;
	zend_string *key;
	zend_string *iv;
	zend_string *aad;
	zend_string *in;
	zend_long taglen;
	zend_string *out;
	size_t outlen, left;

	ZEND_PARSE_PARAMETERS_START(5, 5)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(aad)
		Z_PARAM_LONG(taglen)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) < SM4_GCM_MIN_IV_SIZE
		|| ZSTR_LEN(iv) > SM4_GCM_MAX_IV_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM IV length invalid", 0);
		return;
	}

	if (taglen > SM4_GCM_MAX_TAG_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM Tag size length should <= 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in) + SM4_GCM_MAX_TAG_SIZE, 0);

	if (sm4_gcm_encrypt_init(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key),
			(uint8_t *)ZSTR_VAL(iv), ZSTR_LEN(iv),
			(uint8_t *)ZSTR_VAL(aad), ZSTR_LEN(aad),
			(size_t)taglen) != 1
		||sm4_gcm_encrypt_update(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
			(uint8_t *)ZSTR_VAL(out), &outlen) != 1
		||sm4_gcm_encrypt_finish(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(out) + outlen, &left) != 1) {

		gmssl_secure_clear(&gcm_ctx, sizeof(gcm_ctx));
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "encryption failure", 0);
		return;
	}
	gmssl_secure_clear(&gcm_ctx, sizeof(gcm_ctx));

	ZSTR_LEN(out) = outlen + left;
	ZSTR_VAL(out)[ZSTR_LEN(out)] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm4_gcm_decrypt)
{
	SM4_GCM_CTX gcm_ctx;
	zend_string *key;
	zend_string *iv;
	zend_string *aad;
	zend_string *in;
	zend_long taglen;
	zend_string *out;
	size_t outlen, left;

	ZEND_PARSE_PARAMETERS_START(5, 5)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(aad)
		Z_PARAM_LONG(taglen)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != SM4_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) < SM4_GCM_MIN_IV_SIZE
		|| ZSTR_LEN(iv) > SM4_GCM_MAX_IV_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM IV length invalid", 0);
		return;
	}

	if (taglen > SM4_GCM_MAX_TAG_SIZE) {
		zend_throw_exception(zend_ce_error, "SM4-GCM Tag size should <= 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in), 0);

	if (sm4_gcm_decrypt_init(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key),
			(uint8_t *)ZSTR_VAL(iv), ZSTR_LEN(iv),
			(uint8_t *)ZSTR_VAL(aad), ZSTR_LEN(aad),
			(size_t)taglen) != 1
		|| sm4_gcm_decrypt_update(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
			(uint8_t *)ZSTR_VAL(out), &outlen) != 1
		|| sm4_gcm_decrypt_finish(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(out) + outlen, &left) != 1) {
		gmssl_secure_clear(&gcm_ctx, sizeof(gcm_ctx));
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "encryption failure", 0);
		return;
	}
	gmssl_secure_clear(&gcm_ctx, sizeof(gcm_ctx));

	ZSTR_LEN(out) = outlen + left;
	ZSTR_VAL(out)[ZSTR_LEN(out)] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_zuc_encrypt)
{
	ZUC_STATE zuc_state;
	zend_string *key;
	zend_string *iv;
	zend_string *in;
	zend_string *out;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) != ZUC_KEY_SIZE) {
		zend_throw_exception(zend_ce_error, "ZUC key length must be 16", 0);
		return;
	}

	if (ZSTR_LEN(iv) != ZUC_IV_SIZE) {
		zend_throw_exception(zend_ce_error, "ZUC IV length must be at 16", 0);
		return;
	}

	out = zend_string_alloc(ZSTR_LEN(in), 0);

	zuc_init(&zuc_state, (uint8_t *)ZSTR_VAL(key), (uint8_t *)ZSTR_VAL(iv));
	zuc_encrypt(&zuc_state, (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out));
	gmssl_secure_clear(&zuc_state, sizeof(zuc_state));

	ZSTR_VAL(out)[ZSTR_LEN(in)] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm2_key_generate)
{
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_NONE();

	ret = zend_string_alloc(sizeof(SM2_KEY), 0);

	if (sm2_key_generate((SM2_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM2_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm2_compute_z)
{
	zend_string *ret;
	zend_string *sm2_pub;
	zend_string *id;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(sm2_pub)
		Z_PARAM_STR(id)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(sm2_pub) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 private key size", 0);
		return;
	}

	ret = zend_string_alloc(SM3_DIGEST_SIZE, 0);

	if (sm2_compute_z((uint8_t *)ZSTR_VAL(ret), &((SM2_KEY *)ZSTR_VAL(sm2_pub))->public_key, ZSTR_VAL(id), ZSTR_LEN(id)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_error, "libgmssl inner error", 0);
		return;
	}

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm2_private_key_info_encrypt_to_pem)
{
	zend_string *keypair;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(keypair)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(keypair) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 private key size", 0);
		RETURN_FALSE;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm2_private_key_info_encrypt_to_pem((SM2_KEY *)ZSTR_VAL(keypair), ZSTR_VAL(pass), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm2_private_key_info_decrypt_from_pem)
{
	zend_string *ret;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM2_KEY), 0);

	if (sm2_private_key_info_decrypt_from_pem((SM2_KEY *)ZSTR_VAL(ret), ZSTR_VAL(pass), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM2_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm2_public_key_info_to_pem)
{
	zend_string *keypair;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(keypair)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(keypair) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 public key size", 0);
		RETURN_FALSE;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm2_public_key_info_to_pem((SM2_KEY *)ZSTR_VAL(keypair), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm2_public_key_info_from_pem)
{
	zend_string *ret;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM2_KEY), 0);

	if (sm2_public_key_info_from_pem((SM2_KEY *)ZSTR_VAL(ret), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM2_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm2_sign)
{
	SM2_SIGN_CTX sign_ctx;
	size_t siglen;
	zend_string *ret;
	zend_string *keypair;
	zend_string *id;
	zend_string *msg;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(keypair)
		Z_PARAM_STR(id)
		Z_PARAM_STR(msg)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(keypair) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 private key size", 0);
		return;
	}

	ret = zend_string_alloc(SM2_MAX_SIGNATURE_SIZE, 0);

	if (sm2_sign_init(&sign_ctx, (SM2_KEY *)ZSTR_VAL(keypair), ZSTR_VAL(id), ZSTR_LEN(id)) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| sm2_sign_finish(&sign_ctx, (uint8_t *)ZSTR_VAL(ret), &siglen) != 1) {
		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

	ZSTR_LEN(ret) = siglen;
	ZSTR_VAL(ret)[siglen] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm2_verify)
{
	SM2_SIGN_CTX sign_ctx;
	zend_string *pubkey;
	zend_string *id;
	zend_string *msg;
	zend_string *sig;
	int ret;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_STR(pubkey)
		Z_PARAM_STR(id)
		Z_PARAM_STR(msg)
		Z_PARAM_STR(sig)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(pubkey) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 public key size", 0);
		return;
	}

	if (sm2_verify_init(&sign_ctx, (SM2_KEY *)ZSTR_VAL(pubkey), ZSTR_VAL(id), ZSTR_LEN(id)) != 1
		|| sm2_verify_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| (ret = sm2_verify_finish(&sign_ctx, (uint8_t *)ZSTR_VAL(sig), ZSTR_LEN(sig))) < 0) {

		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

	if (ret == 1) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(gmssl_sm2_encrypt)
{
	zend_string *pubkey;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(pubkey)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(pubkey) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 public key size", 0);
		return;
	}

	out = zend_string_alloc(SM2_MAX_CIPHERTEXT_SIZE, 0);

	if (sm2_encrypt((SM2_KEY *)ZSTR_VAL(pubkey), (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm2_decrypt)
{
	zend_string *keypair;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(keypair)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(keypair) != sizeof(SM2_KEY)) {
		zend_throw_exception(zend_ce_exception, "invalid SM2 private key size", 0);
		return;
	}

	out = zend_string_alloc(SM2_MAX_PLAINTEXT_SIZE, 0);

	if (sm2_decrypt((SM2_KEY *)ZSTR_VAL(keypair), (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm9_sign_master_key_generate)
{
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_NONE();

	ret = zend_string_alloc(sizeof(SM9_SIGN_MASTER_KEY), 0);

	if (sm9_sign_master_key_generate((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM9_SIGN_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_sign_master_key_extract_key)
{
	zend_string *master_key;
	zend_string *id;
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(master_key)
		Z_PARAM_STR(id)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_key) != sizeof(SM9_SIGN_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_MASTER_KEY", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_SIGN_KEY), 0);

	if (sm9_sign_master_key_extract_key((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(master_key),
		ZSTR_VAL(id), ZSTR_LEN(id), (SM9_SIGN_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM9_SIGN_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_sign_master_key_info_encrypt_to_pem)
{
	zend_string *master_key;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(master_key)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_key) != sizeof(SM9_SIGN_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_MASTER_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_sign_master_key_info_encrypt_to_pem((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(master_key), ZSTR_VAL(pass), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_sign_master_key_info_decrypt_from_pem)
{
	zend_string *ret;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_SIGN_MASTER_KEY), 0);

	if (sm9_sign_master_key_info_decrypt_from_pem((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(ret), ZSTR_VAL(pass), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_SIGN_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_sign_master_public_key_to_pem)
{
	zend_string *master_pubkey;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(master_pubkey)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_pubkey) != sizeof(SM9_SIGN_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_MASTER_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_sign_master_public_key_to_pem((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(master_pubkey), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_sign_master_public_key_from_pem)
{
	zend_string *ret;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_SIGN_MASTER_KEY), 0);

	if (sm9_sign_master_public_key_from_pem((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(ret), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_SIGN_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}


PHP_FUNCTION(gmssl_sm9_sign_key_info_encrypt_to_pem)
{
	zend_string *pri_key;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(pri_key)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(pri_key) != sizeof(SM9_SIGN_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_sign_key_info_encrypt_to_pem((SM9_SIGN_KEY *)ZSTR_VAL(pri_key), ZSTR_VAL(pass), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_sign_key_info_decrypt_from_pem)
{
	zend_string *ret;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_SIGN_KEY), 0);

	if (sm9_sign_key_info_decrypt_from_pem((SM9_SIGN_KEY *)ZSTR_VAL(ret), ZSTR_VAL(pass), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_SIGN_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_sign)
{
	SM9_SIGN_CTX sign_ctx;
	size_t siglen;
	zend_string *sign_key;
	zend_string *msg;
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(sign_key)
		Z_PARAM_STR(msg)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(sign_key) != sizeof(SM9_SIGN_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_KEY", 0);
		return;
	}

	ret = zend_string_alloc(SM9_SIGNATURE_SIZE, 0);

	if (sm9_sign_init(&sign_ctx) != 1
		|| sm9_sign_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| sm9_sign_finish(&sign_ctx, (SM9_SIGN_KEY *)ZSTR_VAL(sign_key), (uint8_t *)ZSTR_VAL(ret), &siglen) != 1) {

		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

	ZSTR_LEN(ret) = siglen;
	ZSTR_VAL(ret)[siglen] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_verify)
{
	SM9_SIGN_CTX sign_ctx;
	zend_string *master_key;
	zend_string *id;
	zend_string *msg;
	zend_string *sig;
	int ret;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_STR(master_key)
		Z_PARAM_STR(id)
		Z_PARAM_STR(msg)
		Z_PARAM_STR(sig)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_key) != sizeof(SM9_SIGN_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_SIGN_MASTER_KEY", 0);
		return;
	}

	if (sm9_verify_init(&sign_ctx) != 1
		|| sm9_verify_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| (ret = sm9_verify_finish(&sign_ctx, (uint8_t *)ZSTR_VAL(sig), ZSTR_LEN(sig),
			(SM9_SIGN_MASTER_KEY *)ZSTR_VAL(master_key), ZSTR_VAL(id), ZSTR_LEN(id))) < 0) {

		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

	if (ret == 1) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(gmssl_sm9_enc_master_key_generate)
{
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_NONE();

	ret = zend_string_alloc(sizeof(SM9_ENC_MASTER_KEY), 0);

	if (sm9_enc_master_key_generate((SM9_ENC_MASTER_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM9_ENC_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_enc_master_key_extract_key)
{
	zend_string *master_key;
	zend_string *id;
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(master_key)
		Z_PARAM_STR(id)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_key) != sizeof(SM9_ENC_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_MASTER_KEY", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_ENC_KEY), 0);

	if (sm9_enc_master_key_extract_key((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_key),
		ZSTR_VAL(id), ZSTR_LEN(id), (SM9_ENC_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM9_ENC_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_enc_master_key_info_encrypt_to_pem)
{
	zend_string *master_key;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(master_key)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_key) != sizeof(SM9_ENC_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_MASTER_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_enc_master_key_info_encrypt_to_pem((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_key), ZSTR_VAL(pass), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_enc_master_key_info_decrypt_from_pem)
{
	zend_string *ret;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_ENC_MASTER_KEY), 0);

	if (sm9_enc_master_key_info_decrypt_from_pem((SM9_ENC_MASTER_KEY *)ZSTR_VAL(ret), ZSTR_VAL(pass), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_ENC_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_enc_master_public_key_to_pem)
{
	zend_string *master_pubkey;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(master_pubkey)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_pubkey) != sizeof(SM9_ENC_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_MASTER_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_enc_master_public_key_to_pem((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_pubkey), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_enc_master_public_key_from_pem)
{
	zend_string *ret;
	zend_string *file;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_ENC_MASTER_KEY), 0);

	if (sm9_enc_master_public_key_from_pem((SM9_ENC_MASTER_KEY *)ZSTR_VAL(ret), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_ENC_MASTER_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_enc_key_info_encrypt_to_pem)
{
	zend_string *pri_key;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(pri_key)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(pri_key) != sizeof(SM9_ENC_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_KEY", 0);
		return;
	}

	if (!(fp = fopen(ZSTR_VAL(file), "wb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		RETURN_FALSE;
	}

	if (sm9_enc_key_info_encrypt_to_pem((SM9_ENC_KEY *)ZSTR_VAL(pri_key), ZSTR_VAL(pass), fp) != 1) {
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		RETURN_FALSE;
	}
	fclose(fp);

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_sm9_enc_key_info_decrypt_from_pem)
{
	zend_string *ret;
	zend_string *file;
	zend_string *pass;
	FILE *fp;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(file)
		Z_PARAM_STR(pass)
	ZEND_PARSE_PARAMETERS_END();

	if (!(fp = fopen(ZSTR_VAL(file), "rb"))) {
		zend_throw_exception(zend_ce_exception, "open file error", 0);
		return;
	}

	ret = zend_string_alloc(sizeof(SM9_ENC_KEY), 0);

	if (sm9_enc_key_info_decrypt_from_pem((SM9_ENC_KEY *)ZSTR_VAL(ret), ZSTR_VAL(pass), fp) != 1) {
		zend_string_efree(ret);
		fclose(fp);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
	fclose(fp);

	ZSTR_VAL(ret)[sizeof(SM9_ENC_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_sm9_encrypt)
{
	zend_string *master_pubkey;
	zend_string *id;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(master_pubkey)
		Z_PARAM_STR(id)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(master_pubkey) != sizeof(SM9_ENC_MASTER_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_MASTER_KEY", 0);
		return;
	}

	out = zend_string_alloc(SM9_MAX_CIPHERTEXT_SIZE, 0);

	if (sm9_encrypt((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_pubkey), ZSTR_VAL(id), ZSTR_LEN(id),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_sm9_decrypt)
{
	zend_string *pri_key;
	zend_string *id;
	zend_string *in;
	zend_string *out;
	size_t outlen;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(pri_key)
		Z_PARAM_STR(id)
		Z_PARAM_STR(in)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(pri_key) != sizeof(SM9_ENC_KEY)) {
		zend_throw_exception(zend_ce_error, "invalid SM9_ENC_KEY", 0);
		return;
	}

	out = zend_string_alloc(SM9_MAX_PLAINTEXT_SIZE, 0);

	if (sm9_decrypt((SM9_ENC_KEY *)ZSTR_VAL(pri_key), ZSTR_VAL(id), ZSTR_LEN(id),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_efree(out);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}

PHP_FUNCTION(gmssl_cert_from_pem)
{
	zend_string *ret;
	zend_string *file;
	uint8_t *cert = NULL;
	size_t certlen;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(file)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_new_from_file(&cert, &certlen, ZSTR_VAL(file)) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ret = zend_string_alloc(certlen, 0);

	memcpy(ZSTR_VAL(ret), cert, certlen);
	ZSTR_VAL(ret)[certlen] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_cert_print)
{
	zend_string *cert;
	zend_string *label;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(cert)
		Z_PARAM_STR(label)
	ZEND_PARSE_PARAMETERS_END();

	x509_cert_print(stdout, 0, 0, ZSTR_VAL(label), (uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert));

	RETURN_TRUE;
}

PHP_FUNCTION(gmssl_cert_get_serial_number)
{
	zend_string *ret;
	zend_string *cert;
	const uint8_t *serial;
	size_t serial_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(cert)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_get_issuer_and_serial_number((uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert), NULL, 0, &serial, &serial_len) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ret = zend_string_alloc(serial_len, 0);

	memcpy(ZSTR_VAL(ret), serial, serial_len);
	ZSTR_VAL(ret)[serial_len] = 0;

	RETURN_NEW_STR(ret);
}

static int gmssl_parse_attr_type_and_value(zval *arr, const uint8_t *d, size_t dlen)
{
	int oid, tag;
	const uint8_t *val;
	size_t vlen;

	if (x509_name_type_from_der(&oid, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (oid == OID_email_address) {
		if (asn1_ia5_string_from_der((const char **)&val, &vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (x509_directory_name_from_der(&tag, &val, &vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
	}
	add_assoc_stringl(arr, x509_name_type_name(oid), (char *)val, vlen);

	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

static int gmssl_parse_rdn(zval *arr, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (gmssl_parse_attr_type_and_value(arr, p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int gmssl_parse_name(zval *arr, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	while (dlen) {
		if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (gmssl_parse_rdn(arr, p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

PHP_FUNCTION(gmssl_cert_get_issuer)
{
	zend_string *cert;
	const uint8_t *issuer;
	size_t issuer_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(cert)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_get_issuer((uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert), &issuer, &issuer_len) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	array_init(return_value);
	add_assoc_stringl(return_value, "raw_data", (char *)issuer, issuer_len);

	if (gmssl_parse_name(return_value, issuer, issuer_len) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
}

PHP_FUNCTION(gmssl_cert_get_validity)
{
	zend_string *cert;
	time_t not_before;
	time_t not_after;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(cert)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_get_details((uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert),
		NULL,
		NULL, NULL,
		NULL,
		NULL, NULL,
		&not_before, &not_after,
		NULL, NULL,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL) != 1) {
	}

	array_init(return_value);
	add_assoc_long(return_value, "notBefore", not_before);
	add_assoc_long(return_value, "notAfter", not_after);
}

PHP_FUNCTION(gmssl_cert_get_subject)
{
	zend_string *cert;
	const uint8_t *subject;
	size_t subject_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(cert)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_get_subject((uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert), &subject, &subject_len) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	array_init(return_value);
	add_assoc_stringl(return_value, "raw_data", (char *)subject, subject_len);

	if (gmssl_parse_name(return_value, subject, subject_len) != 1) {
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}
}

PHP_FUNCTION(gmssl_cert_get_subject_public_key)
{
	zend_string *ret;
	zend_string *cert;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(cert)
	ZEND_PARSE_PARAMETERS_END();

	ret = zend_string_alloc(sizeof(SM2_KEY), 0);

	if (x509_cert_get_subject_public_key((uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert), (SM2_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_efree(ret);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM2_KEY)] = 0;

	RETURN_NEW_STR(ret);
}

PHP_FUNCTION(gmssl_cert_verify_by_ca_cert)
{
	zend_string *cert;
	zend_string *cacert;
	zend_string *sm2_id;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(cert)
		Z_PARAM_STR(cacert)
		Z_PARAM_STR(sm2_id)
	ZEND_PARSE_PARAMETERS_END();

	if (x509_cert_verify_by_ca_cert(
		(uint8_t *)ZSTR_VAL(cert), ZSTR_LEN(cert),
		(uint8_t *)ZSTR_VAL(cacert), ZSTR_LEN(cacert),
		ZSTR_VAL(sm2_id), ZSTR_LEN(sm2_id)) != 1) {
		zend_throw_exception(zend_ce_error, "cert verify failure", 0);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}


PHP_RINIT_FUNCTION(gmssl)
{
#if defined(ZTS) && defined(COMPILE_DL_GMSSL)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}

PHP_MINFO_FUNCTION(gmssl)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "gmssl support", "enabled");
	php_info_print_table_row(2, "gmssl library version", gmssl_version_str());
	php_info_print_table_end();
}



ZEND_BEGIN_ARG_INFO(arginfo_none, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_size, 0)
	ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_in, 0)
	ZEND_ARG_INFO(0,in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_key_in, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_pass_salt_iter_outlen, 0)
	ZEND_ARG_INFO(0, pass)
	ZEND_ARG_INFO(0, salt)
	ZEND_ARG_INFO(0, iter)
	ZEND_ARG_INFO(0, outlen)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_key_iv_in, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, iv)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_key_iv_aad_taglen_in, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, iv)
	ZEND_ARG_INFO(0, aad)
	ZEND_ARG_INFO(0, taglen)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_keypair_file_pass, 0)
	ZEND_ARG_INFO(0, keypair)
	ZEND_ARG_INFO(0, file)
	ZEND_ARG_INFO(0, pass)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_file_pass, 0)
	ZEND_ARG_INFO(0, file)
	ZEND_ARG_INFO(0, pass)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_keypair_file, 0)
	ZEND_ARG_INFO(0, keypair)
	ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_file, 0)
	ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_keypair_id_msg, 0)
	ZEND_ARG_INFO(0, keypair)
	ZEND_ARG_INFO(0, id)
	ZEND_ARG_INFO(0, msg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_pubkey_id_msg_sig, 0)
	ZEND_ARG_INFO(0, pubkey)
	ZEND_ARG_INFO(0, id)
	ZEND_ARG_INFO(0, msg)
	ZEND_ARG_INFO(0, sig)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_pubkey_in, 0)
	ZEND_ARG_INFO(0, pubkey)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_keypair_in, 0)
	ZEND_ARG_INFO(0, keypair)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_keypair_id, 0)
	ZEND_ARG_INFO(0, keypair)
	ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_cert, 0)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_cert_label, 0)
	ZEND_ARG_INFO(0, cert)
	ZEND_ARG_INFO(0, label)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_cert_cacert_id, 0)
	ZEND_ARG_INFO(0, cert)
	ZEND_ARG_INFO(0, cacert)
	ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()


static const zend_function_entry gmssl_functions[] = {
	PHP_FE(gmssl_rand_bytes,				arginfo_size)
	PHP_FE(gmssl_sm3,					arginfo_in)
	PHP_FE(gmssl_sm3_hmac,					arginfo_key_in)
	PHP_FE(gmssl_sm3_pbkdf2,				arginfo_pass_salt_iter_outlen)
	PHP_FE(gmssl_sm4_encrypt,				arginfo_key_in)
	PHP_FE(gmssl_sm4_decrypt,				arginfo_key_in)
	PHP_FE(gmssl_sm4_cbc_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_cbc_decrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_ctr_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_gcm_encrypt,				arginfo_key_iv_aad_taglen_in)
	PHP_FE(gmssl_sm4_gcm_decrypt,				arginfo_key_iv_aad_taglen_in)
	PHP_FE(gmssl_zuc_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm2_key_generate,				arginfo_none)
	PHP_FE(gmssl_sm2_compute_z,				arginfo_keypair_id)
	PHP_FE(gmssl_sm2_private_key_info_encrypt_to_pem,	arginfo_keypair_file_pass)
	PHP_FE(gmssl_sm2_private_key_info_decrypt_from_pem,	arginfo_file_pass)
	PHP_FE(gmssl_sm2_public_key_info_to_pem,		arginfo_keypair_file)
	PHP_FE(gmssl_sm2_public_key_info_from_pem,		arginfo_file)
	PHP_FE(gmssl_sm2_sign,					arginfo_keypair_id_msg)
	PHP_FE(gmssl_sm2_verify,				arginfo_pubkey_id_msg_sig)
	PHP_FE(gmssl_sm2_encrypt,				arginfo_pubkey_in)
	PHP_FE(gmssl_sm2_decrypt,				arginfo_keypair_in)
	PHP_FE(gmssl_sm9_sign_master_key_generate,		arginfo_none)
	PHP_FE(gmssl_sm9_sign_master_key_extract_key,		arginfo_keypair_id)
	PHP_FE(gmssl_sm9_sign_master_key_info_encrypt_to_pem,	arginfo_keypair_file_pass)
	PHP_FE(gmssl_sm9_sign_master_key_info_decrypt_from_pem,	arginfo_file_pass)
	PHP_FE(gmssl_sm9_sign_master_public_key_to_pem,		arginfo_keypair_file)
	PHP_FE(gmssl_sm9_sign_master_public_key_from_pem,	arginfo_file)
	PHP_FE(gmssl_sm9_sign_key_info_encrypt_to_pem,		arginfo_keypair_file_pass)
	PHP_FE(gmssl_sm9_sign_key_info_decrypt_from_pem,	arginfo_file_pass)
	PHP_FE(gmssl_sm9_sign,					arginfo_keypair_in)
	PHP_FE(gmssl_sm9_verify,				arginfo_pubkey_id_msg_sig)
	PHP_FE(gmssl_sm9_enc_master_key_generate,		arginfo_none)
	PHP_FE(gmssl_sm9_enc_master_key_extract_key,		arginfo_keypair_id)
	PHP_FE(gmssl_sm9_enc_master_key_info_encrypt_to_pem,	arginfo_keypair_file_pass)
	PHP_FE(gmssl_sm9_enc_master_key_info_decrypt_from_pem,	arginfo_file_pass)
	PHP_FE(gmssl_sm9_enc_master_public_key_to_pem,		arginfo_keypair_file)
	PHP_FE(gmssl_sm9_enc_master_public_key_from_pem,	arginfo_file)
	PHP_FE(gmssl_sm9_enc_key_info_encrypt_to_pem,		arginfo_keypair_file_pass)
	PHP_FE(gmssl_sm9_enc_key_info_decrypt_from_pem,		arginfo_file_pass)
	PHP_FE(gmssl_sm9_encrypt,				arginfo_keypair_id_msg)
	PHP_FE(gmssl_sm9_decrypt,				arginfo_keypair_id_msg)
	PHP_FE(gmssl_cert_from_pem,				arginfo_file)
	PHP_FE(gmssl_cert_print,				arginfo_cert_label)
	PHP_FE(gmssl_cert_get_serial_number,			arginfo_cert)
	PHP_FE(gmssl_cert_get_issuer,				arginfo_cert)
	PHP_FE(gmssl_cert_get_validity,				arginfo_cert)
	PHP_FE(gmssl_cert_get_subject,				arginfo_cert)
	PHP_FE(gmssl_cert_get_subject_public_key,		arginfo_cert)
	PHP_FE(gmssl_cert_verify_by_ca_cert,			arginfo_cert_cacert_id)
	PHP_FE_END
};

zend_module_entry gmssl_module_entry = {
	STANDARD_MODULE_HEADER,
	"gmssl",			/* Extension name */
	gmssl_functions,		/* zend_function_entry */
	PHP_MINIT(gmssl),		/* PHP_MINIT - Module initialization */
	NULL,				/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(gmssl),		/* PHP_RINIT - Request initialization */
	NULL,				/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(gmssl),		/* PHP_MINFO - Module info */
	PHP_GMSSL_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};



#ifdef COMPILE_DL_GMSSL
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(gmssl)
#endif
