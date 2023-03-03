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
#include <gmssl/aead.h>
#include <gmssl/pbkdf2.h>


PHP_FUNCTION(gmssl_version_num)
{
	ZEND_PARSE_PARAMETERS_NONE();

	RETVAL_LONG((zend_long)gmssl_version_num());
}

PHP_FUNCTION(gmssl_version_str)
{
	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_STRING(gmssl_version_str());
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
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		zend_string_release_ex(bytes, 0);
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
	zend_string *msg;
	zend_string *key;
	uint8_t hmac[SM3_HMAC_SIZE];

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(key)
		Z_PARAM_STR(msg)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(key) < 16) {
		zend_throw_exception(zend_ce_error, "Key length must be at least 16", 0);
		return;
	}

	sm3_hmac((uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg), (uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key), hmac);

	RETURN_STRINGL((char *)hmac, sizeof(hmac));
}

PHP_FUNCTION(gmssl_sm3_pbkdf2)
{
	zend_string *out;
	zend_long outlen;
	zend_string *pass;
	zend_string *salt;
	zend_long iter;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_LONG(outlen)
		Z_PARAM_STR(pass)
		Z_PARAM_STR(salt)
		Z_PARAM_LONG(iter)
	ZEND_PARSE_PARAMETERS_END();

	out = zend_string_alloc(outlen, 0);

	if (pbkdf2_hmac_sm3_genkey(ZSTR_VAL(pass), ZSTR_LEN(pass), (uint8_t *)ZSTR_VAL(salt), ZSTR_LEN(salt),
		iter, outlen, (uint8_t *)ZSTR_VAL(out)) != 1) {

		zend_string_release_ex(out, 0);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

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

	sm4_set_encrypt_key(&sm4_key, ZSTR_VAL(key));

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

	sm4_set_decrypt_key(&sm4_key, ZSTR_VAL(key));

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

	sm4_set_encrypt_key(&sm4_key, ZSTR_VAL(key));
	memcpy(ctr, ZSTR_VAL(iv), ZSTR_LEN(iv));

	sm4_ctr_encrypt(&sm4_key, ctr, (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out));

	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));

	ZSTR_VAL(out)[ZSTR_LEN(in)] = 0;

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

	zuc_init(&zuc_state, ZSTR_VAL(key), ZSTR_VAL(iv));
	zuc_encrypt(&zuc_state, (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out));
	gmssl_secure_clear(&zuc_state, sizeof(zuc_state));

	ZSTR_VAL(out)[ZSTR_LEN(in)] = 0;

	RETURN_NEW_STR(out);
}


#define GMSSL_GCM_MAC_TAG_SIZE 16

PHP_FUNCTION(gmssl_sm4_gcm_encrypt)
{
	SM4_GCM_CTX gcm_ctx;
	zend_string *key;
	zend_string *iv;
	zend_string *aad;
	zend_string *in;
	zend_string *out;
	size_t outlen, left;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(aad)
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

	out = zend_string_alloc(ZSTR_LEN(in) + GMSSL_GCM_MAC_TAG_SIZE, 0);

	if (sm4_gcm_encrypt_init(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key),
			(uint8_t *)ZSTR_VAL(iv), ZSTR_LEN(iv),
			(uint8_t *)ZSTR_VAL(aad), ZSTR_LEN(aad),
			GMSSL_GCM_MAC_TAG_SIZE) != 1
		||sm4_gcm_encrypt_update(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
			(uint8_t *)ZSTR_VAL(out), &outlen) != 1
		||  sm4_gcm_encrypt_finish(&gcm_ctx,
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
	zend_string *out;
	size_t outlen, left;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_STR(aad)
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

	out = zend_string_alloc(ZSTR_LEN(in), 0);

	if (sm4_gcm_decrypt_init(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(key), ZSTR_LEN(key),
			(uint8_t *)ZSTR_VAL(iv), ZSTR_LEN(iv),
			(uint8_t *)ZSTR_VAL(aad), ZSTR_LEN(aad),
			GMSSL_GCM_MAC_TAG_SIZE) != 1
		||sm4_gcm_decrypt_update(&gcm_ctx,
			(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
			(uint8_t *)ZSTR_VAL(out), &outlen) != 1
		||  sm4_gcm_decrypt_finish(&gcm_ctx,
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

PHP_FUNCTION(gmssl_sm2_key_generate)
{
	zend_string *ret;

	ZEND_PARSE_PARAMETERS_NONE();

	ret = zend_string_alloc(sizeof(SM2_KEY), 0);

	if (sm2_key_generate((SM2_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_release_ex(ret, 0);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_VAL(ret)[sizeof(SM2_KEY)] = 0;

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
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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

	ret = zend_string_alloc(SM2_MAX_SIGNATURE_SIZE, 0);

	if (sm2_sign_init(&sign_ctx, (SM2_KEY *)ZSTR_VAL(keypair), ZSTR_VAL(id), ZSTR_LEN(id)) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| sm2_sign_finish(&sign_ctx, (uint8_t *)ZSTR_VAL(ret), &siglen) != 1) {

		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_string_release_ex(ret, 0);
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

	out = zend_string_alloc(SM2_MAX_CIPHERTEXT_SIZE, 0);

	if (sm2_encrypt((SM2_KEY *)ZSTR_VAL(pubkey), (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_release_ex(out, 0);
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

	out = zend_string_alloc(SM2_MAX_PLAINTEXT_SIZE, 0);

	if (sm2_decrypt((SM2_KEY *)ZSTR_VAL(keypair), (uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in),
		(uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_release_ex(out, 0);
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
		zend_string_release_ex(ret, 0);
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

	ret = zend_string_alloc(sizeof(SM9_SIGN_KEY), 0);

	if (sm9_sign_master_key_extract_key((SM9_SIGN_MASTER_KEY *)ZSTR_VAL(master_key),
		ZSTR_VAL(id), ZSTR_LEN(id), (SM9_SIGN_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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

	ret = zend_string_alloc(SM9_SIGNATURE_SIZE, 0);

	if (sm9_sign_init(&sign_ctx) != 1
		|| sm9_sign_update(&sign_ctx, (uint8_t *)ZSTR_VAL(msg), ZSTR_LEN(msg)) != 1
		|| sm9_sign_finish(&sign_ctx, (SM9_SIGN_KEY *)ZSTR_VAL(sign_key), (uint8_t *)ZSTR_VAL(ret), &siglen) != 1) {

		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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

	ret = zend_string_alloc(sizeof(SM9_ENC_KEY), 0);

	if (sm9_enc_master_key_extract_key((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_key),
		ZSTR_VAL(id), ZSTR_LEN(id), (SM9_ENC_KEY *)ZSTR_VAL(ret)) != 1) {
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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
		zend_string_release_ex(ret, 0);
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

	out = zend_string_alloc(SM9_MAX_CIPHERTEXT_SIZE, 0);

	if (sm9_encrypt((SM9_ENC_MASTER_KEY *)ZSTR_VAL(master_pubkey), ZSTR_VAL(id), ZSTR_LEN(id),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_release_ex(out, 0);
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

	out = zend_string_alloc(SM9_MAX_PLAINTEXT_SIZE, 0);

	if (sm9_decrypt((SM9_ENC_KEY *)ZSTR_VAL(pri_key), ZSTR_VAL(id), ZSTR_LEN(id),
		(uint8_t *)ZSTR_VAL(in), ZSTR_LEN(in), (uint8_t *)ZSTR_VAL(out), &outlen) != 1) {
		zend_string_release_ex(out, 0);
		zend_throw_exception(zend_ce_exception, "libgmssl inner error", 0);
		return;
	}

	ZSTR_LEN(out) = outlen;
	ZSTR_VAL(out)[outlen] = 0;

	RETURN_NEW_STR(out);
}


PHP_RINIT_FUNCTION(gmssl)
{
#if defined(ZTS) && defined(COMPILE_DL_GMSSL)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(gmssl)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "gmssl support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ arginfo
 */
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

ZEND_BEGIN_ARG_INFO(arginfo_outlen_pass_salt_iter, 0)
	ZEND_ARG_INFO(0, outlen)
	ZEND_ARG_INFO(0, pass)
	ZEND_ARG_INFO(0, salt)
	ZEND_ARG_INFO(0, iter)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_key_iv_in, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, iv)
	ZEND_ARG_INFO(0, in)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_key_iv_aad_in, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, iv)
	ZEND_ARG_INFO(0, aad)
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
/* }}} */

/* {{{ gmssl_functions[]
 */
static const zend_function_entry gmssl_functions[] = {
	PHP_FE(gmssl_version_num,				arginfo_none)
	PHP_FE(gmssl_version_str,				arginfo_none)
	PHP_FE(gmssl_rand_bytes,				arginfo_size)
	PHP_FE(gmssl_sm3,					arginfo_in)
	PHP_FE(gmssl_sm3_hmac,					arginfo_key_in)
	PHP_FE(gmssl_sm3_pbkdf2,				arginfo_outlen_pass_salt_iter)
	PHP_FE(gmssl_sm4_cbc_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_cbc_decrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_ctr_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_zuc_encrypt,				arginfo_key_iv_in)
	PHP_FE(gmssl_sm4_gcm_encrypt,				arginfo_key_iv_aad_in)
	PHP_FE(gmssl_sm4_gcm_decrypt,				arginfo_key_iv_aad_in)
	PHP_FE(gmssl_sm2_key_generate,				arginfo_none)
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
	PHP_FE_END
};
/* }}} */

/* {{{ gmssl_module_entry
 */
zend_module_entry gmssl_module_entry = {
	STANDARD_MODULE_HEADER,
	"gmssl",			/* Extension name */
	gmssl_functions,		/* zend_function_entry */
	NULL,				/* PHP_MINIT - Module initialization */
	NULL,				/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(gmssl),		/* PHP_RINIT - Request initialization */
	NULL,				/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(gmssl),		/* PHP_MINFO - Module info */
	PHP_GMSSL_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_GMSSL
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(gmssl)
#endif
