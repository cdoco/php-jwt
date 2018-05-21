/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2017 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:   ZiHang Gao <ocdoco@gmail.com>                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#include "php.h"
#include "php_jwt.h"
#include "zend_smart_str.h"
#include "ext/standard/base64.h"

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/buffer.h"
#include "openssl/pem.h"

/* Routines to support crypto in JWT using OpenSSL. */

/* Functions to make libjwt backward compatible with OpenSSL version < 1.1.0
 * See https://wiki.openssl.org/index.php/1.1_API_Changes
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
	if (pr != NULL)
		*pr = sig->r;
	if (ps != NULL)
		*ps = sig->s;
}

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return 1;
}

#endif

int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len) {

    const EVP_MD *alg;

	switch (jwt->alg) {
        /* HMAC */
	case JWT_ALG_HS256:
		alg = EVP_sha256();
		break;
	case JWT_ALG_HS384:
		alg = EVP_sha384();
		break;
	case JWT_ALG_HS512:
		alg = EVP_sha512();
		break;
	default:
		return EINVAL;
	}

    *out = emalloc(EVP_MAX_MD_SIZE);
	if (*out == NULL) {
        return ENOMEM;
    }
		
	HMAC(alg, ZSTR_VAL(jwt->key), ZSTR_LEN(jwt->key),
	     (const unsigned char *)ZSTR_VAL(jwt->str), ZSTR_LEN(jwt->str), (unsigned char *)*out,
	     len);

    return 0;
}

int jwt_verify_sha_hmac(jwt_t *jwt, const char *sig)
{
	unsigned char res[EVP_MAX_MD_SIZE];
	BIO *bmem = NULL, *b64 = NULL;
	unsigned int res_len;
	const EVP_MD *alg;
	char *buf;
	int len, ret = EINVAL;

	switch (jwt->alg) {
	case JWT_ALG_HS256:
		alg = EVP_sha256();
		break;
	case JWT_ALG_HS384:
		alg = EVP_sha384();
		break;
	case JWT_ALG_HS512:
		alg = EVP_sha512();
		break;
	default:
		return EINVAL;
	}

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL)
		return ENOMEM;

	bmem = BIO_new(BIO_s_mem());
	if (bmem == NULL) {
		BIO_free(b64);
		return ENOMEM;
	}

	BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	HMAC(alg, ZSTR_VAL(jwt->key), ZSTR_LEN(jwt->key),
	     (const unsigned char *)ZSTR_VAL(jwt->str), ZSTR_LEN(jwt->str), res, &res_len);

	BIO_write(b64, res, res_len);

	(void)BIO_flush(b64);

	len = BIO_pending(bmem);
	if (len < 0)
		goto jwt_verify_hmac_done;

	buf = alloca(len + 1);
	if (!buf) {
		ret = ENOMEM;
		goto jwt_verify_hmac_done;
	}

	len = BIO_read(bmem, buf, len);
	buf[len] = '\0';

    zend_string *zs = php_base64_encode((const unsigned char *)buf, len);

	/* And now... */
	ret = strcmp(ZSTR_VAL(zs), sig) ? EINVAL : 0;

    zend_string_free(zs);

jwt_verify_hmac_done:
	BIO_free_all(b64);

	return ret;
}