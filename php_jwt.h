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

#ifndef PHP_JWT_H
#define PHP_JWT_H

#include <php.h>
#include <php_ini.h>

#include <zend_smart_str.h>
#include <zend_exceptions.h>

#include <ext/spl/spl_exceptions.h>
#include <ext/standard/base64.h>
#include <ext/json/php_json.h>
#include <ext/standard/info.h>
#include <ext/standard/php_string.h>

extern zend_module_entry jwt_module_entry;
#define phpext_jwt_ptr &jwt_module_entry

#define PHP_JWT_VERSION "0.2.5"

#ifdef ZTS
#include "TSRM.h"
#endif

#define JWT_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(jwt, v)

ZEND_BEGIN_MODULE_GLOBALS(jwt)
  time_t expiration;
  time_t not_before;
  char *iss;
  time_t iat;
  char *jti;
  zval *aud;
  char *sub;
  size_t leeway;
  char *algorithm;
ZEND_END_MODULE_GLOBALS(jwt)

/** JWT algorithm types. */
typedef enum jwt_alg {
  JWT_ALG_NONE = 0,
  JWT_ALG_HS256,
  JWT_ALG_HS384,
  JWT_ALG_HS512,
  JWT_ALG_RS256,
  JWT_ALG_RS384,
  JWT_ALG_RS512,
  JWT_ALG_ES256,
  JWT_ALG_ES384,
  JWT_ALG_ES512,
  JWT_ALG_TERM
} jwt_alg_t;

#define JWT_ALG_INVAL JWT_ALG_TERM

/** Opaque JWT object. */
typedef struct jwt {
  jwt_alg_t alg;
  zend_string *key;
  zend_string *str;
} jwt_t;

char *jwt_b64_url_encode(zend_string *input);
void jwt_b64_url_encode_ex(char *str);
zend_string *jwt_b64_url_decode(const char *src);

int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len);
int jwt_verify_sha_hmac(jwt_t *jwt, const char *sig);

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len);
int jwt_verify_sha_pem(jwt_t *jwt, const char *sig_b64);

#if defined(ZTS) && defined(COMPILE_DL_JWT)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif	/* PHP_JWT_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
