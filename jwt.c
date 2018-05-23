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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"

#include "zend_smart_str.h"
#include "zend_exceptions.h"
#include "ext/json/php_json.h"
#include "ext/standard/base64.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"

#include "php_jwt.h"

const char *jwt_alg_str(jwt_alg_t alg)
{
    switch (alg) {
    case JWT_ALG_NONE:
        return "none";
    case JWT_ALG_HS256:
        return "HS256";
    case JWT_ALG_HS384:
        return "HS384";
    case JWT_ALG_HS512:
        return "HS512";
    case JWT_ALG_RS256:
        return "RS256";
    case JWT_ALG_RS384:
        return "RS384";
    case JWT_ALG_RS512:
        return "RS512";
    case JWT_ALG_ES256:
        return "ES256";
    case JWT_ALG_ES384:
        return "ES384";
    case JWT_ALG_ES512:
        return "ES512";
    default:
        return NULL;
    }
}

jwt_alg_t jwt_str_alg(const char *alg)
{
    if (alg == NULL)
        return JWT_ALG_INVAL;

    if (!strcasecmp(alg, "none"))
        return JWT_ALG_NONE;
    else if (!strcasecmp(alg, "HS256"))
        return JWT_ALG_HS256;
    else if (!strcasecmp(alg, "HS384"))
        return JWT_ALG_HS384;
    else if (!strcasecmp(alg, "HS512"))
        return JWT_ALG_HS512;
    else if (!strcasecmp(alg, "RS256"))
        return JWT_ALG_RS256;
    else if (!strcasecmp(alg, "RS384"))
        return JWT_ALG_RS384;
    else if (!strcasecmp(alg, "RS512"))
        return JWT_ALG_RS512;
    else if (!strcasecmp(alg, "ES256"))
        return JWT_ALG_ES256;
    else if (!strcasecmp(alg, "ES384"))
        return JWT_ALG_ES384;
    else if (!strcasecmp(alg, "ES512"))
        return JWT_ALG_ES512;

    return JWT_ALG_INVAL;
}

static int jwt_sign(jwt_t *jwt, char **out, unsigned int *len)
{
    switch (jwt->alg) {
    /* HMAC */
    case JWT_ALG_HS256:
    case JWT_ALG_HS384:
    case JWT_ALG_HS512:
        return jwt_sign_sha_hmac(jwt, out, len);

    /* RSA */
    case JWT_ALG_RS256:
    case JWT_ALG_RS384:
    case JWT_ALG_RS512:

    /* ECC */
    case JWT_ALG_ES256:
    case JWT_ALG_ES384:
    case JWT_ALG_ES512:
        return jwt_sign_sha_pem(jwt, out, len);

    /* You wut, mate? */
    default:
        return EINVAL;
    }
}

static int jwt_verify(jwt_t *jwt, const char *sig)
{
    switch (jwt->alg) {
    /* HMAC */
    case JWT_ALG_HS256:
    case JWT_ALG_HS384:
    case JWT_ALG_HS512:
        return jwt_verify_sha_hmac(jwt, sig);

    /* RSA */
    case JWT_ALG_RS256:
    case JWT_ALG_RS384:
    case JWT_ALG_RS512:

    /* ECC */
    case JWT_ALG_ES256:
    case JWT_ALG_ES384:
    case JWT_ALG_ES512:
        return jwt_verify_sha_pem(jwt, sig);

    /* You wut, mate? */
    default:
        return EINVAL;
    }
}

int jwt_new(jwt_t **jwt)
{
    if (!jwt) {
        return EINVAL;
    }

    *jwt = emalloc(sizeof(jwt_t));
    if (!*jwt) {
        return ENOMEM;
    }

    memset(*jwt, 0, sizeof(jwt_t));

    return 0;
}

void jwt_free(jwt_t *jwt)
{
    if (!jwt) {
        return;
    }

    efree(jwt);
}

void jwt_b64_url_encode_ex(char *str)
{
    int len = strlen(str);
    int i, t;

    for (i = t = 0; i < len; i++) {
        switch (str[i]) {
        case '+':
            str[t++] = '-';
            break;
        case '/':
            str[t++] = '_';
            break;
        case '=':
            break;
        default:
            str[t++] = str[i];
        }
    }

    str[t] = '\0';
}

char *jwt_b64_url_encode(zend_string *input)
{
    zend_string *b64_str = NULL;
    b64_str = php_base64_encode((const unsigned char *)ZSTR_VAL(input), ZSTR_LEN(input));

    /* replace str */
    zend_string *new = zend_string_dup(b64_str, 0);

    jwt_b64_url_encode_ex(ZSTR_VAL(new));

    zend_string_free(new);
    zend_string_free(input);
    zend_string_free(b64_str);

    return ZSTR_VAL(new);
}

zend_string *jwt_b64_url_decode(zend_string *input)
{
    zend_string *rs = NULL;
    char *new, *src = ZSTR_VAL(input);
    int len, i, z;

    /* Decode based on RFC-4648 URI safe encoding. */
    len = ZSTR_LEN(input);
    new = alloca(len + 4);
    if (!new) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        switch (src[i]) {
        case '-':
            new[i] = '+';
            break;
        case '_':
            new[i] = '/';
            break;
        default:
            new[i] = src[i];
        }
    }
    z = 4 - (i % 4);
    if (z < 4) {
        while (z--) {
            new[i++] = '=';
        }	
    }
    new[i] = '\0';

    /* base64 decode */
    rs = php_base64_decode_ex((const unsigned char *)new, strlen(new), 1);

    zend_string_free(input);

    return rs;
}

void jwt_implode(zval *arr, zval *return_value)
{
    zend_string *delim = zend_string_init(".", strlen("."), 0);

    php_implode(delim, arr, return_value);
    zend_string_free(delim);
}

void jwt_explode(zend_string *str, zval *return_value)
{
    zend_string *delim = zend_string_init(".", strlen("."), 0);

    php_explode(delim, str, return_value, 3);
    zend_string_free(delim);
}

PHP_FUNCTION(jwt_encode)
{
    zval *claims = NULL, header, segments, buf;
    zend_string *key = NULL, *alg = NULL;
    smart_str json_header = {0}, json_claims = {0};

    char *sig = NULL;
    unsigned int sig_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "aS|S", &claims, &key, &alg) == FAILURE) {
        return;
    }

    /* not set algorithm */
    if (alg == NULL) {
        alg = zend_string_init("HS256", strlen("HS256"), 0);
    }

    /* init */
    array_init(&segments);
    array_init(&header);

    /* JWT header array */
    add_assoc_string(&header, "typ", "JWT");
    add_assoc_string(&header, "alg", ZSTR_VAL(alg));

    /* json encode */
    php_json_encode(&json_header, &header, 0);
    php_json_encode(&json_claims, claims, 0);

    /* base64 encode */
    add_next_index_string(&segments, jwt_b64_url_encode(json_header.s));
    add_next_index_string(&segments, jwt_b64_url_encode(json_claims.s));
    
    jwt_implode(&segments, &buf);

    /* set jwt struct */
    jwt_t *jwt = NULL;

    jwt_new(&jwt);
    jwt->alg = jwt_str_alg(ZSTR_VAL(alg));
    jwt->key = key;
    jwt->str = Z_STR(buf);

    /* sign */
    if (jwt_sign(jwt, &sig, &sig_len)) {
        efree(sig);
        zend_throw_exception(zend_ce_exception, "Signature error", 0);
    }
    
    add_next_index_string(&segments, jwt_b64_url_encode(zend_string_init(sig, sig_len, 0)));
    jwt_implode(&segments, return_value);

    /* free */
    efree(sig);
    jwt_free(jwt);
    zval_ptr_dtor(&buf);
    zval_ptr_dtor(&header);
    zval_ptr_dtor(&segments);
    zend_string_free(alg);
}

PHP_FUNCTION(jwt_decode)
{
    zval jwt_arr, header, claims, *value = NULL;
    zend_string *jwt = NULL, *key = NULL, *alg = NULL;

    zend_ulong i;
    smart_str segments = {0};

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|S", &jwt, &key, &alg) == FAILURE) {
        return;
    }

    /* not set algorithm */
    if (alg == NULL) {
        alg = zend_string_init("HS256", strlen("HS256"), 0);
    }

    /* init */
    array_init(&jwt_arr);

    /* get header and claims */
    jwt_explode(jwt, &jwt_arr);

    ZEND_HASH_FOREACH_NUM_KEY_VAL(Z_ARRVAL(jwt_arr), i, value) {
        zend_string *vs = jwt_b64_url_decode(Z_STR_P(value));

        switch (i) {
        case 0:
            smart_str_appendl(&segments, Z_STRVAL_P(value), Z_STRLEN_P(value));
            smart_str_appends(&segments, ".");

            php_json_decode_ex(&header, ZSTR_VAL(vs), ZSTR_LEN(vs), PHP_JSON_OBJECT_AS_ARRAY, 512);

            zval *zalg = zend_hash_str_find(Z_ARRVAL(header), "alg", strlen("alg"));
            
            if (!zend_string_equals(Z_STR_P(zalg), alg)) {
                zend_throw_exception(zend_ce_exception, "Algorithm not allowed", 0);
            }

            break;
        case 1:
            smart_str_appendl(&segments, Z_STRVAL_P(value), Z_STRLEN_P(value));
            php_json_decode_ex(&claims, ZSTR_VAL(vs), ZSTR_LEN(vs), PHP_JSON_OBJECT_AS_ARRAY, 512);
            break;
        case 2:
            smart_str_0(&segments);

            /* set jwt struct */
            jwt_t *jwt = NULL;

            jwt_new(&jwt);
            jwt->alg = jwt_str_alg(ZSTR_VAL(alg));
            jwt->key = key;
            jwt->str = segments.s;

            if (jwt_verify(jwt, Z_STRVAL_P(value))) {
                zend_throw_exception(zend_ce_exception, "Signature verification failed", 0);
            }

            jwt_free(jwt);
            break;
        }

        zend_string_free(vs);
    } ZEND_HASH_FOREACH_END();
    
    /* free */
    zend_string_free(alg);
    zval_ptr_dtor(&jwt_arr);
    smart_str_free(&segments);

    RETURN_ZVAL(&claims, 0, 1);
}

const zend_function_entry jwt_functions[] = {
    PHP_FE(jwt_encode,	NULL)
    PHP_FE(jwt_decode,	NULL)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(jwt)
{
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(jwt)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(jwt)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "jwt support", "enabled");
    php_info_print_table_row(2, "Version", PHP_JWT_VERSION);
    php_info_print_table_end();
}

zend_module_entry jwt_module_entry = {
    STANDARD_MODULE_HEADER,
    "jwt",
    jwt_functions,
    PHP_MINIT(jwt),
    PHP_MSHUTDOWN(jwt),
    NULL,		/* Replace with NULL if there's nothing to do at request start */
    NULL,	/* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(jwt),
    PHP_JWT_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_JWT
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(jwt)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
