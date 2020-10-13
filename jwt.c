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

#include <php_jwt.h>

/* OpenSSL includes */
#include <openssl/conf.h>

/* Exceptions */
static zend_class_entry *jwt_signature_invalid_cex;
static zend_class_entry *jwt_before_valid_cex;
static zend_class_entry *jwt_expired_signature_cex;
static zend_class_entry *jwt_invalid_issuer_cex;
static zend_class_entry *jwt_invalid_aud_cex;
static zend_class_entry *jwt_invalid_jti_cex;
static zend_class_entry *jwt_invalid_iat_cex;
static zend_class_entry *jwt_invalid_sub_cex;

static zend_class_entry *jwt_ce;

ZEND_DECLARE_MODULE_GLOBALS(jwt)

ZEND_BEGIN_ARG_INFO_EX(arginfo_jwt_encode, 0, 0, 2)
    ZEND_ARG_ARRAY_INFO(0, payload, 1)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, alg, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_jwt_decode, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, token, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

/* register internal class */
static zend_class_entry *jwt_register_class(const char *name)
{
    zend_class_entry ce;

    INIT_CLASS_ENTRY_EX(ce, name, strlen(name), NULL);
    return zend_register_internal_class_ex(&ce, zend_ce_exception);
}

/* string to algorithm */
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

/* jwt sign */
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

/* jwt verify */
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

/* jwt new */
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

/* jwt free */
void jwt_free(jwt_t *jwt)
{
    if (!jwt) {
        return;
    }

    efree(jwt);
}

/* base64 url safe encode */
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

/* base64 encode */
char *jwt_b64_url_encode(zend_string *input)
{
    zend_string *b64_str = php_base64_encode((const unsigned char *)ZSTR_VAL(input), ZSTR_LEN(input));

    /* replace str */
    char *new = estrdup(ZSTR_VAL(b64_str));
    jwt_b64_url_encode_ex(new);

    zend_string_free(b64_str);

    return new;
}

/* base64 decode */
zend_string *jwt_b64_url_decode(const char *src)
{
    char *new;
    int len, i, z;

    /* Decode based on RFC-4648 URI safe encoding. */
    len = strlen(src);
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
    return php_base64_decode_ex((const unsigned char *)new, strlen(new), 1);
}

/* hash find string */
char *jwt_hash_str_find_str(zval *arr, char *key)
{
    char *str = NULL;
    zval *zv = zend_hash_str_find(Z_ARRVAL_P(arr), key, strlen(key));

    if (zv != NULL) {
        if (Z_TYPE_P(zv) == IS_STRING) {
            str = Z_STRVAL_P(zv);
        } else {
            php_error_docref(NULL, E_WARNING, "%s type must be string", key);
        }
    } 

    return str;
}

/* hash find long */
long jwt_hash_str_find_long(zval *arr, char *key)
{
    zval *zv = zend_hash_str_find(Z_ARRVAL_P(arr), key, strlen(key));

    if (zv != NULL) {
        if (Z_TYPE_P(zv) == IS_LONG) {
            return Z_LVAL_P(zv);
        } else {
            php_error_docref(NULL, E_WARNING, "%s type must be long", key);
        }
    }

    return 0;
}

/* verify string claims */
int jwt_verify_claims_str(zval *arr, char *key, char *str)
{
    char *rs = jwt_hash_str_find_str(arr, key);
    if (rs && str && strcmp(rs, str)) {
        return FAILURE;
    }

    return 0;
}

/* array equals */
int jwt_array_equals(zend_array *arr1, zend_array *arr2) {
    zend_ulong i;
    zval *value = NULL;

    if (arr1 && arr2) {
        if (zend_array_count(arr1) != zend_array_count(arr2)) {
            return FAILURE;
        }

        ZEND_HASH_FOREACH_NUM_KEY_VAL(arr1, i, value) {
            zval *tmp = zend_hash_index_find(arr2, i);

            if (value && tmp){
                if (Z_TYPE_P(value) == IS_STRING && Z_TYPE_P(tmp) == IS_STRING) {
                    if (strcmp(Z_STRVAL_P(value), Z_STRVAL_P(tmp))) {
                        return FAILURE;
                    }
                } else {
                    php_error_docref(NULL, E_WARNING, "Aud each item type must be string");
                }
            }
        } ZEND_HASH_FOREACH_END();
    }

    return 0;
}

/* verify body */
int jwt_verify_body(char *body, zval *return_value)
{
    zend_class_entry *ce;
    char *err_msg = NULL;
    time_t curr_time = time((time_t*)NULL);
    zend_string *vs = jwt_b64_url_decode(body);

#define FORMAT_CEX_TIME(t, cex) do {                                                            \
       struct tm *timeinfo;                                                                     \
       char buf[128];                                                                           \
       timeinfo = localtime(&t);                                                                \
       strftime(buf, sizeof(buf), "Cannot handle token prior to %Y-%m-%d %H:%M:%S", timeinfo);  \
       ce = cex;                                                                                \
       err_msg = buf;                                                                           \
    } while(0);

#define FORMAT_CEX_MSG(msg, cex) do {   \
        ce = cex;                       \
        err_msg = msg;                  \
    } while(0);

    if (!vs) {
        FORMAT_CEX_MSG("Invalid body", spl_ce_UnexpectedValueException);
        goto done;
    }

    /* decode json to array */
    php_json_decode_ex(return_value, ZSTR_VAL(vs), ZSTR_LEN(vs), PHP_JSON_OBJECT_AS_ARRAY, 512);
    zend_string_free(vs);

    if (Z_TYPE(*return_value) == IS_ARRAY) {
        /* set expiration and not before */
        JWT_G(expiration) = jwt_hash_str_find_long(return_value, "exp");
        JWT_G(not_before) = jwt_hash_str_find_long(return_value, "nbf");
        JWT_G(iat) = jwt_hash_str_find_long(return_value, "iat");

        /* expiration */
        if (JWT_G(expiration) && (curr_time - JWT_G(leeway)) >= JWT_G(expiration))
            FORMAT_CEX_MSG("Expired token", jwt_expired_signature_cex);
        /* not before */
        if (JWT_G(not_before) && JWT_G(not_before) > (curr_time + JWT_G(leeway)))
            FORMAT_CEX_TIME(JWT_G(not_before), jwt_before_valid_cex);
        /* iat */
        if (JWT_G(iat) && JWT_G(iat) > (curr_time + JWT_G(leeway)))
            FORMAT_CEX_TIME(JWT_G(iat), jwt_invalid_iat_cex);
        /* iss */
        if (jwt_verify_claims_str(return_value, "iss", JWT_G(iss)))
            FORMAT_CEX_MSG("Invalid Issuer", jwt_invalid_issuer_cex);
        /* jti */
        if (jwt_verify_claims_str(return_value, "jti", JWT_G(jti)))
            FORMAT_CEX_MSG("Invalid Jti", jwt_invalid_jti_cex);

        /* aud */
        size_t flag = 0;
        zval *zv_aud = zend_hash_str_find(Z_ARRVAL_P(return_value), "aud", strlen("aud"));

        if (zv_aud && JWT_G(aud)) {
            switch(Z_TYPE_P(zv_aud)) {
            case IS_ARRAY:
                if (jwt_array_equals(Z_ARRVAL_P(JWT_G(aud)), Z_ARRVAL_P(zv_aud))) flag = 1;
                break;
            case IS_STRING:
                if (strcmp(Z_STRVAL_P(JWT_G(aud)), Z_STRVAL_P(zv_aud))) flag = 1;
                break;
            default:
                php_error_docref(NULL, E_WARNING, "Aud type must be string or array");
                break;
            }

            if (flag) FORMAT_CEX_MSG("Invalid Aud", jwt_invalid_aud_cex);
        }

        /* sub */
        if (jwt_verify_claims_str(return_value, "sub", JWT_G(sub)))
            FORMAT_CEX_MSG("Invalid Sub", jwt_invalid_sub_cex);
    } else {
        FORMAT_CEX_MSG("Json decode error", spl_ce_UnexpectedValueException);
    }

done:
    if (err_msg) {
        zend_throw_exception(ce, err_msg, 0);
        return FAILURE;
    }

    return 0;
}

/* parse options */
int jwt_parse_options(zval *options)
{
    /* check options */
    if (options != NULL) {
        switch(Z_TYPE_P(options)) {
        case IS_ARRAY:
            {
                /* check algorithm */
                char *alg = jwt_hash_str_find_str(options, "algorithm");
                if (alg) {
                    JWT_G(algorithm) = alg;
                }
                
                /* options */
                JWT_G(leeway) = jwt_hash_str_find_long(options, "leeway");
                JWT_G(iss) = jwt_hash_str_find_str(options, "iss");
                JWT_G(jti) = jwt_hash_str_find_str(options, "jti");
                JWT_G(aud) = zend_hash_str_find(Z_ARRVAL_P(options), "aud", strlen("aud"));
                JWT_G(sub) = jwt_hash_str_find_str(options, "sub");
            }
            break;
        case IS_NULL:
        case IS_FALSE:
            JWT_G(algorithm) = "none";
            break;
        default:
            break;
        }
    }

    return 0;
}

/* Jwt encode */
static void php_jwt_encode(INTERNAL_FUNCTION_PARAMETERS) {
    zval *payload = NULL, header;
    zend_string *key = NULL;
    smart_str json_header = {0}, json_payload = {0};

    char *sig = NULL, *alg = "HS256", *buf = NULL;
    unsigned int sig_len;
    size_t alg_len;
    jwt_t *jwt = NULL;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "aS|s", &payload, &key, &alg, &alg_len) == FAILURE) {
        return;
    }

    /* init jwt */
    jwt_new(&jwt);

    /* check algorithm */
    jwt->alg = jwt_str_alg(alg);

    if (jwt->alg == JWT_ALG_INVAL) {
        zend_throw_exception(spl_ce_UnexpectedValueException, "Algorithm not supported", 0);
        goto encode_done;
    }

    /* init */
    array_init(&header);

    /* JWT header array */
    add_assoc_string(&header, "typ", "JWT");
    add_assoc_string(&header, "alg", alg);

    /* json encode */
    php_json_encode(&json_header, &header, 0);
    char *header_b64 = jwt_b64_url_encode(json_header.s);

    php_json_encode(&json_payload, payload, 0);
    char *payload_b64 = jwt_b64_url_encode(json_payload.s);

    zval_ptr_dtor(&header);
    smart_str_free(&json_header);
    smart_str_free(&json_payload);

    int buflen = strlen(header_b64) + strlen(payload_b64) + 2;
    buf = (char *)ecalloc(buflen, 1);
    strcpy(buf, header_b64);
    strcat(buf, ".");
    strcat(buf, payload_b64);

    efree(header_b64);
    efree(payload_b64);

    /* sign */
    if (jwt->alg == JWT_ALG_NONE) {
	buflen += 1;
        /* alg none */
        buf = (char *)erealloc(buf, buflen);
        strcat(buf, ".");
	buf[buflen] = '\0';
    } else {
        /* set jwt struct */
        jwt->key = key;
        jwt->str = zend_string_init(buf, strlen(buf), 0);

        /* sign */
        if (jwt_sign(jwt, &sig, &sig_len)) {
            zend_throw_exception(spl_ce_DomainException, "OpenSSL unable to sign data", 0);
            zend_string_free(jwt->str);
            goto encode_done;
        }

        /* string concatenation */
        zend_string *sig_str = zend_string_init(sig, sig_len, 0);
        char *sig_b64 = jwt_b64_url_encode(sig_str);

	buflen = strlen(sig_b64) + strlen(buf) + 2;
        char *tmp = (char *)ecalloc(buflen, 1);
        sprintf(tmp, "%s.%s", buf, sig_b64);

        efree(buf);
        buf = tmp;

        efree(sig_b64);
        zend_string_free(jwt->str);
        zend_string_free(sig_str);
    }

encode_done:
    /* free */
    if (sig)
        efree(sig);

    jwt_free(jwt);

    RETVAL_STRINGL(buf, strlen(buf));
    efree(buf);
}

/* Jwt decode */
static void php_jwt_decode(INTERNAL_FUNCTION_PARAMETERS) {
    zend_string *token = NULL, *key = NULL;
    zval *options = NULL;
    smart_str buf = {0};
    char *body = NULL, *sig = NULL;
    jwt_t *jwt = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|z", &token, &key, &options) == FAILURE) {
        return;
    }

    char *head = estrdup(ZSTR_VAL(token));

    /* jwt init */
    jwt_new(&jwt);

    /* Parse options */
    if (jwt_parse_options(options) == FAILURE) {
        zend_throw_exception(spl_ce_UnexpectedValueException, "Options parse error", 0);
        goto decode_done;
    }

    /* Algorithm */
    jwt->alg = jwt_str_alg(JWT_G(algorithm));

    if (jwt->alg == JWT_ALG_INVAL) {
        zend_throw_exception(spl_ce_UnexpectedValueException, "Algorithm not supported", 0);
        goto decode_done;
    }

    /* Find the components. */
    for (body = head; body[0] != '.'; body++) {
        if (body[0] == '\0') {
            goto decode_done;
        }	
    }

    body[0] = '\0';
    body++;

    for (sig = body; sig[0] != '.'; sig++) {
        if (sig[0] == '\0') {
            goto decode_done;
        }
    }

    sig[0] = '\0';
    sig++;

    /* verify head */
    zval zv;
    zend_string *json_h = jwt_b64_url_decode(head);

    if (!json_h) {
        zend_throw_exception(spl_ce_UnexpectedValueException, "Base64 decode error", 0);
        goto decode_done;
    }

    php_json_decode_ex(&zv, ZSTR_VAL(json_h), ZSTR_LEN(json_h), PHP_JSON_OBJECT_AS_ARRAY, 512);
    zend_string_free(json_h);

    if (Z_TYPE(zv) == IS_ARRAY) {
        zval *zalg = zend_hash_str_find(Z_ARRVAL(zv), "alg", strlen("alg"));

        zval_ptr_dtor(&zv);

        if (strcmp(Z_STRVAL_P(zalg), JWT_G(algorithm))) {
            zend_throw_exception(spl_ce_UnexpectedValueException, "Algorithm not allowed", 0);
            goto decode_done;
        }
    } else {
        zend_throw_exception(spl_ce_UnexpectedValueException, "Json decode error", 0);
        goto decode_done;
    }

    /* verify */
    if (jwt->alg == JWT_ALG_NONE) {
        /* done */
    } else {
        /* set jwt struct */
        jwt->key = key;

        smart_str_appends(&buf, head);
        smart_str_appends(&buf, ".");
        smart_str_appends(&buf, body);

        jwt->str = buf.s;

        if (jwt_verify(jwt, sig)) {
            zend_throw_exception(jwt_signature_invalid_cex, "Signature verification failed", 0);
            goto decode_done;
        }
    }

    /* verify body */
    if (jwt_verify_body(body, return_value) == FAILURE) {
        goto decode_done;
    }

decode_done:
    efree(head);
    jwt_free(jwt);
    smart_str_free(&buf);
}

/* function jwt_encode() */
PHP_FUNCTION(jwt_encode)
{
    php_jwt_encode(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* function jwt_decode() */
PHP_FUNCTION(jwt_decode)
{
    php_jwt_decode(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* JWT::encode() */
PHP_METHOD(jwt, encode)
{
    php_jwt_encode(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* JWT::decode() */
PHP_METHOD(jwt, decode)
{
    php_jwt_decode(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static const zend_function_entry jwt_functions[] = {
    PHP_FE(jwt_encode, arginfo_jwt_encode)
    PHP_FE(jwt_decode, arginfo_jwt_decode)
    PHP_FE_END
};

static const zend_function_entry jwt_methods[] = {
    PHP_ME(jwt, encode, arginfo_jwt_encode, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(jwt, decode, arginfo_jwt_decode, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};

/* GINIT */
PHP_GINIT_FUNCTION(jwt) {
    jwt_globals->expiration = 0;
    jwt_globals->not_before = 0;
    jwt_globals->iss = NULL;
    jwt_globals->iat = 0;
    jwt_globals->jti = NULL;
    jwt_globals->aud = NULL;
    jwt_globals->sub = NULL;
    jwt_globals->leeway = 0;
    jwt_globals->algorithm = "HS256";
}

PHP_MINIT_FUNCTION(jwt)
{
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Cdoco\\JWT", jwt_methods);
    jwt_ce = zend_register_internal_class(&ce);

    /* register exception class */
    jwt_signature_invalid_cex = jwt_register_class("SignatureInvalidException");
    jwt_before_valid_cex = jwt_register_class("BeforeValidException");
    jwt_expired_signature_cex = jwt_register_class("ExpiredSignatureException");
    jwt_invalid_issuer_cex = jwt_register_class("InvalidIssuerException");
    jwt_invalid_aud_cex = jwt_register_class("InvalidAudException");
    jwt_invalid_jti_cex = jwt_register_class("InvalidJtiException");
    jwt_invalid_iat_cex = jwt_register_class("InvalidIatException");
    jwt_invalid_sub_cex = jwt_register_class("InvalidSubException");

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(jwt)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(jwt)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "JWT support", "enabled");
    php_info_print_table_row(2, "JWT Version", PHP_JWT_VERSION);
    php_info_print_table_row(2, "JWT Author", "ZiHang Gao <ocdoco@gmail.com>");
    php_info_print_table_row(2, "JWT Issues", "https://github.com/cdoco/php-jwt/issues");

    /* openssl version info */
    php_info_print_table_row(2, "OpenSSL Library Version", SSLeay_version(SSLEAY_VERSION));
    php_info_print_table_row(2, "OpenSSL Header Version", OPENSSL_VERSION_TEXT);

    php_info_print_table_end();
}

static const zend_module_dep jwt_deps[] = {
    ZEND_MOD_REQUIRED("json")
    ZEND_MOD_END
};

zend_module_entry jwt_module_entry = {
    STANDARD_MODULE_HEADER_EX, NULL,
    jwt_deps,
    "jwt",
    jwt_functions,
    PHP_MINIT(jwt),
    PHP_MSHUTDOWN(jwt),
    NULL,		/* Replace with NULL if there's nothing to do at request start */
    NULL,	/* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(jwt),
    PHP_JWT_VERSION,
    PHP_MODULE_GLOBALS(jwt),
    PHP_GINIT(jwt),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
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
