dnl $Id$
dnl config.m4 for extension jwt

PHP_ARG_ENABLE(jwt, whether to enable jwt support,
  [  --enable-jwt             Enable jwt support])

PHP_ARG_WITH(openssl, whether to use OpenSSL library,
  [  --with-openssl[=DIR]     Ignore presence of OpenSSL library (requires OpenSSL >= 0.9.8)], no, no)

if test "$PHP_OPENSSL" != "no"; then
  AC_CHECK_HEADERS([openssl/hmac.h openssl/evp.h])
  PHP_CHECK_LIBRARY(crypto, EVP_sha512,
    [
      PHP_ADD_INCLUDE($PHP_OPENSSL/include)
      PHP_ADD_LIBRARY_WITH_PATH(crypto, $PHP_OPENSSL/lib, JWT_SHARED_LIBADD)
    ],
    [AC_MSG_ERROR(OpenSSL library not found)])
else
  for i in /usr/local /usr/local/opt /usr; do
    if test -f $i/openssl/include/openssl/hmac.h; then
      OPENSSL_LIB=$i/openssl/lib
      OPENSSL_INC=$i/openssl/include
    fi
  done

  if test -z "$OPENSSL_INC"; then
    AC_MSG_ERROR(OpenSSL library not found)
  fi

  PHP_ADD_INCLUDE($OPENSSL_INC)
  PHP_ADD_LIBRARY_WITH_PATH(crypto, $OPENSSL_LIB, JWT_SHARED_LIBADD)
fi

if test "$PHP_JWT" != "no"; then
  PHP_SUBST(JWT_SHARED_LIBADD)
  PHP_NEW_EXTENSION(jwt, jwt.c openssl.c, $ext_shared)
fi
