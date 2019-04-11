dnl $Id$
dnl config.m4 for extension jwt

PHP_ARG_ENABLE(jwt, whether to enable jwt support,
  [  --enable-jwt             Enable jwt support])

PHP_ARG_WITH(openssl, whether to use OpenSSL library,
  [  --with-openssl[=DIR]     Ignore presence of OpenSSL library (requires OpenSSL >= 1.1.0j)])

if test "$PHP_JWT" != "no"; then

  SEARCH_PATH="/usr/local /usr /usr/local/opt"
  SEARCH_FOR="/include/openssl/hmac.h"
  if test -r $PHP_OPENSSL/$SEARCH_FOR; then
    OPENSSL_DIR=$PHP_OPENSSL
  else
    AC_MSG_CHECKING([for OpenSSL library in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        OPENSSL_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  if test -z "$OPENSSL_DIR"; then
    AC_MSG_RESULT([OpenSSL library not found])
    AC_MSG_ERROR([Please reinstall the OpenSSL library])
  fi

  PHP_ADD_INCLUDE($OPENSSL_DIR/include)

  AC_CHECK_HEADERS([openssl/hmac.h openssl/evp.h])
  PHP_CHECK_LIBRARY(crypto, EVP_sha512,
  [
    PHP_ADD_INCLUDE($OPENSSL_DIR/include)
    PHP_ADD_LIBRARY_WITH_PATH(crypto, $OPENSSL_DIR/lib, JWT_SHARED_LIBADD)
  ],[
    AC_MSG_ERROR(wrong OpenSSL library version)
  ],[
    -L$OPENSSL_DIR/lib -lcrypto
  ])

  PHP_SUBST(JWT_SHARED_LIBADD)
  PHP_ADD_EXTENSION_DEP(jwt, json)
  PHP_NEW_EXTENSION(jwt, jwt.c openssl.c, $ext_shared)
fi
