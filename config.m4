dnl $Id$
dnl config.m4 for extension jwt

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(jwt, for jwt support,
dnl Make sure that the comment is aligned:
dnl [  --with-jwt             Include jwt support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(jwt, whether to enable jwt support,
dnl Make sure that the comment is aligned:
dnl [  --enable-jwt           Enable jwt support])

if test "$PHP_JWT" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-jwt -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/jwt.h"  # you most likely want to change this
  dnl if test -r $PHP_JWT/$SEARCH_FOR; then # path given as parameter
  dnl   JWT_DIR=$PHP_JWT
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for jwt files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       JWT_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$JWT_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the jwt distribution])
  dnl fi

  dnl # --with-jwt -> add include path
  dnl PHP_ADD_INCLUDE($JWT_DIR/include)

  dnl # --with-jwt -> check for lib and symbol presence
  dnl LIBNAME=jwt # you may want to change this
  dnl LIBSYMBOL=jwt # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $JWT_DIR/$PHP_LIBDIR, JWT_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_JWTLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong jwt lib version or lib not found])
  dnl ],[
  dnl   -L$JWT_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(JWT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(jwt, jwt.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
