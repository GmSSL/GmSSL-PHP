dnl config.m4 for extension gmssl

PHP_ARG_WITH([gmssl],
  [for gmssl support],
  [AS_HELP_STRING([[--with-gmssl[=DIR]]],
    [Include GmSSL support. DIR is the GmSSL installation prefix])],
  [yes])

if test "$PHP_GMSSL" != "no"; then
  AC_MSG_CHECKING([for GmSSL])

  if test "$PHP_GMSSL" != "yes"; then
    GMSSL_DIR="$PHP_GMSSL"
  elif test -n "$GMSSL_DIR"; then
    GMSSL_DIR="$GMSSL_DIR"
  else
    GMSSL_DIR=""
  fi

  if test -z "$GMSSL_DIR"; then
    PKG_CHECK_MODULES([GMSSL], [gmssl >= 3.1.0], [
      PHP_EVAL_INCLINE([$GMSSL_CFLAGS])
      PHP_EVAL_LIBLINE([$GMSSL_LIBS], [GMSSL_SHARED_LIBADD])
      gmssl_found=yes
    ], [
      gmssl_found=no
    ])
  else
    gmssl_found=no
  fi

  if test "$gmssl_found" = "no"; then
    for i in "$GMSSL_DIR" /usr/local /usr /opt/homebrew /opt/local; do
      if test -n "$i" && test -r "$i/include/gmssl/version.h"; then
        GMSSL_DIR="$i"
        gmssl_found=yes
        break
      fi
    done

    if test "$gmssl_found" = "yes"; then
      PHP_ADD_INCLUDE([$GMSSL_DIR/include])
      if test -d "$GMSSL_DIR/$PHP_LIBDIR"; then
        PHP_ADD_LIBRARY_WITH_PATH([gmssl], [$GMSSL_DIR/$PHP_LIBDIR], [GMSSL_SHARED_LIBADD])
      else
        PHP_ADD_LIBRARY_WITH_PATH([gmssl], [$GMSSL_DIR/lib], [GMSSL_SHARED_LIBADD])
      fi
      PHP_ADD_LIBRARY([m], 1, [GMSSL_SHARED_LIBADD])
    fi
  fi

  if test "$gmssl_found" != "yes"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([GmSSL >= 3.1.0 not found. Install GmSSL or pass --with-gmssl=/path/to/gmssl])
  fi

  AC_MSG_RESULT([found])

  PHP_CHECK_LIBRARY([gmssl], [gmssl_version_str], [
    AC_DEFINE([HAVE_GMSSL], [1], [Have GmSSL support])
  ], [
    AC_MSG_ERROR([GmSSL library found, but gmssl_version_str is not linkable. Check library path or runtime linker configuration.])
  ], [
    $GMSSL_SHARED_LIBADD
  ])

  PHP_SUBST([GMSSL_SHARED_LIBADD])
  PHP_NEW_EXTENSION([gmssl], [gmssl.c], [$ext_shared])
fi
