dnl Process this file with autoconf to produce a configure script.

AC_INIT([oauth-utils], [0.3.3], [robin AT gareus DOT org])
AC_CONFIG_SRCDIR(src/oauthsign.c)

AC_CANONICAL_TARGET([])
AC_COPYRIGHT([Copyright (C) Robin Gareus 2008, 2009, 2010])

AM_INIT_AUTOMAKE(oauth-utils, $PACKAGE_VERSION)
AM_CONFIG_HEADER(src/config.h)
AC_SUBST(VERSION)
ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

dnl Checks for programs.
AC_PROG_INSTALL
#AC_PROG_CC
AM_PROG_CC_C_O

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/param.h sys/time.h time.h sys/mkdev.h sys/sysmacros.h string.h memory.h fcntl.h dirent.h sys/ndir.h ndir.h alloca.h locale.h )

#jm_CHECK_TYPE_STRUCT_UTIMBUF
AC_HEADER_MAJOR
AC_FUNC_ALLOCA
AC_STRUCT_TM
AC_STRUCT_ST_BLOCKS
AC_FUNC_CLOSEDIR_VOID
AC_CHECK_FUNCS(mkfifo)
AC_CHECK_FUNC(mknod)

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.

PKG_CHECK_MODULES(OAUTH, oauth, HAVE_OAUTH=yes,
        HAVE_OAUTH=no
	AC_MSG_WARN([
	Could not find liboauth. please update PKG_CONFIG_PATH to 
	point the path where liboauth installed it's .pc files.
	])) 
AC_SUBST(OAUTH_LIBS)

AC_OUTPUT(Makefile src/Makefile oauth-utils.lsm oauth-utils.spec)
