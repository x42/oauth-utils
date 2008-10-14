SUBDIRS = src

EXTRA_DIST=oauth_utils.lsm.in oauth_utils.spec.in doc/oauth_utils.texinfo

#  if you write a self-test script named `chk', uncomment the
#  following and add `chk' to the EXTRA_DIST list
#TESTS=chk

#  build and install the .info pages
info_TEXINFOS = doc/oauth_utils.texinfo
oauth_utils_TEXINFOS = doc/gpl.texinfo

#  install the man pages
man_MANS=doc/oauth_utils.1 doc/oauthsign.1

MAINTAINERCLEANFILES = \
 Makefile.in \
 aclocal.m4 \
 compile \
 config.guess \
 config.h.in \
 config.sub \
 configure \
 depcomp \
 install-sh \
 Makefile.in \
 missing

CLEANFILES = stamp-doxygen stamp-doc

