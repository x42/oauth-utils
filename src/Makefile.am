bin_PROGRAMS=oauthsign oauthverify
COMMON_SOURCES=\
	oauth_common.c oauth_common.h keyfile.c \
	xmalloc.c xmalloc.h getopt.c getopt1.c getopt.h system.h

oauthsign_SOURCES=oauthsign.c ${COMMON_SOURCES}
oauthsign_CFLAGS=
oauthsign_LDADD=@OAUTH_LIBS@

oauthverify_SOURCES=oauthverify.c ${COMMON_SOURCES}
oauthverify_CFLAGS=
oauthverify_LDADD=@OAUTH_LIBS@
