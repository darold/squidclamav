
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@

cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=squidclamav.la

squidclamav_la_LIBADD = @MODULES_LIBADD@
clamav_la_CFLAGS=  -I../../include/
squidclamav_la_LDFLAGS=  -module -avoid-version
squidclamav_la_SOURCES = squidclamav.c

EXTRA_DIST = squidclamav.h squidclamav.conf
