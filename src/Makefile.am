
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=squidclamav.la

squidclamav_la_LIBADD = @MODULES_LIBADD@
squidclamav_la_LDFLAGS= -module -avoid-version
squidclamav_la_CFLAGS=  -I../../include/ @HAVE_TEMPLATE@
squidclamav_la_SOURCES = squidclamav.c

EXTRA_DIST = squidclamav.h
