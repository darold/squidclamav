
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=squidclamav.la

DEFS = @DEFS@

squidclamav_la_LIBADD = @MODULES_LIBADD@ -larchive -lz -lbz2
squidclamav_la_LDFLAGS= -module -avoid-version
squidclamav_la_CFLAGS=  -I../../include/ @HAVE_TEMPLATE@ @HAVE_HASALLDATA@ -DCONFIGDIR=\"$(CONFIGDIR)\"
squidclamav_la_SOURCES = squidclamav.c

EXTRA_DIST = squidclamav.h
