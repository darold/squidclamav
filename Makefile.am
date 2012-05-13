SUBDIRS = src etc
cicapmoduledir=@MODSDIR@
DISTCLEANFILES = stamp-h stamp-h[0-9]*
EXTRA_DIST = \
	ChangeLog \
	COPYING \
	INSTALL \
	README \
	bootstrap.sh
DEFAULT_PREFIX          = $(prefix)
DEFAULT_CONFIG_FILE     = $(sysconfdir)/squidclamav.conf
DEFAULT_DOC_DIR         = $(datadir)/squidclamav
DEFAULT_LIBEXEC_DIR     = $(libexecdir)/squidclamav

DEFS = @DEFS@ -DDEFAULT_CONFIG_FILE=\"$(DEFAULT_CONFIG_FILE)\"

man1_MANS = doc/squidclamav.1
docdir = $(DEFAULT_DOC_DIR)
doc_DATA = doc/README

install-data-local: install-docDATA
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_DOC_DIR)
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_LIBEXEC_DIR)
	cp cgi-bin/* $(DESTDIR)$(DEFAULT_LIBEXEC_DIR)

