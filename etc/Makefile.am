
CONFS = squidclamav.conf
cicapdatadir=@DATADIR@
CONFIGDIR = @CONFDIR@
CFGINST = @CFGDIR@

TMPLS = templates/en/MALWARE_FOUND

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(CFGINST)
	for f in $(CONFS); do \
		$(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f.default; \
		if test ! -f $(DESTDIR)$(CONFIGDIR)/$$f; then $(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f; fi \
	done
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/squidclamav/en/
	for f in $(TMPLS); do $(INSTALL) $$f $(DESTDIR)$(cicapdatadir)/templates/squidclamav/en/; done

EXTRA_DIST = squidclamav.conf $(TMPLS)

