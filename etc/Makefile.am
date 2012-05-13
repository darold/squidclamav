EXTRA_DIST = squidclamav.conf
CFGINST = @CFGDIR@

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(CFGINST)
	@if test -f "$(DESTDIR)$(CFGINST)/squidclamav.conf" ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(CFGINST)/squidclamav.conf" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/squidclamav.conf $(DESTDIR)$(CFGINST)"; \
		$(INSTALL_DATA) $(srcdir)/squidclamav.conf $(DESTDIR)$(CFGINST)/squidclamav.conf; \
	fi

