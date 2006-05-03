##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	test -f "$(sysconfdir)/init.d/munge" && f="munge.new" || f="munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/init.d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.init \
	  "$(DESTDIR)$(sysconfdir)/init.d/$$f"; \
	test -d "$(sysconfdir)/sysconfig" && d="sysconfig" || d="default"; \
	test -f "$(sysconfdir)/$$d/munge" && f="munge.new" || f="munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/$$d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.sysconfig \
	  "$(DESTDIR)$(sysconfdir)/$$d/$$f"
