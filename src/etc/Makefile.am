##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/init.d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.init \
	  "$(DESTDIR)$(sysconfdir)/init.d/munge"; \
	test -d "/etc/sysconfig" && d="sysconfig" || d="default"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/$$d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.sysconfig \
	  "$(DESTDIR)$(sysconfdir)/$$d/munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)$(localstatedir)/lib/munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)$(localstatedir)/run/munge"; \
	$(INSTALL) -m 700 -d "$(DESTDIR)$(sysconfdir)/munge"
