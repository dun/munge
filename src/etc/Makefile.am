##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	$(INSTALL) -m 755 -d "$(DESTDIR)/etc/init.d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.init \
	  "$(DESTDIR)/etc/init.d/munge"; \
	test -d "/etc/sysconfig" && d="sysconfig" || d="default"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)/etc/$$d"; \
	$(INSTALL) -m 755 $(srcdir)/munge.sysconfig \
	  "$(DESTDIR)/etc/$$d/munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)/var/lib/munge"; \
	$(INSTALL) -m 755 -d "$(DESTDIR)/var/run/munge"; \
	$(INSTALL) -m 700 -d "$(DESTDIR)/etc/munge"
