##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	if test -d "$(sysconfdir)/init.d"; then \
	  $(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/init.d"; \
	  $(INSTALL) -m 755 $(srcdir)/munge.init \
	    "$(DESTDIR)$(sysconfdir)/init.d/munge"; \
	fi
	if test -d "$(sysconfdir)/sysconfig"; then \
	  $(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/sysconfig"; \
	  $(INSTALL) -m 755 $(srcdir)/munge.sysconfig \
	    "$(DESTDIR)$(sysconfdir)/sysconfig/munge"; \
	fi
