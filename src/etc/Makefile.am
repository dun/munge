##*****************************************************************************
## $Id: Makefile.am,v 1.1 2003/04/30 17:58:59 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	if test -d /etc/rc.d/init.d; then \
	  $(INSTALL) -m 755 -d $(DESTDIR)/etc/rc.d/init.d; \
	  $(INSTALL) -m 755 munge.init $(DESTDIR)/etc/rc.d/init.d/munge; \
	fi
