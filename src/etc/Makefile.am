##*****************************************************************************
## $Id: Makefile.am,v 1.2 2003/10/28 22:16:21 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	@for d in /etc/rc.d/init.d /etc/init.d; do \
	  if test -d "$$d"; then \
	    echo $(INSTALL) -m 755 -d $(DESTDIR)$$d; \
	    $(INSTALL) -m 755 -d $(DESTDIR)$$d; \
	    echo $(INSTALL) -m 755 munge.init $(DESTDIR)$$d/munge; \
	    $(INSTALL) -m 755 munge.init $(DESTDIR)$$d/munge; \
	    break; \
	  fi; \
	done
