##*****************************************************************************
## $Id: Makefile.am,v 1.4 2004/10/15 16:50:50 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

install-data-local:
	@for d in $(sysconfdir)/init.d $(sysconfdir)/rc.d/init.d; do \
	  if test -d "$$d"; then \
	    echo $(INSTALL) -m 755 -d $(DESTDIR)$$d; \
	    $(INSTALL) -m 755 -d $(DESTDIR)$$d; \
	    echo $(INSTALL) -m 755 munge.init $(DESTDIR)$$d/munge; \
	    $(INSTALL) -m 755 munge.init $(DESTDIR)$$d/munge; \
	    break; \
	  fi; \
	done
