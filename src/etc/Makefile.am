##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

noinst_DATA = \
	munge.init

install-data-local:
	expr "`id`" : 'uid=0(' >/dev/null && OWNER="-o daemon" || OWNER=""; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(sysconfdir)/init.d"; \
	test ! -f "$(DESTDIR)$(sysconfdir)/init.d/munge" \
	  || cmp $(srcdir)/munge.init "$(DESTDIR)$(sysconfdir)/init.d/munge" \
	  1>/dev/null 2>&1 || new=".new"; \
	$(INSTALL) -m 0755 $(srcdir)/munge.init \
	  "$(DESTDIR)$(sysconfdir)/init.d/munge$${new}"; \
	test -d "/etc/sysconfig" && d="sysconfig" || d="default"; \
	test ! -f "$(DESTDIR)$(sysconfdir)/$$d/munge" \
	  || cmp $(srcdir)/munge.sysconfig "$(DESTDIR)$(sysconfdir)/$$d/munge" \
	  1>/dev/null 2>&1 || new=".new"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(sysconfdir)/$$d"; \
	$(INSTALL) -m 0755 $(srcdir)/munge.sysconfig \
	  "$(DESTDIR)$(sysconfdir)/$$d/munge$${new}"; \
	$(INSTALL) $$OWNER -m 0700 -d "$(DESTDIR)$(sysconfdir)/munge"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/lib"; \
	$(INSTALL) $$OWNER -m 0711 -d "$(DESTDIR)$(localstatedir)/lib/munge"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/log"; \
	$(INSTALL) $$OWNER -m 0700 -d "$(DESTDIR)$(localstatedir)/log/munge"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/run"; \
	$(INSTALL) $$OWNER -m 0755 -d "$(DESTDIR)$(localstatedir)/run/munge"
