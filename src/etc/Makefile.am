# MUNGE src/etc/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.init.in \
	munge.pc.in \
	munge.service.in \
	munge.sysconfig.in \
	munge.tmpfiles.conf.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munge.init \
	munge.pc \
	munge.service \
	munge.sysconfig \
	munge.tmpfiles.conf \
	# End of SUBSTITUTE_FILES

UNINSTALL_FILES = \
	$(sysconfdir)/rc.d/init.d/munge \
	$(sysconfdir)/init.d/munge \
	$(sysconfdir)/sysconfig/munge \
	$(sysconfdir)/default/munge \
	$(libdir)/pkgconfig/munge.pc \
	$(prefix)/lib/systemd/system/munge.service \
	$(prefix)/lib/tmpfiles.d/munge.conf \
	# End of UNINSTALL_FILES

UNINSTALL_DIRS = \
	$(sysconfdir)/munge \
	$(localstatedir)/lib/munge \
	$(localstatedir)/log/munge \
	$(localstatedir)/run/munge \
	# End of UNINSTALL_DIRS

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.init: munge.init.in
munge.pc: munge.pc.in
munge.service: munge.service.in
munge.sysconfig: munge.sysconfig.in
munge.tmpfiles.conf: munge.tmpfiles.conf.in

noinst_DATA = \
	$(SUBSTITUTE_FILES) \
	# End of noinst_DATA

install-data-hook: install-dirperms install-pkgconfig install-systemd install-sysvinit install-tmpfiles

install-dirperms:
	$(MKDIR_P) -m 0700 "$(DESTDIR)$(sysconfdir)/munge"
	$(MKDIR_P) -m 0711 "$(DESTDIR)$(localstatedir)/lib/munge"
	$(MKDIR_P) -m 0700 "$(DESTDIR)$(localstatedir)/log/munge"
	$(MKDIR_P) -m 0755 "$(DESTDIR)$(localstatedir)/run/munge"

install-pkgconfig: munge.pc
	$(MKDIR_P) "$(DESTDIR)$(libdir)/pkgconfig"
	$(INSTALL_DATA) "$(builddir)/munge.pc" \
	  "$(DESTDIR)$(libdir)/pkgconfig/$(PACKAGE).pc"

install-systemd: munge.service
	$(MKDIR_P) "$(DESTDIR)$(prefix)/lib/systemd/system"
	$(INSTALL_DATA) "$(builddir)/munge.service" \
	  "$(DESTDIR)$(prefix)/lib/systemd/system/$(PACKAGE).service"

install-sysvinit: munge.init install-sysvinit-conf
	test -d /etc/rc.d/init.d && d=rc.d/init.d || d=init.d; \
	  $(MKDIR_P) "$(DESTDIR)$(sysconfdir)/$${d}"; \
	  $(INSTALL_SCRIPT) "$(builddir)/munge.init" \
	    "$(DESTDIR)$(sysconfdir)/$${d}/$(PACKAGE)"

install-sysvinit-conf: munge.sysconfig
	test -d /etc/sysconfig && d=sysconfig || d=default; \
	  $(MKDIR_P) "$(DESTDIR)$(sysconfdir)/$${d}"; \
	  $(INSTALL_DATA) "$(builddir)/munge.sysconfig" \
	    "$(DESTDIR)$(sysconfdir)/$${d}/$(PACKAGE)"

install-tmpfiles: munge.tmpfiles.conf
	$(MKDIR_P) "$(DESTDIR)$(prefix)/lib/tmpfiles.d"
	$(INSTALL_DATA) "$(builddir)/munge.tmpfiles.conf" \
	  "$(DESTDIR)$(prefix)/lib/tmpfiles.d/$(PACKAGE).conf"

uninstall-local:
	@for p in $(UNINSTALL_FILES); do \
	  test -f "$(DESTDIR)$${p}" || continue; \
	  d=`dirname "$${p}"`; \
	  f=`basename "$${p}"`; \
	  echo " ( cd '$(DESTDIR)$${d}' && rm -f '$${f}' )"; \
	  cd "$(DESTDIR)$${d}" && rm -f "$${f}"; \
	done
	@for d in $(UNINSTALL_DIRS); do \
	  test -d "$(DESTDIR)$${d}" || continue; \
	  echo "rmdir '$${d}'"; \
	  rmdir "$(DESTDIR)$${d}" || :; \
	done
