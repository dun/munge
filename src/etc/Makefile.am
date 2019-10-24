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

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < '$(srcdir)/$@.in' > '$(builddir)/$@'

munge.init: munge.init.in
munge.pc: munge.pc.in
munge.service: munge.service.in
munge.sysconfig: munge.sysconfig.in
munge.tmpfiles.conf: munge.tmpfiles.conf.in

noinst_DATA = \
	$(SUBSTITUTE_FILES) \
	# End of noinst_DATA

install-data-hook: install-dirs install-pkgconfig install-systemd install-sysvinit

uninstall-local: uninstall-dirs uninstall-pkgconfig uninstall-systemd uninstall-sysvinit

install-dirs:
	$(MKDIR_P) -m 0700 '$(DESTDIR)$(sysconfdir)/munge'
	$(MKDIR_P) -m 0711 '$(DESTDIR)$(localstatedir)/lib/munge'
	$(MKDIR_P) -m 0700 '$(DESTDIR)$(localstatedir)/log/munge'
	$(MKDIR_P) -m 0755 '$(DESTDIR)$(runstatedir)/munge'

uninstall-dirs:
	rmdir '$(DESTDIR)$(sysconfdir)/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(localstatedir)/lib/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(localstatedir)/log/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(runstatedir)/munge' 2>/dev/null || :

install-pkgconfig: munge.pc
	@if test 'x$(pkgconfigdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(pkgconfigdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(pkgconfigdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.pc'" \
	      "'$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.pc' \
	      '$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'; \
	fi

uninstall-pkgconfig:
	@if test 'x$(pkgconfigdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'"; \
	  rm -f '$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'; \
	fi

install-systemd: munge.service
	@if test 'x$(systemdunitdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(systemdunitdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(systemdunitdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.service'" \
	      "'$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.service' \
	      '$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'; \
	fi

uninstall-systemd:
	@if test 'x$(systemdunitdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'"; \
	  rm -f '$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'; \
	fi

install-sysvinit: munge.init install-sysvinit-conf
	@if test 'x$(sysvinitddir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(sysvinitddir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(sysvinitddir)'; \
	  echo $(INSTALL_SCRIPT) "'$(builddir)/munge.init'" \
	      "'$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'"; \
	  $(INSTALL_SCRIPT) '$(builddir)/munge.init' \
	      '$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'; \
	fi

uninstall-sysvinit: uninstall-sysvinit-conf
	@if test 'x$(sysvinitddir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'; \
	fi

install-sysvinit-conf: munge.sysconfig
	@if test 'x${sysvinitddir}' != x \
	      && test 'x$(sysconfigdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(sysconfigdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(sysconfigdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.sysconfig'" \
	      "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.sysconfig' \
	      '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi

uninstall-sysvinit-conf:
	@if test 'x$(sysconfigdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi
