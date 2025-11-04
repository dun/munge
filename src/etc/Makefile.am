# MUNGE src/etc/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://github.com/dun/munge>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.logrotate.conf.in \
	munge.pkgconfig.pc.in \
	munge.systemd.service.in \
	munge.systemd.sysconfig.in \
	munge.systemd.sysusers.conf.in \
	munge.sysvinit.init.in \
	munge.sysvinit.sysconfig.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munge.logrotate.conf \
	munge.pkgconfig.pc \
	munge.systemd.service \
	munge.systemd.sysconfig \
	munge.systemd.sysusers.conf \
	munge.sysvinit.init \
	munge.sysvinit.sysconfig \
	# End of SUBSTITUTE_FILES

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < '$(srcdir)/$@.in' > '$(builddir)/$@'

munge.logrotate.conf: munge.logrotate.conf.in
munge.pkgconfig.pc: munge.pkgconfig.pc.in
munge.systemd.service: munge.systemd.service.in
munge.systemd.sysconfig: munge.systemd.sysconfig.in
munge.systemd.sysusers.conf: munge.systemd.sysusers.conf.in
munge.sysvinit.init: munge.sysvinit.init.in
munge.sysvinit.sysconfig: munge.sysvinit.sysconfig.in

noinst_DATA = \
	$(SUBSTITUTE_FILES) \
	# End of noinst_DATA

install-data-hook: install-dirs install-logrotate install-pkgconfig install-systemd install-sysvinit

uninstall-local: uninstall-dirs uninstall-logrotate uninstall-pkgconfig uninstall-systemd uninstall-sysvinit

install-dirs:
	$(MKDIR_P) -m 0700 '$(DESTDIR)$(sysconfdir)/munge'
	$(MKDIR_P) -m 0711 '$(DESTDIR)$(localstatedir)/lib/munge'
	$(MKDIR_P) -m 0700 '$(DESTDIR)$(localstatedir)/log/munge'

uninstall-dirs:
	rmdir '$(DESTDIR)$(sysconfdir)/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(localstatedir)/lib/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(localstatedir)/log/munge' 2>/dev/null || :
	rmdir '$(DESTDIR)$(runstatedir)/munge' 2>/dev/null || :

install-logrotate: munge.logrotate.conf
	@if test 'x$(logrotateddir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(logrotateddir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(logrotateddir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.logrotate.conf'" \
	      "'$(DESTDIR)$(logrotateddir)/$(PACKAGE)'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.logrotate.conf' \
	      '$(DESTDIR)$(logrotateddir)/$(PACKAGE)'; \
	fi

uninstall-logrotate:
	@if test 'x$(logrotateddir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(logrotateddir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(logrotateddir)/$(PACKAGE)'; \
	fi

install-pkgconfig: munge.pkgconfig.pc
	@if test 'x$(pkgconfigdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(pkgconfigdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(pkgconfigdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.pkgconfig.pc'" \
	      "'$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.pkgconfig.pc' \
	      '$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'; \
	fi

uninstall-pkgconfig:
	@if test 'x$(pkgconfigdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'"; \
	  rm -f '$(DESTDIR)$(pkgconfigdir)/$(PACKAGE).pc'; \
	fi

install-systemd: munge.systemd.service install-systemd-sysconfig install-systemd-sysusers
	@if test 'x$(systemdunitdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(systemdunitdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(systemdunitdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.systemd.service'" \
	      "'$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.systemd.service' \
	      '$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'; \
	else \
	  echo $(MKDIR_P) -m 0755 "'$(DESTDIR)$(runstatedir)/munge'"; \
	  $(MKDIR_P) -m 0755 '$(DESTDIR)$(runstatedir)/munge'; \
	fi

uninstall-systemd: uninstall-systemd-sysconfig uninstall-systemd-sysusers
	@if test 'x$(systemdunitdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'"; \
	  rm -f '$(DESTDIR)$(systemdunitdir)/$(PACKAGE).service'; \
	fi

install-systemd-sysconfig: munge.systemd.sysconfig
	@if test 'x$(systemdunitdir)' != x \
	      && test 'x$(sysconfigdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(sysconfigdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(sysconfigdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.systemd.sysconfig'" \
	      "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.systemd.sysconfig' \
	      '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi

uninstall-systemd-sysconfig:
	@if test 'x$(systemdunitdir)' != x \
	      && test 'x$(sysconfigdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi

install-systemd-sysusers:
	@if test 'x$(systemdsysusersdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(systemdsysusersdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(systemdsysusersdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.systemd.sysusers.conf'" \
	      "'$(DESTDIR)$(systemdsysusersdir)/$(PACKAGE).conf'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.systemd.sysusers.conf' \
	      '$(DESTDIR)$(systemdsysusersdir)/$(PACKAGE).conf'; \
	fi

uninstall-systemd-sysusers:
	@if test 'x$(systemdsysusersdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(systemdsysusersdir)/$(PACKAGE).conf'"; \
	  rm -f '$(DESTDIR)$(systemdsysusersdir)/$(PACKAGE).conf'; \
	fi

install-sysvinit: munge.sysvinit.init install-sysvinit-sysconfig
	@if test 'x$(sysvinitddir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(sysvinitddir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(sysvinitddir)'; \
	  echo $(INSTALL_SCRIPT) "'$(builddir)/munge.sysvinit.init'" \
	      "'$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'"; \
	  $(INSTALL_SCRIPT) '$(builddir)/munge.sysvinit.init' \
	      '$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'; \
	fi

uninstall-sysvinit: uninstall-sysvinit-sysconfig
	@if test 'x$(sysvinitddir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(sysvinitddir)/$(PACKAGE)'; \
	fi

install-sysvinit-sysconfig: munge.sysvinit.sysconfig
	@if test 'x$(sysvinitddir)' != x \
	      && test 'x$(sysconfigdir)' != x; then \
	  echo $(MKDIR_P) "'$(DESTDIR)$(sysconfigdir)'"; \
	  $(MKDIR_P) '$(DESTDIR)$(sysconfigdir)'; \
	  echo $(INSTALL_DATA) "'$(builddir)/munge.sysvinit.sysconfig'" \
	      "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  $(INSTALL_DATA) '$(builddir)/munge.sysvinit.sysconfig' \
	      '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi

uninstall-sysvinit-sysconfig:
	@if test 'x$(sysvinitddir)' != x \
	      && test 'x$(sysconfigdir)' != x; then \
	  echo rm -f "'$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'"; \
	  rm -f '$(DESTDIR)$(sysconfigdir)/$(PACKAGE)'; \
	fi
