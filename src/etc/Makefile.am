##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
## Copyright (C) 2002-2007 The Regents of the University of California.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <https://dun.github.io/munge/>.
##
## MUNGE is free software: you can redistribute it and/or modify it under
## the terms of the GNU General Public License as published by the Free
## Software Foundation, either version 3 of the License, or (at your option)
## any later version.  Additionally for the MUNGE library (libmunge), you
## can redistribute it and/or modify it under the terms of the GNU Lesser
## General Public License as published by the Free Software Foundation,
## either version 3 of the License, or (at your option) any later version.
##
## MUNGE is distributed in the hope that it will be useful, but WITHOUT
## ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
## and GNU Lesser General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## and GNU Lesser General Public License along with MUNGE.  If not, see
## <http://www.gnu.org/licenses/>.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

TEMPLATE_FILES = \
	munge.init.in \
	munge.pc.in \
	munge.service.in \
	munge.sysconfig.in \
	munge.tmpfiles.conf.in

SUBSTITUTE_FILES = \
	munge.init \
	munge.pc \
	munge.service \
	munge.sysconfig \
	munge.tmpfiles.conf

UNINSTALL_FILES = \
	$(sysconfdir)/rc.d/init.d/munge \
	$(sysconfdir)/init.d/munge \
	$(sysconfdir)/sysconfig/munge \
	$(sysconfdir)/default/munge \
	$(libdir)/pkgconfig/munge.pc \
	$(prefix)/lib/systemd/system/munge.service \
	$(prefix)/lib/tmpfiles.d/munge.conf

UNINSTALL_DIRS = \
	$(sysconfdir)/munge \
	$(localstatedir)/lib/munge \
	$(localstatedir)/log/munge \
	$(localstatedir)/run/munge

noinst_DATA = $(SUBSTITUTE_FILES)

CLEANFILES = $(SUBSTITUTE_FILES)

EXTRA_DIST = $(TEMPLATE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(subst) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.init: munge.init.in
munge.pc: munge.pc.in
munge.service: munge.service.in
munge.sysconfig: munge.sysconfig.in
munge.tmpfiles.conf: munge.tmpfiles.conf.in

install-data-local:
	test -d "/etc/rc.d/init.d" \
	    && INITDIR="$(sysconfdir)/rc.d/init.d" \
	    || INITDIR="$(sysconfdir)/init.d"; \
	  $(INSTALL) -m 0755 -d "$(DESTDIR)$${INITDIR}"; \
	  $(INSTALL) -m 0755 \
	    "$(builddir)/munge.init" "$(DESTDIR)$${INITDIR}/munge"
	:
	test -d "/etc/sysconfig" \
	    && CONFDIR="$(sysconfdir)/sysconfig" \
	    || CONFDIR="$(sysconfdir)/default"; \
	  $(INSTALL) -m 0755 -d "$(DESTDIR)$${CONFDIR}"; \
	  $(INSTALL) -m 0644 \
	    "$(builddir)/munge.sysconfig" "$(DESTDIR)$${CONFDIR}/munge"
	:
	PKGCONFIGDIR="$(libdir)/pkgconfig"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$${PKGCONFIGDIR}"; \
	$(INSTALL) -m 0644 \
	  "$(builddir)/munge.pc" "$(DESTDIR)$${PKGCONFIGDIR}/munge.pc"
	:
	UNITDIR="$(prefix)/lib/systemd/system"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$${UNITDIR}"; \
	$(INSTALL) -m 0644 \
	  "$(builddir)/munge.service" "$(DESTDIR)$${UNITDIR}/munge.service"
	:
	TMPFILESDIR="$(prefix)/lib/tmpfiles.d"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$${TMPFILESDIR}"; \
	$(INSTALL) -m 0644 \
	  "$(builddir)/munge.tmpfiles.conf" \
	  "$(DESTDIR)$${TMPFILESDIR}/munge.conf"
	:
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(sysconfdir)"
	$(INSTALL) -m 0700 -d "$(DESTDIR)$(sysconfdir)/munge"
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)"
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/lib"
	$(INSTALL) -m 0711 -d "$(DESTDIR)$(localstatedir)/lib/munge"
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/log"
	$(INSTALL) -m 0700 -d "$(DESTDIR)$(localstatedir)/log/munge"
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/run"
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(localstatedir)/run/munge"

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
