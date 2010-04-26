##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
## Copyright (C) 2002-2007 The Regents of the University of California.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <http://munge.googlecode.com/>.
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

noinst_DATA = \
	munge.init

install-data-local:
	expr "`id`" : 'uid=0(' >/dev/null && OWNER="-o daemon" || OWNER=""; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(sysconfdir)/init.d"; \
	new=""; test ! -f "$(DESTDIR)$(sysconfdir)/init.d/munge" \
	  || cmp "$(srcdir)/munge.init" \
	    "$(DESTDIR)$(sysconfdir)/init.d/munge" \
	  1>/dev/null 2>&1 || new=".new"; \
	$(INSTALL) -m 0755 "$(srcdir)/munge.init" \
	  "$(DESTDIR)$(sysconfdir)/init.d/munge$${new}"; \
	test -d "/etc/sysconfig" && d="sysconfig" || d="default"; \
	new=""; test ! -f "$(DESTDIR)$(sysconfdir)/$${d}/munge" \
	  || cmp "$(srcdir)/munge.sysconfig" \
	    "$(DESTDIR)$(sysconfdir)/$${d}/munge" \
	  1>/dev/null 2>&1 || new=".new"; \
	$(INSTALL) -m 0755 -d "$(DESTDIR)$(sysconfdir)/$${d}"; \
	$(INSTALL) -m 0644 "$(srcdir)/munge.sysconfig" \
	  "$(DESTDIR)$(sysconfdir)/$${d}/munge$${new}"; \
	$(INSTALL) $${OWNER} -m 0700 -d \
	  "$(DESTDIR)$(sysconfdir)/munge"; \
	$(INSTALL) -m 0711 -d "$(DESTDIR)$(localstatedir)/lib"; \
	$(INSTALL) $${OWNER} -m 0711 -d \
	  "$(DESTDIR)$(localstatedir)/lib/munge"; \
	$(INSTALL) -m 0711 -d "$(DESTDIR)$(localstatedir)/log"; \
	$(INSTALL) $${OWNER} -m 0700 -d \
	  "$(DESTDIR)$(localstatedir)/log/munge"; \
	$(INSTALL) -m 0711 -d "$(DESTDIR)$(localstatedir)/run"; \
	$(INSTALL) $${OWNER} -m 0755 -d \
	  "$(DESTDIR)$(localstatedir)/run/munge"
	chmod 755 "$(DESTDIR)$(sysconfdir)"
	chmod 755 "$(DESTDIR)$(localstatedir)"
	chmod 755 "$(DESTDIR)$(localstatedir)/lib"
	chmod 755 "$(DESTDIR)$(localstatedir)/log"
	chmod 755 "$(DESTDIR)$(localstatedir)/run"
