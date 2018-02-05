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

include_HEADERS = \
	munge.h

lib_LTLIBRARIES = \
	libmunge.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon

libmunge_la_LDFLAGS = \
	-export-symbols-regex "^munge_.*" \
	-version-info $(META_LT_CURRENT):$(META_LT_REVISION):$(META_LT_AGE)

libmunge_la_LIBADD = \
	$(top_builddir)/src/libcommon/libcommon.la

libmunge_la_SOURCES = \
	auth_send.c \
	auth_send.h \
	ctx.c \
	ctx.h \
	decode.c \
	encode.c \
	enum.c \
	m_msg_client.c \
	m_msg_client.h \
	strerror.c \
	munge.h

man_MANS = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3

install-data-local:
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(includedir)"
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(libdir)"
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(mandir)/man3"
	for man in encode decode strerror; do \
	  ln -f -s munge.3 \
	    "$(DESTDIR)$(mandir)/man3/munge_$${man}.3"; \
	done
	for man in create copy destroy strerror get set; do \
	  ln -f -s munge_ctx.3 \
	    "$(DESTDIR)$(mandir)/man3/munge_ctx_$${man}.3"; \
	done
	for man in is_valid int_to_str str_to_int; do \
	  ln -f -s munge_enum.3 \
	    "$(DESTDIR)$(mandir)/man3/munge_enum_$${man}.3"; \
	done
	chmod 755 "$(DESTDIR)$(includedir)"
	chmod 755 "$(DESTDIR)$(libdir)"
	chmod 755 "$(DESTDIR)$(mandir)"

uninstall-local:
	for man in encode decode strerror; do \
	  rm -f "$(DESTDIR)$(mandir)/man3/munge_$${man}.3"; \
	done
	for man in create copy destroy strerror get set; do \
	  rm -f "$(DESTDIR)$(mandir)/man3/munge_ctx_$${man}.3"; \
	done
	for man in is_valid int_to_str str_to_int; do \
	  rm -f "$(DESTDIR)$(mandir)/man3/munge_enum_$${man}.3"; \
	done
