##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

include_HEADERS = \
	munge.h

lib_LTLIBRARIES = \
	libmunge.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing

libmunge_la_LDFLAGS = \
	-export-symbols-regex "^munge_.*" \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libmunge_la_LIBADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(LIBSOCKET)

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
	$(INSTALL) -d $(DESTDIR)$(mandir)/man3/
	for man in encode decode strerror; do \
	  ln -f -s munge.3 $(DESTDIR)$(mandir)/man3/munge_$$man.3; \
	done
	for man in create copy destroy strerror get set; do \
	  ln -f -s munge_ctx.3 $(DESTDIR)$(mandir)/man3/munge_ctx_$$man.3; \
	done
	for man in is_valid int_to_str str_to_int; do \
	  ln -f -s munge_enum.3 $(DESTDIR)$(mandir)/man3/munge_enum_$$man.3; \
	done
