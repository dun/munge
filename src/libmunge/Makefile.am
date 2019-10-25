# MUNGE src/libmunge/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.3.in \
	munge_ctx.3.in \
	munge_enum.3.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3 \
	# End of SUBSTITUTE_FILES

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < '$(srcdir)/$@.in' > '$(builddir)/$@'

munge.3: munge.3.in
munge_ctx.3: munge_ctx.3.in
munge_enum.3: munge_enum.3.in

include_HEADERS = \
	munge.h \
	# End of include_HEADERS

lib_LTLIBRARIES = \
	libmunge.la \
	# End of lib_LTLIBRARIES

LT_CURRENT = 2
LT_REVISION = 0
LT_AGE = 0

libmunge_la_CPPFLAGS = \
	-DRUNSTATEDIR='"$(runstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-I$(top_srcdir)/src/libcommon \
	# End of libmunge_la_CPPFLAGS

libmunge_la_LDFLAGS = \
	-export-symbols-regex "^munge_.*" \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	# End of libmunge_la_LDFLAGS

libmunge_la_LIBADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	# End of libmunge_la_LIBADD

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
	munge.h \
	# End of libmunge_la_SOURCES

# For dependencies on RUNSTATEDIR via the #define for MUNGE_SOCKET_NAME.
#
$(srcdir)/libmunge_la-ctx.lo: Makefile
$(srcdir)/libmunge_la-m_msg_client.lo: Makefile

man_MANS = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3 \
	# End of man_MANS

install-data-hook: uninstall-local
	$(MKDIR_P) '$(DESTDIR)$(mandir)/man3/'
	( cd '$(DESTDIR)$(mandir)/man3/' \
	    && $(LN_S) munge.3 munge_decode.3 \
	    && $(LN_S) munge.3 munge_encode.3 \
	    && $(LN_S) munge.3 munge_strerror.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_copy.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_create.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_destroy.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_get.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_set.3 \
	    && $(LN_S) munge_ctx.3 munge_ctx_strerror.3 \
	    && $(LN_S) munge_enum.3 munge_enum_int_to_str.3 \
	    && $(LN_S) munge_enum.3 munge_enum_is_valid.3 \
	    && $(LN_S) munge_enum.3 munge_enum_str_to_int.3 )

uninstall-local:
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_copy.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_create.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_destroy.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_get.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_set.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_ctx_strerror.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_decode.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_encode.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_enum_int_to_str.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_enum_is_valid.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_enum_str_to_int.3'
	rm -f '$(DESTDIR)$(mandir)/man3/munge_strerror.3'
