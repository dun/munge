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
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

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
	-DLOCALSTATEDIR='"$(localstatedir)"' \
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

# For dependencies on LOCALSTATEDIR via the #define for MUNGE_SOCKET_NAME.
#
$(srcdir)/libmunge_la-ctx.lo: Makefile
$(srcdir)/libmunge_la-m_msg_client.lo: Makefile

man_MANS = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3 \
	# End of man_MANS

install-data-hook:
	for man in encode decode strerror; do \
	  ( cd "$(DESTDIR)$(mandir)/man3/" && \
	    rm -f munge_$${man}.3 && \
	    $(LN_S) munge.3 munge_$${man}.3 ); \
	done
	for man in create copy destroy strerror get set; do \
	  ( cd "$(DESTDIR)$(mandir)/man3/" && \
	    rm -f munge_ctx_$${man}.3 && \
	    $(LN_S) munge_ctx.3 munge_ctx_$${man}.3 ); \
	done
	for man in is_valid int_to_str str_to_int; do \
	  ( cd "$(DESTDIR)$(mandir)/man3/" && \
	    rm -f munge_enum_$${man}.3 && \
	    $(LN_S) munge_enum.3 munge_enum_$${man}.3 ); \
	done

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
