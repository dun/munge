# MUNGE src/libmunge/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.3.in \
	munge_ctx.3.in \
	munge_enum.3.in

SUBSTITUTE_FILES = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3

EXTRA_DIST = \
	$(TEMPLATE_FILES)

CLEANFILES = \
	$(SUBSTITUTE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.3: munge.3.in
munge_ctx.3: munge_ctx.3.in
munge_enum.3: munge_enum.3.in

include_HEADERS = \
	munge.h

lib_LTLIBRARIES = \
	libmunge.la

LT_CURRENT = 2
LT_REVISION = 0
LT_AGE = 0

libmunge_la_CPPFLAGS = \
	-DLOCALSTATEDIR='"$(localstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-I$(top_srcdir)/src/libcommon

libmunge_la_LDFLAGS = \
	-export-symbols-regex "^munge_.*" \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

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

# For dependencies on LOCALSTATEDIR via the #define for MUNGE_SOCKET_NAME.
#
$(srcdir)/libmunge_la-ctx.lo: Makefile
$(srcdir)/libmunge_la-m_msg_client.lo: Makefile

man_MANS = \
	munge.3 \
	munge_ctx.3 \
	munge_enum.3

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
