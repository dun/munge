# MUNGE src/libmunge/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

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
