# MUNGE top-level Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://github.com/dun/munge>.

include $(top_srcdir)/Make-inc.mk

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	src \
	tests \
	# End of SUBDIRS

EXTRA_DIST = \
	.gitignore \
	AUTHORS \
	COPYING \
	COPYING.LESSER \
	DISCLAIMER.LLNS \
	DISCLAIMER.UC \
	HISTORY \
	INSTALL \
	JARGON \
	KEYS \
	NEWS \
	PLATFORMS \
	QUICKSTART \
	README \
	README.AIX \
	README.MULTILIB \
	THANKS \
	bootstrap \
	build-aux/gen-date \
	build-aux/gen-version \
	build-aux/tap-driver.sh \
	doc \
	portable/inet_ntop.h \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

DISTCLEANFILES = \
	config/*~ \
	$(PACKAGE)-*.tar* \
	# End of DISTCLEANFILES

MAINTAINERCLEANFILES = \
	Makefile.in \
	aclocal.m4 \
	build-aux/compile \
	build-aux/config.guess \
	build-aux/config.sub \
	build-aux/depcomp \
	build-aux/install-sh \
	build-aux/ltmain.sh \
	build-aux/missing \
	build-aux/tap-driver.sh \
	build-aux/test-driver \
	config.h.in \
	configure \
	m4/libtool.m4 \
	m4/ltoptions.m4 \
	m4/ltsugar.m4 \
	m4/ltversion.m4 \
	m4/lt~obsolete.m4 \
	src/Makefile.in \
	src/etc/Makefile.in \
	src/libcommon/Makefile.in \
	src/libmunge/Makefile.in \
	src/munge/Makefile.in \
	src/munged/Makefile.in \
	tests/Makefile.in \
	# End of MAINTAINERCLEANFILES

TEMPLATE_FILES = \
	munge.spec.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munge.spec \
	# End of SUBSTITUTE_FILES

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < '$(srcdir)/$@.in' > '$(builddir)/$@'

munge.spec: munge.spec.in

noinst_DATA = \
	$(SUBSTITUTE_FILES) \
	# End of noinst_DATA

dist-hook: munge.spec
	$(INSTALL_DATA) munge.spec '$(distdir)/munge.spec'
	echo $(VERSION) > '$(distdir)/.dist-version'
	echo $(DATE) > '$(distdir)/.dist-date'
