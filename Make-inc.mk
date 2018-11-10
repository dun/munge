# MUNGE Make-inc.mk
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

# Dependencies to ensure libraries get rebuilt.
#
$(top_builddir)/src/libcommon/libcommon.la \
$(top_builddir)/src/libmissing/libmissing.la \
$(top_builddir)/src/libmunge/libmunge.la \
: force-dependency-check
	@cd `dirname $@` && $(MAKE) `basename $@`

force-dependency-check:

# Generic 'distclean' hook.
#
# The double-colon allows this target to be defined multiple times,
#   thereby allowing a Makefile.am to include its own distclean-local hook.
#
distclean-local::
	-rm -f *~ \#* .\#* cscope*.out core core.* tags TAGS

# Perform autoconf-style variable substitution on stdin.
# Fully expands autoconf variables that depend on other autoconf variables.
#
substitute = $(SED) \
	-e 's,[@]META_ALIAS[@],$(META_ALIAS),g' \
	-e 's,[@]META_AUTHOR[@],$(META_AUTHOR),g' \
	-e 's,[@]META_DATE[@],$(META_DATE),g' \
	-e 's,[@]META_NAME[@],$(META_NAME),g' \
	-e 's,[@]META_RELEASE[@],$(META_RELEASE),g' \
	-e 's,[@]META_VERSION[@],$(META_VERSION),g' \
	-e 's,[@]bindir[@],$(bindir),g' \
	-e 's,[@]datadir[@],$(datadir),g' \
	-e 's,[@]datarootdir[@],$(datarootdir),g' \
	-e 's,[@]docdir[@],$(docdir),g' \
	-e 's,[@]dvidir[@],$(dvidir),g' \
	-e 's,[@]exec_prefix[@],$(exec_prefix),g' \
	-e 's,[@]htmldir[@],$(htmldir),g' \
	-e 's,[@]includedir[@],$(includedir),g' \
	-e 's,[@]infodir[@],$(infodir),g' \
	-e 's,[@]libdir[@],$(libdir),g' \
	-e 's,[@]libexecdir[@],$(libexecdir),g' \
	-e 's,[@]localedir[@],$(localedir),g' \
	-e 's,[@]localstatedir[@],$(localstatedir),g' \
	-e 's,[@]mandir[@],$(mandir),g' \
	-e 's,[@]oldincludedir[@],$(oldincludedir),g' \
	-e 's,[@]pdfdir[@],$(pdfdir),g' \
	-e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
	-e 's,[@]pkgincludedir[@],$(pkgincludedir),g' \
	-e 's,[@]pkglibdir[@],$(pkglibdir),g' \
	-e 's,[@]pkglibexecdir[@],$(pkglibexecdir),g' \
	-e 's,[@]prefix[@],$(prefix),g' \
	-e 's,[@]psdir[@],$(psdir),g' \
	-e 's,[@]runstatedir[@],$(runstatedir),g' \
	-e 's,[@]sbindir[@],$(sbindir),g' \
	-e 's,[@]sharedstatedir[@],$(sharedstatedir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g'
