##*****************************************************************************
## $Id: Make-inc.mk,v 1.1 2003/02/13 17:59:16 dun Exp $
##*****************************************************************************

# Dependencies to ensure libraries get rebuilt.
#
$(top_builddir)/src/libcommon/libcommon.la \
$(top_builddir)/src/libmissing/libmissing.la \
$(top_builddir)/src/libmunge/libmunge.la \
: force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check :
