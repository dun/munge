##*****************************************************************************
## $Id: Makefile.am,v 1.6 2003/04/30 18:44:14 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-rpm.mk
include $(top_srcdir)/config/Make-inc.mk

ACLOCAL_AMFLAGS =       -I config
EXTRA_DIST =            AUTHORS COPYING ChangeLog DISCLAIMER INSTALL JARGON \
			NEWS README munge.spec
SUBDIRS =               src

distclean-local::
	-rm -fr autom4te*.cache autoscan.*
	-rm -fr $(PACKAGE)-*
