##*****************************************************************************
## $Id: Makefile.am,v 1.5 2003/04/08 18:16:10 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-rpm.mk

ACLOCAL_AMFLAGS =       -I config
EXTRA_DIST =            AUTHORS COPYING ChangeLog DISCLAIMER INSTALL JARGON \
			NEWS README munge.spec
SUBDIRS =               src

distclean-local:
	-rm -fr autom4te*.cache autoscan.*
	-find $(PACKAGE)-* -exec chmod u+w {} \;
	-rm -fr $(PACKAGE)-*
