##*****************************************************************************
## $Id: Makefile.am,v 1.3 2002/12/20 21:08:03 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

ACLOCAL_AMFLAGS =       -I config
EXTRA_DIST =            AUTHORS COPYING DISCLAIMER INSTALL NEWS README
EXTRA_DIST +=           ChangeLog munge.spec
SUBDIRS =               src

include config/Make-rpm.mk

distclean-local:
	-rm -fr autom4te*.cache autoscan.*
	-find $(PACKAGE)-* -exec chmod u+w {} \;
	-rm -fr $(PACKAGE)-*
