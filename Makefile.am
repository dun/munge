##*****************************************************************************
## $Id: Makefile.am,v 1.2 2002/12/20 20:44:33 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

ACLOCAL_AMFLAGS =       -I config
EXTRA_DIST =            AUTHORS COPYING DISCLAIMER INSTALL NEWS README
EXTRA_DIST +=           ChangeLog munge.spec
SUBDIRS =               src

distclean-local:
	-rm -fr autom4te*.cache autoscan.*
	-find $(PACKAGE)-* -exec chmod u+w {} \;
	-rm -fr $(PACKAGE)-*
