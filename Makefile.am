##*****************************************************************************
## $Id: Makefile.am,v 1.1 2002/12/20 20:30:57 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************
## Copyright (C) 2002-2003 The Regents of the University of California.
## Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## UCRL-CODE-2003-???.
## 
## This file is part of Munge, an authentication library.
## For details, see <http://www.llnl.gov/linux/munge/>.
## 
## Munge is free software; you can redistribute it and/or modify it under
## the terms of the GNU General Public License as published by the Free
## Software Foundation; either version 2 of the License, or (at your option)
## any later version.
## 
## Munge is distributed in the hope that it will be useful, but WITHOUT ANY
## WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
## FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
## details.
## 
## You should have received a copy of the GNU General Public License along
## with Munge; if not, write to the Free Software Foundation, Inc.,
## 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
##*****************************************************************************

ACLOCAL_AMFLAGS =       -I config
EXTRA_DIST =            AUTHORS COPYING DISCLAIMER INSTALL NEWS README
EXTRA_DIST +=           ChangeLog munge.spec
SUBDIRS =               src

distclean-local:
	-rm -fr autom4te*.cache autoscan.*
	-find $(PACKAGE)-* -exec chmod u+w {} \;
	-rm -fr $(PACKAGE)-*
