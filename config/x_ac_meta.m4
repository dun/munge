##*****************************************************************************
## $Id: x_ac_meta.m4,v 1.5 2004/11/11 00:06:36 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_META
#
#  DESCRIPTION:
#    Set metadata tags from the META file.
##*****************************************************************************

AC_DEFUN([X_AC_META], [
  AC_MSG_CHECKING([metadata])

  _x_ac_meta_got_file=no
  if test -f "$srcdir/META"; then
    _x_ac_meta_got_file=yes

    PACKAGE="`perl -ne \
      'print,exit if s/^\s*(?:NAME|PACKAGE):\s*(\S+).*/\1/i' $srcdir/META`"
    AC_DEFINE_UNQUOTED([PACKAGE], ["$PACKAGE"],
      [Define the package name.]
    )
    AC_SUBST([PACKAGE])

    VERSION="`perl -ne \
      'print,exit if s/^\s*VERSION:\s*(\S+).*/\1/i' $srcdir/META`"
    AC_DEFINE_UNQUOTED([VERSION], ["$VERSION"],
      [Define the package version.]
    )
    AC_SUBST([VERSION])

    DATE="`perl -ne \
      'print,exit if s/^\s*DATE:\s*(\S+).*/\1/i' $srcdir/META`"
    AC_DEFINE_UNQUOTED([DATE], ["$DATE"],
      [Define the package release date.] 
    )
    AC_SUBST([DATE])

    AUTHOR="`perl -ne \
      'print,exit if s/^\s*AUTHOR:\s*(\S+).*/\1/i' $srcdir/META`"
    AC_DEFINE_UNQUOTED([AUTHOR], ["$AUTHOR"],
      [Define the package author.]
    )
    AC_SUBST([AUTHOR])
  fi

  AC_MSG_RESULT([$_x_ac_meta_got_file])
  ]
)
