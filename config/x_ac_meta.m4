##*****************************************************************************
## $Id$
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

    LT_CURRENT="`perl -ne \
      'print,exit if s/^\s*LT_CURRENT:\s*(\S+).*/\1/i' $srcdir/META`"
    test -z "$LT_CURRENT" && LT_CURRENT="0"
    AC_DEFINE_UNQUOTED([LT_CURRENT], ["$LT_CURRENT"],
      [Define the libtool library 'current' version information.]
    )
    AC_SUBST([LT_CURRENT])

    LT_REVISION="`perl -ne \
      'print,exit if s/^\s*LT_REVISION:\s*(\S+).*/\1/i' $srcdir/META`"
    test -z "$LT_REVISION" && LT_REVISION="0"
    AC_DEFINE_UNQUOTED([LT_REVISION], ["$LT_REVISION"],
      [Define the libtool library 'revision' version information.]
    )
    AC_SUBST([LT_REVISION])

    LT_AGE="`perl -ne \
      'print,exit if s/^\s*LT_AGE:\s*(\S+).*/\1/i' $srcdir/META`"
    test -z "$LT_AGE" && LT_AGE="0"
    AC_DEFINE_UNQUOTED([LT_AGE], ["$LT_AGE"],
      [Define the libtool library 'age' version information.]
    )
    AC_SUBST([LT_AGE])
  fi

  AC_MSG_RESULT([$_x_ac_meta_got_file])
  ]
)
