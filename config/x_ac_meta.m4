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

  META="$srcdir/META"
  _x_ac_meta_got_file=no
  if test -f "$META"; then
    _x_ac_meta_got_file=yes

    META_NAME="`perl -ne \
      'print,exit if s/^\s*(?:NAME|PROJECT|PACKAGE):\s*(\S+).*/\1/i' $META`"
    if test -n "$META_NAME"; then
      AC_DEFINE_UNQUOTED([META_NAME], ["$META_NAME"],
        [Define the project name.]
      )
      AC_SUBST([META_NAME])
    fi

    META_VERSION="`perl -ne \
      'print,exit if s/^\s*VERSION:\s*(\S+).*/\1/i' $META`"
    if test -n "$META_VERSION"; then
      AC_DEFINE_UNQUOTED([META_VERSION], ["$META_VERSION"],
        [Define the project version.]
      )
      AC_SUBST([META_VERSION])
    fi

    META_RELEASE="`perl -ne \
      'print,exit if s/^\s*RELEASE:\s*(\S+).*/\1/i' $META`"
    if test -n "$META_RELEASE"; then
      AC_DEFINE_UNQUOTED([META_RELEASE], ["$META_RELEASE"],
        [Define the project release.]
      )
      AC_SUBST([META_RELEASE])
    fi

    if test -n "$META_NAME" -a -n "$META_VERSION"; then
        META_ALIAS="$META_NAME-$META_VERSION"
        test -n "$META_RELEASE" && META_ALIAS="$META_ALIAS-$META_RELEASE"
        AC_DEFINE_UNQUOTED([META_ALIAS], ["$META_ALIAS"],
          [Define the project alias string (name-version-release).]
        )
        AC_SUBST([META_ALIAS])
    fi

    META_DATE="`perl -ne \
      'print,exit if s/^\s*DATE:\s*(\S+).*/\1/i' $META`"
    if test -n "$META_DATE"; then
      AC_DEFINE_UNQUOTED([META_DATE], ["$META_DATE"],
        [Define the project release date.] 
      )
      AC_SUBST([META_DATE])
    fi

    META_AUTHOR="`perl -ne \
      'print,exit if s/^\s*AUTHOR:\s*(\S+).*/\1/i' $META`"
    if test -n "$META_AUTHOR"; then
      AC_DEFINE_UNQUOTED([META_AUTHOR], ["$META_AUTHOR"],
        [Define the project author.]
      )
      AC_SUBST([META_AUTHOR])
    fi

    META_LT_CURRENT="`perl -ne \
      'print,exit if s/^\s*LT_CURRENT:\s*(\S+).*/\1/i' $META`"
    META_LT_REVISION="`perl -ne \
      'print,exit if s/^\s*LT_REVISION:\s*(\S+).*/\1/i' $META`"
    META_LT_AGE="`perl -ne \
      'print,exit if s/^\s*LT_AGE:\s*(\S+).*/\1/i' $META`"
    if test -n "$META_LT_CURRENT" \
         -o -n "$META_LT_REVISION" \
         -o -n "$META_LT_AGE"; then
      test -n "$META_LT_CURRENT" || META_LT_CURRENT="0"
      test -n "$META_LT_REVISION" || META_LT_REVISION="0"
      test -n "$META_LT_AGE" || META_LT_AGE="0"
      AC_DEFINE_UNQUOTED([META_LT_CURRENT], ["$META_LT_CURRENT"],
        [Define the libtool library 'current' version information.]
      )
      AC_DEFINE_UNQUOTED([META_LT_REVISION], ["$META_LT_REVISION"],
        [Define the libtool library 'revision' version information.]
      )
      AC_DEFINE_UNQUOTED([META_LT_AGE], ["$META_LT_AGE"],
        [Define the libtool library 'age' version information.]
      )
      AC_SUBST([META_LT_CURRENT])
      AC_SUBST([META_LT_REVISION])
      AC_SUBST([META_LT_AGE])
    fi
  fi

  AC_MSG_RESULT([$_x_ac_meta_got_file])
  ]
)
