#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_META
#
#  DESCRIPTION:
#    Read metadata from the META file.
#
#    The META file format is as follows:
#      ^[ ]*KEY:[ \t]+VALUE$
#
#    In other words:
#    - KEY is separated from VALUE by a colon and one or more spaces/tabs.
#    - KEY and VALUE are case sensitive.
#    - Leading spaces are ignored.
#    - First match wins for duplicate keys.
#
#    A line can be commented out by preceding it with a '#' (or technically any
#    non-space character since that will prevent the regex from matching).
#
#  WARNING:
#    Placing a colon followed by a space or tab (ie, ":[ \t]+") within the
#    VALUE will prematurely terminate the string since that sequence is
#    used as the awk field separator.
#
#  KEYS:
#    The following META keys are recognized:
#      Name, Version, Release, Date, Author, LT_Current, LT_Revision, LT_Age
#******************************************************************************

AC_DEFUN([X_AC_META], [
  AC_PROG_AWK
  AC_MSG_CHECKING([metadata])

  META="$srcdir/META"
  _x_ac_meta_got_file=no
  if test -f "$META"; then
    _x_ac_meta_got_file=yes

    META_NAME=_X_AC_META_GETVAL([(Name|Project|Package)]);
    if test -n "$META_NAME"; then
      PACKAGE="$META_NAME"
      AC_SUBST([PACKAGE])
      AC_DEFINE_UNQUOTED([META_NAME], ["$META_NAME"],
        [Define the project name.]
      )
      AC_SUBST([META_NAME])
    fi

    META_VERSION=_X_AC_META_GETVAL([Version]);
    if test -n "$META_VERSION"; then
      VERSION="$META_VERSION"
      AC_SUBST([VERSION])
      AC_DEFINE_UNQUOTED([META_VERSION], ["$META_VERSION"],
        [Define the project version.]
      )
      AC_SUBST([META_VERSION])
    fi

    META_RELEASE=_X_AC_META_GETVAL([Release]);
    if test -n "$META_RELEASE"; then
      AC_DEFINE_UNQUOTED([META_RELEASE], ["$META_RELEASE"],
        [Define the project release.]
      )
      AC_SUBST([META_RELEASE])
    fi

    if test -n "$META_NAME" -a -n "$META_VERSION"; then
        META_ALIAS="$META_NAME-$META_VERSION"
        test -n "$META_RELEASE" -a "$META_RELEASE" != "1" \
          && META_ALIAS="$META_ALIAS-$META_RELEASE"
        AC_DEFINE_UNQUOTED([META_ALIAS], ["$META_ALIAS"],
          [Define the project alias string (name-ver or name-ver-rel).]
        )
        AC_SUBST([META_ALIAS])
    fi

    META_DATE=_X_AC_META_GETVAL([Date]);
    if test -n "$META_DATE"; then
      AC_DEFINE_UNQUOTED([META_DATE], ["$META_DATE"],
        [Define the project release date.]
      )
      AC_SUBST([META_DATE])
    fi

    META_AUTHOR=_X_AC_META_GETVAL([Author]);
    if test -n "$META_AUTHOR"; then
      AC_DEFINE_UNQUOTED([META_AUTHOR], ["$META_AUTHOR"],
        [Define the project author.]
      )
      AC_SUBST([META_AUTHOR])
    fi

    m4_pattern_allow([^LT_(CURRENT|REVISION|AGE)$])
    META_LT_CURRENT=_X_AC_META_GETVAL([LT_Current]);
    META_LT_REVISION=_X_AC_META_GETVAL([LT_Revision]);
    META_LT_AGE=_X_AC_META_GETVAL([LT_Age]);
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

# _X_AC_META_GETVAL (KEY_NAME_OR_REGEX)
#
# Returns the META VALUE associated with the given KEY_NAME_OR_REGEX expr.
#
# Despite their resemblance to line noise,
#   the "@<:@" and "@:>@" constructs are quadrigraphs for "[" and "]".
#   <https://www.gnu.org/software/autoconf/manual/autoconf.html#Quadrigraphs>
#
# The "$[]1" and "$[]2" constructs prevent M4 parameter expansion
#   so a literal $1 and $2 will be passed to the resulting awk script,
#   whereas the "$1" will undergo M4 parameter expansion for the META key.
#   <https://www.gnu.org/software/autoconf/manual/autoconf.html#Quoting-and-Parameters>
#
AC_DEFUN([_X_AC_META_GETVAL],
   [`$AWK -F ':@<:@ \t@:>@+' '$[]1 ~ /^ *$1$/ { print $[]2; exit }' $META`]dnl
)
