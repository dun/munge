#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_EXPAND_INSTALL_DIRS
#
#  DESCRIPTION:
#    Expand the installation directory variables.
#******************************************************************************

AC_DEFUN([X_AC_EXPAND_INSTALL_DIRS], [
  AC_MSG_CHECKING([installation directory variables])

  _x_ac_expand_install_dirs_prefix="$prefix"
  test "$prefix" = NONE && prefix="$ac_default_prefix"
  _x_ac_expand_install_dirs_exec_prefix="$exec_prefix"
  test "$exec_prefix" = NONE && exec_prefix="$prefix"

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_PREFIX], [$prefix])
  AC_DEFINE_UNQUOTED([X_PREFIX], ["$X_PREFIX"],
    [Expansion of the "prefix" installation directory.])
  AC_SUBST([X_PREFIX])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_EXEC_PREFIX], [$exec_prefix])
  AC_DEFINE_UNQUOTED([X_EXEC_PREFIX], ["$X_EXEC_PREFIX"],
    [Expansion of the "exec_prefix" installation directory.])
  AC_SUBST([X_EXEC_PREFIX])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_BINDIR], [$bindir])
  AC_DEFINE_UNQUOTED([X_BINDIR], ["$X_BINDIR"],
    [Expansion of the "bindir" installation directory.])
  AC_SUBST([X_BINDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_SBINDIR], [$sbindir])
  AC_DEFINE_UNQUOTED([X_SBINDIR], ["$X_SBINDIR"],
    [Expansion of the "sbindir" installation directory.])
  AC_SUBST([X_SBINDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_LIBEXECDIR], [$libexecdir])
  AC_DEFINE_UNQUOTED([X_LIBEXECDIR], ["$X_LIBEXECDIR"],
    [Expansion of the "libexecdir" installation directory.])
  AC_SUBST([X_LIBEXECDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_DATADIR], [$datadir])
  AC_DEFINE_UNQUOTED([X_DATADIR], ["$X_DATADIR"],
    [Expansion of the "datadir" installation directory.])
  AC_SUBST([X_DATADIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_SYSCONFDIR], [$sysconfdir])
  AC_DEFINE_UNQUOTED([X_SYSCONFDIR], ["$X_SYSCONFDIR"],
    [Expansion of the "sysconfdir" installation directory.])
  AC_SUBST([X_SYSCONFDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_SHAREDSTATEDIR], [$sharedstatedir])
  AC_DEFINE_UNQUOTED([X_SHAREDSTATEDIR], ["$X_SHAREDSTATEDIR"],
    [Expansion of the "sharedstatedir" installation directory.])
  AC_SUBST([X_SHAREDSTATEDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_LOCALSTATEDIR], [$localstatedir])
  AC_DEFINE_UNQUOTED([X_LOCALSTATEDIR], ["$X_LOCALSTATEDIR"],
    [Expansion of the "localstatedir" installation directory.])
  AC_SUBST([X_LOCALSTATEDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_LIBDIR], [$libdir])
  AC_DEFINE_UNQUOTED([X_LIBDIR], ["$X_LIBDIR"],
    [Expansion of the "libdir" installation directory.])
  AC_SUBST([X_LIBDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_INCLUDEDIR], [$includedir])
  AC_DEFINE_UNQUOTED([X_INCLUDEDIR], ["$X_INCLUDEDIR"],
    [Expansion of the "includedir" installation directory.])
  AC_SUBST([X_INCLUDEDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_OLDINCLUDEDIR], [$oldincludedir])
  AC_DEFINE_UNQUOTED([X_OLDINCLUDEDIR], ["$X_OLDINCLUDEDIR"],
    [Expansion of the "oldincludedir" installation directory.])
  AC_SUBST([X_OLDINCLUDEDIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_INFODIR], [$infodir])
  AC_DEFINE_UNQUOTED([X_INFODIR], ["$X_INFODIR"],
    [Expansion of the "infodir" installation directory.])
  AC_SUBST([X_INFODIR])

  _X_AC_EXPAND_INSTALL_DIRS_EVAL([X_MANDIR], [$mandir])
  AC_DEFINE_UNQUOTED([X_MANDIR], ["$X_MANDIR"],
    [Expansion of the "mandir" installation directory.])
  AC_SUBST([X_MANDIR])

  prefix="$_x_ac_expand_install_dirs_prefix"
  exec_prefix="$_x_ac_expand_install_dirs_exec_prefix"

  AC_MSG_RESULT([yes])
])

AC_DEFUN([_X_AC_EXPAND_INSTALL_DIRS_EVAL],
  [_eval_old="$2"
  for _eval_cnt in 1 2 3 4 5 6 7 8; do
    eval _eval_new="$_eval_old"
    test "$_eval_new" = "$_eval_old" && break
    _eval_old="$_eval_new"
  done
  $1="$_eval_old" dnl]
)
