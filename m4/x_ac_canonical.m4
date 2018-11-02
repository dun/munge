#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CANONICAL
#
#  DESCRIPTION:
#    Set the canonical host system type.
#******************************************************************************

AC_DEFUN([X_AC_CANONICAL], [
  AC_CANONICAL_HOST

  AC_SUBST(host)
  AC_DEFINE_UNQUOTED([HOST], ["$host"],
    [Define the canonical host type.]
  )
  AC_SUBST(host_cpu)
  AC_DEFINE_UNQUOTED([HOST_CPU], ["$host_cpu"],
    [Define the canonical host CPU type.]
  )
  AC_SUBST(host_os)
  AC_DEFINE_UNQUOTED([HOST_OS], ["$host_os"],
    [Define the canonical host OS type.]
  )
  AC_SUBST(host_vendor)
  AC_DEFINE_UNQUOTED([HOST_VENDOR], ["$host_vendor"],
    [Define the canonical host vendor type.]
  )
  ]
)
