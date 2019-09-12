###############################################################################
#  SYNOPSIS:
#    X_AC_HUMOR
#
#  DESCRIPTION:
#    Check for random silliness.
###############################################################################

AC_DEFUN([X_AC_HUMOR], [
  AC_MSG_CHECKING([for a sense of humor])
  [n=$(expr $$ % 16)]
  AS_IF(
    [test "${n}" -eq  0], [x_ac_humor="no"],
    [test "${n}" -eq  1], [x_ac_humor="yes"],
    [test "${n}" -eq  2], [x_ac_humor="meh"],
    [test "${n}" -eq  3], [x_ac_humor="narf"],
    [test "${n}" -eq  4], [x_ac_humor="try again"],
    [test "${n}" -eq  5], [x_ac_humor="that tickles"],
    [test "${n}" -eq  6], [x_ac_humor="inconceivable"],
    [test "${n}" -eq  7], [x_ac_humor="good news, everyone"],
    [test "${n}" -eq  8], [x_ac_humor="where's the kaboom?"],
    [test "${n}" -eq  9], [x_ac_humor="missed it by that much"],
    [test "${n}" -eq 10], [x_ac_humor="roll for ability check"],
    [test "${n}" -eq 11], [x_ac_humor="it goes to eleven"],
    [test "${n}" -eq 12], [x_ac_humor="a hollow voice says 'PLUGH'"],
    [test "${n}" -eq 13], [x_ac_humor="no boom today... boom tomorrow"],
    [test "${n}" -eq 14], [x_ac_humor="and now for something completely different"],
    [x_ac_humor="don't panic"])
  AC_MSG_RESULT([$x_ac_humor])
])
