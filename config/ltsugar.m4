# ltsugar.m4 -- libtool m4 base layer.                         -*-Autoconf-*-
#
# Copyright (C) 2004, 2005 Free Software Foundation, Inc.
# Written by Gary V. Vaughan.
#
# This file is free software; the Free Software Foundation gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

# serial 2

# This is to help aclocal find these macros, as it can't see m4_define.
AC_DEFUN([LTSUGAR_VERSION], [m4_if([0.1])])


# lt_join(SEP, ARG1, [ARG2...])
# -----------------------------
# Produce ARG1SEPARG2...SEPARGn, omitting [] arguments and their
# associated separator.
m4_define([lt_join],
[m4_case([$#],
	 [0], [m4_fatal([$0: too few arguments: $#])],
	 [1], [],
	 [2], [[$2]],
	 [m4_ifval([$2],
		   [m4_ifval([$3],
			     [[$2][$1][]$0([$1], m4_shiftn(2, $@))],
		       [m4_if([$#], [3],
			      [$2],
			   [$0([$1], [$2], m4_shiftn(3, $@))])])],
	      [$0([$1], m4_shiftn(2, $@))])])[]dnl
])


# lt_car(LIST)
# lt_cdr(LIST)
# ------------
# Manipulate m4 lists.
# These macros are necessary as long as will still need to support
# Autoconf-2.59 which quotes differently.
m4_define([lt_car], [[$1]])
m4_define([lt_cdr],
[m4_if([$#], 0, [m4_fatal([$0: cannot be called without arguments])],
       [$#], 1, [],
       [m4_dquote(m4_shift($@))])])


# lt_combine(SEP, PREFIX-LIST, INFIX, SUFFIX1, [SUFFIX2...])
# ----------------------------------------------------------
# Produce a SEP delimited list of all paired combinations of elements of
# PREFIX-LIST with SUFFIX1 through SUFFIXn.  Each element of the list
# has the form PREFIXmINFIXSUFFIXn.
m4_define([lt_combine],
[m4_if([$2], [], [],
       [lt_join(m4_quote(m4_default([$1], [[, ]])),
		_$0([$1], lt_car($2)[$3], m4_shiftn(3, $@)),
		$0([$1], lt_cdr($2), m4_shiftn(2, $@)))])])
m4_define([_lt_combine],
[m4_if([$3], [], [],
       [lt_join(m4_quote(m4_default([$1], [[, ]])),
		[$2$3],
		$0([$1], [$2], m4_shiftn(3, $@)))])[]dnl
])


# lt_if_append_uniq(MACRO-NAME, VARNAME, [SEPARATOR], [UNIQ], [NOT-UNIQ])
# -----------------------------------------------------------------------
# Iff MACRO-NAME does not yet contain VARNAME, then append it (delimited
# by SEPARATOR if supplied) and expand UNIQ, else NOT-UNIQ.
m4_define([lt_if_append_uniq],
[m4_ifdef([$1],
	[m4_bmatch($3[]m4_defn([$1])$3, $3[]m4_re_escape([$2])$3,
		[$5],
	    [m4_append([$1], [$2], [$3])$4])],
    [m4_append([$1], [$2], [$3])$4])])


# lt_dict_add(DICT, KEY, VALUE)
# -----------------------------
m4_define([lt_dict_add],
[m4_define([$1($2)], [$4])])


# lt_dict_add_subkey(DICT, KEY, SUBKEY, VALUE)
# --------------------------------------------
m4_define([lt_dict_add_subkey],
[m4_define([$1($2:$3)], [$4])])


# lt_dict_fetch(DICT, KEY, [SUBKEY])
# ----------------------------------
m4_define([lt_dict_fetch],
[m4_ifval([$3],
	m4_ifdef([$1($2:$3)], [m4_defn([$1($2:$3)])]),
    m4_ifdef([$1($2)], [m4_defn([$1($2)])]))])


# lt_if_dict_fetch(DICT, KEY, [SUBKEY], VALUE, IF-TRUE, [IF-FALSE])
# -----------------------------------------------------------------
m4_define([lt_if_dict_fetch],
[m4_if(lt_dict_fetch([$1], [$2], [$3]), [$4],
	[$5],
    [$6])])


# lt_dict_filter(DICT, [SUBKEY], VALUE, [SEPARATOR], KEY, [...])
# ------------------------------------------------------------
m4_define([lt_dict_filter],
[m4_if([$5], [], [],
  [lt_join(m4_quote(m4_default([$4], [[, ]])),
	   m4_quote(lt_if_dict_fetch([$1], [$5], [$2], [$3], [$5])),
	   m4_quote($0([$1], [$2], [$3], [$4], m4_shiftn(5, $@))))])dnl
])
