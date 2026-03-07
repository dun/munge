###############################################################################
# SYNOPSIS:
#   X_AC_HUMOR
#
# DESCRIPTION:
#   Report silliness.
#
#   Keep the number of entries prime, so a constant stride in "$$" between
#   builds cannot select a short cycle.
#
#   The entries are rot13-encoded to keep them unspoiled for the casual reader.
#   tr decodes the selected entry.  Both of its sets are spelled out in full,
#   since Solaris /usr/bin/tr does not recognize a range such as "A-Z".
#   Encode a new entry with rot13 before adding it.
#
#   The list is m4-quoted to stop m4 from scanning the entries for macro
#   names.  m4 still substitutes "$" followed by a digit, "#", "*", or "@",
#   and the shell expands the rest, since the list is a double-quoted string.
#   An entry cannot contain "$", a double quote, or a backtick.  Brackets in
#   an entry must balance, since "[" and "]" are autoconf's m4 quotes.
###############################################################################

AC_DEFUN([X_AC_HUMOR], [
  AC_MSG_CHECKING([for a sense of humor])
  x_ac_humor_list="[
    n ubyybj ibvpr fnlf cyhtu
    naq abj sbe fbzrguvat pbzcyrgryl qvssrerag
    naq fb vg ortvaf
    naq gurer jnf zhpu erwbvpvat
    ner lbh cbaqrevat jung v'z cbaqrevat?
    nf lbh jvfu
    orjner bs gur yrbcneq
    ol tenogune'f unzzre
    pnershy, zna, gurer'f n orirentr urer!
    pbeerpg ubefr onggrel fgncyr
    qnatre mbar!
    qba'g cnavp
    raq bs yvar
    snfpvangvat
    seryy!
    tnzr bire, zna, tnzr bire!
    tb grnz iragher!
    tbbq arjf, rirelbar!
    unir lbh gevrq gheavat vg bss naq ba ntnva?
    uvtuyl vyybtvpny
    ubhfgba, jr unir n ceboyrz
    v nz n yrns ba gur jvaq
    v jbhyq cersre abg gb
    v'z nsenvq v pna'g qb gung
    v'z nyy bhg bs ohooyrthz
    vapbaprvinoyr
    vg tbrf gb ryrira
    vg unf prnfrq gb or
    vg'f n genc!
    vg'f ovttre ba gur vafvqr
    xynngh onenqn avxgb
    znex vg mreb!
    zvffrq vg ol gung zhpu
    zbfgyl unezyrff
    zl ibvpr vf zl cnffcbeg; irevsl zr
    anes!
    ab obbz gbqnl; obbz gbzbeebj
    abguvat unccraf
    abguvat gb frr urer
    bu ab, abg ntnva
    erfvfgnapr vf shgvyr
    frgrp nfgebabzl
    fuval!
    fdhrnzvfu bffvsentr
    gung eht ernyyl gvrq gur ebbz gbtrgure
    gurer pna or bayl bar
    gurfr nera'g gur qebvqf lbh'er ybbxvat sbe
    jung n penml enaqbz unccrafgnapr
    jung'f hc, qbp?
    jurer'f gur xnobbz?
    jbhyq lbh yvxr n wryyl onol?
    jbhyq lbh yvxr gb cynl n tnzr?
    lbh ner yvxryl gb or rngra ol n tehr
    ]"
  x_ac_humor_list=$(printf '%s\n' "${x_ac_humor_list}" | \
    sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d')
  x_ac_humor_count=$(printf '%s\n' "${x_ac_humor_list}" | wc -l | tr -d ' ')
  x_ac_humor_entry=$(printf '%s\n' "${x_ac_humor_list}" | \
    sed -n "$(($$ % x_ac_humor_count + 1))p")
  x_ac_humor=$(printf '%s\n' "${x_ac_humor_entry}" | \
    tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' \
       'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm' 2>/dev/null)
  AC_MSG_RESULT([${x_ac_humor:-whoops!}])
])
