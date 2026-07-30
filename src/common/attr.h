/******************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
 *
 *  MUNGE is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation, either version 3 of the License, or (at your option)
 *  any later version.  Additionally for the MUNGE library (libmunge), you
 *  can redistribute it and/or modify it under the terms of the GNU Lesser
 *  General Public License as published by the Free Software Foundation,
 *  either version 3 of the License, or (at your option) any later version.
 *
 *  MUNGE is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  and GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  and GNU Lesser General Public License along with MUNGE.  If not, see
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/

#ifndef MUNGE_ATTR_H
#define MUNGE_ATTR_H

/**
 *  ATTR_FORMAT(type, fmt_idx, first_idx) enables the compiler's -Wformat
 *  checking of a function's arguments against its format string, via the GNU
 *  "format" function attribute.
 *
 *  [type] is the format archetype, given in its reserved-identifier form
 *  (__printf__, __scanf__, __strftime__) so it cannot collide with a macro of
 *  the same name; see the GCC "Common Function Attributes" documentation for
 *  the full list.  [fmt_idx] is the 1-based position of the format-string
 *  parameter.  [first_idx] is the 1-based position of the first argument
 *  to check against it, or 0 when there are no such arguments to check
 *  (a strftime format, or a function that forwards a va_list).
 *
 *  Apply an annotation after the parameter list and before the semicolon of a
 *  function's declaration:
 *
 *    char * strdupf (const char *fmt, ...) ATTR_FORMAT (__printf__, 1, 2);
 *
 *  The annotation must be visible to every caller, so for a function with a
 *  public prototype it goes on the declaration in the ".h" header (the header
 *  also covers the definition's own translation unit, so it need not be
 *  repeated on the definition in the ".c" file).  For a static function with
 *  no header declaration, put it on the definition (or a forward declaration)
 *  in the ".c" file.
 *
 *  https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
 *  https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html
 */

#if defined (__GNUC__)                  /* also defined by Clang */
#define ATTR_FORMAT(type, fmt_idx, first_idx) \
        __attribute__ ((__format__ (type, fmt_idx, first_idx)))
#else
#define ATTR_FORMAT(type, fmt_idx, first_idx) /* empty */
#endif /* __GNUC__ */

#endif /* MUNGE_ATTR_H */
