/*****************************************************************************
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


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>


/*****************************************************************************
 *  Get an integer value from an environment variable.
 *
 *  This function is only available in debug builds for use by the test suite.
 *  In production builds (NDEBUG defined), it always fails with ENOSYS.
 *
 *  Args:
 *    name:    Environment variable name to read
 *    dst_val: Pointer to store the parsed integer value
 *
 *  Returns:
 *     0 on success with *dst_val set to the parsed integer
 *    -1 on error with errno set to:
 *       ENOSYS: Function not available (production build)
 *       EINVAL: NULL parameter or value cannot be parsed as int
 *       ENOENT: Environment variable not set
 *
 *  Notes:
 *  - Value must fit within int range [INT_MIN, INT_MAX]
 *  - Accepts decimal, octal (0-prefix), and hex (0x-prefix) integers
 *  - Entire environment variable value must be consumed (no trailing chars)
 *****************************************************************************/
int
test_get_env_int (const char *name, int *dst_val)
{
#ifdef NDEBUG
    errno = ENOSYS;
    return -1;

#else  /* !NDEBUG */
    const char *env;
    char *end;
    long val;

    if (!name || !dst_val) {
        errno = EINVAL;
        return -1;
    }
    env = getenv (name);
    if (!env) {
        errno = ENOENT;
        return -1;
    }
    val = strtol (env, &end, 0);
    if (*end != '\0' || val < INT_MIN || val > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    *dst_val = (int) val;
    return 0;
#endif /* !NDEBUG */
}
