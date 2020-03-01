/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2020 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://dun.github.io/munge/>.
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
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "path.h"
#include "tap.h"


/*  Relative path tests presume CWD is /tmp.
 */
#define CHDIR_PATH "/tmp"


typedef struct {
    const char *src;
    const char *dst;
} path_test_t;

path_test_t path_test[] = {
    { ".",      "/tmp"     },
    { "..",     "/"        },
    { "...",    "/tmp/..." },
    { "foo",    "/tmp/foo" },
    { "./.",    "/tmp"     },
    { "./..",   "/"        },
    { "./...",  "/tmp/..." },
    { "./foo",  "/tmp/foo" },
    { "../.",   "/"        },
    { "../..",  "/"        },
    { "../...", "/..."     },
    { "../foo", "/foo"     },
    { "/.",     "/"        },
    { "/..",    "/"        },
    { "/...",   "/..."     },
    { "/foo",   "/foo"     },
    { "/",      "/"        },
    { "//",     "/"        },
    { "//foo",  "/foo"     }
};


int
main (int argc, char *argv[])
{
    char src [PATH_MAX];
    char dst [PATH_MAX];
    int  n;
    int  i;
    int  rv;

    rv = chdir (CHDIR_PATH);
    if (rv == -1) {
        fprintf (stderr, "%s: Failed to chdir to \"%s\": %s\n",
                argv[0], CHDIR_PATH, strerror (errno));
        exit (EXIT_FAILURE);
    }
    plan (NO_PLAN);

    /*  Test input parms.
     */
    rv = path_canonicalize (NULL, dst, sizeof (dst));
    ok (rv == -1 && errno == EINVAL, "null src error");

    rv = path_canonicalize ("x", NULL, sizeof (dst));
    ok (rv == -1 && errno == EINVAL, "null dst error");

    rv = path_canonicalize ("x", dst, PATH_MAX - 1);
    ok (rv == -1 && errno == EINVAL, "dst buffer size error");

    /*  Test empty src string.
     */
    rv = path_canonicalize ("", dst, sizeof (dst));
    ok (rv == -1 && errno == ENOENT, "src empty string error");

    /*  Test boundary condition for maximum dst buffer.
     *  Create maximum filename for "/tmp/" dir prefix and terminating null.
     *  Check a path that exceeds the given buffer by 1 byte, and then step
     *    back a byte to test a path that completely fills the buffer.
     */
    assert (sizeof (src) >= 6);
    memset (src, 'x', sizeof (src));
    src[sizeof (src) - 5] = '\0';
    assert (strlen (src) == sizeof (src) - 5);
    rv = path_canonicalize (src, dst, sizeof (dst));
    ok (rv == -1 && errno == ENAMETOOLONG,
            "max dst buffer plus 1 boundary error");

    src[sizeof (src) - 6] = '\0';
    assert (strlen (src) == sizeof (src) - 6);
    rv = path_canonicalize (src, dst, sizeof (dst));
    ok (rv == 0, "max dst buffer boundary");

    /*  Test expected output.
     */
    n = sizeof (path_test) / sizeof (path_test[0]);
    for (i = 0; i < n; i++) {
        rv = path_canonicalize (path_test[i].src, dst, sizeof (dst));
        if (rv < 0) {
            fail ("output for \"%s\" (e=%d: %s)", path_test[i].src,
                    errno, strerror (errno));
        }
        else {
            is (dst, path_test[i].dst, "output for \"%s\"", path_test[i].src);
        }
    }
    done_testing ();

    exit (EXIT_SUCCESS);
}
