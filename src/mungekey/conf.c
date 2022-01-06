/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2022 Lawrence Livermore National Security, LLC.
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "conf.h"
#include "license.h"
#include "log.h"
#include "missing.h"
#include "munge_defs.h"
#include "version.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

/*  GETOPT_DEBUG_SHORT_OPTS is defined when configured with --enable-debug
 *    in order to test the case of a command-line option being unimplemented.
 */
#ifdef NDEBUG
#define GETOPT_DEBUG_SHORT_OPTS ""
#else  /* !NDEBUG */
#define GETOPT_DEBUG_SHORT_OPTS "8"
#endif /* !NDEBUG */

const char * const short_opts = ":b:cfhk:LvV" GETOPT_DEBUG_SHORT_OPTS ;

#include <getopt.h>
struct option long_opts[] = {
    { "bits",     required_argument, NULL, 'b' },
    { "create",   no_argument,       NULL, 'c' },
    { "force",    no_argument,       NULL, 'f' },
    { "help",     no_argument,       NULL, 'h' },
    { "keyfile",  required_argument, NULL, 'k' },
    { "license",  no_argument,       NULL, 'L' },
    { "verbose",  no_argument,       NULL, 'v' },
    { "version",  no_argument,       NULL, 'V' },
    {  NULL,      0,                 NULL,  0  }
};


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void _conf_parse_bits_opt (int *dstp, const char *src, int sopt,
        const char *lopt);

static void _conf_parse_keyfile_opt (char **dstp, const char *src, int sopt,
        const char *lopt);

static void _conf_display_help (const char *prog);

static const char * _conf_get_opt_string (int short_opt, const char *long_opt,
        const char *argv_str);

static int _conf_set_int (int *dstp, const char *src, long min, long max);

static int _conf_set_str (char **dstp, const char *src);

static void _conf_validate (conf_t *confp);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Create and return a new initialized conf_t.
 */
conf_t *
create_conf (void)
{
    conf_t *confp;

    confp = calloc (sizeof (struct conf), 1);
    if (confp == NULL) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                "Failed to allocate conf struct");
    }
    confp->key_path = strdup (MUNGE_KEYFILE_PATH);
    if (confp->key_path == NULL) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                "Failed to dup key_path string");
    }
    confp->key_num_bytes = MUNGE_KEY_LEN_DFL_BYTES;

    _conf_validate (confp);
    return confp;
}


/*  Destroy the conf_t [confp].
 */
void
destroy_conf (conf_t *confp)
{
    assert (confp != NULL);

    if (confp == NULL) {
        return;
    }
    if (confp->key_path != NULL) {
        free (confp->key_path);
        confp->key_path = NULL;
    }
    free (confp);
}


/*  Parse the command-line, storing the config in [confp].
 */
void
parse_cmdline (conf_t *confp, int argc, char **argv)
{
    char       *p;
    char       *prog;
    int         long_ind;
    const char *long_opt;
    int         c;

    assert (confp != NULL);
    assert (argv != NULL);

    opterr = 0;                         /* suppress default getopt err msgs */

    p = strrchr (argv[0], '/');
    prog = (p != NULL) ? p + 1 : argv[0];

    for (;;) {

        long_ind = -1;
        c = getopt_long (argc, argv, short_opts, long_opts, &long_ind);
        long_opt = (long_ind >= 0) ? long_opts[long_ind].name : NULL;

        if (c == -1) {                  /* reached end of option list */
            break;
        }
        switch (c) {
            case 'b':
                _conf_parse_bits_opt (&confp->key_num_bytes, optarg, c,
                        long_opt);
                break;
            case 'c':
                confp->do_create = 1;
                break;
            case 'f':
                confp->do_force = 1;
                break;
            case 'h':
                _conf_display_help (prog);
                exit (EXIT_SUCCESS);
                break;
            case 'k':
                _conf_parse_keyfile_opt (&confp->key_path, optarg, c,
                        long_opt);
                break;
            case 'L':
                display_license ();
                exit (EXIT_SUCCESS);
                break;
            case 'v':
                confp->do_verbose = 1;
                break;
            case 'V':
                display_version ();
                exit (EXIT_SUCCESS);
                break;
            case '?':
                /* long_opt not set */
                log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Option \"%s\" is invalid",
                        _conf_get_opt_string (optopt, NULL,
                            (optind > 1) ? argv[optind - 1] : NULL));
                break;
            case ':':
                /* long_opt not set */
                log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Option \"%s\" is missing a required argument",
                        _conf_get_opt_string (optopt, NULL,
                            (optind > 1) ? argv[optind - 1] : NULL));
                break;
            default:
                /* long_opt and optopt not set */
                log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Option \"%s\" is not implemented",
                        _conf_get_opt_string (c, NULL,
                            (optind > 1) ? argv[optind - 1] : NULL));
                break;
        }
    }
    if (optind < argc) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Option \"%s\" is unrecognized",
                (optind > 0) ? argv[optind] : "???");
    }
    /*  Default to creating a key if no operation is specified.
     */
    if (!confp->do_create) {
        confp->do_create = 1;
    }
    _conf_validate (confp);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

/*  Parse the --bits command-line option arising from short-option [sopt]
 *    or long-option [lopt].
 *  The [dstp] arg is passed by reference for storing the result of the
 *    required argument specified in the [src] string.
 */
static void
_conf_parse_bits_opt (int *dstp, const char *src, int sopt, const char *lopt)
{
    int min = MUNGE_KEY_LEN_MIN_BYTES * 8;
    int max = MUNGE_KEY_LEN_MAX_BYTES * 8;
    int n;
    int rv;

    assert (dstp != NULL);
    assert (src != NULL);

    n = 0;                              /* suppress uninitialized warning */
    rv = _conf_set_int (&n, src, min, max);
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Option \"%s\" has invalid value \"%s\" (range is %d-%d)",
                _conf_get_opt_string (sopt, lopt, NULL), src, min, max);

    }
    /*  Round-up to the next byte.
     */
    n = (n + 7) / 8;

    *dstp = n;
}


/*  Parse the --keyfile command-line option arising from short-option [sopt]
 *    or long-option [lopt].
 *  The [dstp] arg is passed by reference for storing the result of the
 *    required argument specified in the [src] string.
 */
static void
_conf_parse_keyfile_opt (char **dstp, const char *src, int sopt,
        const char *lopt)
{
    int rv;

    assert (dstp != NULL);
    assert (src != NULL);

    rv = _conf_set_str (dstp, src);
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Option \"%s\" failed to copy argument string",
                _conf_get_opt_string (sopt, lopt, NULL));
    }
}


/*  Display a help message describing the command-line options for [prog].
 */
static void
_conf_display_help (const char *prog)
{
    const int w = -25;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, "-c, --create",
            "Create keyfile");

    printf ("\n");

    printf ("  %*s %s\n", w, "-b, --bits=INT",
            "Specify number of bits in key being created");

    printf ("  %*s %s\n", w, "-f, --force",
            "Force keyfile to be overwritten if it exists");

    printf ("  %*s %s [%s]\n", w, "-k, --keyfile=PATH",
            "Specify keyfile pathname", MUNGE_KEYFILE_PATH);

    printf ("  %*s %s\n", w, "-v, --verbose",
            "Be verbose");

    printf ("\n");

    printf ("  %*s %s\n", w, "-h, --help",
            "Display this help message");

    printf ("  %*s %s\n", w, "-L, --license",
            "Display license information");

    printf ("  %*s %s\n", w, "-V, --version",
            "Display version information");

    printf ("\n");
}


/*  Convert the specified command-line option into a null-terminated string
 *    that will have a leading single-hyphen for a short-option or a leading
 *    double-hyphen for a long-option.
 *  The [short_opt] character is the integer value returned by getopt_long().
 *    The [long_opt] string is the one specified in the longopts option struct
 *    and lacks the leading double-hyphen.  The [argv_str] string is from the
 *    argv[] array.
 *  Return a ptr to a static buffer or string containing the text of the
 *    command-line option.
 */
static const char *
_conf_get_opt_string (int short_opt, const char *long_opt,
        const char *argv_str)
{
    static char buf[1024];

    if (long_opt != NULL) {
        (void) snprintf (buf, sizeof (buf), "--%s", long_opt);
        return buf;
    }
    else if ((argv_str != NULL) && (strncmp (argv_str, "--", 2) == 0)) {
        return argv_str;
    }
    else if (isprint (short_opt)) {
        (void) snprintf (buf, sizeof (buf), "-%c", short_opt);
        return buf;
    }
    log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to process command-line");
    return NULL;                        /* not reached */
}


/*  Set the int ptr [dstp] to the integer value specified by the string [src].
 *    This value must be within the [min] and [max] bounds.
 *  Return 0 on success with [dstp] set to the new int, or -1 on error
 *    with [dstp] unchanged and errno set.
 */
static int
_conf_set_int (int *dstp, const char *src, long min, long max)
{
    long  l;
    char *endp;

    if ((dstp == NULL) || (src == NULL)) {
        errno = EINVAL;
        return -1;
    }
    /*  strtol() can legitimately return 0, LONG_MIN, or LONG_MAX on both
     *    success and failure.  Consequently, set errno before the call to
     *    determine if an error actually occurred.
     */
    errno = 0;
    l = strtol (src, &endp, 10);
    if ((src == endp) || (*endp != '\0')) {
        errno = EINVAL;
        return -1;
    }
    if ((errno == ERANGE) && ((l == LONG_MIN) || (l == LONG_MAX))) {
        return -1;
    }
    if ((l < INT_MIN) || (l > INT_MAX)) {
        errno = ERANGE;
        return -1;
    }
    if ((l < min) || (l > max)) {
        errno = ERANGE;
        return -1;
    }
    if (errno != 0) {
        return -1;
    }
    *dstp = (int) l;
    return 0;
}


/*  Set the string ptr [dstp] to a newly-allocated string copied from [src].
 *    If [dstp] refers to an existing string, the old string will be freed
 *    before [dstp] is updated.
 *  Return 0 on success with [dstp] set to the new string, or -1 on error
 *    with [dstp] unchanged and errno set.
 */
static int
_conf_set_str (char **dstp, const char *src)
{
    char *p;

    if ((dstp == NULL) || (src == NULL)) {
        errno = EINVAL;
        return -1;
    }
    p = strdup (src);
    if (p == NULL) {
        return -1;
    }
    if (*dstp != NULL) {
        free (*dstp);
    }
    *dstp = p;
    return 0;
}


/*  Validate [confp] to check that everything is properly initialized
 *    and within the appropriate limits.
 */
void
_conf_validate (conf_t *confp)
{
    if (confp == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate conf: struct undefined");
    }
    if (confp->key_path == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate conf: key_path undefined");
    }
    if (confp->key_num_bytes > MUNGE_KEY_LEN_MAX_BYTES) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate conf: key_num_bytes above maximum");
    }
    if (confp->key_num_bytes < MUNGE_KEY_LEN_MIN_BYTES) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate conf: key_num_bytes below minimum");
    }
}
