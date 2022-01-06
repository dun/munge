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
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before in.h for bsd       */
#include <netinet/in.h>                 /* include before inet.h for bsd     */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>                      /* for gethostbyaddr()               */
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>                 /* for AF_INET                       */
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "license.h"
#include "log.h"
#include "missing.h"                    /* for inet_ntop()                   */
#include "read.h"
#include "version.h"
#include "xsignal.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAX_TIME_STR 64


/*****************************************************************************
 *  Typedefs
 *****************************************************************************/

typedef struct conf * conf_t;

typedef void display_func_t (conf_t);

typedef struct {
    int             val;
    char           *str;
    display_func_t *fp;
} display_key_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);
void destroy_conf (conf_t conf);
void parse_cmdline (conf_t conf, int argc, char **argv);
void display_help (char *prog);
void parse_keys (conf_t conf, char *keys);
void display_keys (void);
void open_files (conf_t conf);
void display_meta (conf_t conf);
void display_status (conf_t conf);
void display_encode_host (conf_t conf);
void display_encode_time (conf_t conf);
void display_decode_time (conf_t conf);
void display_time (conf_t conf, int munge_key);
void display_ttl (conf_t conf);
void display_cipher_type (conf_t conf);
void display_mac_type (conf_t conf);
void display_zip_type (conf_t conf);
void display_uid (conf_t conf);
void display_gid (conf_t conf);
void display_uid_restriction (conf_t conf);
void display_gid_restriction (conf_t conf);
void display_length (conf_t conf);
void display_data (conf_t conf);
int key_str_to_val (const char *str);
const char * key_val_to_str (int val);


/*****************************************************************************
 *  MUNGE Keys
 *****************************************************************************/

typedef enum {
    MUNGE_KEY_STATUS,
    MUNGE_KEY_ENCODE_HOST,
    MUNGE_KEY_ENCODE_TIME,
    MUNGE_KEY_DECODE_TIME,
    MUNGE_KEY_TTL,
    MUNGE_KEY_CIPHER_TYPE,
    MUNGE_KEY_MAC_TYPE,
    MUNGE_KEY_ZIP_TYPE,
    MUNGE_KEY_UID,
    MUNGE_KEY_GID,
    MUNGE_KEY_UID_RESTRICTION,
    MUNGE_KEY_GID_RESTRICTION,
    MUNGE_KEY_LENGTH,
    MUNGE_KEY_LAST
} munge_key_t;

display_key_t munge_keys[] = {
    { MUNGE_KEY_STATUS,          "STATUS",          display_status          },
    { MUNGE_KEY_ENCODE_HOST,     "ENCODE_HOST",     display_encode_host     },
    { MUNGE_KEY_ENCODE_TIME,     "ENCODE_TIME",     display_encode_time     },
    { MUNGE_KEY_DECODE_TIME,     "DECODE_TIME",     display_decode_time     },
    { MUNGE_KEY_TTL,             "TTL",             display_ttl             },
    { MUNGE_KEY_CIPHER_TYPE,     "CIPHER",          display_cipher_type     },
    { MUNGE_KEY_MAC_TYPE,        "MAC",             display_mac_type        },
    { MUNGE_KEY_ZIP_TYPE,        "ZIP",             display_zip_type        },
    { MUNGE_KEY_UID,             "UID",             display_uid             },
    { MUNGE_KEY_GID,             "GID",             display_gid             },
    { MUNGE_KEY_UID_RESTRICTION, "UID_RESTRICTION", display_uid_restriction },
    { MUNGE_KEY_GID_RESTRICTION, "GID_RESTRICTION", display_gid_restriction },
    { MUNGE_KEY_LENGTH,          "LENGTH",          display_length          },
    { MUNGE_KEY_LAST,             NULL,             NULL }
};


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

const char * const short_opts = ":hLVi:nm:o:k:KNS:";

#include <getopt.h>
struct option long_opts[] = {
    { "help",      no_argument,       NULL, 'h' },
    { "license",   no_argument,       NULL, 'L' },
    { "version",   no_argument,       NULL, 'V' },
    { "input",     required_argument, NULL, 'i' },
    { "no-output", no_argument,       NULL, 'n' },
    { "metadata",  required_argument, NULL, 'm' },
    { "output",    required_argument, NULL, 'o' },
    { "keys",      required_argument, NULL, 'k' },
    { "list-keys", no_argument,       NULL, 'K' },
    { "numeric",   no_argument,       NULL, 'N' },
    { "socket",    required_argument, NULL, 'S' },
    {  NULL,       0,                 NULL,  0  }
};


/*****************************************************************************
 *  Configuration
 *****************************************************************************/

struct conf {
    munge_ctx_t  ctx;                   /* munge context                     */
    munge_err_t  status;                /* error status unmunging the cred   */
    char        *fn_in;                 /* input filename, '-' for stdin     */
    char        *fn_meta;               /* metadata filename, '-' for stdout */
    char        *fn_out;                /* output filename, '-' for stdout   */
    FILE        *fp_in;                 /* input file pointer                */
    FILE        *fp_meta;               /* metadata file pointer             */
    FILE        *fp_out;                /* output file pointer               */
    int          clen;                  /* munged credential length          */
    char        *cred;                  /* munged credential                 */
    int          dlen;                  /* unmunged payload data length      */
    void        *data;                  /* unmunged payload data             */
    uid_t        uid;                   /* process uid according to cred     */
    gid_t        gid;                   /* process gid according to cred     */
    char         key[ MUNGE_KEY_LAST ]; /* key flag array (true if enabled)  */
    int          key_width;             /* num chars reserved for key field  */
    unsigned     got_numeric:1;         /* flag for NUMERIC option           */
};


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t       conf;
    int          rc;
    const char  *p;

    xsignal_ignore (SIGHUP);
    xsignal_ignore (SIGPIPE);
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    read_data_from_file (conf->fp_in, (void **) &conf->cred, &conf->clen);

    conf->status = munge_decode (conf->cred, conf->ctx,
            &conf->data, &conf->dlen, &conf->uid, &conf->gid);

    /*  If the credential is expired, rewound, or replayed, the integrity
     *    of its contents is valid even though the credential itself is not.
     *  As such, display the metadata & payload with an appropriate status
     *    if the integrity checks succeed; o/w, exit out here with an error.
     */
    if  ((conf->status != EMUNGE_SUCCESS)      &&
         (conf->status != EMUNGE_CRED_EXPIRED) &&
         (conf->status != EMUNGE_CRED_REWOUND) &&
         (conf->status != EMUNGE_CRED_REPLAYED))
    {
        p = munge_ctx_strerror (conf->ctx);
        if (p == NULL) {
            p = munge_strerror (conf->status);
        }
        log_err (conf->status, LOG_ERR, "%s", p);
    }
    display_meta (conf);
    display_data (conf);

    rc = conf->status;
    destroy_conf (conf);
    log_close_file ();
    exit (rc);
}


conf_t
create_conf (void)
{
    conf_t conf;
    int    i;
    int    len;
    int    maxlen;

    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate conf");
    }
    if (!(conf->ctx = munge_ctx_create ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to create conf ctx");
    }
    conf->status = -1;
    conf->fn_in = "-";
    conf->fn_meta = "-";
    conf->fn_out = "-";
    conf->fp_in = NULL;
    conf->fp_meta = NULL;
    conf->fp_out = NULL;
    conf->clen = 0;
    conf->cred = NULL;
    conf->dlen = 0;
    conf->data = NULL;
    conf->uid = UID_SENTINEL;
    conf->gid = GID_SENTINEL;
    for (i = 0, maxlen = 0; i < MUNGE_KEY_LAST; i++) {
        conf->key[i] = 0;
        len = strlen (key_val_to_str (i));
        maxlen = MAX (maxlen, len);
    }
    conf->key_width = maxlen + 1;       /* separate longest key by one space */
    conf->got_numeric = 0;

    return (conf);
}


void
destroy_conf (conf_t conf)
{
    /*  XXX: Don't free() conf's fn_in/fn_meta/fn_out
     *       since they point inside argv[].
     */
    if (conf->fp_in != NULL) {
        if (fclose (conf->fp_in) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close input file");
        }
        conf->fp_in = NULL;
    }
    if (conf->fp_meta != NULL) {
        if ((fclose (conf->fp_meta) < 0) && (errno != EPIPE)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to close metadata output file");
        }
        conf->fp_meta = NULL;
    }
    if (conf->fp_out != NULL) {
        if (conf->fn_out                        &&
            conf->fn_meta                       &&
            strcmp (conf->fn_out, conf->fn_meta))
        {
            if ((fclose (conf->fp_out) < 0) && (errno != EPIPE)) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to close payload output file");
            }
        }
        conf->fp_out = NULL;
    }
    if (conf->cred) {
        assert (conf->clen > 0);
        memburn (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
    if (conf->data) {
        assert (conf->dlen > 0);
        memburn (conf->data, 0, conf->dlen);
        free (conf->data);
        conf->data = NULL;
    }
    munge_ctx_destroy (conf->ctx);
    free (conf);
    return;
}


void
parse_cmdline (conf_t conf, int argc, char **argv)
{
    int          got_keys = 0;
    char        *prog;
    int          c;
    munge_err_t  e;
    const char  *p;
    int          i;

    opterr = 0;                         /* suppress default getopt err msgs */

    prog = (prog = strrchr (argv[0], '/')) ? prog + 1 : argv[0];

    for (;;) {

        c = getopt_long (argc, argv, short_opts, long_opts, NULL);

        if (c == -1) {                  /* reached end of option list */
            break;
        }
        switch (c) {
            case 'h':
                display_help (prog);
                exit (EMUNGE_SUCCESS);
                break;
            case 'L':
                display_license ();
                exit (EMUNGE_SUCCESS);
                break;
            case 'V':
                display_version ();
                exit (EMUNGE_SUCCESS);
                break;
            case 'i':
                conf->fn_in = optarg;
                break;
            case 'n':
                conf->fn_meta = NULL;
                conf->fn_out = NULL;
                break;
            case 'm':
                conf->fn_meta = optarg;
                break;
            case 'o':
                conf->fn_out = optarg;
                break;
            case 'k':
                got_keys = 1;
                parse_keys (conf, optarg);
                break;
            case 'K':
                display_keys ();
                exit (EMUNGE_SUCCESS);
                break;
            case 'N':
                conf->got_numeric = 1;
                break;
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS) {
                    p = munge_ctx_strerror (conf->ctx);
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Failed to set munge socket name: %s",
                            (p ? p : "Unspecified error"));
                }
                break;
            case '?':
                if (optopt > 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Invalid option \"-%c\"", optopt);
                }
                else if (optind > 1) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Invalid option \"%s\"", argv[optind - 1]);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Failed to process command-line");
                }
                break;
            case ':':
                if ((optind > 1) && (!strncmp (argv[optind - 1], "--", 2))) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Missing argument for option \"%s\"",
                            argv[optind - 1]);
                }
                else if (optopt > 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Missing argument for option \"-%c\"", optopt);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Failed to process command-line");
                }
                break;
            default:
                if ((optind > 1) && (!strncmp (argv[optind - 1], "--", 2))) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Unimplemented option \"%s\"", argv[optind - 1]);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Unimplemented option \"-%c\"", c);
                }
                break;
        }
    }
    if (argv[optind]) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unrecognized parameter \"%s\"", argv[optind]);
    }
    /*  Enable all metadata keys if a subset was not specified.
     */
    if (!got_keys) {
        for (i = 0; i < MUNGE_KEY_LAST; i++) {
            conf->key[i] = 1;
        }
    }
    return;
}


void
display_help (char *prog)
{
    const int w = -25;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, "-h, --help",
            "Display this help message");

    printf ("  %*s %s\n", w, "-L, --license",
            "Display license information");

    printf ("  %*s %s\n", w, "-V, --version",
            "Display version information");

    printf ("\n");

    printf ("  %*s %s\n", w, "-i, --input=PATH",
            "Input credential from file");

    printf ("  %*s %s\n", w, "-n, --no-output",
            "Discard all output");

    printf ("  %*s %s\n", w, "-m, --metadata=PATH",
            "Output metadata to file");

    printf ("  %*s %s\n", w, "-o, --output=PATH",
            "Output payload to file");

    printf ("\n");

    printf ("  %*s %s\n", w, "-k, --keys=STR",
            "Specify subset of metadata keys to output");

    printf ("  %*s %s\n", w, "-K, --list-keys",
            "Display list of metadata keys");

    printf ("  %*s %s\n", w, "-N, --numeric",
            "Display metadata values numerically");

    printf ("  %*s %s\n", w, "-S, --socket=PATH",
            "Specify local socket for munged");

    printf ("\n");
    printf ("By default, credential read from stdin, "
            "metadata & payload written to stdout.\n\n");
    return;
}


void
parse_keys (conf_t conf, char *keys)
{
    const char *separators = " \t\n.,;";
    char       *key;
    int         val;

    if (!keys || !*keys) {
        return;
    }
    key = strtok (keys, separators);
    while (key != NULL) {
        val = key_str_to_val (key);
        if (val >= 0) {
            conf->key[val] = 1;
        }
        key = strtok (NULL, separators);
    }
    return;
}


void
display_keys (void)
{
    int i;

    printf ("Metadata keys:\n\n");
    for (i = 0; i < MUNGE_KEY_LAST; i++) {
        printf ("  %s\n", munge_keys[i].str);
    }
    printf ("\n");
    return;
}


void
open_files (conf_t conf)
{
    if (conf->fn_in) {
        if (!strcmp (conf->fn_in, "-")) {
            conf->fp_in = stdin;
        }
        else if (!(conf->fp_in = fopen (conf->fn_in, "r"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to read from \"%s\"", conf->fn_in);
        }
    }
    if (conf->fn_meta) {
        if (!strcmp (conf->fn_meta, "-")) {
            conf->fp_meta = stdout;
        }
        else if (conf->fn_in && !strcmp (conf->fn_meta, conf->fn_in)) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Cannot read and write to the same file \"%s\"",
                    conf->fn_meta);
        }
        else if (!(conf->fp_meta = fopen (conf->fn_meta, "w"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to write to \"%s\"", conf->fn_meta);
        }
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-")) {
            conf->fp_out = stdout;
        }
        else if (conf->fn_in && !strcmp (conf->fn_out, conf->fn_in)) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Cannot read and write to the same file \"%s\"",
                    conf->fn_out);
        }
        else if (conf->fn_meta && !strcmp (conf->fn_out, conf->fn_meta)) {
            conf->fp_out = conf->fp_meta;
        }
        else if (!(conf->fp_out = fopen (conf->fn_out, "w"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to write to \"%s\"", conf->fn_out);
        }
    }
    return;
}


void
display_meta (conf_t conf)
{
    int i;

    assert (conf != NULL);

    if (conf->fp_meta == NULL) {
        return;
    }
    for (i = 0; i < MUNGE_KEY_LAST; i++) {
        if (conf->key[i] && munge_keys[i].fp) {
            (*(munge_keys[i].fp)) (conf);
        }
    }
    /*  Since we've been ignoring the return values of fprintf(),
     *    check for errors on fp_meta.
     */
    if (ferror (conf->fp_meta)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Write error");
    }
    /*  Separate metadata from payload with a newline
     *    if they are being written to the same file stream.
     */
    if (conf->fp_meta == conf->fp_out) {
        fprintf (conf->fp_meta, "\n");
    }
    return;
}


void
display_status (conf_t conf)
{
    const char *key;
    int         num_spaces;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_STATUS);
    num_spaces = conf->key_width - strlen (key);
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20,
                conf->status);
    }
    else {
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", key, num_spaces, 0x20,
                munge_strerror (conf->status), conf->status);
    }
    return;
}


void
display_encode_host (conf_t conf)
{
    const char           *key;
    int                   num_spaces;
    munge_err_t           err;
    const char           *p;
    struct in_addr        addr;
    char                  addr_str[ INET_ADDRSTRLEN ];
    struct hostent       *hostent_ptr;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_ENCODE_HOST);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_ADDR4, &addr);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (!inet_ntop (AF_INET, &addr, addr_str, sizeof (addr_str))) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to convert %s to string: %s", key, strerror (errno));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%s\n", key, num_spaces, 0x20, addr_str);
    }
    else {
        hostent_ptr = gethostbyaddr (&addr, sizeof (addr), AF_INET);
        fprintf (conf->fp_meta, "%s:%*c%s (%s)\n", key, num_spaces, 0x20,
                (hostent_ptr ? hostent_ptr->h_name : "???"), addr_str);
    }
    return;
}


void
display_encode_time (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    time_t       t;
    struct tm   *tm_ptr;
    int          t_len;
    char         t_buf[ MAX_TIME_STR ];

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_ENCODE_TIME);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_ENCODE_TIME, &t);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%ld\n", key, num_spaces, 0x20,
                (long) t);
    }
    else {
        tm_ptr = localtime (&t);
        if (tm_ptr == NULL) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to convert %s to local time", key);
        }
        t_len = strftime (t_buf, sizeof (t_buf),
                "%Y-%m-%d %H:%M:%S %z", tm_ptr);
        if ((t_len == 0) || (t_len >= sizeof (t_buf))) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                    "Failed to format %s: exceeded buffer", key);
        }
        /*  Since ISO C does not support the '%s' strftime() format option...
         */
        if (strcatf (t_buf, sizeof (t_buf), " (%ld)", (long) t) < 0) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                    "Failed to format %s: exceeded buffer", key);
        }
        fprintf (conf->fp_meta, "%s:%*c%s\n", key, num_spaces, 0x20, t_buf);
    }
    return;
}


void
display_decode_time (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    time_t       t;
    struct tm   *tm_ptr;
    int          t_len;
    char         t_buf[ MAX_TIME_STR ];

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_DECODE_TIME);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_DECODE_TIME, &t);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%ld\n", key, num_spaces, 0x20,
                (long) t);
    }
    else {
        tm_ptr = localtime (&t);
        if (tm_ptr == NULL) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to convert %s to local time", key);
        }
        t_len = strftime (t_buf, sizeof (t_buf),
                "%Y-%m-%d %H:%M:%S %z", tm_ptr);
        if ((t_len == 0) || (t_len >= sizeof (t_buf))) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                    "Failed to format %s: exceeded buffer", key);
        }
        /*  Since ISO C does not support the '%s' strftime() format option...
         */
        if (strcatf (t_buf, sizeof (t_buf), " (%ld)", (long) t) < 0) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                    "Failed to format %s: exceeded buffer", key);
        }
        fprintf (conf->fp_meta, "%s:%*c%s\n", key, num_spaces, 0x20, t_buf);
    }
    return;
}


void
display_ttl (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    int          i;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_TTL);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_TTL, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20, i);
    return;
}


void
display_cipher_type (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    int          i;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_CIPHER_TYPE);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_CIPHER_TYPE, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20, i);
    }
    else {
        p = munge_enum_int_to_str (MUNGE_ENUM_CIPHER, i);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", key, num_spaces, 0x20,
                (p ? p : "???"), i);
    }
    return;
}


void
display_mac_type (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    int          i;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_MAC_TYPE);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_MAC_TYPE, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20, i);
    }
    else {
        p = munge_enum_int_to_str (MUNGE_ENUM_MAC, i);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", key, num_spaces, 0x20,
                (p ? p : "???"), i);
    }
    return;
}


void
display_zip_type (conf_t conf)
{
    const char  *key;
    int          num_spaces;
    munge_err_t  err;
    const char  *p;
    int          i;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_ZIP_TYPE);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_ZIP_TYPE, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20, i);
    }
    else {
        p = munge_enum_int_to_str (MUNGE_ENUM_ZIP, i);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", key, num_spaces, 0x20,
                (p ? p : "???"), i);
    }
    return;
}


void
display_uid (conf_t conf)
{
    const char    *key;
    int            num_spaces;
    struct passwd *pw_ptr;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_UID);
    num_spaces = conf->key_width - strlen (key);
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%u\n", key, num_spaces, 0x20,
                (unsigned int) conf->uid);
    }
    else {
        pw_ptr = getpwuid (conf->uid);
        fprintf (conf->fp_meta, "%s:%*c%s (%u)\n", key, num_spaces, 0x20,
                (pw_ptr ? pw_ptr->pw_name : "???"), (unsigned int) conf->uid);
    }
    return;
}


void
display_gid (conf_t conf)
{
    const char    *key;
    int            num_spaces;
    struct group  *gr_ptr;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_GID);
    num_spaces = conf->key_width - strlen (key);
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%u\n", key, num_spaces, 0x20,
                (unsigned int) conf->gid);
    }
    else {
        gr_ptr = getgrgid (conf->gid);
        fprintf (conf->fp_meta, "%s:%*c%s (%u)\n", key, num_spaces, 0x20,
                (gr_ptr ? gr_ptr->gr_name : "???"), (unsigned int) conf->gid);
    }
    return;
}


void
display_uid_restriction (conf_t conf)
{
    const char    *key;
    int            num_spaces;
    munge_err_t    err;
    const char    *p;
    int            i;
    struct passwd *pw_ptr;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_UID_RESTRICTION);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_UID_RESTRICTION, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (i == MUNGE_UID_ANY) {
        return;
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%u\n", key, num_spaces, 0x20,
                (unsigned int) i);
    }
    else {
        pw_ptr = getpwuid (i);
        fprintf (conf->fp_meta, "%s:%*c%s (%u)\n", key, num_spaces, 0x20,
                (pw_ptr ? pw_ptr->pw_name : "???"), (unsigned int) i);
    }
    return;
}


void
display_gid_restriction (conf_t conf)
{
    const char    *key;
    int            num_spaces;
    munge_err_t    err;
    const char    *p;
    int            i;
    struct group  *gr_ptr;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_GID_RESTRICTION);
    num_spaces = conf->key_width - strlen (key);
    err = munge_ctx_get (conf->ctx, MUNGE_OPT_GID_RESTRICTION, &i);
    if (err != EMUNGE_SUCCESS) {
        p = munge_ctx_strerror (conf->ctx);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to retrieve %s: %s", key,
                (p ? p : "Unspecified error"));
    }
    if (i == MUNGE_GID_ANY) {
        return;
    }
    if (conf->got_numeric) {
        fprintf (conf->fp_meta, "%s:%*c%u\n", key, num_spaces, 0x20,
                (unsigned int) i);
    }
    else {
        gr_ptr = getgrgid (i);
        fprintf (conf->fp_meta, "%s:%*c%s (%u)\n", key, num_spaces, 0x20,
                (gr_ptr ? gr_ptr->gr_name : "???"), (unsigned int) i);
    }
    return;
}


void
display_length (conf_t conf)
{
    const char *key;
    int         num_spaces;

    assert (conf != NULL);

    key = key_val_to_str (MUNGE_KEY_LENGTH);
    num_spaces = conf->key_width - strlen (key);
    fprintf (conf->fp_meta, "%s:%*c%d\n", key, num_spaces, 0x20, conf->dlen);
    return;
}


void
display_data (conf_t conf)
{
    if ((conf->dlen <= 0) || (!conf->data)) {
        return;
    }
    if (!conf->fp_out) {
        return;
    }
    if (fwrite (conf->data, 1, conf->dlen, conf->fp_out) != conf->dlen) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Write error");
    }
    /*  If outputting to a tty, append a final newline if one is missing.
     */
    if (isatty (fileno (conf->fp_out)) &&
            ((char *) conf->data) [conf->dlen - 1] != '\n') {
        fprintf (conf->fp_out, "\n");
    }
    return;
}


int
key_str_to_val (const char *str)
{
    int i;

    if ((str == NULL) || (str[0] == '\0')) {
        return (-1);
    }
    for (i = 0; i < MUNGE_KEY_LAST; i++) {
        if (!strcasecmp (str, munge_keys[i].str)) {
            return (i);
        }
    }
    return (-1);
}


const char *
key_val_to_str (int val)
{
    assert (val >= 0);
    assert (val < MUNGE_KEY_LAST);
    assert (munge_keys[val].str != NULL);

    return (munge_keys[val].str);
}
