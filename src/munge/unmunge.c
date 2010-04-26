/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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
#include "missing.h"                    /* for inet_ntop()                   */
#include "read.h"
#include "version.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAX_TIME_STR 33                 /* YYYY-MM-DD HH:MM:SS (4294967296)  */


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

const char * const short_opts = ":hLVi:nm:o:k:KS:";

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
    { "socket",    required_argument, NULL, 'S' },
    {  NULL,       0,                 NULL,  0  }
};


/*****************************************************************************
 *  Metadata Keys
 *****************************************************************************/

typedef struct {
    int   val;
    char *str;
} strval_t;

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

strval_t munge_keys[] = {
    { MUNGE_KEY_STATUS,          "STATUS"          },
    { MUNGE_KEY_ENCODE_HOST,     "ENCODE_HOST"     },
    { MUNGE_KEY_ENCODE_TIME,     "ENCODE_TIME"     },
    { MUNGE_KEY_DECODE_TIME,     "DECODE_TIME"     },
    { MUNGE_KEY_TTL,             "TTL"             },
    { MUNGE_KEY_CIPHER_TYPE,     "CIPHER"          },
    { MUNGE_KEY_MAC_TYPE,        "MAC"             },
    { MUNGE_KEY_ZIP_TYPE,        "ZIP"             },
    { MUNGE_KEY_UID,             "UID"             },
    { MUNGE_KEY_GID,             "GID"             },
    { MUNGE_KEY_UID_RESTRICTION, "UID_RESTRICTION" },
    { MUNGE_KEY_GID_RESTRICTION, "GID_RESTRICTION" },
    { MUNGE_KEY_LENGTH,          "LENGTH"          },
    { MUNGE_KEY_LAST,             NULL             }
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
    char         key[MUNGE_KEY_LAST];   /* key flag array (true if enabled)  */
    int          key_max_str_len;       /* max strlen of any given key       */
};

typedef struct conf * conf_t;


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
void display_data (conf_t conf);
int key_str_to_val (char *str);
char * key_val_to_str (int val);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t       conf;
    int          rc;
    const char  *p;

    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);
    }
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    rc = read_data_from_file (conf->fp_in,
        (void **) &conf->cred, &conf->clen);
    if (rc < 0) {
        if (errno == ENOMEM) {
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to read input");
        }
        else {
            log_err (EMUNGE_SNAFU, LOG_ERR, "Read error");
        }
    }
    conf->status = munge_decode (conf->cred, conf->ctx,
        &conf->data, &conf->dlen, &conf->uid, &conf->gid);

    /*  If the credential is expired, rewound, or replayed, the integrity
     *    of its contents is valid even though the credential itself is not.
     *  As such, display the metadata & payload with an appropriate status
     *    if the integrity checks succeed; o/w, exit out here with an error.
     */
    if  (  (conf->status != EMUNGE_SUCCESS)
        && (conf->status != EMUNGE_CRED_EXPIRED)
        && (conf->status != EMUNGE_CRED_REWOUND)
        && (conf->status != EMUNGE_CRED_REPLAYED) )
    {
        if (!(p = munge_ctx_strerror (conf->ctx)))
            p = munge_strerror (conf->status);
        log_err (conf->status, LOG_ERR, "%s", p);
    }

    display_meta (conf);
    display_data (conf);

    rc = conf->status;
    destroy_conf (conf);
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
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf");
    }
    if (!(conf->ctx = munge_ctx_create ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf ctx");
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
    conf->uid = -1;
    conf->gid = -1;
    for (i=0, maxlen=0; i<MUNGE_KEY_LAST; i++) {
        conf->key[i] = 0;
        len = strlen (key_val_to_str (i));
        maxlen = MAX (maxlen, len);
    }
    conf->key_max_str_len = maxlen;

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
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close infile");
        }
        conf->fp_in = NULL;
    }
    if (conf->fp_meta != NULL) {
        if ((fclose (conf->fp_meta) < 0) && (errno != EPIPE)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close metadata outfile");
        }
        conf->fp_meta = NULL;
    }
    if (conf->fp_out != NULL) {
        if (conf->fn_out && conf->fn_meta
                && strcmp (conf->fn_out, conf->fn_meta)) {
            if ((fclose (conf->fp_out) < 0) && (errno != EPIPE)) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to close payload outfile");
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
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set munge socket name: %s",
                        munge_ctx_strerror (conf->ctx));
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
                        "Unable to process command-line");
                }
                break;
            case ':':
                if ((optind > 1)
                        && (strncmp (argv[optind - 1], "--", 2) == 0)) {
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
                        "Unable to process command-line");
                }
                break;
            default:
                if ((optind > 1)
                        && (strncmp (argv[optind - 1], "--", 2) == 0)) {
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
        for (i=0; i<MUNGE_KEY_LAST; i++) {
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
            "Display this help");

    printf ("  %*s %s\n", w, "-L, --license",
            "Display license information");

    printf ("  %*s %s\n", w, "-V, --version",
            "Display version information");

    printf ("\n");

    printf ("  %*s %s\n", w, "-i, --input=FILE",
            "Input credential from FILE");

    printf ("  %*s %s\n", w, "-n, --no-output",
            "Discard all output");

    printf ("  %*s %s\n", w, "-m, --metadata=FILE",
            "Output metadata to FILE");

    printf ("  %*s %s\n", w, "-o, --output=FILE",
            "Output payload to FILE");

    printf ("\n");

    printf ("  %*s %s\n", w, "-k, --keys=STRING",
            "Specify subset of metadata keys to output");

    printf ("  %*s %s\n", w, "-K, --list-keys",
            "Display list of metadata keys");

    printf ("  %*s %s\n", w, "-S, --socket=STRING",
            "Specify local domain socket for daemon");

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
    for (i=0; i<MUNGE_KEY_LAST; i++) {
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
                "Unable to read from \"%s\"", conf->fn_in);
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
                "Unable to write to \"%s\"", conf->fn_meta);
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
                "Unable to write to \"%s\"", conf->fn_out);
        }
    }
    return;
}


void
display_meta (conf_t conf)
{
    int             pad;                /* num chars reserved for key field  */
    char           *s;                  /* key field string                  */
    int             w;                  /* width of space chars to fill pad  */
    munge_err_t     e;                  /* munge error condition             */
    struct in_addr  addr;               /* IPv4 addr                         */
    struct hostent *hptr;               /* ptr to static hostent struct      */
    char            ip_buf[INET_ADDRSTRLEN]; /* ip addr string buffer        */
    time_t          t;                  /* time (seconds since epoch)        */
    struct tm      *tm_ptr;             /* ptr to broken-down time entry     */
    int             t_len;              /* length of time string             */
    char            t_buf[MAX_TIME_STR];/* time string buffer                */
    int             i;                  /* all-purpose int                   */
    struct passwd  *pw_ptr;             /* ptr to broken-down password entry */
    struct group   *gr_ptr;             /* ptr to broken-down group entry    */

    if (!conf->fp_meta) {
        return;
    }
    pad = conf->key_max_str_len + 2;

    if (conf->key[MUNGE_KEY_STATUS]) {
        s = key_val_to_str (MUNGE_KEY_STATUS);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_strerror (conf->status), conf->status);
    }
    if (conf->key[MUNGE_KEY_ENCODE_HOST]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ADDR4, &addr);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve origin ip address: %s",
                munge_ctx_strerror (conf->ctx));
        }
        hptr = gethostbyaddr ((char *) &addr, sizeof (addr), AF_INET);
        if (!inet_ntop (AF_INET, &addr, ip_buf, sizeof (ip_buf))) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to convert ip address string");
        }
        s = key_val_to_str (MUNGE_KEY_ENCODE_HOST);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%s)\n", s, w, 0x20,
            (hptr ? hptr->h_name : "???"), ip_buf);
    }
    if (conf->key[MUNGE_KEY_ENCODE_TIME]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ENCODE_TIME, &t);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve encode time: %s",
                munge_ctx_strerror (conf->ctx));
        }
        tm_ptr = localtime (&t);
        t_len = strftime (t_buf, sizeof (t_buf), "%Y-%m-%d %H:%M:%S", tm_ptr);
        if ((t_len == 0) || (t_len >= sizeof (t_buf))) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for encode time");
        }
        /*  Since ISO C does not support the '%s' strftime format option ...
         */
        if (strcatf (t_buf, sizeof (t_buf), " (%ld)", (long) t) < 0) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for encode time");
        }
        s = key_val_to_str (MUNGE_KEY_ENCODE_TIME);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s\n", s, w, 0x20, t_buf);
    }
    if (conf->key[MUNGE_KEY_DECODE_TIME]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_DECODE_TIME, &t);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve decode time: %s",
                munge_ctx_strerror (conf->ctx));
        }
        tm_ptr = localtime (&t);
        t_len = strftime (t_buf, sizeof (t_buf), "%Y-%m-%d %H:%M:%S", tm_ptr);
        if ((t_len == 0) || (t_len >= sizeof (t_buf))) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for decode time");
        }
        /*  Since ISO C does not support the '%s' strftime format option ...
         */
        if (strcatf (t_buf, sizeof (t_buf), " (%ld)", (long) t) < 0) {
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for decode time");
        }
        s = key_val_to_str (MUNGE_KEY_DECODE_TIME);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s\n", s, w, 0x20, t_buf);
    }
    if (conf->key[MUNGE_KEY_TTL]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_TTL, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve ttl: %s",
                munge_ctx_strerror (conf->ctx));
        }
        s = key_val_to_str (MUNGE_KEY_TTL);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, i);
    }
    if (conf->key[MUNGE_KEY_CIPHER_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_CIPHER_TYPE, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve cipher type: %s",
                munge_ctx_strerror (conf->ctx));
        }
        s = key_val_to_str (MUNGE_KEY_CIPHER_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_enum_int_to_str (MUNGE_ENUM_CIPHER, i), i);
    }
    if (conf->key[MUNGE_KEY_MAC_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_MAC_TYPE, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve message auth code type: %s",
                munge_ctx_strerror (conf->ctx));
        }
        s = key_val_to_str (MUNGE_KEY_MAC_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_enum_int_to_str (MUNGE_ENUM_MAC, i), i);
    }
    if (conf->key[MUNGE_KEY_ZIP_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ZIP_TYPE, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve compression type: %s",
                munge_ctx_strerror (conf->ctx));
        }
        s = key_val_to_str (MUNGE_KEY_ZIP_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_enum_int_to_str (MUNGE_ENUM_ZIP, i), i);
    }
    if (conf->key[MUNGE_KEY_UID]) {
        pw_ptr = getpwuid (conf->uid);
        s = key_val_to_str (MUNGE_KEY_UID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            (pw_ptr ? pw_ptr->pw_name : "???"), (int) conf->uid);
    }
    if (conf->key[MUNGE_KEY_GID]) {
        gr_ptr = getgrgid (conf->gid);
        s = key_val_to_str (MUNGE_KEY_GID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            (gr_ptr ? gr_ptr->gr_name : "???"), (int) conf->gid);
    }
    if (conf->key[MUNGE_KEY_UID_RESTRICTION]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_UID_RESTRICTION, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve uid restriction: %s",
                munge_ctx_strerror (conf->ctx));
        }
        if (i != MUNGE_UID_ANY) {
            pw_ptr = getpwuid (i);
            s = key_val_to_str (MUNGE_KEY_UID_RESTRICTION);
            w = pad - strlen (s);
            fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
                (pw_ptr ? pw_ptr->pw_name : "???"), i);
        }
    }
    if (conf->key[MUNGE_KEY_GID_RESTRICTION]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_GID_RESTRICTION, &i);
        if (e != EMUNGE_SUCCESS) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve gid restriction: %s",
                munge_ctx_strerror (conf->ctx));
        }
        if (i != MUNGE_GID_ANY) {
            gr_ptr = getgrgid (i);
            s = key_val_to_str (MUNGE_KEY_GID_RESTRICTION);
            w = pad - strlen (s);
            fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
                (gr_ptr ? gr_ptr->gr_name : "???"), i);
        }
    }
    if (conf->key[MUNGE_KEY_LENGTH]) {
        s = key_val_to_str (MUNGE_KEY_LENGTH);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->dlen);
    }
    /*  Since we've been ignoring the return values of fprintf(),
     *    check for errors on fp_meta.
     */
    if (ferror (conf->fp_meta)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Write error");
    }
    /*  Separate metadata from payload with a newline
     *    if they are both going to the same place.
     */
    if (conf->fp_meta == conf->fp_out) {
        fprintf (conf->fp_meta, "\n");
    }
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
    return;
}


int
key_str_to_val (char *str)
{
    int i;

    if (!str || !*str) {
        return (-1);
    }
    for (i=0; i<MUNGE_KEY_LAST; i++) {
        if (!strcasecmp (str, munge_keys[i].str)) {
            return (i);
        }
    }
    return (-1);
}


char *
key_val_to_str (int val)
{
    int i;

    for (i=0; i<MUNGE_KEY_LAST; i++) {
        if (val == munge_keys[i].val) {
            return (munge_keys[i].str);
        }
    }
    return (NULL);
}
