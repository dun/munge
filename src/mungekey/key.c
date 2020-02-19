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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>                     /* basename, dirname */
#include <limits.h>                     /* PATH_MAX */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>                   /* fstat */
#include <sys/types.h>
#include <unistd.h>
#include "common.h"
#include "conf.h"
#include "entropy.h"
#include "fd.h"
#include "hkdf.h"
#include "log.h"
#include "munge_defs.h"
#include "str.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void _get_key_path_components (const char *key_path,
        char **keydir_name, char **key_name);

static void _write_key_to_file (const char *key_path, int fd,
        size_t num_bytes);

static int _create_key_secret (unsigned char *buf, size_t buflen);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Create a key for the config [confp].
 *  If the process is running as root, set the ownership of the key file to
 *    match that of the key's directory.  Protect against TOCTOU.
 */
void
create_key (conf_t *confp)
{
    char *keydir_name;
    char *key_name;
    int keydir_fd;
    int key_fd;
    struct stat keydir_stat;
    int got_chown = 0;
    int rv;

    assert (confp != NULL);
    assert (confp->key_path != NULL);
    assert (confp->key_path[0] == '/');

    _get_key_path_components (confp->key_path, &keydir_name, &key_name);

    keydir_fd = open (keydir_name, O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
    if (keydir_fd == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to open directory \"%s\"", keydir_name);
    }
    rv = fstat (keydir_fd, &keydir_stat);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to stat directory \"%s\"", keydir_name);
    }
    if (confp->do_force) {
        rv = unlinkat (keydir_fd, key_name, 0);
        if ((rv == -1) && (errno != ENOENT)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to remove \"%s\"", confp->key_path);
        }
    }
    key_fd = openat (keydir_fd, key_name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (key_fd == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create \"%s\"", confp->key_path);
    }
    _write_key_to_file (confp->key_path, key_fd, confp->key_num_bytes);

    if (geteuid () == 0) {
        rv = fchown (key_fd, keydir_stat.st_uid, keydir_stat.st_gid);
        if (rv == -1) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to chown \"%s\"", confp->key_path);
        }
        got_chown = 1;
    }
    rv = close (key_fd);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to close \"%s\"", confp->key_path);
    }
    rv = close (keydir_fd);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to close directory \"%s\"", keydir_name);
    }
    if (confp->do_verbose) {
        char log_msg_buf[64] = "";

        if (got_chown) {
            rv = snprintf (log_msg_buf, sizeof (log_msg_buf), "(%lu:%lu) ",
                    (unsigned long) keydir_stat.st_uid,
                    (unsigned long) keydir_stat.st_gid);
            if ((rv < 0) || (rv >= sizeof (log_msg_buf))) {
                log_msg_buf[0] = '\0';
            }
        }
        log_msg (LOG_INFO, "Created \"%s\" %swith %d-bit key",
                confp->key_path, log_msg_buf, confp->key_num_bytes * 8);
    }
    free (keydir_name);
    free (key_name);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

/*  Separate the absolute path [key_path] into dirname and basename components.
 *  Upon return, [keydir_name] and [key_name] will point to null-terminated
 *    strings.
 */
static void
_get_key_path_components (const char *key_path, char **keydir_name,
        char **key_name)
{
    char buf [PATH_MAX];
    size_t n;
    char *p;

    assert (key_path != NULL);
    assert (keydir_name != NULL);
    assert (key_name != NULL);

    if (key_path[0] != '/') {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Invalid keyfile: Not an absolute pathname");
    }
    n = strlen (key_path);
    if (n >= sizeof (buf)) {
        errno = ENAMETOOLONG;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Invalid keyfile");
    }
    strncpy (buf, key_path, n + 1);
    p = dirname (buf);
    if (p[0] != '/') {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Invalid keyfile directory name: Not an absolute pathname");
    }
    p = strdup (buf);
    if (p == NULL) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to copy keyfile directory name");
    }
    *keydir_name = p;

    strncpy (buf, key_path, n + 1);
    p = basename (buf);
    if (( p[0] == '\0') ||
        ((p[0] == '/' || p[0] == '.') && p[1] == '\0') ||
        ((p[0] == '.') && (p[1] == '.') && (p[2] == '\0'))) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Invalid keyfile: Not a file");
    }
    p = strdup (buf);
    if (p == NULL) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to copy keyfile name");
    }
    *key_name = p;
}


/*  FIXME
 */
static void
_write_key_to_file (const char *key_path, int fd, size_t num_bytes)
{
    unsigned char buf [MUNGE_KEY_LEN_MAX_BYTES];
    int n;
    int rv;

    assert (key_path != NULL);
    assert (fd >= 0);
    assert (num_bytes > 0);

    if (num_bytes > sizeof (buf)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create \"%s\": %zu-byte key exceeds %zu-byte buffer",
                key_path, num_bytes, sizeof (buf));
    }
    rv = _create_key_secret (buf, num_bytes);
    if (rv == -1) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create \"%s\"", key_path);
    }
    n = fd_write_n (fd, buf, num_bytes);
    if (n != num_bytes) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to write %d bytes to \"%s\"", num_bytes, key_path);
    }
    (void) memburn (buf, 0, sizeof (buf));
}


/*  Create the key secret, writing it to the buffer [buf] of length [buflen].
 *  Return 0 on success, or -1 on error.
 */
static int
_create_key_secret (unsigned char *buf, size_t buflen)
{
    unsigned char      key[ENTROPY_NUM_BYTES_GUARANTEED];
    unsigned int       salt;
    const munge_mac_t  md = MUNGE_DEFAULT_MAC;
    const char        *md_str;
    const char        *info_prefix = "MUNGEKEY";
    int                num_bits;
    char               info[1024];
    hkdf_ctx_t        *hkdfp = NULL;
    int                rv;

    assert (buf != NULL);
    assert (buflen > 0);

    /*  Read entropy from the kernel's CSPRNG for the input keying material.
     */
    rv = entropy_read (key, sizeof (key), NULL);
    if (rv == -1) {
        goto err;
    }
    /*  Read entropy independent of the kernel's CSPRNG for use as a salt.
     */
    rv = entropy_read_uint (&salt);
    if (rv == -1) {
        goto err;
    }
    /*  Create a distinguisher that embeds the use, algorithm, and key length.
     *    For example, "MUNGEKEY:sha256:1024:".
     */
    md_str = munge_enum_int_to_str (MUNGE_ENUM_MAC, md);
    if (md_str == NULL) {
        log_msg (LOG_ERR, "Failed to lookup text string for md=%d", md);
        rv = -1;
        goto err;
    }
    num_bits = buflen * 8;
    rv = snprintf (info, sizeof (info), "%s:%s:%d:",
            info_prefix, md_str, num_bits);
    if ((rv < 0) || (rv >= sizeof (info))) {
        log_msg (LOG_ERR, "Failed to create key distinguisher info: "
                "exceeded %zu-byte buffer", sizeof (info));
        rv = -1;
        goto err;
    }
    /*  Mix it all together in the key derivation function.
     */
    hkdfp = hkdf_ctx_create ();
    if (hkdfp == NULL) {
        log_msg (LOG_ERR, "Failed to allocate memory for HKDF context");
        rv = -1;
        goto err;
    }
    rv = hkdf_ctx_set_md (hkdfp, md);
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to set HKDF message digest to md=%d", md);
        goto err;
    }
    rv = hkdf_ctx_set_key (hkdfp, key, sizeof (key));
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to set HKDF input keying material");
        goto err;
    }
    rv = hkdf_ctx_set_salt (hkdfp, &salt, sizeof (salt));
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to set HKDF salt");
        goto err;
    }
    rv = hkdf_ctx_set_info (hkdfp, info, strlen (info));
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to set HKDF info");
        goto err;
    }
    rv = hkdf (hkdfp, buf, &buflen);
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to compute HKDF key derivation");
        goto err;
    }
err:
    (void) memburn (key, 0, sizeof (key));
    (void) memburn (&salt, 0, sizeof (salt));
    hkdf_ctx_destroy (hkdfp);
    return rv;
}
