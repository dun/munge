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
#include <errno.h>
#include <fcntl.h>
#include <string.h>
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

static int _create_key_secret (unsigned char *buf, size_t buflen);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Create a key for the config in [confp].
 */
void
create_key (conf_t *confp)
{
    unsigned char buf[MUNGE_KEY_LEN_MAX_BYTES];
    int           fd;
    int           n;
    int           rv;

    assert (confp != NULL);
    assert (confp->key_num_bytes <= MUNGE_KEY_LEN_MAX_BYTES);
    assert (confp->key_num_bytes >= MUNGE_KEY_LEN_MIN_BYTES);

    if (confp->key_num_bytes > sizeof (buf)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create \"%s\": %d-byte key exceeds %zu-byte buffer",
                confp->key_path, confp->key_num_bytes, sizeof (buf));
    }
    if (confp->do_force) {
        do {
            rv = unlink (confp->key_path);
        } while ((rv == -1) && (errno == EINTR));

        if ((rv == -1) && (errno != ENOENT)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to remove \"%s\"",
                    confp->key_path);
        }
    }
    fd = open (confp->key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create \"%s\"",
                confp->key_path);
    }
    rv = _create_key_secret (buf, confp->key_num_bytes);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create \"%s\"",
                confp->key_path);
    }
    n = fd_write_n (fd, buf, confp->key_num_bytes);
    if (n != confp->key_num_bytes) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to write %d bytes to \"%s\"",
                confp->key_num_bytes, confp->key_path);
    }
    rv = close (fd);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close \"%s\"",
                confp->key_path);
    }
    (void) memburn (buf, 0, sizeof (buf));
    if (confp->do_verbose) {
        log_msg (LOG_INFO, "Created \"%s\" with %d-bit key",
                confp->key_path, confp->key_num_bytes * 8);
    }
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

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
