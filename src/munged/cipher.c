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
#include <munge.h>
#include <string.h>
#include "cipher.h"


/*****************************************************************************
 *  Private Data
 *****************************************************************************/

static int _cipher_is_initialized = 0;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void _cipher_init_subsystem (void);
static int _cipher_init (cipher_ctx *x, munge_cipher_t cipher,
    unsigned char *key, unsigned char *iv, int enc);
static int _cipher_update (cipher_ctx *x, void *dst, int *dstlenp,
    const void *src, int srclen);
static int _cipher_final (cipher_ctx *x, void *dst, int *dstlenp);
static int _cipher_cleanup (cipher_ctx *x);
static int _cipher_block_size (munge_cipher_t cipher);
static int _cipher_iv_size (munge_cipher_t cipher);
static int _cipher_key_size (munge_cipher_t cipher);
static int _cipher_map_enum (munge_cipher_t cipher, void *dst);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
cipher_init_subsystem (void)
{
/*  Note that this call is *NOT* thread-safe.
 */
    if (! _cipher_is_initialized) {
        _cipher_init_subsystem ();
        _cipher_is_initialized++;
    }
    return;
}


int
cipher_init (cipher_ctx *x, munge_cipher_t cipher,
             unsigned char *key, unsigned char *iv, int enc)
{
    int rc;

    assert (_cipher_is_initialized);

    if (!x || !key || !iv
            || !((enc == CIPHER_DECRYPT) || (enc == CIPHER_ENCRYPT))) {
        return (-1);
    }
    rc = _cipher_init (x, cipher, key, iv, enc);
    return (rc);
}


int
cipher_update (cipher_ctx *x, void *dst, int *dstlenp,
               const void *src, int srclen)
{
    int rc;

    assert (_cipher_is_initialized);

    if (!x || !dst || !dstlenp || (*dstlenp < 0) || !src || (srclen < 0)) {
        return (-1);
    }
    rc = _cipher_update (x, dst, dstlenp, src, srclen);
    return (rc);
}


int
cipher_final (cipher_ctx *x, void *dst, int *dstlenp)
{
    int rc;

    assert (_cipher_is_initialized);

    if (!x || !dst || !dstlenp || (*dstlenp < 0)) {
        return (-1);
    }
    rc = _cipher_final (x, dst, dstlenp);
    return (rc);
}


int
cipher_cleanup (cipher_ctx *x)
{
    int rc;

    assert (_cipher_is_initialized);

    if (!x) {
        return (-1);
    }
    rc = _cipher_cleanup (x);
    memset (x, 0, sizeof (*x));
    return (rc);
}


int
cipher_block_size (munge_cipher_t cipher)
{
    assert (_cipher_is_initialized);
    return (_cipher_block_size (cipher));
}


int
cipher_iv_size (munge_cipher_t cipher)
{
    assert (_cipher_is_initialized);
    return (_cipher_iv_size (cipher));
}


int
cipher_key_size (munge_cipher_t cipher)
{
    assert (_cipher_is_initialized);
    return (_cipher_key_size (cipher));
}


int
cipher_map_enum (munge_cipher_t cipher, void *dst)
{
    assert (_cipher_is_initialized);
    return (_cipher_map_enum (cipher, dst));
}


/*****************************************************************************
 *  Private Functions (Libgcrypt)
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>
#include <string.h>
#include "common.h"
#include "log.h"

static int _cipher_map [MUNGE_CIPHER_LAST_ITEM];

static int _cipher_update_aux (cipher_ctx *x, void *dst, int *dstlenp,
    const void *src, int srclen);


void
_cipher_init_subsystem (void)
{
    int i;

    for (i = 0; i < MUNGE_CIPHER_LAST_ITEM; i++) {
        _cipher_map [i] = -1;
    }
    _cipher_map [MUNGE_CIPHER_BLOWFISH] = GCRY_CIPHER_BLOWFISH;
    _cipher_map [MUNGE_CIPHER_CAST5] = GCRY_CIPHER_CAST5;
    _cipher_map [MUNGE_CIPHER_AES128] = GCRY_CIPHER_AES128;
    _cipher_map [MUNGE_CIPHER_AES256] = GCRY_CIPHER_AES256;
    return;
}


static int
_cipher_init (cipher_ctx *x, munge_cipher_t cipher,
              unsigned char *key, unsigned char *iv, int enc)
{
    gcry_error_t  e;
    int           algo;
    size_t        nbytes;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    e = gcry_cipher_open (&(x->ctx), algo, GCRY_CIPHER_MODE_CBC, 0);
    if (e != 0) {
        log_msg (LOG_DEBUG, "gcry_cipher_open failed for cipher=%d: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    e = gcry_cipher_algo_info (algo, GCRYCTL_GET_KEYLEN, NULL, &nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG,
            "gcry_cipher_algo_info failed for cipher=%d key length: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    e = gcry_cipher_setkey (x->ctx, key, nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG, "gcry_cipher_setkey failed for cipher=%d: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    e = gcry_cipher_algo_info (algo, GCRYCTL_GET_BLKLEN, NULL, &nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG,
            "gcry_cipher_algo_info failed for cipher=%d block length: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    e = gcry_cipher_setiv (x->ctx, iv, nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG, "gcry_cipher_setiv failed for cipher=%d: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    x->do_encrypt = enc;
    x->len = 0;
    x->blklen = (int) nbytes;
    return (0);
}


static int
_cipher_update (cipher_ctx *x, void *vdst, int *dstlenp,
                const void *vsrc, int srclen)
{
/*  During encryption, any remaining src data that is not a multiple of the
 *    cipher block size is saved in the context's partial block buffer.
 *    This buffer will be padded when the encryption is finalized
 *    (see PKCS #5, rfc2898).
 *  During decryption, the partial block buffer will always contain data at
 *    the end of each update to ensure the padding is properly removed when
 *    the decryption is finalized.
 */
    int            n;
    int            n_written;
    int            n_partial;
    int            n_complete;
    unsigned char *dst = vdst;
    unsigned char *src = (void *) vsrc;

    n_written = 0;
    /*
     *  Continue processing a partial block if one exists.
     */
    if (x->len > 0) {
        assert (x->len < x->blklen);
        n_partial = MIN (srclen, x->blklen - x->len);
        memcpy (&(x->buf[x->len]), src, n_partial);
        x->len += n_partial;
        src += n_partial;
        srclen -= n_partial;

        /*  If the partial block buffer is full, process the block unless
         *    decryption is being performed and there is no more data.
         *    This exception is to ensure _cipher_final() is able to
         *    validate & remove the PKCS #5 padding.
         */
        if (x->len == x->blklen) {
            if ((x->do_encrypt) || (srclen > 0)) {
                n = *dstlenp;
                if (_cipher_update_aux (x, dst, &n, x->buf, x->blklen) < 0) {
                    goto err;
                }
                assert (n == x->blklen);
                dst += n;
                n_written += n;
                x->len = 0;
            }
        }
    }
    /*  Compute the number of bytes for complete blocks, and the remainder
     *    that will be saved in the partial block buffer.  During decryption,
     *    the partial block buffer will always contain data to ensure
     *    _cipher_final() is able to validate & remove the PKCS #5 padding.
     */
    n_partial = srclen % x->blklen;
    if ((!x->do_encrypt) && (n_partial == 0)) {
        n_partial = x->blklen;
    }
    n_complete = srclen - n_partial;

    /*  Process complete blocks.
     */
    if (n_complete > 0) {
        assert (x->len == 0);
        assert (n_complete % x->blklen == 0);
        n = *dstlenp - n_written;
        if (_cipher_update_aux (x, dst, &n, src, n_complete) < 0) {
            goto err;
        }
        assert (n == n_complete);
        src += n;
        srclen -= n;
        n_written += n;
    }
    /*  Copy src leftovers to the partial block buf.
     */
    if (n_partial > 0) {
        assert (x->len == 0);
        assert (n_partial <= x->blklen);
        memcpy (x->buf, src, n_partial);
        x->len = n_partial;
    }
    /*  Ensure the partial block buffer is never empty during decryption.
     */
    assert ((x->do_encrypt) || (x->len > 0));

    /*  Set the number of bytes written.
     */
    *dstlenp = n_written;
    return (0);

err:
    *dstlenp = 0;
    return (-1);
}


static int
_cipher_update_aux (cipher_ctx *x, void *dst, int *dstlenp,
                    const void *src, int srclen)
{
    gcry_error_t e;
    int          dstlen = *dstlenp;

    if (x->do_encrypt) {
        e = gcry_cipher_encrypt (x->ctx, dst, dstlen, src, srclen);
    }
    else {
        e = gcry_cipher_decrypt (x->ctx, dst, dstlen, src, srclen);
    }
    if (e != 0) {
        log_msg (LOG_DEBUG, "%s failed: %s",
            (x->do_encrypt ? "gcry_cipher_encrypt" : "gcry_cipher_decrypt"),
            gcry_strerror (e));
        *dstlenp = 0;
        return (-1);
    }
    if ((src != NULL) || (srclen != 0)) {
        *dstlenp = srclen;
    }
    return (0);
}


static int
_cipher_final (cipher_ctx *x, void *dst, int *dstlenp)
{
    int n;
    int i;
    int pad;

    if (x->do_encrypt) {
        assert (x->len < x->blklen);
        pad = x->blklen - x->len;
        for (i = x->len; i < x->blklen; i++) {
            x->buf[i] = pad;
        }
        if (_cipher_update_aux (x, dst, dstlenp, x->buf, x->blklen) < 0) {
            return (-1);
        }
    }
    else {
        /*  Final cipher block should always be full due to padding.
         */
        if (x->len != x->blklen) {
            log_msg (LOG_DEBUG,
                "Final decryption block has only %d of %d bytes",
                x->len, x->blklen);
            return (-1);
        }
        /*  Perform in-place decryption of final cipher block.
         */
        n = x->blklen;
        if (_cipher_update_aux (x, x->buf, &n, NULL, 0) < 0) {
            return (-1);
        }
        assert (n == x->blklen);
        /*
         *  Validate PKCS #5 block padding.
         */
        pad = x->buf[x->blklen - 1];
        if ((pad <= 0) || (pad > x->blklen)) {
            log_msg (LOG_DEBUG,
                "Final decryption block has invalid pad of %d", pad);
            return (-1);
        }
        for (i = x->blklen - pad; i < x->blklen; i++) {
            if (x->buf[i] != pad) {
                log_msg (LOG_DEBUG,
                    "Final decryption block has padding error at byte %d", i);
                return (-1);
            }
        }
        /*  Copy decrypted plaintext to dst.
         */
        n = x->blklen - pad;
        if (n > 0) {
            if (*dstlenp < n) {
                return (-1);
            }
            memcpy (dst, x->buf, n);
        }
        *dstlenp = n;
    }
    return (0);
}


static int
_cipher_cleanup (cipher_ctx *x)
{
    gcry_cipher_close (x->ctx);
    return (0);
}


static int
_cipher_block_size (munge_cipher_t cipher)
{
    gcry_error_t e;
    int          algo;
    size_t       nbytes;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    e = gcry_cipher_algo_info (algo, GCRYCTL_GET_BLKLEN, NULL, &nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG,
            "gcry_cipher_algo_info failed for cipher=%d block length: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    return (nbytes);
}


static int
_cipher_iv_size (munge_cipher_t cipher)
{
    return (_cipher_block_size (cipher));
}


static int
_cipher_key_size (munge_cipher_t cipher)
{
    gcry_error_t e;
    int          algo;
    size_t       nbytes;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    e = gcry_cipher_algo_info (algo, GCRYCTL_GET_KEYLEN, NULL, &nbytes);
    if (e != 0) {
        log_msg (LOG_DEBUG,
            "gcry_cipher_algo_info failed for cipher=%d key length: %s",
            cipher, gcry_strerror (e));
        return (-1);
    }
    return (nbytes);
}


static int
_cipher_map_enum (munge_cipher_t cipher, void *dst)
{
    int algo = -1;

    if ((cipher > MUNGE_CIPHER_DEFAULT) && (cipher < MUNGE_CIPHER_LAST_ITEM)) {
        algo = _cipher_map [cipher];
    }
    if (algo < 0) {
        return (-1);
    }
    if (dst != NULL) {
        * (int *) dst = algo;
    }
    return (0);
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/

#if HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/evp.h>

static const EVP_CIPHER *_cipher_map [MUNGE_CIPHER_LAST_ITEM];


void
_cipher_init_subsystem (void)
{
    int i;

    for (i = 0; i < MUNGE_CIPHER_LAST_ITEM; i++) {
        _cipher_map [i] = NULL;
    }
    _cipher_map [MUNGE_CIPHER_BLOWFISH] = EVP_bf_cbc ();
    _cipher_map [MUNGE_CIPHER_CAST5] = EVP_cast5_cbc ();

#if HAVE_EVP_AES_128_CBC
    _cipher_map [MUNGE_CIPHER_AES128] = EVP_aes_128_cbc ();
#endif /* HAVE_EVP_AES_128_CBC */

#if HAVE_EVP_AES_256_CBC && HAVE_EVP_SHA256
    _cipher_map [MUNGE_CIPHER_AES256] = EVP_aes_256_cbc ();
#endif /* HAVE_EVP_AES_256_CBC && HAVE_EVP_SHA256 */

    return;
}


static int
_cipher_init (cipher_ctx *x, munge_cipher_t cipher,
              unsigned char *key, unsigned char *iv, int enc)
{
    EVP_CIPHER *algo;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
#if HAVE_EVP_CIPHER_CTX_NEW
    /*  OpenSSL >= 0.9.8b  */
    x->ctx = EVP_CIPHER_CTX_new ();
#else  /* !HAVE_EVP_CIPHER_CTX_NEW */
    x->ctx = OPENSSL_malloc (sizeof (EVP_CIPHER_CTX));
#endif /* !HAVE_EVP_CIPHER_CTX_NEW */
    if (x->ctx == NULL) {
        return (-1);
    }

#if HAVE_EVP_CIPHERINIT_EX
#if HAVE_EVP_CIPHER_CTX_INIT
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    EVP_CIPHER_CTX_init (x->ctx);
#endif /* HAVE_EVP_CIPHER_CTX_INIT */
    /*  OpenSSL >= 0.9.7  */
    if (EVP_CipherInit_ex (x->ctx, algo, NULL, key, iv, enc) != 1) {
        return (-1);
    }
#elif HAVE_EVP_CIPHERINIT_RETURN_INT
    /*  EVP_CipherInit() implicitly initializes the EVP_CIPHER_CTX.  */
    /*  OpenSSL > 0.9.5a  */
    if (EVP_CipherInit (x->ctx, algo, key, iv, enc) != 1) {
        return (-1);
    }
#elif HAVE_EVP_CIPHERINIT
    /*  EVP_CipherInit() implicitly initializes the EVP_CIPHER_CTX.  */
    /*  OpenSSL <= 0.9.5a  */
    EVP_CipherInit (x->ctx, algo, key, iv, enc);
#else  /* !HAVE_EVP_CIPHERINIT */
#error "No OpenSSL EVP_CipherInit"
#endif /* !HAVE_EVP_CIPHERINIT */

    return (0);
}


static int
_cipher_update (cipher_ctx *x, void *dst, int *dstlenp,
                const void *src, int srclen)
{
#if HAVE_EVP_CIPHERUPDATE_RETURN_INT
    /*  OpenSSL > 0.9.5a  */
    if (EVP_CipherUpdate (x->ctx, dst, dstlenp, (void *) src, srclen) != 1) {
        return (-1);
    }
#elif HAVE_EVP_CIPHERUPDATE
    /*  OpenSSL <= 0.9.5a  */
    EVP_CipherUpdate (x->ctx, dst, dstlenp, (void *) src, srclen);
#else  /* !HAVE_EVP_CIPHERUPDATE */
#error "No OpenSSL EVP_CipherUpdate"
#endif /* !HAVE_EVP_CIPHERUPDATE */

    return (0);
}


static int
_cipher_final (cipher_ctx *x, void *dst, int *dstlenp)
{
#if HAVE_EVP_CIPHERFINAL_EX
    /*  OpenSSL >= 0.9.7  */
    if (EVP_CipherFinal_ex (x->ctx, dst, dstlenp) != 1) {
        return (-1);
    }
#elif HAVE_EVP_CIPHERFINAL
    if (EVP_CipherFinal (x->ctx, dst, dstlenp) != 1) {
        return (-1);
    }
#else  /* !HAVE_EVP_CIPHERFINAL */
#error "No OpenSSL EVP_CipherFinal"
#endif /* !HAVE_EVP_CIPHERFINAL */

    return (0);
}


static int
_cipher_cleanup (cipher_ctx *x)
{
    int rv = 0;

#if HAVE_EVP_CIPHER_CTX_FREE
    /*  OpenSSL >= 0.9.8b  */
    EVP_CIPHER_CTX_free (x->ctx);
#else  /* !HAVE_EVP_CIPHER_CTX_FREE */
#if HAVE_EVP_CIPHER_CTX_CLEANUP_RETURN_INT
    /*  OpenSSL > 0.9.5a, < 1.1.0  */
    if (EVP_CIPHER_CTX_cleanup (x->ctx) != 1) {
        rv = -1;
    }
#elif HAVE_EVP_CIPHER_CTX_CLEANUP
    /*  OpenSSL <= 0.9.5a  */
    EVP_CIPHER_CTX_cleanup (x->ctx);
#endif /* HAVE_EVP_CIPHER_CTX_CLEANUP */
    OPENSSL_free (x->ctx);
#endif /* !HAVE_EVP_CIPHER_CTX_FREE */

    x->ctx = NULL;
    return (rv);
}


static int
_cipher_block_size (munge_cipher_t cipher)
{
    EVP_CIPHER *algo;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    return (EVP_CIPHER_block_size (algo));
}


static int
_cipher_iv_size (munge_cipher_t cipher)
{
    EVP_CIPHER *algo;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    return (EVP_CIPHER_iv_length (algo));
}


static int
_cipher_key_size (munge_cipher_t cipher)
{
    EVP_CIPHER *algo;

    if (_cipher_map_enum (cipher, &algo) < 0) {
        return (-1);
    }
    return (EVP_CIPHER_key_length (algo));
}


static int
_cipher_map_enum (munge_cipher_t cipher, void *dst)
{
    const EVP_CIPHER *algo = NULL;

    if ((cipher > MUNGE_CIPHER_DEFAULT) && (cipher < MUNGE_CIPHER_LAST_ITEM)) {
        algo = _cipher_map [cipher];
    }
    if (algo == NULL) {
        return (-1);
    }
    if (dst != NULL) {
        * (const EVP_CIPHER **) dst = algo;
    }
    return (0);
}

#endif /* HAVE_OPENSSL */
