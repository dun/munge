/*****************************************************************************
 *  $Id: strlcpy.h,v 1.1 2003/02/13 17:54:27 dun Exp $
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef HAVE_STRLCPY
#define HAVE_STRLCPY

size_t strlcpy(char *dst, const char *src, size_t siz);
/*
 *  Copy src to string dst of size siz.  At most siz-1 characters
 *    will be copied.  Always NUL terminates (unless siz == 0).
 *  Returns strlen(src); if retval >= siz, truncation occurred.
 */

#endif /* !HAVE_STRLCPY */
