/*****************************************************************************
 *  $Id: strlcat.h,v 1.1 2003/02/13 17:54:27 dun Exp $
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef HAVE_STRLCAT
#define HAVE_STRLCAT

size_t strlcat(char *dst, const char *src, size_t siz);
/*
 *  Appends src to string dst of size siz (unlike strncat, siz is the
 *    full size of dst, not space left).  At most siz-1 characters
 *    will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 *  Returns strlen(src) + MIN(siz, strlen(initial dst)).
 *  If retval >= siz, truncation occurred.
 */

#endif /* !HAVE_STRLCAT */
