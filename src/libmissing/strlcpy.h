/*****************************************************************************
 *  $Id: strlcpy.h,v 1.2 2003/02/18 19:46:20 dun Exp $
 *****************************************************************************/

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#if HAVE_STRLCPY
#else /* !HAVE_STRLCPY */
#define HAVE_STRLCPY 1

size_t strlcpy(char *dst, const char *src, size_t siz);
/*
 *  Copy src to string dst of size siz.  At most siz-1 characters
 *    will be copied.  Always NUL terminates (unless siz == 0).
 *  Returns strlen(src); if retval >= siz, truncation occurred.
 */

#endif /* !HAVE_STRLCPY */
