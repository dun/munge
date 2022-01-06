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
#include <sys/types.h>                  /* before ifaddrs.h for NetBSD 7.1.2 */
#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif /* HAVE_IFADDRS_H */
#include <limits.h>                     /* _POSIX_HOST_NAME_MAX */
#include <netdb.h>
#include <netinet/in.h>                 /* in_addr, sockaddr_in */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>                 /* AF_INET, sockaddr */
#include <unistd.h>
#include <munge.h>
#include "net.h"

/*  _HOST_NAME_MAX:
 *  The maximum length of a hostname as returned by gethostname(),
 *    not including the terminating null byte.
 *  _POSIX_HOST_NAME_MAX is the most restrictive value for this according to
 *    POSIX.1-2001.  If it is not defined, assume a conservative value.
 */
#ifdef _POSIX_HOST_NAME_MAX
#define _HOST_NAME_MAX  _POSIX_HOST_NAME_MAX
#else  /* !_POSIX_HOST_NAME_MAX */
#define _HOST_NAME_MAX  255
#endif /* !_POSIX_HOST_NAME_MAX */


/*****************************************************************************
 *  Internal Prototypes
 *****************************************************************************/

static int _net_get_hostaddr_via_ifaddrs (
        const char *name, struct in_addr *inaddrp, char **ifnamep);

#if HAVE_GETIFADDRS

static const struct ifaddrs * _net_get_ifa_via_ifname (
        const char *name, const struct ifaddrs *ifa_list);

static const struct ifaddrs * _net_get_ifa_via_addr (
        const struct hostent *h, const struct ifaddrs *ifa_list);

#endif /* HAVE_GETIFADDRS */


/*****************************************************************************
 *  External Functions
 *****************************************************************************/

/*  Lookup the hostname for the current machine.
 *  Return 0 on success with [result] set to a null-terminated string,
 *    or -1 on error.
 */
int
net_get_hostname (char **result)
{
    char  buf[_HOST_NAME_MAX + 1];      /* +1 for terminating null byte */
    char *p;

    if (result == NULL) {
        errno = EINVAL;
        return -1;
    }
    /*  When gethostname() is passed an array of insufficient length, the
     *    returned name shall be truncated, and it is unspecified whether
     *    the string will be null-terminated.
     *  When gethostname() fails, it is unspecified whether it sets errno.
     */
    if (gethostname (buf, sizeof (buf)) == -1) {
        return -1;
    }
    p = strdup (buf);
    if (p == NULL) {
        return -1;
    }
    *result = p;
    return 0;
}


/*  Lookup the network address for the [name] string which can be a hostname,
 *    IPv4 address, or local network interface name.
 *  Return 0 on success, or -1 on error.
 *  On success, [inaddrp] will be set to this address, and [ifnamep] will be
 *    set to either a new string containing the name of the corresponding local
 *    network interface (if available) or NULL (if not).  The caller is
 *    responsible for freeing this new string.
 */
int
net_get_hostaddr (const char *name, struct in_addr *inaddrp, char **ifnamep)
{
    struct hostent *h;
    int             rv;

    if ((name == NULL) || (inaddrp == NULL) || (ifnamep == NULL)) {
        errno = EINVAL;
        return -1;
    }
    rv = _net_get_hostaddr_via_ifaddrs (name, inaddrp, ifnamep);
    /*
     *  If unable to set addr via getifaddrs(), fallback to traditional lookup.
     *  FIXME: gethostbyname() obsolete as of POSIX.1-2001.  Use getaddrinfo().
     */
    if (rv < 0) {
        h = gethostbyname (name);
        if ((h != NULL) && (h->h_addrtype == AF_INET)) {
            *inaddrp = * (struct in_addr *) h->h_addr;
            rv = 0;
        }
    }
    return rv;
}


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

/*  Check if [name] matches an address assigned to a local network interface.
 *  Return 0 if a matching address is found, or -1 on error.
 *  On success, [inaddrp] will be set to this address, and [ifnamep] will be
 *    set to either a new string containing the name of the corresponding local
 *    network interface (if available) or NULL (if not).  The caller is
 *    responsible for freeing this new string.
 *  Note: getifaddrs() is not in POSIX.1-2001.
 */
static int
_net_get_hostaddr_via_ifaddrs (const char *name, struct in_addr *inaddrp,
        char **ifnamep)
{
#if HAVE_GETIFADDRS
    struct ifaddrs       *ifa_list;
    const struct ifaddrs *ifa;
    struct hostent       *h;
    int                   rv = -1;

    assert (name != NULL);
    assert (inaddrp != NULL);
    assert (ifnamep != NULL);

    if (getifaddrs (&ifa_list) < 0) {
        return -1;
    }
    /*  Check if NAME matches the name of a local network interface.
     */
    ifa = _net_get_ifa_via_ifname (name, ifa_list);
    /*
     *  Check if NAME matches a hostname or IP address assigned to a local
     *    network interface.
     *  FIXME: gethostbyname() obsolete as of POSIX.1-2001.  Use getaddrinfo().
     */
    if (ifa == NULL) {
        h = gethostbyname (name);
        if (h != NULL) {
            ifa = _net_get_ifa_via_addr (h, ifa_list);
        }
    }
    /*  If a match is found...
     */
    if (ifa != NULL) {
        *inaddrp = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
        *ifnamep = ((ifa->ifa_name != NULL) && (ifa->ifa_name[0] != '\0'))
                ? strdup (ifa->ifa_name)
                : NULL;
        rv = 0;
    }
    /*  If a match is not found, but host lookup succeeded...
     */
    else if ((h != NULL) && (h->h_addrtype == AF_INET)) {
        *inaddrp = * (struct in_addr *) h->h_addr;
        *ifnamep = NULL;
        rv = 0;
    }
    freeifaddrs (ifa_list);
    return rv;

#else  /* !HAVE_GETIFADDRS */
    errno = ENOTSUP;
    return -1;
#endif /* !HAVE_GETIFADDRS */
}


#if HAVE_GETIFADDRS

/*  Search the linked list of structures returned by getifaddrs() [ifa_list]
 *    for an interface name matching the string [name].
 *  Return a ptr to the matching ifaddrs struct, or NULL if no match is found.
 */
static const struct ifaddrs *
_net_get_ifa_via_ifname (const char *name, const struct ifaddrs *ifa_list)
{
    const struct ifaddrs *ifa;

    assert (name != NULL);
    assert (ifa_list != NULL);

    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (ifa->ifa_name == NULL) {
            continue;
        }
        if (strcmp (ifa->ifa_name, name) == 0) {
            return ifa;
        }
    }
    return NULL;
}


/*  Search the linked list of structures returned by getifaddrs() [ifa_list]
 *    for an interface IPv4 address matching [name], where [name] is either a
 *    hostname or IP address.
 *  Return a ptr to the matching ifaddrs struct, or NULL if no match is found.
 */
static const struct ifaddrs *
_net_get_ifa_via_addr (const struct hostent *h, const struct ifaddrs *ifa_list)
{
    const struct ifaddrs  *ifa;
    struct sockaddr_in    *sai;
    struct in_addr       **hap;

    assert (h != NULL);
    assert (ifa_list != NULL);

    if (h->h_addrtype != AF_INET) {
        return NULL;
    }
    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            sai = (struct sockaddr_in *) ifa->ifa_addr;
            for (hap = (struct in_addr **) h->h_addr_list; *hap; hap++) {
                if ((**hap).s_addr == sai->sin_addr.s_addr) {
                    return ifa;
                }
            }
        }
    }
    return NULL;
}

#endif /* HAVE_GETIFADDRS */
