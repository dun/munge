/*****************************************************************************
 *  Copyright (C) 2007-2025 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
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
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif /* HAVE_IFADDRS_H */
#include <netdb.h>                      /* getaddrinfo */
#include <netinet/in.h>                 /* in_addr, sockaddr_in */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>                 /* AF_INET, sockaddr */
#include <sys/types.h>
#include <munge.h>
#include "net.h"


/*****************************************************************************
 *  Internal Prototypes
 *****************************************************************************/

static int _net_resolve_local_interface (
        const char *name, struct in_addr *inaddrp, char **ifnamep);

#if HAVE_GETIFADDRS

static const struct ifaddrs * _net_find_interface_by_name (
        const char *name, const struct ifaddrs *ifa_list);

static const struct ifaddrs * _net_find_interface_by_addrinfo (
        const struct addrinfo *ai, const struct ifaddrs *ifa_list);

#endif /* HAVE_GETIFADDRS */


/*****************************************************************************
 *  External Functions
 *****************************************************************************/

/*  Resolve the network address for the [name] string which can be a hostname,
 *  IPv4 address, or local network interface name.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 *
 *  On success, [inaddrp] will be set to this address, and [ifnamep] will be
 *  set to either a new string containing the name of the corresponding local
 *  network interface (if available) or NULL (if not).  The caller is
 *  responsible for freeing this new string.
 *
 *  Note: Various getaddrinfo() failures are mapped to EHOSTUNREACH for
 *  simplicity, though the standard strerror() message ("No route to host")
 *  may not accurately describe DNS resolution failures.  Callers should
 *  provide appropriate error messages based on context.
 */
int
net_resolve_address (const char *name, struct in_addr *inaddrp, char **ifnamep)
{
    struct addrinfo hints, *res;
    struct sockaddr_in *sin;
    int rv;

    if (!name || !inaddrp || !ifnamep) {
        errno = EINVAL;
        return -1;
    }
    /*  First try to resolve as a local network interface.
     */
    rv = _net_resolve_local_interface (name, inaddrp, ifnamep);
    if (rv == 0) {
        return 0;
    }
    /*  Then fall back to standard hostname/address resolution.
     *  Set hints.ai_socktype since some older systems might return
     *    duplicate results without it.
     */
    memset (&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo (name, NULL, &hints, &res);
    if (rv != 0) {
        switch (rv) {
            case EAI_MEMORY:
                errno = ENOMEM;
                break;
            case EAI_ADDRFAMILY:
                errno = ENOTSUP;
                break;
            case EAI_NONAME:
            case EAI_NODATA:
            case EAI_AGAIN:
            case EAI_FAIL:
                errno = EHOSTUNREACH;
                break;
            case EAI_SYSTEM:
                /* errno already set */
                break;
            default:
                errno = EINVAL;
                break;
        }
        return -1;
    }
    sin = (struct sockaddr_in *) res->ai_addr;
    *inaddrp = sin->sin_addr;
    *ifnamep = NULL;
    freeaddrinfo (res);
    return 0;
}


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

/*  Check if [name] matches a local network interface or resolves to an address
 *  assigned to a local network interface.
 *
 *  [name] can be a:
 *  - network interface name
 *  - IPv4 address that is assigned to a local interface
 *  - hostname that resolves to an IPv4 address assigned to a local interface
 *
 *  Return 0 if a matching local interface is found, or -1 on error.
 *
 *  On success, [inaddrp] will be set to the interface's address, and [ifnamep]
 *  will be set to either a new string containing the name of the interface or
 *  NULL (if the interface name is unavailable).  The caller is responsible for
 *  freeing this string.
 */
static int
_net_resolve_local_interface (const char *name, struct in_addr *inaddrp,
        char **ifnamep)
{
#if HAVE_GETIFADDRS
    struct ifaddrs *ifa_list;
    const struct ifaddrs *ifa;
    struct addrinfo hints, *res;
    int gai_error;
    int rv = -1;

    assert (name != NULL);
    assert (inaddrp != NULL);
    assert (ifnamep != NULL);

    if (getifaddrs (&ifa_list) < 0) {
        return -1;
    }
    /*  Try interface name match
     */
    ifa = _net_find_interface_by_name (name, ifa_list);

    if (ifa == NULL) {
        /*
         *  Try numeric IP match
         */
        memset (&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICHOST;

        gai_error = getaddrinfo (name, NULL, &hints, &res);
        if (gai_error == 0) {
            ifa = _net_find_interface_by_addrinfo (res, ifa_list);
            freeaddrinfo (res);
        }
        else if (gai_error == EAI_NONAME) {
            /*
             *  Try hostname resolution match
             */
            hints.ai_flags = 0;
            gai_error = getaddrinfo (name, NULL, &hints, &res);
            if (gai_error == 0) {
                ifa = _net_find_interface_by_addrinfo (res, ifa_list);
                freeaddrinfo (res);
            }
        }
    }
    /*  If a matching interface is found, set [inaddrp] and [ifnamep].
     */
    if (ifa != NULL) {
        *inaddrp = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
        *ifnamep = ((ifa->ifa_name != NULL) && (ifa->ifa_name[0] != '\0'))
            ? strdup (ifa->ifa_name)
            : NULL;
        if ((*ifnamep == NULL) && (ifa->ifa_name != NULL)) {
            /* strdup() failed */
            errno = ENOMEM;
            rv = -1;
        }
        else {
            rv = 0;
        }
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
 *  for an interface name matching the string [name].
 *
 *  Return a ptr to the matching ifaddrs struct, or NULL if no match is found.
 */
static const struct ifaddrs *
_net_find_interface_by_name (const char *name, const struct ifaddrs *ifa_list)
{
    const struct ifaddrs *ifa;

    assert (name != NULL);
    assert (ifa_list != NULL);

    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_name == NULL)
            continue;
        if (strcmp (ifa->ifa_name, name) == 0)
            return ifa;
    }
    return NULL;
}


/*  Search the linked list of structures returned by getifaddrs() [ifa_list]
 *  for an interface IPv4 address matching any address in [ai].
 *
 *  Return a ptr to the matching ifaddrs struct, or NULL if no match is found.
 */
static const struct ifaddrs *
_net_find_interface_by_addrinfo (const struct addrinfo *ai,
        const struct ifaddrs *ifa_list)
{
    const struct ifaddrs *ifa;
    struct sockaddr_in *ifa_addr, *ai_addr;
    const struct addrinfo *aip;

    assert (ai != NULL);
    assert (ifa_list != NULL);

    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        ifa_addr = (struct sockaddr_in *) ifa->ifa_addr;

        for (aip = ai; aip != NULL; aip = aip->ai_next) {
            if (aip->ai_family != AF_INET)
                continue;
            ai_addr = (struct sockaddr_in *) aip->ai_addr;
            if (ai_addr->sin_addr.s_addr == ifa_addr->sin_addr.s_addr)
                return ifa;
        }
    }
    return NULL;
}

#endif /* HAVE_GETIFADDRS */
