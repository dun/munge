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

#include <munge.h>


const char *
munge_strerror (munge_err_t errnum)
{
    switch (errnum) {
        case EMUNGE_SUCCESS:
            return ("Success");
        case EMUNGE_SNAFU:
            return ("Internal error");
        case EMUNGE_BAD_ARG:
            return ("Invalid argument");
        case EMUNGE_BAD_LENGTH:
            return ("Exceeded maximum message length");
        case EMUNGE_OVERFLOW:
            return ("Buffer overflow");
        case EMUNGE_NO_MEMORY:
            return ("Out of memory");
        case EMUNGE_SOCKET:
            return ("Socket communication error");
        case EMUNGE_TIMEOUT:
            return ("Socket timeout");
        case EMUNGE_BAD_CRED:
            return ("Invalid credential format");
        case EMUNGE_BAD_VERSION:
            return ("Invalid credential version");
        case EMUNGE_BAD_CIPHER:
            return ("Invalid cipher type");
        case EMUNGE_BAD_MAC:
            return ("Invalid MAC type");
        case EMUNGE_BAD_ZIP:
            return ("Invalid compression type");
        case EMUNGE_BAD_REALM:
            return ("Unrecognized security realm");
        case EMUNGE_CRED_INVALID:
            return ("Invalid credential");
        case EMUNGE_CRED_EXPIRED:
            return ("Expired credential");
        case EMUNGE_CRED_REWOUND:
            return ("Rewound credential");
        case EMUNGE_CRED_REPLAYED:
            return ("Replayed credential");
        case EMUNGE_CRED_UNAUTHORIZED:
            return ("Unauthorized credential");
        default:
            break;
    }
    return ("Unknown error");
}
