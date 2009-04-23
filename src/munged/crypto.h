/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2009 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#ifndef CRYPTO_H
#define CRYPTO_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#if HAVE_LIBGCRYPT && HAVE_OPENSSL
#  error "Libgcrypt and OpenSSL are mutually-exclusive"
#endif


void crypto_init (void);
/*
 *  Initializes the cryptographic subsystem.
 */

void crypto_fini (void);
/*
 *  Shuts down the cryptographic subsystem.
 */


#if HAVE_OPENSSL

#include "log.h"

void openssl_log_msg (int priority);
/*
 *  Logs all OpenSSL errors in this thread's error queue (should any exist)
 *    at the specified [priority] level.
 */

#endif /* HAVE_OPENSSL */


#endif /* !CRYPTO_H */
