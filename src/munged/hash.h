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
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#ifndef HASH_H
#define HASH_H


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  If an item's key is modified after insertion, the hash will be unable to
 *  locate it if the new key should hash to a different slot in the table.
 *
 *  If WITH_PTHREADS is defined, these routines will be thread-safe.
 */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct hash * hash_t;
/*
 *  Hash table opaque data type.
 */

typedef unsigned int (*hash_key_f) (const void *key);
/*
 *  Function prototype for the hash function responsible for converting
 *    the data's [key] into an unsigned integer hash value.
 */

typedef int (*hash_cmp_f) (const void *key1, const void *key2);
/*
 *  Function prototype for comparing two keys.
 *  Returns an integer that is less than zero if [key1] is less than [key2],
 *    equal to zero if [key1] is equal to [key2], and greater than zero if
 *    [key1] is greater than [key2].
 */

typedef void (*hash_del_f) (void *data);
/*
 *  Function prototype for de-allocating a data item stored within a hash.
 *  This function is responsible for freeing all memory associated with
 *    the [data] item, including any subordinate items.
 */

typedef int (*hash_arg_f) (void *data, const void *key, void *arg);
/*
 *  Function prototype for operating on each element in the hash table.
 *  The function will be invoked once for each [data] item in the hash,
 *    with the item's [key] and the specified [arg] being passed in as args.
 */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

hash_t hash_create (int size,
    hash_key_f key_f, hash_cmp_f cmp_f, hash_del_f del_f);

void hash_destroy (hash_t h);

void hash_reset (hash_t h);

int hash_is_empty (hash_t h);

int hash_count (hash_t h);

void * hash_find (hash_t h, const void *key);

void * hash_insert (hash_t h, const void *key, void *data);

void * hash_remove (hash_t h, const void *key);

int hash_delete_if (hash_t h, hash_arg_f argf, void *arg);

int hash_for_each (hash_t h, hash_arg_f argf, void *arg);

void hash_drop_memory (void);

unsigned int hash_key_string (const char *str);


#endif /* !HASH_H */
