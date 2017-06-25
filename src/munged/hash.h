/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2017 Lawrence Livermore National Security, LLC.
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
/*
 *  Creates and returns a new hash table on success.
 *    Returns lsd_nomem_error() with errno=ENOMEM if memory allocation fails.
 *    Returns NULL with errno=EINVAL if [keyf] or [cmpf] is not specified.
 *  The [size] is the number of slots in the table; a larger table requires
 *    more memory, but generally provide quicker access times.  If set <= 0,
 *    the default size is used.
 *  The [keyf] function converts a key into a hash value.
 *  The [cmpf] function determines whether two keys are equal.
 *  The [delf] function de-allocates memory used by items in the hash;
 *    if set to NULL, memory associated with these items will not be freed
 *    when the hash is destroyed.
 */

void hash_destroy (hash_t h);
/*
 *  Destroys hash table [h].  If a deletion function was specified when the
 *    hash was created, it will be called for each item contained within.
 *  Abadoning a hash without calling hash_destroy() will cause a memory leak.
 */

void hash_reset (hash_t h);
/*
 *  Resets hash table [h] back to an empty state.  If a deletion function was
 *    specified when the hash was created, it will be called for each item
 *    contained within.
 */

int hash_is_empty (hash_t h);
/*
 *  Returns non-zero if hash table [h] is empty; o/w, returns zero.
 */

int hash_count (hash_t h);
/*
 *  Returns the number of items in hash table [h].
 */

void * hash_find (hash_t h, const void *key);
/*
 *  Searches for the item corresponding to [key] in hash table [h].
 *  Returns a ptr to the found item's data on success.
 *    Returns NULL with errno=0 if no matching item is found.
 *    Returns NULL with errno=EINVAL if [key] is not specified.
 */

void * hash_insert (hash_t h, const void *key, void *data);
/*
 *  Inserts [data] with the corresponding [key] into hash table [h];
 *    note that it is permissible for [key] to be set equal to [data].
 *  Returns a ptr to the inserted item's data on success.
 *    Returns NULL with errno=EEXIST if [key] already exists in the hash.
 *    Returns NULL with errno=EINVAL if [key] or [data] is not specified.
 *    Returns lsd_nomem_error() with errno=ENOMEM if memory allocation fails.
 */

void * hash_remove (hash_t h, const void *key);
/*
 *  Removes the item corresponding to [key] from hash table [h].
 *  Returns a ptr to the removed item's data on success.
 *    Returns NULL with errno=0 if no matching item is found.
 *    Returns NULL with errno=EINVAL if [key] is not specified.
 */

int hash_delete_if (hash_t h, hash_arg_f argf, void *arg);
/*
 *  Conditionally deletes (and de-allocates) items from hash table [h].
 *  The [argf] function is invoked once for each item in the hash, with
 *    [arg] being passed in as an argument.  Items for which [argf] returns
 *    greater-than-zero are deleted.
 *  Returns the number of items deleted.
 *    Returns -1 with errno=EINVAL if [argf] is not specified.
 */

int hash_for_each (hash_t h, hash_arg_f argf, void *arg);
/*
 *  Invokes the [argf] function once for each item in hash table [h],
 *    with [arg] being passed in as an argument.
 *  Returns the number of items for which [argf] returns greater-than-zero.
 *    Returns -1 with errno=EINVAL if [argf] is not specified.
 */

unsigned int hash_key_string (const char *str);
/*
 *  A hash_key_f function that hashes the string [str].
 */

void hash_drop_memory (void);
/*
 *  Frees memory that has been internally allocated.  No reference counting is
 *    performed to determine whether memory regions are still in use.
 *  This may be useful for explicitly de-allocating memory before program
 *    termination when checking for memory leaks.
 *  WARNING: Do not call this routine until ALL hashes have been destroyed.
 */


#endif /* !HASH_H */
