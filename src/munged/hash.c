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
 *****************************************************************************
 *  Refer to "hash.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "thread.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define HASH_DEF_SIZE           1213
#define HASH_NODE_ALLOC_NUM     1024


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct hash_node {
    struct hash_node   *next;           /* next node in list                 */
    void               *data;           /* ptr to hashed item                */
    const void         *hkey;           /* ptr to hashed item's key          */
};

struct hash {
    int                 count;          /* number of items in hash table     */
    int                 size;           /* num slots allocated in hash table */
    struct hash_node  **table;          /* hash table array of node ptrs     */
    hash_cmp_f          cmp_f;          /* key comparison function           */
    hash_del_f          del_f;          /* item deletion function            */
    hash_key_f          key_f;          /* key hash function                 */
#if WITH_PTHREADS
    pthread_mutex_t     mutex;          /* mutex to protect access to hash   */
#endif /* WITH_PTHREADS */
};


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static struct hash_node * hash_node_alloc (void);

static void hash_node_free (struct hash_node *node);


/*****************************************************************************
 *  Variables
 *****************************************************************************/

static struct hash_node *hash_mem_list = NULL;
/*
 *  Singly-linked list for tracking memory allocations from hash_node_alloc()
 *    for eventual de-allocation via hash_drop_memory().  Each block allocation
 *    begins with a pointer for chaining these allocations together.  The block
 *    is broken up into individual hash_node structs and placed on the
 *    hash_free_list.
 */

static struct hash_node *hash_free_list = NULL;
/*
 *  Singly-linked list of hash_node structs available for use.  These are
 *    allocated via hash_node_alloc() in blocks of HASH_NODE_ALLOC_NUM.  This
 *    bulk approach uses less RAM and CPU than allocating/de-allocating objects
 *    individually as needed.
 */

#if WITH_PTHREADS
static pthread_mutex_t hash_free_list_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 *  Mutex for protecting access to hash_mem_list and hash_free_list.
 */
#endif /* WITH_PTHREADS */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

hash_t
hash_create (int size, hash_key_f key_f, hash_cmp_f cmp_f, hash_del_f del_f)
{
    hash_t h;

    if (!cmp_f || !key_f) {
        errno = EINVAL;
        return (NULL);
    }
    if (size <= 0) {
        size = HASH_DEF_SIZE;
    }
    if (!(h = malloc (sizeof (*h)))) {
        return (NULL);
    }
    if (!(h->table = calloc (size, sizeof (struct hash_node *)))) {
        free (h);
        return (NULL);
    }
    h->count = 0;
    h->size = size;
    h->cmp_f = cmp_f;
    h->del_f = del_f;
    h->key_f = key_f;
    lsd_mutex_init (&h->mutex);
    return (h);
}


void
hash_destroy (hash_t h)
{
    int i;
    struct hash_node *p, *q;

    if (!h) {
        errno = EINVAL;
        return;
    }
    lsd_mutex_lock (&h->mutex);
    for (i = 0; i < h->size; i++) {
        for (p = h->table[i]; p != NULL; p = q) {
            q = p->next;
            if (h->del_f)
                h->del_f (p->data);
            hash_node_free (p);
        }
    }
    lsd_mutex_unlock (&h->mutex);
    lsd_mutex_destroy (&h->mutex);
    free (h->table);
    free (h);
    return;
}


void hash_reset (hash_t h)
{
    int i;
    struct hash_node *p, *q;

    if (!h) {
        errno = EINVAL;
        return;
    }
    lsd_mutex_lock (&h->mutex);
    for (i = 0; i < h->size; i++) {
        for (p = h->table[i]; p != NULL; p = q) {
            q = p->next;
            if (h->del_f)
                h->del_f (p->data);
            hash_node_free (p);
        }
        h->table[i] = NULL;
    }
    h->count = 0;
    lsd_mutex_unlock (&h->mutex);
    return;
}


int
hash_is_empty (hash_t h)
{
    int n;

    if (!h) {
        errno = EINVAL;
        return (0);
    }
    lsd_mutex_lock (&h->mutex);
    n = h->count;
    lsd_mutex_unlock (&h->mutex);
    return (n == 0);
}


int
hash_count (hash_t h)
{
    int n;

    if (!h) {
        errno = EINVAL;
        return (0);
    }
    lsd_mutex_lock (&h->mutex);
    n = h->count;
    lsd_mutex_unlock (&h->mutex);
    return (n);
}


void *
hash_find (hash_t h, const void *key)
{
    unsigned int slot;
    int cmpval;
    struct hash_node *p;
    void *data = NULL;

    if (!h || !key) {
        errno = EINVAL;
        return (NULL);
    }
    errno = 0;
    lsd_mutex_lock (&h->mutex);
    slot = h->key_f (key) % h->size;
    for (p = h->table[slot]; p != NULL; p = p->next) {
        cmpval = h->cmp_f (p->hkey, key);
        if (cmpval < 0) {
            continue;
        }
        if (cmpval == 0) {
            data = p->data;
        }
        break;
    }
    lsd_mutex_unlock (&h->mutex);
    return (data);
}


void *
hash_insert (hash_t h, const void *key, void *data)
{
    unsigned int slot;
    int cmpval;
    struct hash_node **pp;
    struct hash_node *p;

    if (!h || !key || !data) {
        errno = EINVAL;
        return (NULL);
    }
    lsd_mutex_lock (&h->mutex);
    slot = h->key_f (key) % h->size;
    for (pp = &(h->table[slot]); (p = *pp) != NULL; pp = &(p->next)) {
        cmpval = h->cmp_f (p->hkey, key);
        if (cmpval < 0) {
            continue;
        }
        if (cmpval == 0) {
            errno = EEXIST;
            data = NULL;
            goto end;
        }
        break;
    }
    if (!(p = hash_node_alloc ())) {
        data = NULL;
        goto end;
    }
    p->hkey = key;
    p->data = data;
    p->next = *pp;
    *pp = p;
    h->count++;

end:
    lsd_mutex_unlock (&h->mutex);
    return (data);
}


void *
hash_remove (hash_t h, const void *key)
{
    unsigned int slot;
    int cmpval;
    struct hash_node **pp;
    struct hash_node *p;
    void *data = NULL;

    if (!h || !key) {
        errno = EINVAL;
        return (NULL);
    }
    errno = 0;
    lsd_mutex_lock (&h->mutex);
    slot = h->key_f (key) % h->size;
    for (pp = &(h->table[slot]); (p = *pp) != NULL; pp = &(p->next)) {
        cmpval = h->cmp_f (p->hkey, key);
        if (cmpval < 0) {
            continue;
        }
        if (cmpval == 0) {
            data = p->data;
            *pp = p->next;
            hash_node_free (p);
            h->count--;
        }
        break;
    }
    lsd_mutex_unlock (&h->mutex);
    return (data);
}


int
hash_delete_if (hash_t h, hash_arg_f arg_f, void *arg)
{
    int i;
    struct hash_node **pp;
    struct hash_node *p;
    int n = 0;

    if (!h || !arg_f) {
        errno = EINVAL;
        return (-1);
    }
    lsd_mutex_lock (&h->mutex);
    for (i = 0; i < h->size; i++) {
        pp = &(h->table[i]);
        while ((p = *pp) != NULL) {
            if (arg_f (p->data, p->hkey, arg) > 0) {
                if (h->del_f)
                    h->del_f (p->data);
                *pp = p->next;
                hash_node_free (p);
                h->count--;
                n++;
            }
            else {
                pp = &(p->next);
            }
        }
    }
    lsd_mutex_unlock (&h->mutex);
    return (n);
}


int
hash_for_each (hash_t h, hash_arg_f arg_f, void *arg)
{
    int i;
    struct hash_node *p;
    int n = 0;

    if (!h || !arg_f) {
        errno = EINVAL;
        return (-1);
    }
    lsd_mutex_lock (&h->mutex);
    for (i = 0; i < h->size; i++) {
        for (p = h->table[i]; p != NULL; p = p->next) {
            if (arg_f (p->data, p->hkey, arg) > 0) {
                n++;
            }
        }
    }
    lsd_mutex_unlock (&h->mutex);
    return (n);
}


void
hash_drop_memory (void)
{
    struct hash_node *p;

    lsd_mutex_lock (&hash_free_list_lock);
    while (hash_mem_list != NULL) {
        p = hash_mem_list;
        hash_mem_list = p->next;
        free (p);
    }
    hash_free_list = NULL;
    lsd_mutex_unlock (&hash_free_list_lock);
    return;
}


/*****************************************************************************
 *  Hash Functions
 *****************************************************************************/

unsigned int
hash_key_string (const char *str)
{
    unsigned char *p;
    unsigned int hval = 0;
    const unsigned int multiplier = 31;

    for (p = (unsigned char *) str; *p != '\0'; p++) {
        hval += (multiplier * hval) + *p;
    }
    return (hval);
}


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

static struct hash_node *
hash_node_alloc (void)
{
/*  Allocates a hash node from the freelist.
 *  Returns a ptr to the object, or NULL if memory allocation fails.
 */
    size_t size;
    struct hash_node *p;
    int i;

    assert (HASH_NODE_ALLOC_NUM > 0);
    lsd_mutex_lock (&hash_free_list_lock);

    if (!hash_free_list) {
        size = sizeof (p) + (HASH_NODE_ALLOC_NUM * sizeof (*p));
        p = malloc (size);

        if (p != NULL) {
            p->next = hash_mem_list;
            hash_mem_list = p;
            hash_free_list = (struct hash_node *)
                    ((unsigned char *) p + sizeof (p));

            for (i = 0; i < HASH_NODE_ALLOC_NUM - 1; i++) {
                hash_free_list[i].next = &hash_free_list[i+1];
            }
            hash_free_list[i].next = NULL;
        }
    }
    if (hash_free_list) {
        p = hash_free_list;
        hash_free_list = p->next;
        memset (p, 0, sizeof (*p));
    }
    else {
        errno = ENOMEM;
    }
    lsd_mutex_unlock (&hash_free_list_lock);
    return (p);
}


static void
hash_node_free (struct hash_node *node)
{
/*  De-allocates the object [node], returning it to the freelist.
 */
    assert (node != NULL);
    lsd_mutex_lock (&hash_free_list_lock);
    node->next = hash_free_list;
    hash_free_list = node;
    lsd_mutex_unlock (&hash_free_list_lock);
    return;
}
