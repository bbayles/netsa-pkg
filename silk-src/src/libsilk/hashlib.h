/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

/*
**  hashlib.h
**
**    Defines interface to core hash library functions.
**
*/

#ifndef _HASHLIB_H
#define _HASHLIB_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_HASHLIB_H, "$SiLK: hashlib.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/**
 *  @file
 *
 *    Implementation of a hashtable.
 *
 *    This file is part of libsilk.
 */


/*
 *  **************************************************************************
 */


/**
 *    Return codes for functions in hashlib. Note that >= 0 are
 *    success codes.
 */

/**  function was successful */
#define OK 0
/**  entry already exists */
#define OK_DUPLICATE 1
/**  could not find entry */
#define ERR_NOTFOUND -1
/**  no more entries available */
#define ERR_NOMOREENTRIES -2
/**  no longer in use */
#define ERR_INDEXOUTOFBOUNDS -3
/**  could not open a file */
#define ERR_FILEOPENERROR -4
/**  illegal argument value */
#define ERR_BADARGUMENT -5
/**  corrupt internal state */
#define ERR_INTERNALERROR -6
/**  operation not supported for this table*/
#define ERR_NOTSUPPORTED -7
/**  read error (corrupt data file) */
#define ERR_FILEREADERROR -8
/**  write error */
#define ERR_FILEWRITEERROR -9
/**  attempt to operate on a sorted table */
#define ERR_SORTTABLE -10
/**  attempted to aloc > max. # of blocks */
#define ERR_NOMOREBLOCKS -254
/**  a call to malloc failed */
#define ERR_OUTOFMEMORY -255

/* Types of hash tables */

/**
 *    UNUSED.
 */
#define HTT_INPLACE 0

/**
 *    UNUSED.
 */
#define HTT_BYREFERENCE 1

/**
 *    Indicates table allows deletion. Items are only removed from the
 *    table after a rehash.  Deleted items have the value
 *    del_value_ptr.
 *
 *    UNSUPPORTED.
 */
#define HTT_ALLOWDELETION 0

/**
 *    Default load is 185 (72.27%). Generally, this is the value that
 *    should be passed to hashlib_create_table for the load factor.
 */
#define DEFAULT_LOAD_FACTOR 185

/**
 *    Maximum number of block-indexes allowed by the hash iterator.
 */
#define HASHLIB_ITER_MAX_BLOCKS 16

/**
 *    Maximum byte-length of the key
 */
#define HASHLIB_MAX_KEY_WIDTH    UINT8_MAX

/**
 *    Maximum byte-length of the value.
 */
#define HASHLIB_MAX_VALUE_WIDTH  UINT8_MAX


/**
 *    The HashTable structure.
 */
typedef struct HashTable_st HashTable;

/**  HashTable iteration object */
typedef struct HashIter_st {
    /* Current block. Negative value is beginning or end */
    int         block;
    /* Current index into block */
    uint64_t    index;
    /* When working with a sorted table, index into each block */
    uint32_t    block_idx[HASHLIB_ITER_MAX_BLOCKS];
} HASH_ITER;


/**
 *    Signature of a callback function used by
 *    hashlib_sort_entries_usercmp() to sort the keys in a HashTable
 *    prior to iterating over them.
 *
 *    The function is expected to compare the keys in 'key_a' and
 *    'key_b' and return -1, 0, or 1 depending on whether 'key_a' is
 *    less than, equal to, or greater than 'key_b'.
 *
 *    The 'cmp_userdata' parameter is a context pointer for the
 *    function to use.
 */
typedef int
(*hashlib_sort_key_cmp_fn)(
    const void         *key_a,
    const void         *key_b,
    void               *cmp_userdata);


/**
 *    Creates a new hash table. The initial table includes a single
 *    block big enough to accomodate estimated_size entries with less
 *    than the specified load_factor.
 *
 *    Parameters:
 *
 *    key_width:      The width of a key in bytes.
 *    value_width:    The width of a value in bytes
 *    data_type:      UNUSED.
 *    no_value_ptr:   A sequence of value_width bytes used to represent
 *                    "no value" (i.e., an empty entry).  The hash table
 *                    makes a copy of this value.  If 'no_value_ptr' is
 *                    NULL, values will be initialized to all 0.
 *    app_data_ptr:   UNUSED.
 *    app_data_size:  UNUSED.
 *    estimated_size: An estimate of the number of unique entries that will
 *                    ultimately be inserted into the table.
 *    load_factor:    Generally, simply use DEFAULT_LOAD_FACTOR here. This
 *                    specifies what load level triggers the allocation of
 *                    a new hash block or a rehash (i.e., the maximum load
 *                    for a block). This is a percentage expressed as a
 *                    fraction of 255.
 *
 *    Returns:
 *
 *    A pointer to the new table.
 *    Will return NULL in the case of a memory allocation error.
 */
HashTable *
hashlib_create_table(
    uint8_t             key_width,
    uint8_t             value_width,
    uint8_t             data_type,
    uint8_t            *no_value_ptr,
    uint8_t            *app_data_ptr,
    uint32_t            app_data_size,
    uint64_t            estimated_size,
    uint8_t             load_factor);


/**
 *    Modifies the hash table so that hashlib_iterate() returns
 *    the entries sorted by their key.
 *
 *    NOTE THAT hashlib_iterate() WILL CONTINUE TO USE 'cmp_fn' AND
 *    'cmp_userdata'.  THE 'cmp_fn' AND 'user_data' MUST REMAIN VALID
 *    THE UNTIL THE TABLE IS DESTROYED!
 *
 *    The comparison function will be passed three parameters; the
 *    first two parameters are hash entry keys.  'cmp_fn' must return
 *    a value less than 0 if key 'a' is less than key 'b', greater
 *    than 0 if key 'a' is greater than key 'b', or 0 if the two keys
 *    are identical.  The 'user_data' parameter will be passed
 *    unchanged to the comparison function, which allows the
 *    comparison function to use additional data without using global
 *    variables.
 *
 *    NOTE: Once the hash table has been sorted, insert, lookup, and
 *    rehash are invalid.  One may only iterate over a sorted table or
 *    delete it.
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to the table to sort.
 *
 *    cmp_fn:         The comparison function to use to compare keys
 *
 *    cmp_userdata:   Value passed unchanged to 'cmp_fn'.
 *
 *    Returns:
 *
 *    OK in the case when the data in the table has been successfully
 *    sorted.
 *
 *    ERR_BADARGUMENT when no 'cmp_fn' is provided.
 */
int
hashlib_sort_entries_usercmp(
    HashTable              *table_ptr,
    hashlib_sort_key_cmp_fn cmp_fn,
    void                   *cmp_userdata);


/**
 *    A wrapper around hashlib_sort_entries_usercmp() that uses
 *    memcmp() to compare the keys.
 */
int
hashlib_sort_entries(
    HashTable          *table_ptr);


/*
 *    NOT IMPLEMENTED
 */
int
hashlib_mark_deleted(
    HashTable          *table_ptr,
    const uint8_t      *key_ptr);


/**
 *    Inserts a new entry into the hash table, and returns a pointer
 *    to the memory in the hash table used to store the value. The
 *    application should store the value associated with the entry in
 *    *(value_pptr). If the entry already exists, *(value_pptr) will
 *    point to the value currently associated with the given key.
 *
 *    NOTE: An application should never store the sequence of bytes
 *    used to represent "no value" here.
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to the table to modify.
 *    key_ptr:        A pointer to a sequence of bytes (table_ptr->key_width
 *                    bytes in length) corresponding to the key.
 *    value_pptr:     A reference to a pointer that points to existing value
 *                    memory associated with a key, or a newly created entry.
 *
 *    Returns:
 *
 *    OK in the case when a new entry has been added successfully,
 *
 *    OK_DUPLICATE if an entry with the given key already exists. May
 *    return
 *
 *    ERR_OUTOFMEMORY in the case of a memory allocation failure.
 *
 *    ERR_SORTTABLE if hashlib_sort_entries() has been called on the table.
 */
int
hashlib_insert(
    HashTable          *table_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **value_pptr);


/**
 *    Looks up an entry with the given key in the hash table. If an
 *    entry with the given key does not exist, value_pptr is
 *    untouched. Otherwise, a reference to the value memory is
 *    returned in *value_pptr as above.
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to the table to modify.
 *    key_ptr:        A pointer to a sequence of bytes (table_ptr->key_width
 *                    bytes in length) corresponding to the key.
 *    value_pptr:     A reference to a pointer that points to existing value
 *                    memory associated with a key (if in the table).
 *
 *    Returns:
 *
 *    OK if the entry exists.
 *
 *    ERR_NOTFOUND if the entry does not exist in the table.
 *
 *    ERR_SORTTABLE if hashlib_sort_entries() has been called on the table.
 */
int
hashlib_lookup(
    const HashTable    *table_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **value_pptr);


/**
 *    Creates an iterator. Calling this function is the first step in
 *    iterating over the contents of a table. See hashlib_iterate.
 *
 *    table_ptr:      A pointer to the table to iterate over.
 *
 *    Returns:
 *
 *    An iterator to use in subsequent calls to hashlib_iterate().
 */
HASH_ITER
hashlib_create_iterator(
    const HashTable    *table_ptr);


/**
 *    Retrieves next available entry during iteration. After calling
 *    hashlib_create_iterator(), this function should be called
 *    repeatedly until ERR_NOMOREENTRIES is returned. References to
 *    the key and value associated with the entry are returned as
 *    *(key_pptr) and *(val_pptr).
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to the current table being iterated over.
 *    iter_ptr:       A pointer to the iterator being used.
 *    key_pptr:       A reference to a pointer whose value will be set
 *                    to the key in the current entry (i.e., *key_pptr
 *                    will point to the key stored in the table).
 *    val_pptr:       A reference to a pointer whose value will be set
 *                    to the value in the current entry (i.e., *val_pptr
 *                    will point to the value in the table).
 *
 *    Returns:
 *
 *    OK until the end of the table is reached.
 *
 *    ERR_NOMOREENTRIES to indicate the iterator has visited all entries.
 */
int
hashlib_iterate(
    const HashTable    *table_ptr,
    HASH_ITER          *iter_ptr,
    uint8_t           **key_pptr,
    uint8_t           **val_pptr);


/**
 *    Frees the memory associated with a table.  Does nothing if
 *    'table_ptr' is NULL.
 *
 *    Parameters:
 *
 *    table_ptr:      The table to free.
 */
void
hashlib_free_table(
    HashTable          *table_ptr);


/**
 *    Force a rehash of a table. Generally, this will be used when a
 *    series of insertions has been completed before a very large
 *    number of lookups (relative to the number of inserts). That is,
 *    when it is likely that the rehash cost is less than the cost
 *    associated with performing searches over multiple blocks.  This
 *    is an advanced function. As a rule, it never make sense to call
 *    this function when the table holds a single block.
 *
 *    Parameters:
 *
 *    table_ptr:      The table to rehash.
 *
 *    Returns:
 *
 *    Returns either OK or ERR_OUTOFMEMORY in the case of a memory
 *    allocation failure.
 *
 *    ERR_SORTTABLE if hashlib_sort_entries() has been called on the table.
 */
int
hashlib_rehash(
    HashTable          *table_ptr);


/**
 *    Returns the total number of buckets that have been allocated.
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to a table.
 *
 *    Returns:
 *
 *    A count
 */
uint64_t
hashlib_count_buckets(
    const HashTable    *table_ptr);


/**
 *    Returns the total number of entries in the table.  This function
 *    sums the current entry count for each of the blocks that make up
 *    the table.  The return value should be equal to
 *    hashlib_count_nonempties().
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to a table.
 *
 *    Returns:
 *
 *    A count
 */
uint64_t
hashlib_count_entries(
    const HashTable    *table_ptr);


/**
 *    Returns the total number of entries in the table.  This function
 *    does a complete scan of the table, looking at each bucket to see
 *    if it is empty.  hashlib_count_entries() should produce the same
 *    result in much less time.
 *
 *    Parameters:
 *
 *    table_ptr:      A pointer to a table.
 *
 *    Returns:
 *
 *    A count
 */
uint64_t
hashlib_count_nonempties(
    const HashTable    *table_ptr);


/*
 *    NOT IMPLEMENTED
 */
uint64_t
hashlib_count_nondeleted(
    const HashTable    *table_ptr);


/*
 *    Debugging functions for printing table info as text
 */
void
hashlib_dump_table_header(
    FILE               *fp,
    const HashTable    *table_ptr);
void
hashlib_dump_table(
    FILE               *fp,
    const HashTable    *table_ptr);


/* #define HASHLIB_RECORD_STATS */

/* Statistics */
#ifdef HASHLIB_RECORD_STATS
struct hashlib_stats_st {
    /* number of allocations */
    uint32_t blocks_allocated;
    /* number of times table rehashed */
    uint32_t rehashes;
    /* number of inserts due to rehash */
    uint64_t rehash_inserts;
    /* number of inserts */
    uint64_t inserts;
    /* number of lookups */
    uint64_t lookups;
    /* number of finds (due to insert & lookup) */
    uint64_t find_entries;
    /* number of collisions */
    uint64_t find_collisions;
    /* number of steps required to resolve collisions */
    uint64_t collision_hops;
};
typedef struct hashlib_stats_st hashlib_stats_t;

void
hashlib_clear_stats(
    HashTable          *table_ptr);

void
hashlib_get_stats(
    const HashTable    *table_ptr,
    hashlib_stats_t    *hash_stats);

void
hashlib_print_stats(
    FILE               *fp,
    const HashTable    *table_ptr);
#endif /* HASHLIB_RECORD_STATS */

#ifdef __cplusplus
}
#endif
#endif /* _HASHLIB_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
