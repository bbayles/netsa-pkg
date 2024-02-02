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

/* File: hashlib.c: implements core hash library. */

#include <silk/silk.h>

RCSIDENT("$SiLK: hashlib.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/hashlib.h>
#include <silk/utils.h>

#ifdef HASHLIB_TRACE_LEVEL
#define TRACEMSG_LEVEL HASHLIB_TRACE_LEVEL
#endif
#define TRACEMSG(lvl, x)  TRACEMSG_TO_TRACEMSGLVL(lvl, x)
#include <silk/sktracemsg.h>

#if TRACEMSG_LEVEL > 0
#define TRC_FMT         "hashlib.c:%d [%p] "
#define TRC_ARG(v_v)    __LINE__, (void *)(v_v)
#endif


/* Configuration */

/*
 *    The maximum size (in terms of number of bytes) of an individual
 *    hash block.
 */
#define HASH_MAX_MEMORY_BLOCK   ((uint64_t)(SIZE_MAX >> 3))

/*
 *    The maximum size (in terms of number of bytes) for the entire
 *    hash table.  May be modified by the environment variable named
 *    by HASHLIB_ENV_MAXMEM.
 *
 *    The default value is the maximum size of any block multiplied by
 *    three, where the three comes from assuming that the
 *    SECONDARY_BLOCK_FRACTION is set to -3, which is its default.
 */
#define HASH_MAX_MEMORY_TOTAL   (HASH_MAX_MEMORY_BLOCK * 3)

/*
 *    Maximum number of blocks ever allocated, used for sizing the
 *    array of HashBlocks in the HashTable.
 *
 *    Once the primary block reaches HASH_MAX_MEMORY_BLOCK (the
 *    maximum block size), new blocks will be allocated until this
 *    maximum is reached.  This value cannot be greater than the
 *    HASHLIB_ITER_MAX_BLOCKS value defined in hashlib.h.
 */
#define HASH_MAX_BLOCKS 8

#if HASH_MAX_BLOCKS > HASHLIB_ITER_MAX_BLOCKS
#error  "HASH_MAX_BLOCKS may not be greater than HASHLIB_ITER_MAX_BLOCKS"
#endif

/*
 *    When the number of HashBlocks gets to this count, a rehash is
 *    triggered unless the first block is already at the maximum block
 *    size.
 *
 *    This value is not static since hashlib_metrics.c may set it.
 */
uint32_t REHASH_BLOCK_COUNT = 4;

/*
 *    The SECONDARY_BLOCK_FRACTION is used to determine the size
 *    HashBlocks following the first.
 *
 *    If non-negative, tables 1...HASH_MAX_BLOCKS-1 have size given by
 *
 *    table_size >> SECONDARY_BLOCK_FRACTION
 *
 *    May also have one of the following values:
 *
 *    = -1 means to keep halving
 *
 *    = -2 means to keep halving starting at a secondary block size
 *    1/4 of block 0
 *
 *    = -3 means block 1 is 1/2 block 0, and all other blocks are 1/4
 *    block 0.
 *
 *    = -4 means block 1 is 1/4 block 0, and all other blocks are 1/8
 *    block 0.
 *
 *    In all cases, the size of blocks REHASH_BLOCK_COUNT through
 *    HASH_MAX_BLOCKS is fixed.
 *
 *    This value is not static since hashlib_metrics.c may set it.
 */
int32_t SECONDARY_BLOCK_FRACTION = -3;

/*
 *    The minimum number of entries that may be stored in a block.
 *    This value must not be less than 256.
 */
#ifndef MIN_BLOCK_ENTRIES
#define MIN_BLOCK_ENTRIES   (UINT64_C(1) << 8)
#endif

#if MIN_BLOCK_ENTRIES < 256
#error "The MIN_BLOCK_ENTRIES must be greater than 256"
#endif

/*
 *    Environment variable to choose the maximum size of an individual
 *    hash table.
 */
#define HASHLIB_ENV_MAXMEM      "SILK_HASH_MAXMEM"

/* Distinguished values for block index in the iterator */
#define HASH_ITER_BEGIN -1
#define HASH_ITER_END -2


/*
 *    The data in a HashTable is stored in multiple HashBlock structures.
 */
struct HashBlock_st {
    /* Pointer to an array of variable-sized entries */
    uint8_t            *data_ptr;
    /* The table that owns this block */
    const HashTable    *table;
    /* Total capacity of this block as a number of entries */
    uint64_t            max_entries;
    /* Number of occupied entries in the block */
    uint64_t            num_entries;
    /* Number of entries at which block meets the load_factor */
    uint64_t            block_full;
};
typedef struct HashBlock_st HashBlock;


/**  the HashTable structure */
/* typedef struct HashTable_st HashTable; */
struct HashTable_st {
    /**  HTT_ALLOWDELETION or 0 */
    uint8_t             options;
    /**  Storage size of a key in bytes */
    uint8_t             key_len;
    /**  Size of a value in bytes */
    uint8_t             value_len;
    /**  Point at which to resize (fraction of 255) */
    uint8_t             load_factor;
    /**  Number of blocks */
    uint8_t             num_blocks;
    /**  Non-zero if rehashing has failed in the past */
    uint8_t             rehash_failed;
    /**  Non-zero if hash entries are sorted */
    uint8_t             is_sorted;
    /**  Non-zero if we can memset new memory to a value */
    uint8_t             can_memset_val;
    /**  Maximum number of entries the initial block may store */
    uint64_t            max_init_entry;
    /**  Size of key; used as cmp_userdata by hashlib_sort_entries() */
    size_t              keylen_cmp_userdata;
    /**  Pointer to representation of an empty value */
    uint8_t            *no_value_ptr;
    /**  Pointer to representation of a deleted value */
    uint8_t            *del_value_ptr;
    /**  Comparison function to use for a sorted table */
    hashlib_sort_key_cmp_fn     cmp_fn;
    /**  Caller's argument to the cmp_fn comparison function */
    void               *cmp_userdata;
    /**  A pointer to this table, so that macros may accept either a
     *   HashTable or a HashBlock */
    const HashTable    *table;
    /**  The blocks */
    HashBlock          *block_ptrs[HASH_MAX_BLOCKS];
#ifdef HASHLIB_RECORD_STATS
    /**  Statistics for this table */
    hashlib_stats_t     ht_stats;
#endif
};
/* HashTable */


/* LOCAL FUNCTION PROTOTYPES */

/* pull in the code that defines the hash function */
#ifdef HASHLIB_LOOKUP2
/* hash code used up to and including SiLK 2.3.x, defined in
 * hashlib-lookup2.c */
unsigned long
hash(
    const uint8_t      *k,
    unsigned long       len,
    unsigned long       initval);
unsigned long
hash2(
    unsigned long      *k,
    unsigned long       len,
    unsigned long       initval);
unsigned long
hash3(
    uint8_t            *k,
    unsigned long       len,
    unsigned long       initval);
#include "hashlib-lookup2.c"

#else
/* hash code used in SiLK 2.4 and beyond, defined in
 * hashlib-lookup3.c */

uint32_t
hashword(
    const uint32_t     *k,
    size_t              length,
    uint32_t            initval);
void
hashword2(
    const uint32_t     *k,
    size_t              length,
    uint32_t           *pc,
    uint32_t           *pb);
uint32_t
hashlittle(
    const void         *key,
    size_t              length,
    uint32_t            initval);
void
hashlittle2(
    const void         *key,
    size_t              length,
    uint32_t           *pc,
    uint32_t           *pb);
uint32_t
hashbig(
    const void         *key,
    size_t              length,
    uint32_t            initval);
void
hashbig2(
    const void         *key,
    size_t              length,
    uint32_t           *pc,
    uint32_t           *pb);

#include "hashlib-lookup3.c"
/* define hash() according to the byte order */
#if SK_BIG_ENDIAN
#  define hash  hashbig2
#else
#  define hash  hashlittle2
#endif
#endif  /* HASHLIB_LOOKUP2 */

static HashBlock *
hashlib_create_block(
    HashTable          *table_ptr,
    uint64_t            block_entries);
static void
hashlib_free_block(
    HashBlock          *block_ptr);
static int
hashlib_block_find_entry(
    const HashBlock    *block_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **entry_pptr);
static int
hashlib_iterate_sorted(
    const HashTable    *table_ptr,
    HASH_ITER          *iter_ptr,
    uint8_t           **key_pptr,
    uint8_t           **val_pptr);
static void
hashlib_compute_max_initial_entries(
    HashTable          *table_ptr);


/* FUNCTION-LIKE MACROS */

/*
 *    Return the maximum number of entries on the largest block in
 *    the table 'tbl_ptr'.
 */
#define HASH_GET_MAX_BLOCK_ENTRIES(tbl_ptr)                             \
    ((tbl_ptr)->max_init_entry)

/*
 *    Return true if the HashBlock 'blk_ptr' is full; that is, whether
 *    the number of entries meets or exceeds the load factor.
 */
#define HASH_BLOCK_IS_FULL(blk_ptr)                     \
    ((blk_ptr)->num_entries >= (blk_ptr)->block_full)

/*
 *    Get number of bytes of storage required to hold a key in
 *    'tbl_blk_ptr', which may be a HashTable or a HashBlock.
 */
#define HASH_GET_KEY_LEN(tbl_blk_ptr)           \
    ((uint64_t)(tbl_blk_ptr)->table->key_len)

/*
 *    Get number of bytes of storage required to hold a value in
 *    'tbl_blk_ptr', which may be a HashTable or a HashBlock.
 */
#define HASH_GET_VALUE_LEN(tbl_blk_ptr)                 \
    ((uint64_t)(tbl_blk_ptr)->table->value_len)

/*
 *    Get number of bytes of storage required to hold an entry in
 *    'tbl_blk_ptr', which may be a HashTable or a HashBlock.
 */
#define HASH_GET_ENTRY_LEN(tbl_blk_ptr)                                 \
    (HASH_GET_KEY_LEN(tbl_blk_ptr) + HASH_GET_VALUE_LEN(tbl_blk_ptr))

/*
 *    Get a pointer to the storage key part of 'entry_ptr' in
 *    'tbl_blk_ptr' which may be a HashTable or HashBlock.
 */
#define HASHENTRY_GET_KEY(tbl_blk_ptr, entry_ptr)       \
    (entry_ptr)

/*
 *    Get a pointer to the value part of 'entry_ptr' in 'tbl_blk_ptr'
 *    which may be a HashTable or HashBlock.
 */
#define HASHENTRY_GET_VALUE(tbl_blk_ptr, entry_ptr)     \
    ((entry_ptr) + HASH_GET_KEY_LEN(tbl_blk_ptr))

/*
 *    Set the storage key part of 'entry_ptr' in 'tbl_blk_ptr' to
 *    contain the bytes in 'key_bytes'.  'tbl_blk_ptr' may be a
 *    HashTable or HashBlock.
 */
#define HASHENTRY_SET_KEY(tbl_blk_ptr, entry_ptr, key_bytes)            \
    memcpy(HASHENTRY_GET_KEY(tbl_blk_ptr, entry_ptr), (key_bytes),      \
           HASH_GET_KEY_LEN(tbl_blk_ptr))

/*
 *    Return 1 if the bytes in 'value_ptr' match the empty value,
 *    otherwise 0.  'tbl_blk_ptr' may be a HashTable or HashBlock.
 */
#define HASH_VALUE_ISEMPTY(tbl_blk_ptr, value_ptr)                      \
    (0 == memcmp((value_ptr), (tbl_blk_ptr)->table->no_value_ptr,       \
                 HASH_GET_VALUE_LEN(tbl_blk_ptr)))

/*
 *    Return 1 if the value part of the entry at 'entry_ptr' matches
 *    the empty value, otherwise 0.  'tbl_blk_ptr' may be a HashTable
 *    or a HashBlock.
 */
#define HASHENTRY_ISEMPTY(tbl_blk_ptr, entry_ptr)                       \
    HASH_VALUE_ISEMPTY(tbl_blk_ptr,                                     \
                       HASHENTRY_GET_VALUE((tbl_blk_ptr), (entry_ptr)))

/*
 *    Get a pointer to the entry at index 'hash_index' in 'blk_ptr',
 *    which must be a HashBlock.
 */
#define HASH_ENTRY_AT(blk_ptr, hash_index)                              \
    ((blk_ptr)->data_ptr + (HASH_GET_ENTRY_LEN(blk_ptr) * (hash_index)))

/*
 *    Get a pointer to the storage key part of the entry at index
 *    'hash_index' in 'blk_ptr' which must be a HashBlock.
 */
#define HASH_KEY_AT(blk_ptr, hash_index)                                \
    HASHENTRY_GET_KEY((blk_ptr), HASH_ENTRY_AT((blk_ptr), (hash_index)))

/*
 *    Get a pointer to the value part of the entry at index
 *    'hash_index' in 'blk_ptr' which must be a HashBlock.
 */
#define HASH_VALUE_AT(blk_ptr, hash_index)                              \
    HASHENTRY_GET_VALUE((blk_ptr), HASH_ENTRY_AT((blk_ptr), (hash_index)))

/*
 *    Increment the value of 'member' in the hashlib_stats structure
 *    for 'tbl_blk_ptr', which may be a HashTable or a HashBlock.
 */
#ifndef HASHLIB_RECORD_STATS
#define HASH_STAT_INCR(tbl_blk_ptr, member)
#else
/* need to cast away the "const" */
#define HASH_STAT_INCR(tbl_blk_ptr, member)                     \
    ++(((HashTable *)(tbl_blk_ptr)->table)->ht_stats. member )
#endif


#ifdef NDEBUG
#define HASH_ASSERT_SIZE_IS_POWER_2(blk_size)
#else
#define HASH_ASSERT_SIZE_IS_POWER_2(blk_size)   \
    do {                                        \
        uint64_t high_bits;                     \
        BITS_IN_WORD64(&high_bits, (blk_size)); \
        assert(1 == high_bits);                 \
    } while(0)
#endif  /* NDEBUG */


/* FUNCTION DEFINITIONS */

HashTable *
hashlib_create_table(
    uint8_t             key_len,
    uint8_t             value_len,
    uint8_t             value_type,
    uint8_t            *no_value_ptr,
    uint8_t            *appdata_ptr,
    uint32_t            appdata_size,
    uint64_t            estimated_count,
    uint8_t             load_factor)
{
    HashTable *table_ptr = NULL;
    HashBlock *block_ptr = NULL;
    uint64_t initial_entries;

    /* Validate arguments */
    if (0 == key_len || 0 == value_len) {
        TRACEMSG(1,(TRC_FMT "create table: invalid width key %u, value %u",
                    TRC_ARG(table_ptr), key_len, value_len));
        assert(0);
        return NULL;
    }

    /* Allocate memory for the table and initialize attributes.  */
    table_ptr = (HashTable*)calloc(1, sizeof(HashTable));
    if (table_ptr == NULL) {
        TRACEMSG(1,(TRC_FMT "Failed to allocate new HashTable.",
                    TRC_ARG(table_ptr)));
        return NULL;
    }

    /* Initialize the table structure */
    table_ptr->table = table_ptr;
    table_ptr->key_len = key_len;
    table_ptr->value_len = value_len;
    table_ptr->load_factor = load_factor;

    TRACEMSG(3,
             (TRC_FMT "key_len %u, value_len %u, entry_len %u, load_factor %u",
              TRC_ARG(table_ptr), key_len, value_len,
              key_len + value_len, load_factor));

    /* Application data */
    SK_UNUSED_PARAM(value_type);
    SK_UNUSED_PARAM(appdata_ptr);
    SK_UNUSED_PARAM(appdata_size);

    /* Initialize value_ptr to string of zero-valued bytes if NULL */
    table_ptr->no_value_ptr = (uint8_t*)calloc(value_len, sizeof(uint8_t));
    if (table_ptr->no_value_ptr == NULL) {
        TRACEMSG(1,((TRC_FMT "Failed to allocate new no_value_ptr"
                     " for new HashTable."), TRC_ARG(table_ptr)));
        free(table_ptr);
        return NULL;
    }
    if (no_value_ptr == NULL) {
        table_ptr->can_memset_val = 1;
    } else if (table_ptr->value_len == 1) {
        table_ptr->can_memset_val = 1;
        table_ptr->no_value_ptr[0] = no_value_ptr[0];
    } else {
        /* Fill the table's no_value_ptr with the first byte of the
         * caller's no_value_ptr and then compare the complete
         * no_value_ptr values to determine whether we can use
         * memset() to initialize the values of new memory blocks. */
        memset(table_ptr->no_value_ptr, no_value_ptr[0], value_len);
        if (memcmp(table_ptr->no_value_ptr, no_value_ptr, value_len)) {
            /* values differ; cannot use memset */
            table_ptr->can_memset_val = 0;
            memcpy(table_ptr->no_value_ptr, no_value_ptr, value_len);
        } else {
            /* values are the same; use memset */
            table_ptr->can_memset_val = 1;
        }
    }

    /* Compute the maximum number of entries for the initial block */
    hashlib_compute_max_initial_entries(table_ptr);

    /*
     * Calculate the number of entres in the initial block.  This is a
     * power of 2 with at least MIN_BLOCK_ENTRIES entries that
     */
    /* account for the load factor */
    initial_entries = (estimated_count << 8) / table_ptr->load_factor;
    /* compute power of two greater than initial_entries */
    initial_entries = UINT64_C(1) << (1 + skIntegerLog2(initial_entries));

    TRACEMSG(2,((TRC_FMT "estimated_count %" PRIu64 ", initial_entries %"
                 PRIu64 " (calculated %" PRIu64 "), min_entries %" PRIu64
                 ", max_entries %" PRIu64),
                TRC_ARG(table_ptr), estimated_count, initial_entries,
                ((estimated_count << 8) / table_ptr->load_factor),
                MIN_BLOCK_ENTRIES, HASH_GET_MAX_BLOCK_ENTRIES(table_ptr)));

    if (initial_entries < MIN_BLOCK_ENTRIES) {
        initial_entries = MIN_BLOCK_ENTRIES;
        TRACEMSG(2,(TRC_FMT "adjusted initial_entries to %" PRIu64,
                    TRC_ARG(table_ptr), initial_entries));
    } else {
        if (initial_entries > HASH_GET_MAX_BLOCK_ENTRIES(table_ptr)) {
            initial_entries = HASH_GET_MAX_BLOCK_ENTRIES(table_ptr);
        }
        TRACEMSG(2,(TRC_FMT "adjusted initial_entries to %" PRIu64,
                    TRC_ARG(table_ptr), initial_entries));
        assert(initial_entries >= MIN_BLOCK_ENTRIES);
    }

    TRACEMSG(1,(TRC_FMT "Adding block #0...", TRC_ARG(table_ptr)));

    /* Start with one block */
    table_ptr->num_blocks = 1;
    block_ptr = hashlib_create_block(table_ptr, initial_entries);
    while (NULL == block_ptr) {
        TRACEMSG(1,(TRC_FMT "Adding block #0 failed.", TRC_ARG(table_ptr)));
        if (initial_entries <= MIN_BLOCK_ENTRIES) {
            table_ptr->num_blocks = 0;
            hashlib_free_table(table_ptr);
            return NULL;
        }
        initial_entries >>= 1;
        TRACEMSG(2,(TRC_FMT "adjusted initial_entries to %" PRIu64,
                    TRC_ARG(table_ptr), initial_entries));
        assert(initial_entries >= MIN_BLOCK_ENTRIES);
    }
    table_ptr->block_ptrs[0] = block_ptr;

    TRACEMSG(1,(TRC_FMT "Added block #%u.",
                TRC_ARG(table_ptr), table_ptr->num_blocks - 1));

    return table_ptr;
}


void
hashlib_free_table(
    HashTable          *table_ptr)
{
    unsigned int k;

    if (NULL == table_ptr) {
        return;
    }

    TRACEMSG(1,(TRC_FMT "Freeing HashTable...", TRC_ARG(table_ptr)));
    /* Free all the blocks in the table */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        TRACEMSG(2,(TRC_FMT "Freeing block #%u", TRC_ARG(table_ptr), k));
        hashlib_free_block(table_ptr->block_ptrs[k]);
    }

    /* Free the empty pointer memory */
    free(table_ptr->no_value_ptr);

    /* Free the table structure itself */
    free(table_ptr);
    TRACEMSG(1,(TRC_FMT "Freed HashTable.", TRC_ARG(table_ptr)));
}


/*
 *    NOTE: Assumes block_entries is a power of 2.  Very important!
 */
static HashBlock *
hashlib_create_block(
    HashTable          *table_ptr,
    uint64_t            block_entries)
{
    HashBlock *block_ptr;
    uint64_t block_bytes;

    HASH_ASSERT_SIZE_IS_POWER_2(block_entries);

    HASH_STAT_INCR(table_ptr, blocks_allocated);

    block_bytes = block_entries * HASH_GET_ENTRY_LEN(table_ptr);

    TRACEMSG(1,((TRC_FMT "Creating block; requesting %#" PRIx64
                 " %" PRIu64 "-byte entries (%" PRIu64 " bytes)..."),
                TRC_ARG(table_ptr), block_entries,
                HASH_GET_ENTRY_LEN(table_ptr), block_bytes));

#if SIZE_MAX < UINT64_MAX
    /* verify we do not overflow the size of a size_t */
    if (block_bytes > SIZE_MAX) {
        TRACEMSG(1,(TRC_FMT "Cannot create block; size exceeds SIZE_MAX.",
                    TRC_ARG(table_ptr)));
        return NULL;
    }
#endif

    /* Allocate memory for the block and initialize attributes.  */
    block_ptr = (HashBlock*)malloc(sizeof(HashBlock));
    if (block_ptr == NULL) {
        TRACEMSG(1,(TRC_FMT "Failed to allocate new HashBlock.",
                    TRC_ARG(table_ptr)));
        return NULL;
    }
    block_ptr->data_ptr = (uint8_t*)malloc(block_bytes);
    if (block_ptr->data_ptr == NULL) {
        free(block_ptr);
        TRACEMSG(1,(TRC_FMT "Failed to allocate new data block.",
                    TRC_ARG(table_ptr)));
        return NULL;
    }

    block_ptr->table = table_ptr;
    block_ptr->max_entries = block_entries;
    block_ptr->num_entries = 0;
    block_ptr->block_full = table_ptr->load_factor * (block_entries >> 8);

    /* Copy "empty" value to each entry.  Garbage key values are
     * ignored, so we don't bother writing to the keys.  When the
     * application overestimates the amount of memory needed, this can
     * be bottleneck.  */
    if (table_ptr->can_memset_val) {
        memset(block_ptr->data_ptr, table_ptr->no_value_ptr[0], block_bytes);
    } else {
        uint8_t *data_ptr;
        uint64_t i;

        /* Initialize 'data_ptr' to point to at the value part of the
         * first entry in the block; move 'data_ptr' to the next value
         * at every iteration */
        for (i = 0, data_ptr = HASH_VALUE_AT(block_ptr, 0);
             i < block_ptr->max_entries;
             ++i, data_ptr += HASH_GET_ENTRY_LEN(table_ptr))
        {
            memcpy(data_ptr, table_ptr->no_value_ptr,
                   HASH_GET_VALUE_LEN(block_ptr));
        }
    }

    return block_ptr;
}


static void
hashlib_free_block(
    HashBlock          *block_ptr)
{
    /* Free the data and the block itself */
    assert(block_ptr);
    free(block_ptr->data_ptr);
    free(block_ptr);
}


/*
 *    Rehash entire table into a single block.
 */
int
hashlib_rehash(
    HashTable          *table_ptr)
{
    const uint64_t max_entries = HASH_GET_MAX_BLOCK_ENTRIES(table_ptr);
    HashBlock *new_block_ptr = NULL;
    HashBlock *block_ptr = NULL;
    uint64_t num_entries = 0;
    uint64_t initial_entries;
    const uint8_t *key_ref;
    const uint8_t *val_ref;
    uint8_t *entry_ptr;
    uint8_t *new_entry_ptr;
    int rv;
    unsigned int k;
    uint64_t i;

    HASH_STAT_INCR(table_ptr, rehashes);

    if (table_ptr->is_sorted) {
        TRACEMSG(1,(TRC_FMT "ERROR: Attempt to rehash a sorted HashTable",
                    TRC_ARG(table_ptr)));
        assert(0 == table_ptr->is_sorted);
        return ERR_SORTTABLE;
    }

    /*
     *    Count the total number of entries so we know what we need to
     *    allocate.  We base this on the actual size of the blocks,
     *    and use the power of 2 that's double the smallest power of 2
     *    bigger than the sum of block sizes. It's justified by the
     *    intuition that once we reach this point, we've decided that
     *    we're going to explore an order of magnitude larger
     *    table. This particular scheme seems to work well in practice
     *    although it's difficult to justify theoretically--this is a
     *    rather arbitrary definition of "order of magnitude".
     */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        num_entries += table_ptr->block_ptrs[k]->max_entries;
    }
    assert(num_entries > 0);

    TRACEMSG(1,((TRC_FMT "Rehashing table having %" PRIu64
                 " %" PRIu64 "-byte entries..."),
                TRC_ARG(table_ptr), num_entries,
                HASH_GET_ENTRY_LEN(table_ptr)));

    if (num_entries >= max_entries) {
        TRACEMSG(1,((TRC_FMT "Too many entries for rehash; "
                     " num_entries=%" PRIu64 " >= max_entries=%" PRIu64 "."),
                    TRC_ARG(table_ptr), num_entries, max_entries));
        return ERR_OUTOFMEMORY;
    }

    /* Choose the size for the initial block as the next power of 2
     * greater than the number of entries. */
    initial_entries = UINT64_C(1) << (1 + skIntegerLog2(num_entries));
    if (initial_entries < MIN_BLOCK_ENTRIES) {
        initial_entries = MIN_BLOCK_ENTRIES;
    }

    /* double it once more unless we already have 2^28 entries */
    if (((max_entries >> 1) > initial_entries)
        && (initial_entries < UINT64_C(0x10000000)))
    {
        initial_entries <<= 1;
    }
    if (initial_entries > max_entries) {
        TRACEMSG(1,((TRC_FMT "Will not rehash table; new initial_entries=%"
                     PRIu64 " > max_entries=%" PRIu64 "."),
                    TRC_ARG(table_ptr), initial_entries, max_entries));
        return ERR_OUTOFMEMORY;
    }

    TRACEMSG(1,(TRC_FMT "Allocating new rehash block...", TRC_ARG(table_ptr)));

    /* Create the new block */
    new_block_ptr = hashlib_create_block(table_ptr, initial_entries);
    if (new_block_ptr == NULL) {
        TRACEMSG(1,((TRC_FMT "Allocating rehash block failed for %#" PRIx64
                     " entries."), TRC_ARG(table_ptr), initial_entries));
        return ERR_OUTOFMEMORY;
    }
    TRACEMSG(1,(TRC_FMT "Allocated rehash block.", TRC_ARG(table_ptr)));

    /* Walk through each block in the table looking for non-empty
     * entries and insert them into the new block. */
    for (k = table_ptr->num_blocks; k > 0; ) {
        --k;
        block_ptr = table_ptr->block_ptrs[k];
        TRACEMSG(2,(TRC_FMT "Rehashing entries from block #%u",
                    TRC_ARG(table_ptr), k));

        for (i = 0, entry_ptr = HASH_ENTRY_AT(block_ptr, 0);
             i < block_ptr->max_entries;
             ++i, entry_ptr += HASH_GET_ENTRY_LEN(block_ptr))
        {
            key_ref = HASHENTRY_GET_KEY(block_ptr, entry_ptr);
            val_ref = HASHENTRY_GET_VALUE(block_ptr, entry_ptr);

            /* If not empty, then copy the entry into the new block */
            if (!HASH_VALUE_ISEMPTY(block_ptr, val_ref)) {
                rv = hashlib_block_find_entry(new_block_ptr,
                                              key_ref, &new_entry_ptr);
                if (rv != ERR_NOTFOUND) {
                    /* value is not-empty, but we cannot find the key
                     * in the hash table. either the hashlib code is
                     * broken, or the user set a value to the
                     * no_value_ptr value and broke the collision
                     * resolution mechanism.  if assert() is active,
                     * the next line will call abort(). */
                    TRACEMSG(1,((TRC_FMT "During the rehash, unexpectedly"
                                 " found an existing key in the new block"),
                                TRC_ARG(table_ptr)));
                    assert(rv == ERR_NOTFOUND);
                    free(new_block_ptr);
                    table_ptr->num_blocks = 1 + k;
                    return ERR_INTERNALERROR;
                }
                /* Copy the key and value */
                HASHENTRY_SET_KEY(new_block_ptr, new_entry_ptr, key_ref);
                memcpy(HASHENTRY_GET_VALUE(new_block_ptr, new_entry_ptr),
                       val_ref, HASH_GET_VALUE_LEN(block_ptr));
                ++new_block_ptr->num_entries;
                HASH_STAT_INCR(table_ptr, rehash_inserts);
            }
        }

        /* Free the block */
        hashlib_free_block(block_ptr);
        table_ptr->block_ptrs[k] = NULL;
    }                           /* blocks */

    /* Associate the new block with the table */
    table_ptr->num_blocks = 1;
    table_ptr->block_ptrs[0] = new_block_ptr;

    TRACEMSG(1,(TRC_FMT "Rehashed table.", TRC_ARG(table_ptr)));

    return OK;
}


/*
 *    Add a new block to a table.
 */
static int
hashlib_add_block(
    HashTable          *table_ptr,
    uint64_t            new_block_entries)
{
    HashBlock *block_ptr = NULL;

    assert(table_ptr->num_blocks < HASH_MAX_BLOCKS);
    if (table_ptr->num_blocks >= HASH_MAX_BLOCKS) {
        TRACEMSG(1,((TRC_FMT "Cannot allocate another block:"
                     " num_blocks=%" PRIu32 " >= HASH_MAX_BLOCKS=%u."),
                    TRC_ARG(table_ptr), table_ptr->num_blocks,
                    HASH_MAX_BLOCKS));
        return ERR_NOMOREBLOCKS;
    }
    /* Create the new block */
    TRACEMSG(1,((TRC_FMT "Adding block #%u..."),
                TRC_ARG(table_ptr), table_ptr->num_blocks));
    block_ptr = hashlib_create_block(table_ptr, new_block_entries);
    if (block_ptr == NULL) {
        TRACEMSG(1,(TRC_FMT "Adding block #%u failed.",
                    TRC_ARG(table_ptr), table_ptr->num_blocks));
        return ERR_OUTOFMEMORY;
    }

    /* Add it to the table */
    table_ptr->block_ptrs[table_ptr->num_blocks] = block_ptr;
    ++table_ptr->num_blocks;
    TRACEMSG(1,(TRC_FMT "Added block #%u.",
                TRC_ARG(table_ptr), table_ptr->num_blocks - 1));

    return OK;
}


/*
 *    Using the maximum memory_size for the entire hash table (either
 *    from the environment or the HASH_MAX_MEMORY_TOTAL default),
 *    compute the maximum number of entries that the initial block is
 *    allowed to contain and update the hash table with that value.
 */
static void
hashlib_compute_max_initial_entries(
    HashTable          *table_ptr)
{
    /* true if env contains an invalid value */
    static int bad_env = 0;

    /* assume the initial block has this size */
    const uint64_t init_basis = (1 << 16);

    /* based on the initial block having a size of 'init_basis',
     * compute the total size of the hash table using the
     * SECONDARY_BLOCK_FRACTION and the number of hash blocks */
    uint64_t total_basis;

    /* max number of entries in initial block */
    uint64_t max_init_entry;

    uint64_t max_memory = HASH_MAX_MEMORY_TOTAL;
    const char *env;

    /* Determine maximum memory footprint of the entire hash table */
    env = getenv(HASHLIB_ENV_MAXMEM);
    if (bad_env) {
        /* do nothing */
    } else if (env && *env) {
        int rv = skStringParseHumanUint64(&max_memory, env, SK_HUMAN_NORMAL);
        if (rv) {
            bad_env = 1;
            skAppPrintErr("Ignoring Invalid %s '%s': %s",
                          HASHLIB_ENV_MAXMEM, env, skStringParseStrerror(rv));
            max_memory = HASH_MAX_MEMORY_TOTAL;
        }
    }

    assert(HASH_MAX_BLOCKS > 2);
    assert(REHASH_BLOCK_COUNT >= 2);
    assert(REHASH_BLOCK_COUNT < HASH_MAX_BLOCKS);

    /*
     *    When you continually take half of an initial value and add
     *    it to the initial value, the sum approaches 2.  If you only
     *    take half N times, the sum is:
     *
     *    init_value * 2 - (init_value >> (N - 1))
     */

    switch (SECONDARY_BLOCK_FRACTION) {
      case -1:
        /* Keep halving blocks until REHASH_BLOCK_COUNT blocks have
         * been created, then size is constant */
        total_basis = (init_basis * 2
                       + ((init_basis >> (REHASH_BLOCK_COUNT - 1))
                          * (HASH_MAX_BLOCKS - REHASH_BLOCK_COUNT - 1)));
        break;
      case -2:
        /* First secondary block is 1/4 size of main block; other
         * blocks are halved until REHASH_BLOCK_COUNT is reached */
        total_basis = (init_basis + (init_basis >> 1)
                       - ((init_basis >> 2) >> (REHASH_BLOCK_COUNT - 2))
                       + ((init_basis >> REHASH_BLOCK_COUNT)
                          >> (HASH_MAX_BLOCKS - REHASH_BLOCK_COUNT)));
        break;
      case -3:
        /* First secondary block is 1/2 size of main block; all others
         * are 1/4 of main block */
        total_basis = (init_basis + (init_basis >> 1)
                       + (init_basis >> 2) * (HASH_MAX_BLOCKS - 2));
        break;
      case -4:
        /* First secondary block is 1/4 size of main block; all others
         * are 1/8 of main block */
        total_basis = (init_basis + (init_basis >> 2)
                       + (init_basis >> 3) * (HASH_MAX_BLOCKS - 2));
        break;
      case 0:
        /* All blocks are the same size (shift size by 0) */
        total_basis = init_basis * HASH_MAX_BLOCKS;
        break;
      default:
        /* All secondary blocks shifted by SECONDARY_BLOCK_FRACTION
         * from the main block */
        if (SECONDARY_BLOCK_FRACTION < 0) {
            skAbort();
        }
        total_basis = (init_basis + ((init_basis >> SECONDARY_BLOCK_FRACTION)
                                     * (HASH_MAX_BLOCKS - 1)));
        break;
    }

    /*
     *    this is the formula that would compute the total maximum
     *    size of the hash table
     *
     * total_size = initial_bins * record_size * total_basis / init_basis;
     *
     *    using that formula, solve for initial_bins:
     */
    max_init_entry = ((double)max_memory / (double)total_basis
                      * (double)init_basis
                      / (double)HASH_GET_ENTRY_LEN(table_ptr));

    /*
     *    Get the largest power of two less than max_init_entry.
     */
    table_ptr->max_init_entry = UINT64_C(1) << skIntegerLog2(max_init_entry);
    if (table_ptr->max_init_entry < MIN_BLOCK_ENTRIES) {
        table_ptr->max_init_entry = MIN_BLOCK_ENTRIES;
    }

#if TRACEMSG_LEVEL >= 2
    {
        uint64_t total_size;

        total_size = ((double)table_ptr->max_init_entry / (double)init_basis
                      * (double)HASH_GET_ENTRY_LEN(table_ptr)
                      * (double)total_basis);

        TRACEMSG(2,((TRC_FMT "desired max mem = %" PRIu64
                     "; entry size = %" PRIu64
                     "; max total entry = %" PRIu64
                     "; total size / init block size = %.4f"
                     "; max initial entry = %" PRIu64
                     "; log2 initial entry = %" PRIu64
                     "; actual max memory = %" PRIu64
                     "; actual max/desired max = %.4f"),
                    TRC_ARG(table_ptr), max_memory,
                    HASH_GET_ENTRY_LEN(table_ptr),
                    max_memory / HASH_GET_ENTRY_LEN(table_ptr),
                    (double)total_basis/(double)init_basis,
                    max_init_entry, table_ptr->max_init_entry, total_size,
                    ((0 == max_memory)
                     ? DBL_MAX
                     : (double)total_size/max_memory)));
    }
#endif  /* TRACEMSG_LEVEL >= 2 */
}



/*
 *    Compute the size the next hash block.
 */
static uint64_t
hashlib_compute_next_block_entries(
    HashTable          *table_ptr)
{
    uint64_t block_entries = 0;

    /* This condition will only be true when the primary block has
     * reached the maximum block size. */
    if (table_ptr->num_blocks >= REHASH_BLOCK_COUNT) {
        return table_ptr->block_ptrs[table_ptr->num_blocks-1]->max_entries;
    }
    /* Otherwise, it depends on current parameters */
    switch (SECONDARY_BLOCK_FRACTION) {
      case -1:
        /* Keep halving blocks */
        block_entries =
            (table_ptr->block_ptrs[table_ptr->num_blocks-1]->max_entries >> 1);
        break;
      case -2:
        if (table_ptr->num_blocks == 1) {
            /* First secondary block is 1/4 size of main block */
            block_entries = table_ptr->block_ptrs[0]->max_entries >>2;
        } else {
            /* Other secondary blocks are halved */
            block_entries =
                table_ptr->block_ptrs[table_ptr->num_blocks-1]->max_entries >>1;
        }
        break;
      case -3:
        if (table_ptr->num_blocks == 1) {
            /* First secondary block is 1/2 size of main block */
            block_entries = table_ptr->block_ptrs[0]->max_entries >> 1;
        } else {
            /* All others are 1/4 size of main block */
            block_entries = table_ptr->block_ptrs[0]->max_entries >> 2;
        }
        break;
      case -4:
        if (table_ptr->num_blocks == 1) {
            /* First secondary block is 1/4 size of main block */
            block_entries = table_ptr->block_ptrs[0]->max_entries >> 2;
        } else {
            /* All others are 1/8 size of main block */
            block_entries = table_ptr->block_ptrs[0]->max_entries >> 3;
        }
        break;
      case 0:
        /* All blocks are the same size */
        block_entries = table_ptr->block_ptrs[0]->max_entries;
        break;
      default:
        if (SECONDARY_BLOCK_FRACTION < 0) {
            skAppPrintErr("Invalid block fraction %d",
                          SECONDARY_BLOCK_FRACTION);
            skAbort();
        }
        block_entries =
            (table_ptr->block_ptrs[0]->max_entries >> SECONDARY_BLOCK_FRACTION);
        break;
    }
    if (block_entries < MIN_BLOCK_ENTRIES) {
        block_entries = MIN_BLOCK_ENTRIES;
    }
    return block_entries;
}

/*
 *  Algorithm:
 *  - If the primary block is at its maximum, never rehash, only add
 *    new blocks.
 *  - If we have a small table, then don't bother creating
 *    secondary tables.  Simply rehash into a new block.
 *  - If we've exceeded the maximum number of blocks, rehash
 *    into a new block.
 *  - Otherwise, create a new block
 */

static int
hashlib_resize_table(
    HashTable          *table_ptr)
{
    uint64_t new_block_entries;
    int rv;

    TRACEMSG(1,(TRC_FMT "Resizing the table...", TRC_ARG(table_ptr)));

    /* Compute the (potential) size of the new block */
    new_block_entries = hashlib_compute_next_block_entries(table_ptr);
    assert(new_block_entries != 0);

    /* If we're at the maximum number of blocks (which implies that
     * the first block is at its max, and we can't resize, then that's
     * it. */
    if (table_ptr->num_blocks == HASH_MAX_BLOCKS) {
        TRACEMSG(1,((TRC_FMT "Unable to resize table: no more blocks;"
                     " table contains %" PRIu64 " %" PRIu64 "-byte entries"
                     " in %" PRIu64 " buckets across %u blocks"),
                    TRC_ARG(table_ptr), hashlib_count_entries(table_ptr),
                    HASH_GET_ENTRY_LEN(table_ptr),
                    hashlib_count_buckets(table_ptr), table_ptr->num_blocks));
        return ERR_NOMOREBLOCKS;
    }
    /* If the first block is at its maximum size or if we have tried
     * and failed to rehash in the past, then add a new block. Once we
     * reach the maximum block size, we don't rehash.  Instead we keep
     * adding blocks until we reach the maximum. */
    if ((table_ptr->block_ptrs[0]->max_entries
         == HASH_GET_MAX_BLOCK_ENTRIES(table_ptr))
        || table_ptr->rehash_failed)
    {
        assert(new_block_entries > MIN_BLOCK_ENTRIES);
        return hashlib_add_block(table_ptr, new_block_entries);
    }
    /* If we have REHASH_BLOCK_COUNT blocks, or the new block would be
     * too small, we simply rehash. */
    if ((new_block_entries < MIN_BLOCK_ENTRIES) ||
        (table_ptr->num_blocks >= REHASH_BLOCK_COUNT))
    {
        TRACEMSG(1,((TRC_FMT "Resize table forcing rehash;"
                     " new_block_entries = %#" PRIx64
                     "; num_blocks = %u; REHASH_BLOCK_COUNT = %" PRIu32 "."),
                    TRC_ARG(table_ptr), new_block_entries,
                    table_ptr->num_blocks, REHASH_BLOCK_COUNT));
        rv = hashlib_rehash(table_ptr);
        if (rv != ERR_OUTOFMEMORY) {
            return rv;
        }
        /* rehashing failed.  try instead to add a new (small) block */
        table_ptr->rehash_failed = 1;
        if (new_block_entries < MIN_BLOCK_ENTRIES) {
            new_block_entries = MIN_BLOCK_ENTRIES;
        }
        TRACEMSG(1,(TRC_FMT "Rehash failed; creating new block instead...",
                    TRC_ARG(table_ptr)));
    }
    /* Assert several global invariants */
    assert(new_block_entries >= MIN_BLOCK_ENTRIES);
    assert(new_block_entries <= HASH_GET_MAX_BLOCK_ENTRIES(table_ptr));
    assert(table_ptr->num_blocks < HASH_MAX_BLOCKS);

    /* Otherwise, add new a new block */
    return hashlib_add_block(table_ptr, new_block_entries);
}


#if 0
static void
assert_not_already_there(
    const HashTable    *table_ptr,
    const uint8_t      *key_ptr)
{
    const uint8_t *entry_ptr;
    const HashBlock *block_ptr;
    unsigned int k;
    int rv;

    for (k = 0; k < (table_ptr->num_blocks-1); ++k) {
        block_ptr = table_ptr->block_ptrs[k];
        rv = hashlib_block_find_entry(block_ptr, key_ptr, &entry_ptr);
        if (rv == OK) {
            getc(stdin);
        }
    }
}
#endif /* 0 */


int
hashlib_insert(
    HashTable          *table_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **value_pptr)
{
    HashBlock *block_ptr = NULL;
    uint8_t *entry_ptr = NULL;
    unsigned int k;
    int rv;

    assert(table_ptr);

    HASH_STAT_INCR(table_ptr, inserts);

    if (table_ptr->is_sorted) {
        TRACEMSG(1,(TRC_FMT "Attempted an insert into a sorted HashTable",
                    TRC_ARG(table_ptr)));
        assert(0 == table_ptr->is_sorted);
        return ERR_SORTTABLE;
    }

    /* See if we are ready to do a resize by either adding a block or
     * rehashing. */
    if (HASH_BLOCK_IS_FULL(table_ptr->block_ptrs[table_ptr->num_blocks-1])){
        rv = hashlib_resize_table(table_ptr);
        if (rv != OK) {
            return rv;
        }
    }
    assert(table_ptr->num_blocks);

    /* Look in each block for the key */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        block_ptr = table_ptr->block_ptrs[k];
        if (hashlib_block_find_entry(block_ptr, key_ptr, &entry_ptr) == OK) {
            /* Found entry, use it */
            *value_pptr = HASHENTRY_GET_VALUE(block_ptr, entry_ptr);
            return OK_DUPLICATE;
        }
    }
    assert(block_ptr);

    /*
     *  We did not find it; do an insert into the last block by
     *  setting the key AND increasing the count.  The caller will set
     *  the value.
     *
     *  NOTE: entry_ptr is pointer to the insert location and
     *  block_ptr is pointing at the last block, and this is why we
     *  first check whether need to grow the table.
     *
     *  NOTE: Since we return a reference to the value, the user could
     *  either not set the value or mistakenly set the value to the
     *  'no_value_ptr'.  This is problematic, since the internal count
     *  will have been incremented even though in essence no entry has
     *  been added.  This may lead to growing the table sooner than
     *  necesssary.
     *
     *  Even worse is if the user updates an existing entry's value to
     *  the 'no_value_ptr' after there has been a collision on that
     *  entry.  Keys that collided can no longer be found in the table.
     */
    *value_pptr = HASHENTRY_GET_VALUE(block_ptr, entry_ptr);
    HASHENTRY_SET_KEY(block_ptr, entry_ptr, key_ptr);
    ++block_ptr->num_entries;

    return OK;
}


int
hashlib_lookup(
    const HashTable    *table_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **value_pptr)
{
    const HashBlock *block_ptr;
    uint8_t *entry_ptr = NULL;
    unsigned int k;

    assert(table_ptr);

    HASH_STAT_INCR(table_ptr, lookups);

    if (table_ptr->is_sorted) {
        TRACEMSG(1,(TRC_FMT "Attempt to lookup in a sorted HashTable",
                    TRC_ARG(table_ptr)));
        assert(0 == table_ptr->is_sorted);
        return ERR_SORTTABLE;
    }

    /* Look in each block for the key */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        block_ptr = table_ptr->block_ptrs[k];
        if (hashlib_block_find_entry(block_ptr, key_ptr, &entry_ptr) == OK) {
            /* Return pointer to the value in the entry structure */
            *value_pptr = HASHENTRY_GET_VALUE(block_ptr, entry_ptr);
            return OK;
        }
    }
    return ERR_NOTFOUND;
}


/*
 *    If not found, points to insertion point,
 */
static int
hashlib_block_find_entry(
    const HashBlock    *block_ptr,
    const uint8_t      *key_ptr,
    uint8_t           **entry_pptr)
{
#ifdef HASHLIB_RECORD_STATS
    int first_check = 1;
#endif
#ifndef NDEBUG
    uint32_t num_tries = 0;
#endif
    uint64_t hash_index;
    uint64_t hash_value;
    uint64_t hash_probe_increment;
    /* seeds for the hashing function */
    uint32_t hash_primary = 0x53694c4b;
    uint32_t hash_secondary = 0x4361726e;

    HASH_STAT_INCR(block_ptr, find_entries);

    /*
     *  First this code computes the hash for the key, the
     *  'hash_value'.
     *
     *  The 'hash_value' is masked by the size of the block to
     *  determine which bucket to check (the 'hash_index').  Since the
     *  block size is a power of 2, masking can be used as a modulo
     *  operation.
     *
     *  If the bucket is empty, this function is done; the function
     *  passes back a handle to that bucket and returns ERR_NOTFOUND.
     *
     *  If the bucket is not empty, the function checks to see if
     *  bucket's key matches the key passed into the function.  The
     *  comparison is done by memcmp()ing the keys.  If the keys
     *  match, the entry is found; the function passes back a handle
     *  the bucket and returns OK.
     *
     *  If the keys do not match, it means multiple keys return the
     *  same hash value; that is, there is a collision.  A new bucket
     *  is selected by incrementing the 'hash_value' by the
     *  'hash_probe_increment' value and masking the result by the
     *  block size.
     *
     *  The process repeats until either an empty bucket is found or
     *  the keys match.
     *
     *  This collision resolution mechanism is what makes removal
     *  impossible.  To allow removal, we would need either to define
     *  a special "deleted-entry" value or to rehash the table after
     *  each deletion.
     *
     *  Collision resolution is also why the caller should never
     *  update a bucket's value to the no_value_ptr value---though
     *  there is no way for the hashlib code to enforce this.
     */
    hash(key_ptr, HASH_GET_KEY_LEN(block_ptr), &hash_primary, &hash_secondary);
    hash_value = hash_primary + (((uint64_t)hash_secondary) << UINT64_C(32));
    hash_probe_increment = hash_value | 0x01; /* must be odd */
    for (;;) {
        hash_index = hash_value & (block_ptr->max_entries - 1);

        *entry_pptr = HASH_ENTRY_AT(block_ptr, hash_index);
        if (HASHENTRY_ISEMPTY(block_ptr, *entry_pptr)) {
            /* Hit an empty entry, we're done. */
            return ERR_NOTFOUND;
        }
        /* compare the keys */
        if (0 == memcmp(HASHENTRY_GET_KEY(block_ptr, *entry_pptr),
                        key_ptr, HASH_GET_KEY_LEN(block_ptr)))
        {
            /* Found a match, we're done */
            return OK;
        }

        /* increment the hash value */
        hash_value += hash_probe_increment;
        assert(++num_tries < block_ptr->max_entries);
#ifdef HASHLIB_RECORD_STATS
        if (first_check) {
            first_check = 0;
            HASH_STAT_INCR(block_ptr, find_collisions);
        }
        HASH_STAT_INCR(block_ptr, collision_hops);
#endif  /* HASHLIB_RECORD_STATS */
    }
}


#ifdef HASHLIB_RECORD_STATS
void
hashlib_clear_stats(
    HashTable          *table_ptr)
{
    if (table_ptr) {
        memset(&table_ptr->ht_stats, 0, sizeof(table_ptr->ht_stats));
    }
}

void
hashlib_get_stats(
    const HashTable    *table_ptr,
    hashlib_stats_t    *hash_stats)
{
    if (table_ptr && hash_stats) {
        memcpy(hash_stats, &table_ptr->ht_stats, sizeof(table_ptr->ht_stats));
    }
}

void
hashlib_print_stats(
    FILE               *fp,
    const HashTable    *table_ptr)
{
    const hashlib_stats_t *hts = &table_ptr->ht_stats;

    fprintf(fp, "Accumulated hashtable statistics:\n");
    fprintf(fp, "  %" PRIu32 " total allocations.\n",   hts->blocks_allocated);
    fprintf(fp, "  %" PRIu64 " total inserts.\n",       hts->inserts);
    fprintf(fp, "  %" PRIu64 " total lookups.\n",       hts->lookups);
    fprintf(fp, "  %" PRIu32 " total rehashes.\n",      hts->rehashes);
    fprintf(fp, "  %" PRIu64 " inserts due to rehashing.\n",
            hts->rehash_inserts);
    fprintf(fp, "  %" PRIu64 " total finds.\n",         hts->find_entries);
    fprintf(fp, "  %" PRIu64 " total find collisions.\n",
            hts->find_collisions);
    fprintf(fp, "  %" PRIu64 " total collision hops.\n",
            hts->collision_hops);
}
#endif /* HASHLIB_RECORD_STATS */


HASH_ITER
hashlib_create_iterator(
    const HashTable UNUSED(*table_ptr))
{
    HASH_ITER iter;

    memset(&iter, 0, sizeof(HASH_ITER));
    iter.block = HASH_ITER_BEGIN;
    return iter;
}


int
hashlib_iterate(
    const HashTable    *table_ptr,
    HASH_ITER          *iter_ptr,
    uint8_t           **key_pptr,
    uint8_t           **val_pptr)
{
#if TRACEMSG_LEVEL >= 2
    static uint64_t so_far = 0;
#endif
    HashBlock *block_ptr;
    uint8_t *entry_ptr;

    if (iter_ptr->block == HASH_ITER_END) {
        return ERR_NOMOREENTRIES;
    }

    if (table_ptr->is_sorted && table_ptr->num_blocks > 1) {
        /* Use sorted iterator if we should */
        return hashlib_iterate_sorted(table_ptr, iter_ptr, key_pptr, val_pptr);
    }

    /* Start at the first entry in the first block or increment the
     * iterator to start looking at the next entry. */
    if (iter_ptr->block == HASH_ITER_BEGIN) {
        /* Initialize the iterator. */
        memset(iter_ptr, 0, sizeof(HASH_ITER));
#if TRACEMSG_LEVEL >= 2
        TRACEMSG(2,(TRC_FMT "Iterate. Starting to iterate over HashTable...",
                    TRC_ARG(table_ptr)));
        so_far = 0;
#endif
    } else {
        ++iter_ptr->index;
    }

    /* Walk through indices of current block until we find a
     * non-empty.  Once we reach the end of the block, move on to the
     * next block. */
    while (iter_ptr->block < table_ptr->num_blocks) {

        /* Select the current block */
        block_ptr = table_ptr->block_ptrs[iter_ptr->block];

        /* Find the next non-empty entry in the current block (if
         * there is one). */
        for (entry_ptr = HASH_ENTRY_AT(block_ptr, iter_ptr->index);
             iter_ptr->index < block_ptr->max_entries;
             ++iter_ptr->index, entry_ptr += HASH_GET_ENTRY_LEN(block_ptr))
        {
            if (!HASHENTRY_ISEMPTY(block_ptr, entry_ptr)) {
                /* We found an entry, return it */
                *key_pptr = HASHENTRY_GET_KEY(block_ptr, entry_ptr);
                *val_pptr = HASHENTRY_GET_VALUE(block_ptr, entry_ptr);
#if TRACEMSG_LEVEL >= 2
                ++so_far;
#endif
                return OK;
            }
        }

        /* At the end of the block. */
        TRACEMSG(2,((TRC_FMT "Iterate. Finished block #%u containing %" PRIu64
                     " entries. Total visted %" PRIu64),
                    TRC_ARG(table_ptr), iter_ptr->block,
                    block_ptr->num_entries, so_far));

        /* try the next block */
        ++iter_ptr->block;
        iter_ptr->index = 0;
    }

    /* We're past the last entry of the last block, so we're done. */
    *key_pptr = NULL;
    *val_pptr = NULL;
    iter_ptr->block = HASH_ITER_END;
    TRACEMSG(2,(TRC_FMT "Iterate. No more entries. Total visited %"
                PRIu64, TRC_ARG(table_ptr), so_far));

    return ERR_NOMOREENTRIES;
}


static int
hashlib_iterate_sorted(
    const HashTable    *table_ptr,
    HASH_ITER          *iter_ptr,
    uint8_t           **key_pptr,
    uint8_t           **val_pptr)
{
    uint8_t *lowest_entry = NULL;
    unsigned int k;

    assert(iter_ptr->block != HASH_ITER_END);

    /* Start at the first entry in the first block or increment the
     * iterator to start looking at the next entry. */
    if (iter_ptr->block == HASH_ITER_BEGIN) {
        /* Initialize the iterator. */
        memset(iter_ptr, 0, sizeof(HASH_ITER));
        TRACEMSG(2,((TRC_FMT "Iterate. Starting to iterate"
                     " over sorted HashTable..."), TRC_ARG(table_ptr)));
    } else {
        /* Increment the pointer in the block from which we took the
         * entry last time. */
        ++iter_ptr->block_idx[iter_ptr->block];
    }

    /* Find the first available value across all blocks; this is our
     * arbitrary "lowest" value. */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        if (iter_ptr->block_idx[k] < table_ptr->block_ptrs[k]->num_entries) {
            iter_ptr->block = k;
            lowest_entry = HASH_ENTRY_AT(table_ptr->block_ptrs[k],
                                         iter_ptr->block_idx[k]);
            break;
        }
    }

    if (k == table_ptr->num_blocks) {
        /* We've processed all blocks.  Done. */
        *key_pptr = NULL;
        *val_pptr = NULL;
        iter_ptr->block = HASH_ITER_END;
        TRACEMSG(2,(TRC_FMT "Iterate. No more entries.", TRC_ARG(table_ptr)));
        return ERR_NOMOREENTRIES;
    }

    /* Compare our arbitrary "lowest" with every remaining block to
     * find the actual lowest. */
    for ( ++k; k < table_ptr->num_blocks; ++k) {
        if ((iter_ptr->block_idx[k] < table_ptr->block_ptrs[k]->num_entries)
            && (table_ptr->cmp_fn(HASH_ENTRY_AT(table_ptr->block_ptrs[k],
                                                iter_ptr->block_idx[k]),
                                  lowest_entry,
                                  table_ptr->cmp_userdata)
                < 0))
        {
            iter_ptr->block = k;
            lowest_entry = HASH_ENTRY_AT(table_ptr->block_ptrs[k],
                                         iter_ptr->block_idx[k]);
        }
    }

    /* return lowest */
    *key_pptr = HASHENTRY_GET_KEY(table_ptr, lowest_entry);
    *val_pptr = HASHENTRY_GET_VALUE(table_ptr, lowest_entry);
    return OK;
}


uint64_t
hashlib_count_buckets(
    const HashTable    *table_ptr)
{
    unsigned int k;
    uint64_t total = 0;

    for (k = 0; k < table_ptr->num_blocks; ++k) {
        total += table_ptr->block_ptrs[k]->max_entries;
    }
    return total;
}


uint64_t
hashlib_count_entries(
    const HashTable    *table_ptr)
{
    unsigned int k;
    uint64_t total = 0;

    for (k = 0; k < table_ptr->num_blocks; ++k) {
        total += table_ptr->block_ptrs[k]->num_entries;
        TRACEMSG(3,((TRC_FMT "entry count for block #%u is %" PRIu64 "."),
                    TRC_ARG(table_ptr), k,
                    table_ptr->block_ptrs[k]->num_entries));
    }
    return total;
}


uint64_t
hashlib_count_nonempties(
    const HashTable    *table_ptr)
{
    const HashBlock *block_ptr;
    const uint8_t *entry_ptr;
    unsigned int k;
    uint64_t total;
    uint64_t count;
    uint64_t i;

    total = 0;
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        block_ptr = table_ptr->block_ptrs[k];
        count = 0;
        for (i = 0, entry_ptr = HASH_ENTRY_AT(block_ptr, 0);
             i < block_ptr->max_entries;
             ++i, entry_ptr += HASH_GET_ENTRY_LEN(block_ptr))
        {
            if (!HASHENTRY_ISEMPTY(block_ptr, entry_ptr)) {
                ++count;
            }
        }
        total += count;
        TRACEMSG(2,((TRC_FMT "nonempty count for block #%u is %" PRIu64 "."),
                    TRC_ARG(table_ptr), k, count));
    }
    return total;
}


/*
 *    Callback function used by hashlib_sort_entries().
 *
 *    Compare keys in 'a' and 'b' where the length of the keys is
 *    given by 'v_length'.
 */
static int
hashlib_memcmp_keys(
    const void         *a,
    const void         *b,
    void               *v_length)
{
    return memcmp(a, b, *(size_t*)v_length);
}


/*
 *    move the entries in each block to the front of the block, in
 *    preparation for sorting the entries
 */
static void
hashlib_make_contiguous(
    HashTable          *table_ptr)
{
    HashBlock *block_ptr;
    uint64_t i, j;
    unsigned int k;
    uint8_t *entry_i;
    uint8_t *entry_j;
    const uint64_t entry_len = HASH_GET_ENTRY_LEN(table_ptr);
    const uint64_t value_len = HASH_GET_VALUE_LEN(table_ptr);

    TRACEMSG(1,(TRC_FMT "Making the HashTable contiguous...",
                TRC_ARG(table_ptr)));

    for (k = 0; k < table_ptr->num_blocks; ++k) {
        TRACEMSG(2,(TRC_FMT "Making block #%u contiguous",
                    TRC_ARG(table_ptr), k));
        block_ptr = table_ptr->block_ptrs[k];
        if (0 == block_ptr->num_entries) {
            continue;
        }

        /* 'j' starts at the front of the block and moves forward to
         * find empty entries.  'i' starts at the end of the block
         * and moves backward to find occupied entries.  We move
         * non-empty entries from 'i' to 'j' to get rid of holes in
         * the block.  Stop once i and j meet. */
        for (j = 0, entry_j = HASH_ENTRY_AT(block_ptr, 0);
             j < block_ptr->max_entries;
             ++j, entry_j += entry_len)
        {
            if (HASHENTRY_ISEMPTY(block_ptr, entry_j)) {
                break;
            }
        }

        for (i = block_ptr->max_entries-1, entry_i =HASH_ENTRY_AT(block_ptr,i);
             i > j;
             --i, entry_i -= entry_len)
        {
            if (!HASHENTRY_ISEMPTY(block_ptr, entry_i)) {
                memcpy(entry_j, entry_i, entry_len);
                /* set i to the empty value */
                memcpy(HASHENTRY_GET_VALUE(block_ptr, entry_i),
                       table_ptr->no_value_ptr, value_len);
                /* find next empty value */
                for (++j, entry_j += entry_len;
                     j < i;
                     ++j, entry_j += entry_len)
                {
                    if (HASHENTRY_ISEMPTY(block_ptr, entry_j)) {
                        break;
                    }
                }
            }
        }
        assert(j <= block_ptr->num_entries);
    }
    TRACEMSG(1,(TRC_FMT "Made the HashTable contiguous.", TRC_ARG(table_ptr)));
}


int
hashlib_sort_entries_usercmp(
    HashTable              *table_ptr,
    hashlib_sort_key_cmp_fn cmp_fn,
    void                   *cmp_userdata)
{
    HashBlock *block_ptr;
    const size_t entry_len = HASH_GET_ENTRY_LEN(table_ptr);
    unsigned int k;

    TRACEMSG(1,(TRC_FMT "Sorting the HashTable...", TRC_ARG(table_ptr)));

    if (NULL == cmp_fn) {
        return ERR_BADARGUMENT;
    }
    if (!table_ptr->is_sorted) {
        /* first call; make the data in each block contiguous */
        hashlib_make_contiguous(table_ptr);
    }

    table_ptr->cmp_fn = cmp_fn;
    table_ptr->cmp_userdata = cmp_userdata;

    /* we use qsort to sort each block individually; when iterating,
     * return the lowest value among all sorted blocks. */
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        TRACEMSG(2,(TRC_FMT "Sorting block #%u...", TRC_ARG(table_ptr), k));
        block_ptr = table_ptr->block_ptrs[k];
        /* sort the block's entries */
        skQSort_r(block_ptr->data_ptr, block_ptr->num_entries,
                  entry_len, table_ptr->cmp_fn, table_ptr->cmp_userdata);
    }

    TRACEMSG(1,(TRC_FMT "Sorted the HashTable.", TRC_ARG(table_ptr)));

    table_ptr->is_sorted = 1;
    return 0;
}

int
hashlib_sort_entries(
    HashTable          *table_ptr)
{
    /* pass the key length in the context pointer */
    table_ptr->keylen_cmp_userdata = HASH_GET_KEY_LEN(table_ptr);
    return hashlib_sort_entries_usercmp(table_ptr, &hashlib_memcmp_keys,
                                        &table_ptr->keylen_cmp_userdata);
}



/*
 *  ********************************************************************
 *  DEBUGGING FUNCTIONS FOR PRINTING INFO ABOUT A TABLE
 *  ********************************************************************
 */

static void
hashlib_dump_bytes(
    FILE               *fp,
    const uint8_t      *data_ptr,
    uint64_t            data_len)
{
    uint64_t j;

    for (j = 0; j < data_len; ++j) {
        fprintf(fp, "%02x ", data_ptr[j]);
    }
}


static void
hashlib_dump_block_header(
    FILE               *fp,
    const HashBlock    *block_ptr)
{
    /* Dump header info */
    fprintf(fp, ("Block size: \t %" PRIu64 "\n"), block_ptr->max_entries);
    fprintf(fp, ("Num entries:\t %" PRIu64 " (%2.0f%% full)\n"),
            block_ptr->num_entries,
            100 * (float) block_ptr->num_entries / block_ptr->max_entries);
    fprintf(fp, "Key width:\t %u bytes\n", block_ptr->table->key_len);
    fprintf(fp, "Value width:\t %u bytes\n", block_ptr->table->value_len);
    fprintf(fp, "Load factor:\t %u = %2.0f%%\n",
            block_ptr->table->load_factor,
            100 * (float) block_ptr->table->load_factor / 255);
    fprintf(fp, "Empty value representation: ");
    hashlib_dump_bytes(fp, block_ptr->table->no_value_ptr,
                       block_ptr->table->value_len);
    fprintf(fp, "\n");
}


static void
hashlib_dump_block(
    FILE               *fp,
    const HashBlock    *block_ptr)
{
    uint64_t i;                 /* Index of into hash table */
    uint64_t entry_index = 0;
    const uint8_t *entry_ptr;

    hashlib_dump_block_header(fp, block_ptr);
    fprintf(fp, "Data Dump:\n");
    fprintf(fp, "----------\n");
    for (i = 0; i < block_ptr->max_entries; ++i) {
        entry_ptr = HASH_ENTRY_AT(block_ptr, i);
        /* Don't dump empty entries */
        if (HASHENTRY_ISEMPTY(block_ptr, entry_ptr)) {
            continue;
        }
        ++entry_index;

        /* Dump hash index in table, the key and the value */
        fprintf(fp, ("%6" PRIu64 " (%" PRIu64 "). "), entry_index, i);
        hashlib_dump_bytes(fp, HASHENTRY_GET_KEY(block_ptr, entry_ptr),
                           HASH_GET_KEY_LEN(block_ptr));
        fprintf(fp, " -- ");
        hashlib_dump_bytes(fp, HASHENTRY_GET_VALUE(block_ptr, entry_ptr),
                           HASH_GET_VALUE_LEN(block_ptr));
        fprintf(fp, "\n");
    }
}


void
hashlib_dump_table(
    FILE               *fp,
    const HashTable    *table_ptr)
{
    unsigned int k;

    hashlib_dump_table_header(fp, table_ptr);
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        fprintf(fp, "Block #%u:\n", k);
        hashlib_dump_block(fp, table_ptr->block_ptrs[k]);
    }
}


void
hashlib_dump_table_header(
    FILE               *fp,
    const HashTable    *table_ptr)
{
    unsigned int k;
    HashBlock *block_ptr;
    uint64_t total_used_memory = 0;
    uint64_t total_data_memory = 0;

    /* Dump header info */
    fprintf(fp, "Key width:\t %u bytes\n", table_ptr->key_len);
    fprintf(fp, "Value width:\t %d bytes\n", table_ptr->value_len);
    fprintf(fp, "Empty value:\t");
    hashlib_dump_bytes(fp, table_ptr->no_value_ptr, table_ptr->value_len);
    fprintf(fp, "\n");
    fprintf(fp, "Load factor:\t %d = %2.0f%%\n",
            table_ptr->load_factor,
            100 * (float) table_ptr->load_factor / 255);
    fprintf(fp, ("Table has %" PRIu8 " blocks:\n"), table_ptr->num_blocks);
    for (k = 0; k < table_ptr->num_blocks; ++k) {
        block_ptr = table_ptr->block_ptrs[k];
        total_data_memory +=
            HASH_GET_ENTRY_LEN(block_ptr) * block_ptr->max_entries;
        total_used_memory +=
            HASH_GET_ENTRY_LEN(block_ptr) * block_ptr->num_entries;
        fprintf(fp, ("  Block #%u: %" PRIu64 "/%" PRIu64 " (%3.1f%%)\n"),
                k, block_ptr->num_entries, block_ptr->max_entries,
                100 * ((float)block_ptr->num_entries) / block_ptr->max_entries);
    }
    fprintf(fp, ("Total data memory:           %" PRIu64 " bytes\n"),
            total_data_memory);
    fprintf(fp, ("Total allocated data memory: %" PRIu64 " bytes\n"),
            total_used_memory);
    fprintf(fp, ("Excess data memory:          %" PRIu64 " bytes\n"),
            total_data_memory - total_used_memory);
    fprintf(fp, "\n");
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
