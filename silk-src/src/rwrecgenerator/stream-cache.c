/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: stream-cache.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include <silk/redblack.h>
#include "stream-cache.h"

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/* DEFINES AND TYPEDEFS */

/* Message to print when out of memory */
#define FMT_MEM_FAILURE  "Out of memory at %s:%d", __FILE__, __LINE__


/*
 *  The stream_cache_t contains an array of cache_entry_t objects.
 *  The array is allocated with 'max_size' entries when the cache is
 *  created.  The number of valid entries in the array is specified by
 *  'size'.  The cache also contains a redblack tree that is used to
 *  index the entries.
 */
struct stream_cache_st {
    /* Array of cache entries */
    cache_entry_t      *entries;
    /* the redblack tree used for searching */
    struct rbtree      *rbtree;
    /* function called by skCacheLookupOrOpenAdd() to open a file */
    cache_open_fn_t     open_callback;
    /* current number of valid entries */
    int                 size;
    /* maximum number of valid entries */
    int                 max_size;
};


/* LOCAL FUNCTION DECLARATIONS */

static int
cacheEntryAdd(
    stream_cache_t     *cache,
    skstream_t         *stream,
    const cache_key_t  *key,
    cache_entry_t     **new_entry);
static int
cacheEntryCompare(
    const void         *entry1_v,
    const void         *entry2_v,
    const void  UNUSED(*config));
static int
cacheEntryDestroyFile(
    stream_cache_t     *cache,
    cache_entry_t      *entry,
    int                 entry_is_locked);
static void
cacheEntryLogRecordCount(
    cache_entry_t      *entry);
static cache_entry_t *
cacheEntryLookup(
    stream_cache_t     *cache,
    const cache_key_t  *key);


/* FUNCTION DEFINITIONS */

/*
 *  status = cacheEntryAdd(cache, stream, key, &entry);
 *
 *    Add 'stream' to the stream cache 'cache' using 'key' as the key,
 *    and put the entry into the value pointed at by 'entry'.  The
 *    cache must be locked for writing.  The entry's last_accessed
 *    time is set to the current time and the entry is returned in a
 *    locked state.
 *
 *    Return 0 on success.  Return -1 if there is a problem
 *    initializing the entry.  If adding an entry causes an existing
 *    stream to be closed and there is a problem closing the stream,
 *    the new entry is still added and 1 is returned.
 */
static int
cacheEntryAdd(
    stream_cache_t     *cache,
    skstream_t         *stream,
    const cache_key_t  *key,
    cache_entry_t     **new_entry)
{
    cache_entry_t *entry;
    const void *node;
    int retval = 0;

    assert(stream);
    assert(new_entry);

    TRACEMSG(2, ("Adding new entry to cache with %d/%d entries",
                 cache->size, cache->max_size));

    if (cache->size < cache->max_size) {
        /* We're not to the max size yet, so use the next entry in the
         * array */
        entry = &cache->entries[cache->size];
        ++cache->size;
    } else {
        /* The cache is full: flush, close and free the least recently
         * used stream */
        cache_entry_t *e;
        sktime_t min;
        int i;

        e = &cache->entries[0];
        min = e->last_accessed;
        entry = e;

        for (i = 1; i < cache->size; ++i, ++e) {
            if (e->last_accessed < min) {
                min = e->last_accessed;
                entry = e;
            }
        }
        if (cacheEntryDestroyFile(cache, entry, 0)) {
            retval = 1;
        }
    }

    /* fill the new entry */
    entry->key.time_stamp = key->time_stamp;
    entry->key.sensor_id = key->sensor_id;
    entry->key.flowtype_id = key->flowtype_id;
    entry->stream = stream;
    entry->rec_count = skStreamGetRecordCount(stream);
    entry->last_accessed = sktimeNow();

    /* add the entry to the redblack tree */
    node = rbsearch(entry, cache->rbtree);
    if (node != entry) {
        if (node == NULL) {
            CRITMSG(FMT_MEM_FAILURE);
            exit(EXIT_FAILURE);
        }
        CRITMSG(("Duplicate entries in stream cache "
                 "for time=%" PRId64 " sensor=%d flowtype=%d"),
                key->time_stamp, key->sensor_id, key->flowtype_id);
        skAbort();
    }

    /* lock the entry */
    *new_entry = entry;
    return retval;
}


/*
 *  direction = cacheEntryCompare(a, b, config);
 *
 *    The comparison function used by the redblack tree.
 */
static int
cacheEntryCompare(
    const void         *entry1_v,
    const void         *entry2_v,
    const void  UNUSED(*config))
{
    cache_key_t key1 = ((cache_entry_t*)entry1_v)->key;
    cache_key_t key2 = ((cache_entry_t*)entry2_v)->key;

    if (key1.sensor_id < key2.sensor_id) {
        return -1;
    }
    if (key1.sensor_id > key2.sensor_id) {
        return 1;
    }
    if (key1.flowtype_id < key2.flowtype_id) {
        return -1;
    }
    if (key1.flowtype_id > key2.flowtype_id) {
        return 1;
    }
    if (key1.time_stamp < key2.time_stamp) {
        return -1;
    }
    if (key1.time_stamp > key2.time_stamp) {
        return 1;
    }
    return 0;
}


/*
 *  cacheEntryMove(cache, dst, src);
 *
 *    Move an entry from 'dst' to 'src'.  The entry must be unlocked,
 *    and the cache must have a write lock.
 */
static void
cacheEntryMove(
    stream_cache_t     *cache,
    cache_entry_t      *dst_entry,
    cache_entry_t      *src_entry)
{
    const cache_entry_t *node;
    const cache_key_t *key;

    /* remove from tree and destroy */
    rbdelete(src_entry, cache->rbtree);

    /* copy the entry */
    memcpy(dst_entry, src_entry, sizeof(cache_entry_t));

    /* insert entry back into tree */
    node = (const cache_entry_t*)rbsearch(dst_entry, cache->rbtree);
    if (node != dst_entry) {
        if (node == NULL) {
            CRITMSG(FMT_MEM_FAILURE);
            exit(EXIT_FAILURE);
        }
        key = &dst_entry->key;
        CRITMSG(("Duplicate entries in stream cache during move "
                 "for time=%" PRId64 " sensor=%d flowtype=%d"),
                key->time_stamp, key->sensor_id, key->flowtype_id);
        skAbort();
    }
}


/*
 *  status = cacheEntryDestroyFile(cache, entry, entry_is_locked);
 *
 *    Close the stream that 'entry' wraps, destroy the stream, and
 *    remove the entry from the redblack tree.  In addition, log the
 *    number of records written.
 *
 *    This function expects the caller to have a write lock on the
 *    cache.
 *
 *    Returns 0 if the entry's stream was successfully closed;
 *    non-zero otherwise.
 */
static int
cacheEntryDestroyFile(
    stream_cache_t         *cache,
    cache_entry_t          *entry,
    int              UNUSED(entry_is_locked))
{
    int rv;

    TRACEMSG(2, ("Stream cache closing file %s",
                 skStreamGetPathname(entry->stream)));

    cacheEntryLogRecordCount(entry);
    rv = skStreamClose(entry->stream);
    if (rv) {
        skStreamPrintLastErr(entry->stream, rv, &NOTICEMSG);
    }
    skStreamDestroy(&entry->stream);
    rbdelete(entry, cache->rbtree);

    return rv;
}


/*
 *  cacheEntryLogRecordCount(entry);
 *
 *    Write a message to the log giving the name of the file that
 *    'entry' wraps and the number of records written to that file
 *    since it was opened or last flushed.
 *
 *    The 'entry' will be updated with the new record count.
 */
static void
cacheEntryLogRecordCount(
    cache_entry_t      *entry)
{
    uint64_t new_count;

    new_count = skStreamGetRecordCount(entry->stream);

    if (entry->rec_count == new_count) {
        return;
    }
    assert(entry->rec_count < new_count);

    INFOMSG(("%s: %" PRIu64 " recs"),
            skStreamGetPathname(entry->stream),(new_count - entry->rec_count));
    entry->rec_count = new_count;
}


/*
 *  entry = skCacheLookup(cache, key);
 *
 *    Return the stream entry for the specified key.  Return NULL if
 *    no stream entry for the specified values is found.  The cache
 *    should be locked for reading or writing.  The entry's
 *    last_accessed time is updated and the entry is returned in a
 *    locked state.
 */
static cache_entry_t *
cacheEntryLookup(
    stream_cache_t     *cache,
    const cache_key_t  *key)
{
    cache_entry_t *entry;
    cache_entry_t search_key;

    /* fill the search key */
    search_key.key.time_stamp = key->time_stamp;
    search_key.key.sensor_id = key->sensor_id;
    search_key.key.flowtype_id = key->flowtype_id;

    /* try to find the entry */
    entry = (cache_entry_t*)rbfind(&search_key, cache->rbtree);
#if TRACEMSG_LEVEL >= 3
    {
        char tstamp[SKTIMESTAMP_STRLEN];
        char sensor[SK_MAX_STRLEN_SENSOR+1];
        char flowtype[SK_MAX_STRLEN_FLOWTYPE+1];

        sktimestamp_r(tstamp, key->time_stamp, SKTIMESTAMP_NOMSEC),
        sksiteSensorGetName(sensor, sizeof(sensor), key->sensor_id);
        sksiteFlowtypeGetName(flowtype, sizeof(flowtype), key->flowtype_id);

        TRACEMSG(3, ("Cache %s for stream %s %s %s",
                     ((entry == NULL) ? "miss" : "hit"),
                     tstamp, sensor, flowtype));
    }
#endif /* TRACEMSG_LEVEL */

    /* found it, lock it and update its last_accessed timestamp */
    if (entry) {
        entry->last_accessed = sktimeNow();
    }

    return entry;
}


/* add an entry to the cache.  return entry in locked state. */
int
skCacheAdd(
    stream_cache_t     *cache,
    skstream_t         *stream,
    const cache_key_t  *key,
    cache_entry_t     **entry)
{
    int retval;

    retval = cacheEntryAdd(cache, stream, key, entry);

    return retval;
}


/* lock cache, then close and destroy all streams.  unlock cache. */
int
skCacheCloseAll(
    stream_cache_t     *cache)
{
    int retval;

    if (NULL == cache) {
        return 0;
    }

    retval = skCacheLockAndCloseAll(cache);

    return retval;
}


/* create a cache with the specified size and open callback function */
stream_cache_t *
skCacheCreate(
    int                 max_size,
    cache_open_fn_t     open_fn)
{
    stream_cache_t *cache = NULL;

    /* verify input */
    if (max_size < STREAM_CACHE_MINIMUM_SIZE) {
        CRITMSG(("Illegal maximum size (%d) for stream cache;"
                 " must use value >= %u"),
                max_size, STREAM_CACHE_MINIMUM_SIZE);
        return NULL;
    }

    cache = (stream_cache_t*)calloc(1, sizeof(stream_cache_t));
    if (cache == NULL) {
        CRITMSG(FMT_MEM_FAILURE);
        return NULL;
    }

    cache->entries = (cache_entry_t *)calloc(max_size, sizeof(cache_entry_t));
    if (cache->entries == NULL) {
        CRITMSG(FMT_MEM_FAILURE);
        free(cache);
        return NULL;
    }

    cache->rbtree = rbinit(&cacheEntryCompare, NULL);
    if (cache->rbtree == NULL) {
        CRITMSG(FMT_MEM_FAILURE);
        free(cache->entries);
        free(cache);
        return NULL;
    }

    cache->max_size = max_size;
    cache->open_callback = open_fn;

    return cache;
}


/* close all streams, destroy them, and destroy the cache */
int
skCacheDestroy(
    stream_cache_t     *cache)
{
    int retval;

    if (NULL == cache) {
        INFOMSG("Tried to destroy unitialized stream cache.");
        return 0;
    }

    TRACEMSG(1, ("Destroying cache with %d entries", cache->size));

    /* close any open files */
    retval = skCacheLockAndCloseAll(cache);

    /* destroy the redblack tree */
    rbdestroy(cache->rbtree);

    /* Destroy the entries array */
    free(cache->entries);

    /* Free the structure itself */
    free(cache);

    return retval;
}


/* flush all streams in the cache */
int
skCacheFlush(
    stream_cache_t     *cache)
{
#if TRACEMSG_LEVEL >= 3
    char tstamp[SKTIMESTAMP_STRLEN];
#endif
    sktime_t inactive_time;
    cache_entry_t *entry;
    int i;
    int j;
    int rv;
    int retval = 0;

    if (NULL == cache) {
        return 0;
    }

    /* compute the time for determining the inactive files */
    inactive_time = sktimeNow() - STREAM_CACHE_INACTIVE_TIMEOUT;

    TRACEMSG(1, ("Flushing cache with %d entries...", cache->size));
    TRACEMSG(3, ("Will close files inactive since %s",
                 sktimestamp_r(tstamp, inactive_time, 0)));

    for (i = 0, j = 0, entry = cache->entries; i < cache->size; ++i, ++entry) {
        if (entry->last_accessed > inactive_time) {
            /* file is still active; flush it and go to next file */
            rv = skStreamFlush(entry->stream);
            if (rv) {
                skStreamPrintLastErr(entry->stream, rv, &NOTICEMSG);
                retval = -1;
            }
            cacheEntryLogRecordCount(entry);

            if (j != i) {
                TRACEMSG(4, ("Moving entry from %d to %d", i, j));
                cacheEntryMove(cache, &cache->entries[j], entry);
            }
            ++j;

        } else {
            /* file is inactive; remove it from the cache */
            TRACEMSG(3, ("Closing inactive file %s; last_accessed %s",
                         skStreamGetPathname(entry->stream),
                         sktimestamp_r(tstamp, entry->last_accessed, 0)));

            rv = cacheEntryDestroyFile(cache, entry, 1);
            if (rv) {
                retval = -1;
            }
        }
    }
    cache->size = j;

    TRACEMSG(1, ("Flush finished.  Cache size is %d entries.", cache->size));

    return retval;
}


/* lock cache, then close and destroy all streams. do not unlock cache */
int
skCacheLockAndCloseAll(
    stream_cache_t     *cache)
{
    cache_entry_t *entry;
    int i;
    int retval = 0;

    if (NULL == cache) {
        return 0;
    }

    TRACEMSG(1, ("Closing all files in cache with %d entries", cache->size));

    for (i = 0, entry = cache->entries; i < cache->size; ++i, ++entry) {
        if (cacheEntryDestroyFile(cache, entry, 0)) {
            retval = -1;
        }
    }

    cache->size = 0;

    return retval;
}


/* find an entry in the cache.  return entry in locked state. */
cache_entry_t *
skCacheLookup(
    stream_cache_t     *cache,
    const cache_key_t  *key)
{
    cache_entry_t *entry;

    entry = cacheEntryLookup(cache, key);

    return entry;
}


/* find an entry in the cache.  if not present, use the open-callback
 * function to open/create the stream and then add it. */
int
skCacheLookupOrOpenAdd(
    stream_cache_t     *cache,
    const cache_key_t  *key,
    void               *caller_data,
    cache_entry_t     **entry)
{
    skstream_t *stream;
    int retval = 0;

    /* do a standard lookup */
    *entry = cacheEntryLookup(cache, key);

    /* found it; we can return */
    if (*entry) {
        goto END;
    }

    /* use the callback to open the file */
    stream = cache->open_callback(key, caller_data);
    if (NULL == stream) {
        retval = -1;
        goto END;
    }

    /* add the newly opened file to the cache */
    retval = cacheEntryAdd(cache, stream, key, entry);
    if (-1 == retval) {
        skStreamDestroy(&stream);
    }

  END:
    return retval;
}


#ifndef skCacheUnlock
/* unlocks a cache locked by skCacheLockAndCloseAll(). */
void
skCacheUnlock(
    stream_cache_t     *cache)
{
    assert(cache);
}
#endif


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
