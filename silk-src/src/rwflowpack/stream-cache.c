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

/* #define SKTHREAD_DEBUG_MUTEX */
#include <silk/silk.h>

RCSIDENT("$SiLK: stream-cache.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/redblack.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include "stream-cache.h"

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/* DEFINES AND TYPEDEFS */

/*
 *    Maximum value for the time stamp
 */
#define MAX_TIME  (sktime_t)INT64_MAX


/* Message to print when fail to initialize mutex */
#define FMT_MUTEX_FAILURE \
    "Could not initialize a mutex at %s:%d", __FILE__, __LINE__


/**
 *    stream_cache_t contains a red-black tree of cache_entry_t objects.
 *    The number of valid entries in the array is specified by
 *    'size'.  The cache also contains a redblack tree that is used to
 *    index the entries.  Finally, there is a mutex on the cache; the
 *    mutex will be a pthread_rwlock_t mutex if read/write locks are
 *    supported on this system.
 */
struct stream_cache_st {
    /* the redblack tree used for searching */
    struct rbtree      *rbtree;
    /* function called by skCacheLookupOrOpenAdd() to open a file that
     * is not currently in the cache */
    cache_open_fn_t     open_callback;
    /* current number of open entries */
    unsigned int        open_count;
    /* maximum number of open entries the user specified */
    unsigned int        max_open_count;
    /* total number of entries (open and closed) */
    unsigned int        total_count;
    /* mutex for the cache */
    RWMUTEX             mutex;
};
/* typedef struct stream_cache_st stream_cache_t; // stream-cache.h */


/**
 *    The cache_entry_t contains information about an active file in
 *    the stream cache.  The structure contains the file key, the
 *    number of records in the file, and the open file handle.
 *
 *    Users of the stream-cache should view the cache_entry_t as
 *    opaque.  Use the macros and functions to access its members.
 */
struct cache_entry_st {
    /** the key */
    cache_key_t         key;
    /** The mutex associated with this entry */
    pthread_mutex_t     mutex;
    /** the number of records written to the file since it was added
     * to the cache */
    uint64_t            total_rec_count;
    /** the number of records in the file when it was opened */
    uint64_t            opened_rec_count;
    /** when this entry was last accessed */
    sktime_t            last_accessed;
    /** the name of the file */
    const char         *filename;
    /** the open file handle */
    skstream_t         *stream;
    /** the more recently accessed entry */
    cache_entry_t      *more_recent;
    /** the less recently accessed entry */
    cache_entry_t      *less_recent;
};
/* typedef struct cache_entry_st cache_entry_t; // stream-cache.h */


/**
 *    cache_file_iter_t is returned by skCacheFlush() and
 *    skCacheCloseAll().
 */
struct cache_file_iter_st {
    sk_vector_t        *vector;
    size_t              pos;
};
/* typedef struct cache_file_iter_st cache_file_iter_t; // stream-cache.h */


/**
 *    cache_file_t contains information about a file that exists in
 *    the stream cache.  The structure contains the file's key, name,
 *    and the number of records written to the file since it was added
 *    to the cache or since the most recent call to skCacheFlush().
 *
 *    A vector of these structures may be returned by skCacheFlush()
 *    or skCacheCloseAll().
 */
struct cache_file_st {
    /* the key for this closed file */
    cache_key_t         key;
    /* the number of records in the file as of opening or the most
     * recent flush, used for log messages */
    uint64_t            rec_count;
    /* the name of the file */
    const char         *filename;
};
typedef struct cache_file_st cache_file_t;


/* FUNCTION DEFINITIONS */

/**
 *    Close the stream that 'entry' wraps and destroy the stream.  In
 *    addition, update the entry's 'total_rec_count'.
 *
 *    This function expects the caller to have the entry's mutex.
 *
 *    The entry's stream must be open.
 *
 *    Return the result of calling skStreamClose().  Log an error
 *    message if skStreamClose() fails.
 */
static int
cacheEntryClose(
    cache_entry_t      *entry)
{
    uint64_t new_count;
    int rv;

    assert(entry);
    assert(entry->stream);
    ASSERT_MUTEX_LOCKED(&entry->mutex);

    TRACEMSG(2, ("cache: Closing file '%s'", entry->filename));

    /* update the record count */
    new_count = skStreamGetRecordCount(entry->stream);
    assert(entry->opened_rec_count <= new_count);
    entry->total_rec_count += new_count - entry->opened_rec_count;

    /* close the stream */
    rv = skStreamClose(entry->stream);
    if (rv) {
        skStreamPrintLastErr(entry->stream, rv, &NOTICEMSG);
    }
    skStreamDestroy(&entry->stream);

    return rv;
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
    cache_key_t *key1 = &((cache_entry_t *)entry1_v)->key;
    cache_key_t *key2 = &((cache_entry_t *)entry2_v)->key;

    if (key1->sensor_id != key2->sensor_id) {
        return ((key1->sensor_id < key2->sensor_id) ? -1 : 1);
    }
    if (key1->flowtype_id != key2->flowtype_id) {
        return ((key1->flowtype_id < key2->flowtype_id) ? -1 : 1);
    }
    if (key1->time_stamp < key2->time_stamp) {
        return -1;
    }
    return (key1->time_stamp > key2->time_stamp);
}


/**
 *    Close the stream associated with the cache_entry_t 'entry' if it
 *    is open and destroy the 'entry'.  Does not remove 'entry' from
 *    the red-black tree.  This function assumes the caller holds the
 *    entry's mutex.  This is a no-op if 'entry' is NULL.
 *
 *    Return the result of skStreamClose() or 0 if stream was already
 *    closed.
 */
static int
cacheEntryDestroy(
    cache_entry_t      *entry)
{
    int rv = 0;

    if (entry) {
        ASSERT_MUTEX_LOCKED(&entry->mutex);

        if (entry->stream) {
            rv = cacheEntryClose(entry);
        }
        free((void*)entry->filename);
        MUTEX_UNLOCK(&entry->mutex);
        MUTEX_DESTROY(&entry->mutex);
        free(entry);
    }
    return rv;
}


/**
 *    Return the interator entry at 'pos' or return NULL if 'pos' is
 *    out of range.
 */
static cache_file_t *
cacheFileIterAt(
    cache_file_iter_t  *iter,
    size_t              pos)
{
    assert(iter);
    assert(iter->vector);
    return (cache_file_t *)skVectorGetValuePointer(iter->vector, pos);
}


/* lock cache, then close and destroy all streams.  unlock cache. */
int
skCacheCloseAll(
    stream_cache_t     *cache,
    cache_file_iter_t **file_iter)
{
    sk_vector_t *vector;
    struct rbtree *closed_tree;
    RBLIST *iter;
    cache_file_t closed;
    cache_entry_t *entry;
    int retval = 0;
    int rv;

    assert(cache);

    if (NULL == file_iter) {
        vector = NULL;
    } else {
        *file_iter = (cache_file_iter_t *)calloc(1, sizeof(cache_file_iter_t));
        vector = skVectorNew(sizeof(cache_file_t));
        if (*file_iter && vector) {
            (*file_iter)->vector = vector;
        } else {
            skAppPrintOutOfMemory(NULL);
            skVectorDestroy(vector);
            free(*file_iter);
            *file_iter = NULL;
            vector = NULL;
        }
    }

    TRACEMSG(1, ("cache: Closing cache: %u total, %u open, %u closed...",
                 cache->total_count, cache->open_count,
                 cache->total_count - cache->open_count));

    WRITE_LOCK(&cache->mutex);
    if (0 == cache->total_count) {
        RW_MUTEX_UNLOCK(&cache->mutex);
        return 0;
    }

    TRACEMSG(2, ("cache: Closing cache: Closing files..."));

    /* close all open streams */
    iter = rbopenlist(cache->rbtree);
    while ((entry = (cache_entry_t *)rbreadlist(iter)) != NULL) {
        MUTEX_LOCK(&entry->mutex);
        if (entry->stream) {
            rv = cacheEntryClose(entry);
            if (rv) {
                retval = -1;
            }
        }
        MUTEX_UNLOCK(&entry->mutex);
    }
    rbcloselist(iter);

    TRACEMSG(2, ("cache: Closing cache: Creating new rbtree..."));

    /* get a handle to the existing red-black tree and create a new
     * one on the cache. */
    closed_tree = cache->rbtree;
    cache->rbtree = rbinit(&cacheEntryCompare, NULL);
    if (cache->rbtree == NULL) {
        skAppPrintOutOfMemory(NULL);
        RW_MUTEX_UNLOCK(&cache->mutex);
        skAbort();
    }
    cache->open_count = 0;
    cache->total_count = 0;

    /* release the mutex */
    RW_MUTEX_UNLOCK(&cache->mutex);

    if (NULL == vector) {
        /* destroy all the entries */
        TRACEMSG(2, ("cache: Closing cache: Destroying entries..."));
        iter = rbopenlist(closed_tree);
        while ((entry = (cache_entry_t *)rbreadlist(iter)) != NULL) {
            MUTEX_LOCK(&entry->mutex);
            assert(NULL == entry->stream);
            cacheEntryDestroy(entry);
        }
        rbcloselist(iter);
    } else {
        /* move all entries that have a record count from the rbtree
         * into the vector */
        TRACEMSG(2, ("cache: Closing cache: Filling iterator..."));
        iter = rbopenlist(closed_tree);
        while ((entry = (cache_entry_t *)rbreadlist(iter)) != NULL) {
            MUTEX_LOCK(&entry->mutex);
            assert(NULL == entry->stream);
            if (entry->total_rec_count) {
                closed.key = entry->key;
                closed.rec_count = entry->total_rec_count;
                closed.filename = entry->filename;
                entry->filename = NULL;
                if (skVectorAppendValue(vector, &closed)) {
                    skAppPrintOutOfMemory(NULL);
                    free((void *)closed.filename);
                }
            }
            cacheEntryDestroy(entry);
        }
        rbcloselist(iter);
    }

    /* done with the tree */
    rbdestroy(closed_tree);

    TRACEMSG(1, ("cache: Closing cache: Done."));

    return retval;
}


/* create a cache with the specified size and open callback function */
stream_cache_t *
skCacheCreate(
    size_t              max_size,
    cache_open_fn_t     open_fn)
{
    stream_cache_t *cache = NULL;

    /* verify input */
    if (max_size < STREAM_CACHE_MINIMUM_SIZE) {
        CRITMSG(("Illegal maximum size (%" SK_PRIuZ ") for stream cache;"
                 " must use value >= %u"),
                max_size, STREAM_CACHE_MINIMUM_SIZE);
        return NULL;
    }
    if (NULL == open_fn) {
        CRITMSG("No open function provided to stream cache");
        return NULL;
    }

    cache = (stream_cache_t *)calloc(1, sizeof(stream_cache_t));
    if (cache == NULL) {
        skAppPrintOutOfMemory(NULL);
        return NULL;
    }

    if (RW_MUTEX_INIT(&cache->mutex)) {
        CRITMSG(FMT_MUTEX_FAILURE);
        free(cache);
        return NULL;
    }

    cache->rbtree = rbinit(&cacheEntryCompare, NULL);
    if (cache->rbtree == NULL) {
        skAppPrintOutOfMemory(NULL);
        RW_MUTEX_DESTROY(&cache->mutex);
        free(cache);
        return NULL;
    }

    cache->max_open_count = max_size;
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
        TRACEMSG(1, ("cache: Tried to destroy unitialized stream cache"));
        return 0;
    }

    TRACEMSG(1, ("cache: Destroying cache: %u total, %u open, %u closed...",
                 cache->total_count, cache->open_count,
                 cache->total_count - cache->open_count));

    /* close any open files */
    retval = skCacheCloseAll(cache, NULL);

    /* destroy the redblack tree */
    rbdestroy(cache->rbtree);

    RW_MUTEX_UNLOCK(&cache->mutex);
    RW_MUTEX_DESTROY(&cache->mutex);

    /* Free the structure itself */
    free(cache);

    TRACEMSG(1, ("cache: Destroying cache: Done."));

    return retval;
}


/* return the stream member of an entry */
skstream_t *
skCacheEntryGetStream(
    const cache_entry_t    *entry)
{
    assert(entry);
    ASSERT_MUTEX_LOCKED(&((cache_entry_t *)entry)->mutex);
    return entry->stream;
}


/* unlock the entry */
void
skCacheEntryRelease(
    cache_entry_t  *entry)
{
    assert(entry);
    ASSERT_MUTEX_LOCKED(&entry->mutex);
    MUTEX_UNLOCK(&entry->mutex);
}


/* return the number of files in the iterator */
size_t
skCacheFileIterCountEntries(
    const cache_file_iter_t    *iter)
{
    assert(iter);
    return skVectorGetCount(iter->vector);
}

/* destory the iterator and all the files it contains */
void
skCacheFileIterDestroy(
    cache_file_iter_t  *iter)
{
    cache_file_t *file;
    size_t i;

    if (iter) {
        for (i = 0; (file = (cache_file_t *)cacheFileIterAt(iter, i)); ++i) {
            free((void *)file->filename);
        }
        skVectorDestroy(iter->vector);
        free(iter);
    }
}


/* get the next filename and record-count from the iterator */
int
skCacheFileIterNext(
    cache_file_iter_t  *iter,
    const char        **filename,
    uint64_t           *record_count)
{
    cache_file_t *file;

    assert(iter);
    assert(filename);
    assert(record_count);

    file = cacheFileIterAt(iter, iter->pos);
    if (NULL == file) {
        assert(skVectorGetCount(iter->vector) == iter->pos);
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    ++iter->pos;
    *filename = file->filename;
    *record_count = file->rec_count;
    return SK_ITERATOR_OK;
}



/* flush all streams in the cache */
int
skCacheFlush(
    stream_cache_t     *cache,
    cache_file_iter_t **file_iter)
{
#if TRACEMSG_LEVEL >= 3
    char tstamp[SKTIMESTAMP_STRLEN];
#endif
    sktime_t inactive_time;
    cache_entry_t *entry;
    cache_entry_t *del_entry;
    uint64_t old_count;
    sk_vector_t *vector;
    RBLIST *iter;
    cache_file_t flushed;
    int retval = 0;
    int rv;

    assert(cache);
    assert(file_iter);

    *file_iter = (cache_file_iter_t *)calloc(1, sizeof(cache_file_iter_t));
    vector = skVectorNew(sizeof(cache_file_t));
    if (NULL == *file_iter || NULL == vector) {
        skAppPrintOutOfMemory(NULL);
        skVectorDestroy(vector);
        free(*file_iter);
        *file_iter = NULL;
        return -1;
    }
    (*file_iter)->vector = vector;

    if (NULL == cache) {
        TRACEMSG(1, ("cache: Tried to flush unitialized stream cache."));
        return 0;
    }

    WRITE_LOCK(&cache->mutex);

    /* compute the time for determining the inactive files */
    inactive_time = sktimeNow() - STREAM_CACHE_INACTIVE_TIMEOUT;

    TRACEMSG(1, ("cache: Flushing cache: %u total, %u open, %u closed...",
                 cache->total_count, cache->open_count,
                 cache->total_count - cache->open_count));
    TRACEMSG(3, ("cache: Flushing cache: Closing files inactive since %s...",
                 sktimestamp_r(tstamp, inactive_time, 0)));

    /* entry to delete from rbtree; delete it after moving to the next
     * entry in the tree */
    del_entry = NULL;

    iter = rbopenlist(cache->rbtree);
    while ((entry = (cache_entry_t *)rbreadlist(iter)) != NULL) {
        if (del_entry) {
            rbdelete(del_entry, cache->rbtree);
            cacheEntryDestroy(del_entry);
            --cache->total_count;
            del_entry = NULL;
        }
        MUTEX_LOCK(&entry->mutex);
        if (entry->stream && (entry->last_accessed > inactive_time)) {
            /* file is still active; flush it */
            rv = skStreamFlush(entry->stream);
            if (rv) {
                skStreamPrintLastErr(entry->stream, rv, &NOTICEMSG);
                retval = -1;
            }
            old_count = entry->opened_rec_count;
            entry->opened_rec_count = skStreamGetRecordCount(entry->stream);
            assert(old_count <= entry->opened_rec_count);
            entry->total_rec_count += entry->opened_rec_count - old_count;
            if (entry->total_rec_count) {
                /* append an entry to vector; copy the filename */
                flushed.filename = strdup(entry->filename);
                if (!flushed.filename) {
                    skAppPrintOutOfMemory(NULL);
                } else {
                    flushed.key = entry->key;
                    flushed.rec_count = entry->total_rec_count;
                    entry->total_rec_count = 0;
                    if (skVectorAppendValue(vector, &flushed)) {
                        skAppPrintOutOfMemory(NULL);
                        free((void *)flushed.filename);
                    }
                }
            }
            MUTEX_UNLOCK(&entry->mutex);
        } else {
            /* stream is inactive or closed; delete the entry */
            del_entry = entry;
            if (entry->stream) {
                TRACEMSG(3, ("cache: Flushing cache:"
                             " Closing inactive file %s; last_accessed %s",
                             entry->filename,
                             sktimestamp_r(tstamp, entry->last_accessed, 0)));
                rv = cacheEntryClose(entry);
                if (rv) {
                    retval = -1;
                }
                --cache->open_count;
            }
            if (entry->total_rec_count) {
                /* append an entry to the vector; steal the filename
                 * since the entry is being destroyed */
                flushed.key = entry->key;
                flushed.rec_count = entry->total_rec_count;
                flushed.filename = entry->filename;
                entry->filename = NULL;
                if (skVectorAppendValue(vector, &flushed)) {
                    skAppPrintOutOfMemory(NULL);
                    free((void *)flushed.filename);
                }
            }
        }
    }
    rbcloselist(iter);

    if (del_entry) {
        rbdelete(del_entry, cache->rbtree);
        cacheEntryDestroy(del_entry);
        --cache->total_count;
    }

    TRACEMSG(1, ("cache: Flushing cache. %u total, %u open. Done.",
                 cache->total_count, cache->open_count));

    RW_MUTEX_UNLOCK(&cache->mutex);

    return retval;
}


/* find an entry in the cache.  if not present, use the open-callback
 * function to open/create the stream and then add it. */
int
skCacheLookupOrOpenAdd(
    stream_cache_t     *cache,
    const cache_key_t  *key,
    void               *caller_data,
    cache_entry_t     **out_entry)
{
#ifdef SK_HAVE_PTHREAD_RWLOCK
    int have_writelock = 0;
#endif
    cache_entry_t search_key;
    cache_entry_t *e;
    cache_entry_t *entry;
    int retval = 0;
    int rv;
#if TRACEMSG_LEVEL >= 3
    char tstamp[SKTIMESTAMP_STRLEN];
    char sensor[SK_MAX_STRLEN_SENSOR+1];
    char flowtype[SK_MAX_STRLEN_FLOWTYPE+1];

    sktimestamp_r(tstamp, key->time_stamp, SKTIMESTAMP_NOMSEC);
    sksiteSensorGetName(sensor, sizeof(sensor), key->sensor_id);
    sksiteFlowtypeGetName(flowtype, sizeof(flowtype), key->flowtype_id);
#endif /* TRACEMSG_LEVEL */

    search_key.key.time_stamp = key->time_stamp;
    search_key.key.sensor_id = key->sensor_id;
    search_key.key.flowtype_id = key->flowtype_id;

    /* do a lookup holding only the read lock; if there is no support
     * for read-write locks, the entire cache is locked. */
    READ_LOCK(&cache->mutex);

  LOOKUP:
    /* try to find the entry */
    entry = (cache_entry_t *)rbfind(&search_key, cache->rbtree);
    TRACEMSG(3, ("cache: Lookup: %s for stream %s %s %s",
                 ((entry) ? "hit" : "miss"), tstamp, sensor, flowtype));

    /* if we find it and the stream is open, return it */
    if (entry && entry->stream) {
        MUTEX_LOCK(&entry->mutex);
        TRACEMSG(2, ("cache: Lookup: found open stream '%s'",entry->filename));
        entry->last_accessed = sktimeNow();
        *out_entry = entry;
        retval = 0;
        goto END;
    }

#ifdef SK_HAVE_PTHREAD_RWLOCK
    if (!have_writelock) {
        have_writelock = 1;
        /*
         *  we need to either add or reopen the stream.  We want to get a
         *  write lock on the cache, but first we must release the read
         *  lock on the cache.
         *
         *  skip all of these steps if there is no support for read-write
         *  locks, since the entire cache is already locked.
         */
        RW_MUTEX_UNLOCK(&cache->mutex);
        WRITE_LOCK(&cache->mutex);

        /* search for the entry again, in case it was added or opened
         * between releasing the read lock on the cache and getting
         * the write lock on the cache */
        goto LOOKUP;
    }
#endif /* SK_HAVE_PTHREAD_RWLOCK */

    *out_entry = NULL;
    retval = -1;

    if (entry) {
        MUTEX_LOCK(&entry->mutex);
        /* use the callback to open the file */
        entry->stream = cache->open_callback(key, caller_data, entry->filename);
        if (NULL == entry->stream) {
            MUTEX_UNLOCK(&entry->mutex);
            goto END;
        }
        if (strcmp(entry->filename, skStreamGetPathname(entry->stream))) {
            DEBUGMSG("Pathname changed");
            free((void *)entry->filename);
            entry->filename = strdup(skStreamGetPathname(entry->stream));
            if (NULL == entry->filename) {
                skAppPrintOutOfMemory(NULL);
                MUTEX_UNLOCK(&entry->mutex);
                goto END;
            }
        }
        ++cache->open_count;
        TRACEMSG(1, ("cache: Lookup: Opened known file '%s'", entry->filename));

    } else {
        /* create a new entry */
        entry = (cache_entry_t *)calloc(1, sizeof(cache_entry_t));
        if (NULL == entry) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
        if (MUTEX_INIT(&entry->mutex)) {
            CRITMSG(FMT_MUTEX_FAILURE);
            free(entry);
            goto END;
        }
        MUTEX_LOCK(&entry->mutex);
        /* use the callback to open the file */
        entry->stream = cache->open_callback(key, caller_data, NULL);
        if (NULL == entry->stream) {
            cacheEntryDestroy(entry);
            goto END;
        }
        entry->filename = strdup(skStreamGetPathname(entry->stream));
        if (NULL == entry->filename) {
            skAppPrintOutOfMemory(NULL);
            cacheEntryDestroy(entry);
            goto END;
        }

        entry->key.time_stamp = key->time_stamp;
        entry->key.sensor_id = key->sensor_id;
        entry->key.flowtype_id = key->flowtype_id;
        entry->total_rec_count = 0;
        entry->last_accessed = MAX_TIME;

        /* add the entry to the redblack tree */
        e = (cache_entry_t *)rbsearch(entry, cache->rbtree);
        if (e != entry) {
            if (e == NULL) {
                skAppPrintOutOfMemory(NULL);
                cacheEntryDestroy(entry);
                goto END;
            }
            CRITMSG(("Duplicate entries in stream cache "
                     "for time=%" PRId64 " sensor=%d flowtype=%d"),
                    key->time_stamp, key->sensor_id, key->flowtype_id);
            skAbort();
        }

        ++cache->total_count;
        ++cache->open_count;

        TRACEMSG(1, ("cache: Lookup: Opened new file '%s'", entry->filename));
    }

    retval = 0;

    TRACEMSG(2, ("cache: Lookup: %u total, %u open, %u max, %u closed",
                 cache->total_count, cache->open_count, cache->max_open_count,
                 cache->total_count - cache->open_count));

    if (cache->open_count > cache->max_open_count) {
        /* The cache is full: close the least recently used stream.
         * This uses a linear search over all entries. */
        RBLIST *iter;
        cache_entry_t *min_entry;
        sktime_t min_time;

        min_entry = NULL;
        min_time = MAX_TIME;

        /* unlock the entry's mutex to avoid a deadlock */
        MUTEX_UNLOCK(&entry->mutex);

        /* visit entries in the red-black tree; this only finds open
         * entries since closed entries have their time set to
         * MAX_TIME. */
        iter = rbopenlist(cache->rbtree);
        while ((e = (cache_entry_t *)rbreadlist(iter)) != NULL) {
            MUTEX_LOCK(&e->mutex);
            if (e->last_accessed < min_time) {
                min_time = e->last_accessed;
                min_entry = e;
            }
            MUTEX_UNLOCK(&e->mutex);
        }
        rbcloselist(iter);

        assert(min_time < MAX_TIME);
        assert(min_entry != NULL);
        assert(min_entry != entry);
        assert(min_entry->stream != NULL);

        MUTEX_LOCK(&min_entry->mutex);
        rv = cacheEntryClose(min_entry);
        if (rv) {
            retval = -1;
        }
        min_entry->last_accessed = MAX_TIME;
        MUTEX_UNLOCK(&min_entry->mutex);

        --cache->open_count;

        /* re-lock the entry's mutex */
        MUTEX_LOCK(&entry->mutex);
    }

    /* update access time and record count */
    entry->last_accessed = sktimeNow();
    entry->opened_rec_count = skStreamGetRecordCount(entry->stream);
    *out_entry = entry;

  END:
    RW_MUTEX_UNLOCK(&cache->mutex);
    return retval;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
