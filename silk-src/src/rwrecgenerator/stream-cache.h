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
#ifndef _STREAM_CACHE_H
#define _STREAM_CACHE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_STREAM_CACHE_H, "$SiLK: stream-cache.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>

/*
**  stream-cache.h
**
**    A simple interface for maintaining a list of open file handles
**    so we can avoid a lot of open/close cycles.  File handles are
**    indexed by the timestamp of the file, the sensor_id, and the
**    flowtype (class/type) of the data they contain.
*/


#define STREAM_CACHE_MINIMUM_SIZE 2
/*
 *    Smallest maximum cache size.  Code that handles removing items
 *    from end of list assumes at least two entries in the list.
 */

#define STREAM_CACHE_INACTIVE_TIMEOUT  (5 * 60 * 1000)
/*
 *    When skStreamFlush() is called, streams that have not been
 *    written to in the last STREAM_CACHE_INACTIVE_TIMEOUT
 *    milliseconds will be closed.
 */


/* The stream cache object. */
struct stream_cache_st;
typedef struct stream_cache_st stream_cache_t;


/*
 *  The cache_key_t is used as the key to the stream.
 */
typedef struct cache_key_st {
    /* the hour that this file is for */
    sktime_t            time_stamp;
    /* the sensor that this file is for */
    sk_sensor_id_t      sensor_id;
    /* the flowtype (class/type) that this file is for */
    sk_flowtype_id_t    flowtype_id;
} cache_key_t;


/*
 *  The cache_entry_t contains information about the file, the file
 *  handle, and the number of records in the file.
 *
 *  Users of the stream-cache should view the cache_entry_t as opaque.
 *  Use the macros and functions to access it.
 */
typedef struct cache_entry_st {
    /* the number of records in the file as of opening or the most
     * recent flush, used for log messages */
    uint64_t        rec_count;
    /* when this entry was last accessed */
    sktime_t        last_accessed;
    /* the key */
    cache_key_t     key;
    /* the open file handle */
    skstream_t     *stream;
} cache_entry_t;


/*
 *  stream = cache_open_fn_t(key, caller_data);
 *
 *    This function is used by skCacheLookupOrOpenAdd() when the
 *    stream associated with 'key' is not in the cache.  This function
 *    should open an existing file or create a new file as
 *    appriopriate.  The 'caller_data' is for the caller to use as she
 *    sees fit.  The stream does nothing with this value.
 *
 *    This function should return NULL if there was an error opening
 *    the file.
 */
typedef skstream_t *(*cache_open_fn_t)(
    const cache_key_t  *key,
    void               *caller_data);


/*
 *  status = skCacheAdd(cache, stream, key, &entry);
 *
 *    Add 'stream' to the stream cache 'cache' keyed by 'key' and put
 *    the cache-entry associated with the stream into the locatation
 *    pointed at by 'entry'.  The entry is returned in a locked state.
 *    The caller should call skCacheEntryRelease() to unlock the entry
 *    once processing is complete.
 *
 *    After this call, the cache will own the stream and will free it
 *    when the cache is full or when skCacheCloseAll() or
 *    skCacheDestroy() is called.
 *
 *    Return 0 on success, or -1 if there was a problem initializing
 *    the entry.  When the cache is full, adding a stream to the cache
 *    will cause a current stream to close.  If closing the stream
 *    fails, the new stream is still added to the cache, but 1 is
 *    returned to indicate the error.
 */
int
skCacheAdd(
    stream_cache_t     *cache,
    skstream_t         *stream,
    const cache_key_t  *key,
    cache_entry_t     **entry);


/*
 *  status = skCacheCloseAll(cache);
 *
 *    Close all the streams in the cache and remove them from the
 *    cache.  For each file, log the number of records processed since
 *    the most recent flush or open.  Returns zero if all streams were
 *    successfully flushed and closed.  Returns -1 if calling the
 *    skStreamClose() function for any stream returns non-zero, though
 *    all streams will still be closed and destroyed.
 */
int
skCacheCloseAll(
    stream_cache_t     *cache);


/*
 *  cache = skCacheCreate(max_size, open_callback);
 *
 *    Create a stream_cache capable of keeping 'max_size' files open.
 *    The 'open_callback' is the function that the stream_cache will
 *    use when skCacheLookupOrOpenAdd() is called.  If the caller does
 *    not use that function, the 'open_callback' may be NULL.
 *
 *    Returns NULL if memory cannot be allocated.
 */
stream_cache_t *
skCacheCreate(
    int                 max_size,
    cache_open_fn_t     open_fn);


/*
 *  status = skCacheDestroy(cache);
 *
 *    Close all streams and free all memory associated with the
 *    streams.  Free the memory associated with the cache.  The cache
 *    pointer is invalid after a call to this function.
 *
 *    As part of its processing, this function calls
 *    skCacheCloseAll(), and that function's return value is the
 *    return value of this function.
 */
int
skCacheDestroy(
    stream_cache_t     *cache);


/*
 *  stream = skCacheEntryGetStream(entry);
 *
 *    Returns the stream associated with a stream entry.
 */
#define skCacheEntryGetStream(entry) ((entry)->stream)


/*
 *  skCacheEntryRelease(entry);
 *
 *    Releases (unlocks) a stream entry.
 */
#define skCacheEntryRelease(entry)


/*
 *  status = skCacheFlush(cache);
 *
 *    Flush all the streams in the cache, and log the number of
 *    records processed since the most recent flush or open.  Returns
 *    zero if all streams were successfully flushed.  Returns -1 if
 *    calling the skStreamFlush() function for any stream returns
 *    non-zero, though all streams will still be flushed.
 */
int
skCacheFlush(
    stream_cache_t     *cache);


/*
 *  status = skCacheLockAndCloseAll(cache);
 *
 *    Identical to skCacheCloseAll(), except that it keeps a lock on
 *    the cache.  The caller should call skCacheUnlock() to unlock the
 *    cache.
 */
int
skCacheLockAndCloseAll(
    stream_cache_t     *cache);


/*
 *  entry = skCacheLookup(cache, key);
 *
 *    Return the stream entry associated with the specified 'key'.
 *    Return NULL if no stream entry for the specified 'key' is
 *    found.  The entry is returned in a locked state.  The caller
 *    should call skCacheEntryRelease() once the caller has finished
 *    with the entry.
 */
cache_entry_t *
skCacheLookup(
    stream_cache_t     *cache,
    const cache_key_t  *key);


/*
 *  status = skCacheLookupOrOpenAdd(cache, key, caller_data, &entry);
 *
 *    If a stream entry associated with 'key' already exists in the
 *    cache, set 'entry' to that location and return 0.
 *
 *    Otherwise, the cache calls the 'open_callback' that was
 *    registered when the cache was created.  The arguments to that
 *    function will be the 'key' and specified 'caller_data'.  If the
 *    open_callback returns NULL, this function returns -1.
 *    Otherwise, the stream is added to the cache as if skCacheAdd()
 *    had been called, and this function's return status will reflect
 *    the result of that call.
 *
 *    The entry is returned in a locked state.  The caller should call
 *    skCacheEntryRelease() once the caller has finished with the
 *    entry.
 */
int
skCacheLookupOrOpenAdd(
    stream_cache_t     *cache,
    const cache_key_t  *key,
    void               *caller_data,
    cache_entry_t     **entry);


/*
 *  skCacheUnlock(cache);
 *
 *    Unlocks a cache locked by skCacheLockAndCloseAll().
 */
void
skCacheUnlock(
    stream_cache_t     *cache);

#define skCacheUnlock(c)


#ifdef __cplusplus
}
#endif
#endif /* _STREAM_CACHE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
