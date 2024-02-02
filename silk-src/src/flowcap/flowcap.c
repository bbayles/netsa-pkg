/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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

RCSIDENT("$SiLK: flowcap.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/libflowsource.h>
#include <silk/rwrec.h>
#include <silk/skheader.h>
#include <silk/skthread.h>      /* MUTEX_LOCK,MUTEX_UNLOCK */
#include <silk/sktimer.h>
#include <sys/un.h>
#ifdef SK_HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#include "flowcap.h"


/* TYPEDEFS AND DEFINES */

/*
 *  Specify the maximum size (in terms of RECORDS) of the buffer used
 *  to hold records that have been read from the flow-source but not
 *  yet processed.  This value is the number of records as read from
 *  the wire (e.g., PDUs for a NetFlow v5 probe) per PROBE.  The
 *  maximum memory per NetFlow v5 probe will be BUF_REC_COUNT * 1464.
 *  The maximum memory per IPFIX or NetFlow v9 probe will be
 *  BUF_REC_COUNT * 52 (or BUF_REC_COUNT * 88 for IPv6-enabled SiLK).
 *  If records are processed as quickly as they are read, the normal
 *  memory use per probe will be CIRCBUF_CHUNK_MAX_SIZE bytes.
 */
#define BUF_REC_COUNT  32768



/* the reason a file was closed; passed to closeFile() */
typedef enum close_reason_en {
    FC_TIMED_OUT,
    FC_OVERFULL,
    FC_SHUTDOWN
} close_reason_t;


typedef struct flowcap_reader_st {
    /* the source of data that this reader captures */
    union fc_reader_source_un {
        skPDUSource_t      *pdu;
#if SK_ENABLE_IPFIX
        skIPFIXSource_t    *ipfix;
#endif
    }                   source;

    /* probe that this reader is capturing */
    const skpc_probe_t *probe;

    /* name of the probe */
    const char         *probename;

    /* the skStream that is used for writing */
    skstream_t         *stream;

    /* base name of the file; a pointer into 'path' */
    char               *filename;

    /* complete path to file */
    char                path[PATH_MAX];


    /* close timer */
    skTimer_t           timer;

    /* reader lock */
    pthread_mutex_t     mutex;

    /* reader thread */
    pthread_t           reader_thread;

    /* time when the file was opened */
    time_t              start_time;

    /* number of records written to current file */
    uint32_t            records;

    /* whether this file is due to be closed. */
    unsigned            close       : 1;

    /* whether this file is in the process of being closed---protect
     * against size limit and time limit firing simultaneously. */
    unsigned            closing     : 1;

    /* is the source object valid */
    unsigned            valid_source: 1;

    /* is this thread running? */
    unsigned            running     : 1;
} flowcap_reader_t;


/* EXPORTED VARIABLES */

/* Where to write files */
const char *destination_dir = NULL;

/* Compression method for output files */
sk_compmethod_t comp_method;

/* To ensure records are sent along in a timely manner, the files are
 * closed when a timer fires or once they get to a certain size.
 * These variables define those values. */
uint32_t write_timeout = 60;
uint32_t max_file_size = 0;

/* Timer base (0 if none) from which we calculate timeouts */
sktime_t clock_time = 0;

/* Amount of disk space to allow for a new file when determining
 * whether there is disk space available.  This will be max_file_size
 * plus some overhead should the compressed data be larger than the
 * raw data. */
uint64_t alloc_file_size = 0;

/* The version of flowcap files to produce */
uint8_t flowcap_version = FC_VERSION_DEFAULT;

/* The list of probes we care about */
sk_vector_t *probe_vec = NULL;

#ifdef SK_HAVE_STATVFS
/* leave at least this much free space on the disk; specified by
 * --freespace-minimum.  Gets set to DEFAULT_FREESPACE_MINIMUM */
int64_t freespace_minimum = -1;

/* take no more that this amount of the disk; as a percentage.
 * specified by --space-maximum-percent */
double space_maximum_percent = DEFAULT_SPACE_MAXIMUM_PERCENT;
#endif /* SK_HAVE_STATVFS */


/* LOCAL VARIABLES */

/* Reader shut down flag (0 == stop) */
static volatile uint8_t reading;

/* Indicator of whether flowcap is in the process of shutting down */
static volatile int shutting_down = 0;

/* Set to true once skdaemonized() has been called---regardless of
 * whether the --no-daemon switch was given. */
static int daemonized = 0;

/* Main thread id. */
static pthread_t main_thread;

/* The array of readers, and the array's size. */
static flowcap_reader_t *fc_readers;
static size_t num_fc_readers;


/* LOCAL FUNCTION PROTOTYPES */

static skTimerRepeat_t
timerHandler(
    void               *vreader);
static void freeReaders(void);
static int
openFileBase(
    flowcap_reader_t   *reader);
static void
closeFile(
    flowcap_reader_t   *reader,
    close_reason_t      reason);
static int
closeFileBase(
    flowcap_reader_t   *reader,
    close_reason_t      reason);
static int  startReaders(void);
static void stopReaders(void);

#ifdef SK_HAVE_STATVFS
static int checkDiskSpace(void);
#else
#  define checkDiskSpace()  (0)
#endif


/* FUNCTION DEFINITIONS */

/*
 *  appTeardown()
 *
 *    Teardown all modules, close all files, and tidy up all
 *    application state.
 *
 *    This function is idempotent.
 */
void
appTeardown(
    void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint8_t teardownFlag = 0;

    MUTEX_LOCK(&mutex);
    if (teardownFlag) {
        MUTEX_UNLOCK(&mutex);
        return;
    }
    teardownFlag = 1;
    MUTEX_UNLOCK(&mutex);

    if (probe_vec) {
        skVectorDestroy(probe_vec);
        probe_vec = NULL;
    }

    if (!daemonized) {
        skpcTeardown();
        skdaemonTeardown();
        skAppUnregister();
        return;
    }

    NOTICEMSG("Shutting down...");
    shutting_down = 1;

    stopReaders();
    freeReaders();

    skpcTeardown();
    skdaemonTeardown();
    skthread_teardown();
    skAppUnregister();
}


/*
 *  repeat = timerHandler(reader);
 *
 *    The timer fired for 'reader'.  Close the file and restart the
 *    timer.
 */
static skTimerRepeat_t
timerHandler(
    void               *vreader)
{
    register flowcap_reader_t *reader = (flowcap_reader_t*)vreader;

    if (shutting_down) {
        return SK_TIMER_END;
    }

    /* Set the close flag first. */
    reader->close = 1;

    /* Timer handler stuff */
    INFOMSG("Timer fired for '%s'", reader->filename);

    /* Close the file, and open a new one. */
    closeFile(reader, FC_TIMED_OUT);

    return SK_TIMER_REPEAT;
}


/*
 *  createReaders();
 *
 *    Creates all the flowcap reader structures: one for each probe.
 *    Does not open the files.
 */
int
createReaders(
    void)
{
    skpc_probe_t *probe;
    flowcap_reader_t *reader;
    size_t i;

    num_fc_readers = skVectorGetCount(probe_vec);

    fc_readers = ((flowcap_reader_t*)
                  calloc(num_fc_readers, sizeof(flowcap_reader_t)));
    if (fc_readers == NULL) {
        skAppPrintOutOfMemory("readers");
        return -1;
    }

    for (i = 0, reader = fc_readers; i < num_fc_readers; ++i, ++reader) {
        skVectorGetValue(&probe, probe_vec, i);

        /* Fill in the probe */
        reader->probe = probe;
        reader->probename = skpcProbeGetName(probe);
    }

    return 0;
}


/*
 *  freeReaders(void);
 *
 *    Close all the files, destroy any remaining flow-sources, and
 *    destroy the reader array.
 */
static void
freeReaders(
    void)
{
    flowcap_reader_t *reader;
    size_t i;

    NOTICEMSG("Destroying all sources...");

    /* close all sources */
    for (i = 0, reader = fc_readers; i < num_fc_readers; ++i, ++reader) {
        DEBUGMSG("'%s': Stopping file timer", reader->probename);
        reader->close = 1;
        closeFile(reader, FC_SHUTDOWN);

        if (reader->valid_source) {
            reader->valid_source = 0;

            DEBUGMSG("'%s': Destroying source", reader->probename);
            switch (skpcProbeGetType(reader->probe)) {
              case PROBE_ENUM_NETFLOW_V5:
                skPDUSourceDestroy(reader->source.pdu);
                break;
#if SK_ENABLE_IPFIX
              case PROBE_ENUM_SFLOW:
              case PROBE_ENUM_IPFIX:
              case PROBE_ENUM_NETFLOW_V9:
                skIPFIXSourceDestroy(reader->source.ipfix);
                break;
#endif
              default:
                CRITMSG("Invalid probe type id '%d'",
                        (int)skpcProbeGetType(reader->probe));
                skAbortBadCase(skpcProbeGetType(reader->probe));
            }
        }
    }

    NOTICEMSG("Destroyed all sources.");

    free(fc_readers);
    fc_readers = NULL;
}


/*
 *  status = openFileBase(reader);
 *
 *    Open a disk file to store the flows that are being read from the
 *    probe associated with 'reader'.
 *
 *    This function assumes it has the lock for 'reader'.
 *
 *    This function creates two files: a placeholder file and a
 *    temporary file that has the same name as the placeholder folder
 *    except it is prefixed with a dot.  The leading dot tells
 *    rwsender's directory poller to ignore the file.  We write the
 *    data into the temporary file.  In the closeFileBase() function,
 *    we move the temporary file over the placeholder file.
 *
 *    A timer is created for the 'reader' unless one already exists.
 *
 *    This function writes the SiLK header to the temporary file.
 *
 *    This function calls checkDiskSpace().
 *
 *    Return 0 on success, -1 on failure.
 */
static int
openFileBase(
    flowcap_reader_t   *reader)
{
    char dotpath[PATH_MAX];
    char ts[FC_TIMESTAMP_MAX + 1]; /* timestamp */
    sk_file_header_t *hdr;
    sk_file_format_t file_format;
    sk_file_version_t rec_version;
    struct timeval tv;
    struct tm ut;
    int fd;
    int rv;

    DEBUGMSG("Opening new file...");

    /* choose file format based on probe type.  There is no need to
     * use an IPv6 format if the probe is incapable of producing IPv6
     * data */
    switch (skpcProbeGetType(reader->probe)) {
#if SK_ENABLE_IPV6
      case PROBE_ENUM_NETFLOW_V5:
        /* the probe can only send IPv4 flows */
        file_format = FT_FLOWCAP;
        rec_version = flowcap_version;
        break;
#endif
#if SK_ENABLE_IPV6
      default:
        file_format = FT_RWIPV6ROUTING;
        rec_version = SK_RECORD_VERSION_ANY;
        break;
#else
      default:
        file_format = FT_FLOWCAP;
        rec_version = flowcap_version;
        break;
#endif  /* SK_ENABLE_IPV6 */
    }

    /* make sure there is space available */
    if (checkDiskSpace()) {
        return -1;
    }

    /* Create a timestamp */
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &ut);
    strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", &ut);

    /* Create a pathname from the directory, timestamp, and probe.  If
     * you change the number of X's here, be certain to update
     * FC_UNIQUE_MAX in flowcap.h. */
    if ((size_t)snprintf(reader->path, sizeof(reader->path), "%s/%s_%s.XXXXXX",
                         destination_dir, ts, reader->probename)
        >= sizeof(reader->path))
    {
        CRITMSG("Pathname exceeded maximum filename size.");
        return -1;
    }

    /* Open the file; making sure its name is unique */
    fd = mkstemp(reader->path);
    if (fd == -1) {
        CRITMSG("Unable to create file '%s': %s",
                reader->path, strerror(errno));
        return -1;
    }

    DEBUGMSG("Opened placeholder file '%s'", reader->path);

    /* Set the permissions */
    fchmod(fd, 0644);

    rv = close(fd);
    fd = -1;
    if (-1 == rv) {
        CRITMSG("Unable to close file '%s': %s",
                reader->path, strerror(errno));
        unlink(reader->path);
        return -1;
    }

    /* Get the basename of the file */
    reader->filename = strrchr(reader->path, '/');
    ++reader->filename;

    /* Create the name of the dotfile */
    if ((size_t)snprintf(dotpath, sizeof(dotpath), "%s/.%s",
                         destination_dir, reader->filename)
        >= sizeof(dotpath))
    {
        CRITMSG("Dot pathname exceeded buffer size.");
        unlink(reader->path);
        return -1;
    }

    /* Open the dot file.  The while() will repeat only if the dot
     * file already exists and can be removed successfully. */
    while ((fd = open(dotpath, O_WRONLY | O_CREAT | O_EXCL, 0644))
           == -1)
    {
        /* Remove the dotfile if it exists and try again; otherwise
         * give up on this file. */
        int saveerrno = errno;
        if (errno == EEXIST) {
            WARNINGMSG("Working file already exists. Removing '%s'",
                       dotpath);
            if (unlink(dotpath) == 0) {
                continue;
            }
            WARNINGMSG("Failed to unlink existing working file '%s': %s",
                       dotpath, strerror(errno));
        }
        CRITMSG("Could not create '%s': %s",
                dotpath, strerror(saveerrno));
        unlink(reader->path);
        return -1;
    }

    DEBUGMSG("Opened working file '%s'", dotpath);

    /* create a stream bound to the dotfile */
    if ((rv = skStreamCreate(&reader->stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(reader->stream, dotpath))
        || (rv = skStreamFDOpen(reader->stream, fd)))
    {
        skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
        /* NOTE: it is possible for skStreamFDOpen() to have stored
         * the value of 'fd' but return an error. */
        if (reader->stream && skStreamGetDescriptor(reader->stream) != fd) {
            close(fd);
        }
        skStreamDestroy(&reader->stream);
        unlink(dotpath);
        unlink(reader->path);
        return -1;
    }

    /* set and write the file's header */
    hdr = skStreamGetSilkHeader(reader->stream);
    if ((rv = skHeaderSetFileFormat(hdr, file_format))
        || (rv = skHeaderSetRecordVersion(hdr, rec_version))
        || (rv = skHeaderSetByteOrder(hdr, SILK_ENDIAN_BIG))
        || (rv = skHeaderSetCompressionMethod(hdr, comp_method))
        || (rv = skHeaderAddProbename(hdr, reader->probename))
        || (rv = skStreamWriteSilkHeader(reader->stream)))
    {
        skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
        skStreamDestroy(&reader->stream);
        unlink(dotpath);
        unlink(reader->path);
        return -1;
    }


    /* Set up default values */
    reader->start_time = tv.tv_sec;
    reader->records    = 0;
    reader->closing    = 0;
    reader->close      = 0;

    /* set the timer to write_timeout */
    if (NULL == reader->timer) {
        if (clock_time) {
            skTimerCreateAtTime(&reader->timer, write_timeout, clock_time,
                                &timerHandler, (void*)reader);
        } else {
            skTimerCreate(&reader->timer, write_timeout,
                          &timerHandler, (void*)reader);
        }
    }

    INFOMSG("Opened new file '%s'", reader->filename);
    return 0;
}


/*
 *  closeFile(reader, reason);
 *
 *    Close the current disk file associated with 'reader'.
 *
 *    Unless 'resaon' is FC_SHUTDOWN, close the file and then call
 *    openFileBase() to open a new file.
 *
 *    This function must protect against attempts by the size limit
 *    and the time limit to close the file simultaneously.  Unless
 *    reason is FC_SHUTDOWN, simply return if 'reader' is already in
 *    the state of being closed.
 *
 *    Otherwise, get the lock for 'reader' and call closeFileBase() to
 *    close the disk file associated with 'reader'.
 */
static void
closeFile(
    flowcap_reader_t   *reader,
    close_reason_t      reason)
{
    static pthread_mutex_t close_lock = PTHREAD_MUTEX_INITIALIZER;
    uint8_t quit = 0;

    /* Ah, the perils of threads.  reader->closing keeps us from
     * double-closing a reader.  reader->close makes sure we don't honor
     * a request to close a reader that has been closed and reopened
     * since the request. */
    MUTEX_LOCK(&close_lock);

    if (reader->closing || !reader->close) {
        quit = 1;
    } else {
        reader->closing = 1;
    }
    MUTEX_UNLOCK(&close_lock);

    if (quit && (reason != FC_SHUTDOWN)) {
        DEBUGMSG("Avoiding duplicate call to closeFile.");
        return;
    }

    MUTEX_LOCK(&reader->mutex);

    if (closeFileBase(reader, reason)) {
        reader->filename = NULL;
        MUTEX_UNLOCK(&reader->mutex);
        exit(EXIT_FAILURE);
    }
    if (reason != FC_SHUTDOWN) {
        if (openFileBase(reader)) {
            reader->filename = NULL;
            MUTEX_UNLOCK(&reader->mutex);
            exit(EXIT_FAILURE);
        }
    }

    MUTEX_UNLOCK(&reader->mutex);
}


/*
 *  status = closeFileBase(reader, reason);
 *
 *    Close the disk file associated with the 'reader'.
 *
 *    This function assumes it has the lock for 'reader'.
 *
 *    The function closes the temporary dot file.  If the dot file
 *    contains no records, the dot file and placeholder file are
 *    removed.  If the dot file contains records, the dot file is
 *    moved on top of the placeholder file.
 *
 *    If 'reader' has a timer associated with it, the timer is
 *    destroyed unless this function has been called because the timer
 *    fired---that is, if 'reason' is FC_TIMED_OUT.
 *
 *    Return 0 on success; -1 on failure.
 */
static int
closeFileBase(
    flowcap_reader_t   *reader,
    close_reason_t      reason)
{
    const sk_file_header_t *hdr;
    char dotpath[PATH_MAX];
    int64_t uncompress_size;
    int64_t size;
    double change;
    time_t end_time;
    ssize_t rv;

    if (NULL == reader->filename) {
        /* Do not close an unopened file.  An unopened file can occur
         * during start up when there are multiple sources and a
         * source (other than the final source) fails to start. */
        if (reader->timer && (reason != FC_TIMED_OUT)) {
            DEBUGMSG("'%s': Destroying timer", reader->probename);
            skTimerDestroy(reader->timer);
            reader->timer = NULL;
        }
        return 0;
    }

    DEBUGMSG("Closing file '%s'...", reader->filename);

    /* Make certain the timer for this file doesn't fire.  If the file
     * timed out, however, keep the timer, which will just restart.
     * The assumption is that the time to create a new file after this
     * point is less than the timer fire time. */
    if (reader->timer && (reason != FC_TIMED_OUT)) {
        DEBUGMSG("'%s': Destroying timer", reader->probename);
        skTimerDestroy(reader->timer);
        reader->timer = NULL;
    }

    /* get path to the dot file. */
    sprintf(dotpath, "%s/.%s",
            destination_dir, reader->filename);

    /* if no records were written, close and remove the file */
    if (reader->records == 0) {
        end_time = time(NULL);
        rv = skStreamClose(reader->stream);
        if (rv) {
            skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
            CRITMSG("Fatal error closing '%s'", dotpath);
            return -1;
        }
        skStreamDestroy(&reader->stream);
        unlink(dotpath);
        unlink(reader->path);

        INFOMSG(("Removed empty file '%s': %" PRId64 " seconds"),
                reader->filename, (int64_t)(end_time - reader->start_time));

        if (reader->valid_source) {
            switch (skpcProbeGetType(reader->probe)) {
              case PROBE_ENUM_NETFLOW_V5:
                skPDUSourceLogStatsAndClear(reader->source.pdu);
                break;
#if SK_ENABLE_IPFIX
              case PROBE_ENUM_IPFIX:
              case PROBE_ENUM_NETFLOW_V9:
              case PROBE_ENUM_SFLOW:
                skIPFIXSourceLogStatsAndClear(reader->source.ipfix);
                break;
#endif  /* SK_ENABLE_IPFIX */
              default:
                break;
            }
        }


        reader->filename = NULL;
        return 0;
    }

    /* flush the file so we can get its final size */
    rv = skStreamFlush(reader->stream);
    if (rv) {
        skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
        CRITMSG("Fatal error flushing file '%s'", reader->path);
        return -1;
    }
    end_time = time(NULL);

    /* how many uncompressed bytes were processed? */
    hdr = skStreamGetSilkHeader(reader->stream);
    uncompress_size = (skHeaderGetLength(hdr)
                       + reader->records * skHeaderGetRecordLength(hdr));

    /* how many bytes were written to disk? */
    size = (int64_t)skStreamTell(reader->stream);

    /* what's the compression ratio? */
    if (uncompress_size == 0) {
        change = 0.0;
    } else {
        change = (100.0 * (double)(uncompress_size - size)
                  / (double)uncompress_size);
    }

    INFOMSG(("'%s': Closing file '%s': %" PRId64 " seconds,"
             " %" PRIu32 " records, %" PRId64 " bytes, %4.1f%% compression"),
            reader->probename,
            reader->filename,
            (int64_t)(end_time - reader->start_time),
            reader->records,
            size,
            change);

    switch (skpcProbeGetType(reader->probe)) {
      case PROBE_ENUM_NETFLOW_V5:
        assert(reader->valid_source);
        skPDUSourceLogStatsAndClear(reader->source.pdu);
        break;
#if SK_ENABLE_IPFIX
      case PROBE_ENUM_IPFIX:
      case PROBE_ENUM_NETFLOW_V9:
      case PROBE_ENUM_SFLOW:
        assert(reader->valid_source);
        skIPFIXSourceLogStatsAndClear(reader->source.ipfix);
        break;
#endif  /* SK_ENABLE_IPFIX */
      default:
        break;
    }

    /* close the file and destroy the handle */
    rv = skStreamClose(reader->stream);
    if (rv) {
        skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
        CRITMSG("Fatal error closing '%s'", dotpath);
        return -1;
    }
    skStreamDestroy(&(reader->stream));


    /* move the dot-file over the placeholder file. */
    rv = rename(dotpath, reader->path);
    if (rv != 0) {
        CRITMSG("Failed to replace '%s' with '%s': %s",
                reader->path, dotpath, strerror(errno));
        return -1;
    }

    INFOMSG("Finished closing '%s'", reader->filename);
    reader->filename = NULL;
    return 0;
}


#ifdef SK_HAVE_STATVFS
/*
 *  checkDiskSpace();
 *
 *    Verify that we haven't reached the limits of the file system
 *    usage specified by the command line parameters.
 *
 *    If we're out of space, return -1.  Else, return 0.
 */
static int
checkDiskSpace(
    void)
{
    struct statvfs vfs;
    int64_t free_space, total, newfree;
    int rv;
    double percent_used;

    rv = statvfs(destination_dir, &vfs);
    if (rv != 0) {
        CRITMSG("Could not statvfs '%s'", destination_dir);
        return -1;
    }

    /* free bytes is fundamental block size multiplied by the
     * available (non-privileged) blocks. */
    free_space = ((int64_t)vfs.f_frsize * (int64_t)vfs.f_bavail);
    /* to compute the total (non-privileged) blocks, subtract the
     * available blocks from the free (privileged) blocks to get
     * the count of privileged-only blocks, subtract that from the
     * total blocks, and multiply the result by the block size. */
    total = ((int64_t)vfs.f_frsize
             * ((int64_t)vfs.f_blocks
                - ((int64_t)vfs.f_bfree - (int64_t)vfs.f_bavail)));

    newfree = free_space - alloc_file_size * num_fc_readers;
    percent_used = ((double)(total - newfree) /
                    ((double)total / 100.0));

    if (newfree < freespace_minimum) {
        CRITMSG(("Free disk space limit overrun: "
                 "free=%" PRId64 " < min=%" PRId64 " (used %.4f%%)"),
                newfree, freespace_minimum, percent_used);
        /* TODO: Create a wait routine instead of exiting? */
        return -1;
    }
    if (percent_used > space_maximum_percent) {
        CRITMSG(("Free disk space limit overrun: "
                 "used=%.4f%% > max=%.4f%% (free %" PRId64 " bytes)"),
                percent_used, space_maximum_percent, newfree);
        /* TODO: Create a wait routine instead of exiting? */
        return -1;
    }

    DEBUGMSG(("Free space available is %" PRId64 " bytes (%.4f%%)"),
             newfree, percent_used);
    return 0;
}
#endif /* SK_HAVE_STATVFS */


/*
 *  readerWriteRecord(reader, rwrec);
 *
 *    Write the SiLK Flow record 'rwrec' to the output file for
 *    'reader'.  Exit the program if there is an error writing the
 *    record.
 *
 *    If the file has reached its maximum size, call closeFile() to
 *    close the file and open a new file.
 */
static inline void
readerWriteRecord(
    flowcap_reader_t   *reader,
    const rwRec        *rec)
{
    int rv;

    MUTEX_LOCK(&reader->mutex);

    /* Write the record to the file */
    rv = skStreamWriteRecord(reader->stream, rec);
    if (rv) {
        skStreamPrintLastErr(reader->stream, rv, &ERRMSG);
        CRITMSG("Fatal error writing record.");
        MUTEX_UNLOCK(&reader->mutex);
        exit(EXIT_FAILURE);
    }
    ++reader->records;

    /* Check to see if we have reached the size limit */
    if (skStreamGetUpperBound(reader->stream) < max_file_size) {
        MUTEX_UNLOCK(&reader->mutex);
    } else {
        reader->close = 1;
        MUTEX_UNLOCK(&reader->mutex);
        /* Close the file and open a new one in its place */
        closeFile(reader, FC_OVERFULL);
    }
}


/*
 *  readerMainPDU(reader);
 *  readerMainIPFIX(reader);
 *  readerMain<ProbeType>(reader);
 *
 *    Thread entry point for each reader_thread.
 *
 *    Read "foreign" flow records from the probe/flow-source
 *    associated with the 'reader' and call readerWriteRecord() to
 *    write the record to the output file.
 *
 *    This function runs until the flow-source is stopped, at which
 *    point the function returns.
 */
static void *
readerMainPDU(
    void               *vreader)
{
    flowcap_reader_t *reader = (flowcap_reader_t*)vreader;
    rwRec rec;

    assert(reader);
    assert(reader->probe);
    assert(skpcProbeGetType(reader->probe) == PROBE_ENUM_NETFLOW_V5);

    INFOMSG("'%s': Reader thread started.", reader->probename);

    /* Continue as long as there is data to be read */
    while (reading
           && (skPDUSourceGetGeneric(reader->source.pdu, &rec) == 0))
    {
        readerWriteRecord(reader, &rec);
    }

    INFOMSG("'%s': Reader thread ended.", reader->probename);

    /* End thread */
    return NULL;
}


#if SK_ENABLE_IPFIX
static void *
readerMainIPFIX(
    void               *vreader)
{
    flowcap_reader_t *reader = (flowcap_reader_t*)vreader;
    rwRec rec;

    assert(reader);
    assert(reader->probe);
    assert(skpcProbeGetType(reader->probe) == PROBE_ENUM_IPFIX
           || skpcProbeGetType(reader->probe) == PROBE_ENUM_NETFLOW_V9
           || skpcProbeGetType(reader->probe) == PROBE_ENUM_SFLOW);

    INFOMSG("'%s': Reader thread started.", reader->probename);

    /* Continue as long as there is data to be read */
    while (reading
           && (skIPFIXSourceGetGeneric(reader->source.ipfix, &rec) == 0))
    {
        readerWriteRecord(reader, &rec);
    }

    INFOMSG("'%s': Reader thread ended.", reader->probename);

    /* End thread */
    return NULL;
}
#endif /* #if SK_ENABLE_IPFIX */


/*
 *  status = startReaders();
 *
 *    Create the flow-source object associated with the probe that is
 *    stored on each 'reader' object.  Have the flow-sources begin to
 *    collect network traffic, and create a thread for each 'reader'
 *    to read the flows.
 *
 *    Return 0 on success, non-zero otherwise.
 */
static int
startReaders(
    void)
{
    skFlowSourceParams_t params;
    flowcap_reader_t *reader;
    size_t i;
    skpc_probetype_t probe_type;

#if SK_ENABLE_IPFIX
    DEBUGMSG("Setting up IPFIX");
    if (skIPFIXSourcesSetup()) {
        return 1;
    }
#endif  /* SK_ENABLE_IPFIX */

    DEBUGMSG("Configuration file contains these probes:");
    for (i = 0, reader = fc_readers; i < num_fc_readers; ++i, ++reader) {
        skpcProbePrint(reader->probe, &DEBUGMSG);
    }

    NOTICEMSG("Starting all reader threads...");
    reading = 1;

    params.max_pkts = BUF_REC_COUNT;

    for (i = 0, reader = fc_readers; i < num_fc_readers; ++i, ++reader) {
        /* Initialize mutex */
        pthread_mutex_init(&reader->mutex, NULL);

        /* Create the first file */
        MUTEX_LOCK(&reader->mutex);
        if (openFileBase(reader)) {
            reader->filename = NULL;
            MUTEX_UNLOCK(&reader->mutex);
            exit(EXIT_FAILURE);
        }
        MUTEX_UNLOCK(&reader->mutex);

        probe_type = skpcProbeGetType(reader->probe);
        DEBUGMSG("'%s': Starting %s source",
                 reader->probename, skpcProbetypeEnumtoName(probe_type));

        switch (probe_type) {
          case PROBE_ENUM_NETFLOW_V5:
            reader->source.pdu = skPDUSourceCreate(reader->probe, &params);
            if (reader->source.pdu == NULL) {
                WARNINGMSG("'%s': Failed to start source",
                           reader->probename);
                return 1;
            }
            reader->valid_source = 1;
            DEBUGMSG("'%s': Reader thread starting...", reader->probename);
            if (skthread_create(reader->probename, &reader->reader_thread,
                                readerMainPDU, (void*)reader))
            {
                return 1;
            }
            reader->running = 1;
            break;


#if SK_ENABLE_IPFIX
          case PROBE_ENUM_SFLOW:
          case PROBE_ENUM_IPFIX:
          case PROBE_ENUM_NETFLOW_V9:
            reader->source.ipfix = skIPFIXSourceCreate(reader->probe, &params);
            if (reader->source.ipfix == NULL) {
                WARNINGMSG("'%s': Failed to start source",
                           reader->probename);
                return 1;
            }
            reader->valid_source = 1;
            DEBUGMSG("'%s': Reader thread starting...", reader->probename);
            if (skthread_create(reader->probename, &reader->reader_thread,
                                readerMainIPFIX, (void*)reader))
            {
                return 1;
            }
            reader->running = 1;
            break;
#endif  /* SK_ENABLE_IPFIX */

          default:
            CRITMSG("Unsupported probe type id '%d'", (int)probe_type);
            skAbortBadCase(probe_type);
        } /* switch () */
    }

    NOTICEMSG("Started all reader threads.");

    return 0;
}


/*
 *  stopReaders();
 *
 *    Stop all the flow-sources.
 *
 *    For flow-sources that have separate Stop() and Destroy()
 *    functions, call the Stop() function; otherwise, call the
 *    Destroy() function.
 *
 *    Wait for each reader_thread to terminate.
 */
static void
stopReaders(
    void)
{
    flowcap_reader_t *reader;
    size_t i;

    if (!reading) {
        return;
    }

    NOTICEMSG("Stopping all reader threads...");
    reading = 0;

    for (i = 0, reader = fc_readers; i < num_fc_readers; ++i, ++reader) {
        /* Stop the flow-source */
        if (reader->valid_source) {
            DEBUGMSG("'%s': Stopping source", reader->probename);
            switch (skpcProbeGetType(reader->probe)) {
              case PROBE_ENUM_NETFLOW_V5:
                skPDUSourceStop(reader->source.pdu);
                break;
#if SK_ENABLE_IPFIX
              case PROBE_ENUM_SFLOW:
              case PROBE_ENUM_IPFIX:
              case PROBE_ENUM_NETFLOW_V9:
                skIPFIXSourceStop(reader->source.ipfix);
                break;
#endif
              default:
                CRITMSG("Invalid probe type id '%d'",
                        (int)skpcProbeGetType(reader->probe));
                skAbortBadCase(skpcProbeGetType(reader->probe));
            }
        }

        /* Wait for the thread to end */
        if (reader->running) {
            DEBUGMSG("'%s': Joining reader thread", reader->probename);
            pthread_join(reader->reader_thread, NULL);
            reader->running = 0;
        }

        /* Don't destroy until after the files are closed, since we
         * want to get the final stats from the flow-source. */
    }

    NOTICEMSG("Stopped all reader threads.");
}


/* Program entry point. */
int main(int argc, char **argv)
{
    appSetup(argc, argv);               /* never returns on failure */

    sklogOpen();

    /* start the logger and become a daemon */
#ifdef DEBUG
    skdaemonDontFork();
#endif
    if (skdaemonize(&shutting_down, NULL) == -1
        || sklogEnableThreadedLogging() == -1)
    {
        exit(EXIT_FAILURE);
    }
    daemonized = 1;

    /* Store the main thread ID */
    skthread_init("main");
    main_thread = pthread_self();

    /* Start the reader threads */
    if (startReaders()) {
        CRITMSG("Failed to start all readers. Exiting.");
        exit(EXIT_FAILURE);
    }

    /* We now run forever, excepting signals */
    while (!shutting_down) {
        pause();
    }

    appTeardown();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
