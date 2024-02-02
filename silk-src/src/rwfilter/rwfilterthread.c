/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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
**  rwfilterthread.c
**
**    Variables/Functions to support having rwfilter spawn multiple
**    threads to process files.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwfilterthread.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwfilter.h"


/* TYPEDEFS AND DEFINES */

/*
 *    Size of buffer, in bytes, for storing records prior to writing
 *    them.  There will be one of these buffers per destination type
 *    per thread.
 */
#define THREAD_RECBUF_SIZE   0x10000


typedef struct filter_thread_st {
    rwRec          *recbuf[DESTINATION_TYPES];
    filter_stats_t  stats;
    pthread_t       thread;
    int             rv;
} filter_thread_t;


/* LOCAL VARIABLE DEFINITIONS */

/* the main thread */
static pthread_t main_thread;

static pthread_mutex_t next_file_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t dest_mutex[DESTINATION_TYPES];

/* max number of records the recbuf can hold */
static const size_t recbuf_max_recs = THREAD_RECBUF_SIZE / sizeof(rwRec);


/* FUNCTION DEFINITIONS */


/*
 *  appHandleSignal(signal_value)
 *
 *    Set the 'reading_records' global to 0 which will begin the
 *    shutdown process.  Print a message unless the signal is SIGPIPE.
 */
static void
appHandleSignal(
    int                 sig)
{
    reading_records = 0;

    if (sig == SIGPIPE) {
        /* we get SIGPIPE if something downstream, like rwcut, exits
         * early, so don't bother to print a warning, and exit
         * successfully */
        exit(EXIT_SUCCESS);
    } else {
        skAppPrintErr("Caught signal..cleaning up and exiting");
    }
}


/*
 *  status = dumpBuffer(dest_id, rec_buffer, rec_count);
 *
 *    Write 'rec_count' records from 'rec_buffer' to the destinations
 *    in the global 'dest_type' array indexed by 'dest_id' (PASS,
 *    FAIL, ALL).  Return SKSTREAM_OK on success, non-zero on error.
 */
static int
dumpBuffer(
    int                 dest_id,
    const rwRec        *recbuf,
    uint32_t            reccount)
{
    destination_t *dest;
    destination_t *dest_next;
    const rwRec *recbuf_pos;
    const rwRec *end_rec;
    uint64_t total_rec_count;
    int close_after_add = 0;
    int recompute_reading = 0;
    int i;
    int rv = SKSTREAM_OK;

    pthread_mutex_lock(&dest_mutex[dest_id]);

    /* list of destinations to get the records */
    dest = dest_type[dest_id].dest_list;
    if (dest == NULL) {
        assert(dest_type[dest_id].count == 0);
        goto END;
    }

    /* if an output limit was specified, see if we will hit it while
     * adding these records.  If so, adjust the reccount and set a
     * flag to close the output after adding the records. */
    if (dest_type[dest_id].max_records) {
        total_rec_count = skStreamGetRecordCount(dest->stream);
        if (total_rec_count + reccount > dest_type[dest_id].max_records) {
            reccount = dest_type[dest_id].max_records - total_rec_count;
            close_after_add = 1;
            recompute_reading = 1;
        }
    }

    /* find location of our stopping condition */
    end_rec = recbuf + reccount;

    do {
        dest_next = dest->next;
        for (recbuf_pos = recbuf; recbuf_pos < end_rec; ++recbuf_pos) {
            rv = skStreamWriteRecord(dest->stream, recbuf_pos);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                if (skStreamGetLastErrno(dest->stream) == EPIPE) {
                    /* close this stream */
                    closeOneOutput(dest_id, dest);
                    recompute_reading = 1;
                    break;
                } else {
                    /* print the error and return */
                    skStreamPrintLastErr(dest->stream, rv, &skAppPrintErr);
                    reading_records = 0;
                    goto END;
                }
            }
        }
    } while ((dest = dest_next) != NULL);

    if (close_after_add) {
        closeOutputDests(dest_id, 0);
    }

    rv = SKSTREAM_OK;

    if (recompute_reading) {
        /* deadlock avoidance: unlock the mutex for this 'dest_id',
         * then lock the mutexes for all destination types, sum the
         * number of outputs, then free all mutexes in reverse
         * order. */
        int num_outs = 0;
        pthread_mutex_unlock(&dest_mutex[dest_id]);
        for (i = 0; i < DESTINATION_TYPES; ++i) {
            pthread_mutex_lock(&dest_mutex[i]);
            num_outs += dest_type[i].count;
        }
        if (!num_outs) {
            reading_records = 0;
        }
        for (i = DESTINATION_TYPES - 1; i >= 0; --i) {
            pthread_mutex_unlock(&dest_mutex[i]);
        }
        return rv;
    }

  END:
    pthread_mutex_unlock(&dest_mutex[dest_id]);
    return rv;
}


/*
 *  ok = filterFileThreaded(datafile, ipfile_basename, stats, recbuf,reccount);
 *
 *    This is the actual filtering of the file named 'datafile'.
 *    The 'ipfile_basename' parameter is passed to filterCheckFile();
 *    it should be NULL or contain the full-path (minus extension) of the
 *    file that contains Bloom filter or IPset information about the
 *    'datafile'.  The function returns 0 on success; or 1 if the
 *    input file could not be opened.
 *
 *    'recbuf' contains pointers to DESTINATION_TYPES number of record
 *    buffers.  A record buffer may be NULL if that output was not
 *    requested to that dest_id.  'reccount' is the current number of
 *    records in each record buffer.  Records that PASS or FAIL the
 *    checks are written into the appropriate record buffer.  When the
 *    count for the buffer reaches the buffer size, the records in the
 *    buffer are written to the output stream.
 */
static int
filterFileThreaded(
    const char         *datafile,
    const char         *ipfile_basename,
    filter_stats_t     *stats,
    rwRec              *recbuf[],
    uint32_t            recbuf_count[])
{
    rwRec rwrec;
    skstream_t *in_stream;
    int i;
    int fail_entire_file = 0;
    int result = RWF_PASS;
    int rv = SKSTREAM_OK;
    int in_rv = SKSTREAM_OK;
    rwRec *recbuf_pos[DESTINATION_TYPES];

    /* nothing to do in dry-run mode but print the file names */
    if (dryrun_fp) {
        fprintf(dryrun_fp, "%s\n", datafile);
        return 0;
    }

    if (!reading_records) {
        return 0;
    }

    /* initialize: set each buffer's current record pointer to the
     * appropriate location */
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        if (dest_type[i].count) {
            assert(NULL != recbuf[i]);
            recbuf_pos[i] = recbuf[i] + recbuf_count[i];
        } else {
            /* not used.  initialize to avoid gcc warning. */
            recbuf_pos[i] = NULL;
        }
    }

    /* print filenames if requested */
    if (filenames_fp) {
        fprintf(filenames_fp, "%s\n", datafile);
    }

    /* open the input file */
    in_rv = skStreamOpenSilkFlow(&in_stream, datafile, SK_IO_READ);
    if (in_rv) {
        goto END;
    }

    ++stats->files;

    /* determine if all the records in the file will fail the checks */
    if (filterCheckFile(in_stream, ipfile_basename) == 1) {
        /* all records in the file will fail the user's tests */
        fail_entire_file = 1;
        result = RWF_FAIL;

        /* determine if we can more efficiently handle the file */
        if ((dest_type[DEST_ALL].count == 0)
            && (dest_type[DEST_FAIL].count == 0))
        {
            /* no output is being generated for these records */
            if (print_stat == NULL) {
                /* not generating statistics either.  we can move to
                 * the next file */
                goto END;
            }
            if (print_volume_stats == 0) {
                /* all we need to do is to count the records in the
                 * file, which we can do by skipping them all. */
                size_t skipped = 0;
                in_rv = skStreamSkipRecords(in_stream, SIZE_MAX, &skipped);
                stats->read.flows += skipped;
                goto END;
            }
            /* else computing volume stats, and we need to read each
             * record to get its byte and packet counts. */
        }
    }

    /* read and process each record */
    while (reading_records
           && (SKSTREAM_OK == (in_rv = skStreamReadRecord(in_stream, &rwrec))))
    {
        /* increment number of read records */
        INCR_REC_COUNT(stats->read, &rwrec);

        /* the all-dest */
        if (dest_type[DEST_ALL].count) {
            memcpy(recbuf_pos[DEST_ALL], &rwrec, sizeof(rwRec));
            ++recbuf_pos[DEST_ALL];
            ++recbuf_count[DEST_ALL];
            if (recbuf_count[DEST_ALL] == recbuf_max_recs) {
                rv = dumpBuffer(DEST_ALL, recbuf[DEST_ALL],
                                recbuf_count[DEST_ALL]);
                if (rv) {
                    goto END;
                }
                recbuf_pos[DEST_ALL] = recbuf[DEST_ALL];
                recbuf_count[DEST_ALL] = 0;
            }
        }

        if (!fail_entire_file) {
            /* run all checker()'s until end or one doesn't pass */
            for (i=0, result=RWF_PASS;
                 i < checker_count && result == RWF_PASS;
                 ++i)
            {
                result = (*(checker[i]))(&rwrec);
            }
        }

        switch (result) {
          case RWF_PASS:
          case RWF_PASS_NOW:
            /* increment number of record that pass */
            INCR_REC_COUNT(stats->pass, &rwrec);

            /* the pass-dest */
            if (dest_type[DEST_PASS].count) {
                memcpy(recbuf_pos[DEST_PASS], &rwrec, sizeof(rwRec));
                ++recbuf_pos[DEST_PASS];
                ++recbuf_count[DEST_PASS];
                if (recbuf_count[DEST_PASS] == recbuf_max_recs) {
                    rv = dumpBuffer(DEST_PASS, recbuf[DEST_PASS],
                                    recbuf_count[DEST_PASS]);
                    if (rv) {
                        goto END;
                    }
                    recbuf_pos[DEST_PASS] = recbuf[DEST_PASS];
                    recbuf_count[DEST_PASS] = 0;
                }
            }
            break;

          case RWF_FAIL:
            /* the fail-dest */
            if (dest_type[DEST_FAIL].count) {
                memcpy(recbuf_pos[DEST_FAIL], &rwrec, sizeof(rwRec));
                ++recbuf_pos[DEST_FAIL];
                ++recbuf_count[DEST_FAIL];
                if (recbuf_count[DEST_FAIL] == recbuf_max_recs) {
                    rv = dumpBuffer(DEST_FAIL, recbuf[DEST_FAIL],
                                    recbuf_count[DEST_FAIL]);
                    if (rv) {
                        goto END;
                    }
                    recbuf_pos[DEST_FAIL] = recbuf[DEST_FAIL];
                    recbuf_count[DEST_FAIL] = 0;
                }
            }
            break;

          default:
            break;
        }

    } /* while (reading_records && skStreamReadRecord()) */

  END:
    if (in_rv == SKSTREAM_OK || in_rv == SKSTREAM_ERR_EOF) {
        in_rv = 0;
    } else {
        skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
        in_rv = 1;
    }

    /* close input */
    skStreamDestroy(&in_stream);

    if (rv) {
        return -1;
    }
    return in_rv;
}


/*
 *  filename = nextInputThreaded(buf, bufsize);
 *
 *    Fill 'buf', a buffer of size 'bufsize' with the name of the next
 *    file to process.  Return 'buf' if there are more files to
 *    process, NULL if there are no more files or on error.
 */
static char *
nextInputThreaded(
    char               *buf,
    size_t              bufsize)
{
    char *fname;

    pthread_mutex_lock(&next_file_mutex);
    fname = appNextInput(buf, bufsize);
    pthread_mutex_unlock(&next_file_mutex);

    return fname;
}


#ifndef SKTHREAD_UNKNOWN_ID
/* Create a local copy of the function from libsilk-thrd. */
/*
 *    Tell the current thread to ignore all signals except those
 *    indicating a failure (e.g., SIGBUS and SIGSEGV).
 */
static void
skthread_ignore_signals(
    void)
{
    sigset_t sigs;

    sigfillset(&sigs);
    sigdelset(&sigs, SIGABRT);
    sigdelset(&sigs, SIGBUS);
    sigdelset(&sigs, SIGILL);
    sigdelset(&sigs, SIGSEGV);

#ifdef SIGEMT
    sigdelset(&sigs, SIGEMT);
#endif
#ifdef SIGIOT
    sigdelset(&sigs, SIGIOT);
#endif
#ifdef SIGSYS
    sigdelset(&sigs, SIGSYS);
#endif

    pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}
#endif  /* #ifndef SKTHREAD_UNKNOWN_ID */


/*
 *  workerThread(&filter_thread_data);
 *
 *    THREAD ENTRY POINT.
 *
 *    Gets the name of the next file to process and calls
 *    filterFileThreaded() to process that file.  Stops processing
 *    when there are no more files to process or when an error occurs.
 */
static void *
workerThread(
    void               *v_thread)
{
    filter_stats_t *stats = &(((filter_thread_t*)v_thread)->stats);
    rwRec **recbuf = ((filter_thread_t*)v_thread)->recbuf;
    uint32_t recbuf_count[DESTINATION_TYPES];
    char datafile[PATH_MAX];
    int rv = 0;
    int i;

    /* ignore all signals unless this thread is the main thread */
    if (!pthread_equal(main_thread, ((filter_thread_t*)v_thread)->thread)) {
        skthread_ignore_signals();
    }

    memset(recbuf_count, 0, sizeof(recbuf_count));

    ((filter_thread_t*)v_thread)->rv = 0;

    while (nextInputThreaded(datafile, sizeof(datafile)) != NULL) {
        rv = filterFileThreaded(datafile, NULL, stats, recbuf, recbuf_count);
        if (rv < 0) {
            /* fatal error */
            ((filter_thread_t*)v_thread)->rv = rv;
            return NULL;
        }
        /* if (rv > 0) there was an error opening/reading input: ignore */
    }

    /* dump any records still in the buffers */
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        if (recbuf_count[i]) {
            dumpBuffer(i, recbuf[i], recbuf_count[i]);
        }
    }

    return NULL;
}


/*
 *  status = threadedFilter(&stats);
 *
 *    The "main" to use when rwfilter is used with threads.
 *
 *    Creates necessary data structures and then creates threads to
 *    process input files.  Once all input files have been processed,
 *    combines results from all threads to fill in the statistics
 *    structure 'stats'.  Returns 0 on success, non-zero on error.
 */
int
threadedFilter(
    filter_stats_t     *stats)
{
    filter_thread_t *thread;
    int i;
    uint32_t j;
    int rv = 0;

    /* get the main thread */
    main_thread = pthread_self();

    /* set a signal handler */
    if (skAppSetSignalHandler(&appHandleSignal)) {
        skAppPrintErr("Unable to set signal handler");
        exit(EXIT_FAILURE);
    }
    /* override that signal handler and ignore SIGPIPE */
    filterIgnoreSigPipe();

    /* initialize the mutexes for each destination type */
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        pthread_mutex_init(&dest_mutex[i], NULL);
    }

    /* create the data structures used by each thread */
    thread = (filter_thread_t*)calloc(thread_count, sizeof(filter_thread_t));
    if (thread == NULL) {
        goto END;
    }
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        if (dest_type[i].count) {
            for (j = 0; j < thread_count; ++j) {
                thread[j].recbuf[i]
                    = (rwRec*)malloc(recbuf_max_recs * sizeof(rwRec));
                if (thread[j].recbuf[i] == NULL) {
                    goto END;
                }
            }
        }
    }

    /* thread[0] is the main_thread */
    thread[0].thread = main_thread;

    /* create the threads, skip 0 since that is the main thread */
    for (j = 1; j < thread_count; ++j) {
        pthread_create(&thread[j].thread, NULL, &workerThread, &thread[j]);
    }

    /* allow the main thread to also process files */
    workerThread(&thread[0]);

    /* join with the threads as they die off */
    for (j = 0; j < thread_count; ++j) {
        if (j > 0) {
            pthread_join(thread[j].thread, NULL);
        }
        rv |= thread[j].rv;
        stats->read.flows += thread[j].stats.read.flows;
        stats->read.pkts  += thread[j].stats.read.pkts;
        stats->read.bytes += thread[j].stats.read.bytes;
        stats->pass.flows += thread[j].stats.pass.flows;
        stats->pass.pkts  += thread[j].stats.pass.pkts;
        stats->pass.bytes += thread[j].stats.pass.bytes;
        stats->files      += thread[j].stats.files;
#if 0
        fprintf(stderr,
                "thread %d processed %" PRIu32 " files and "
                "passed %" PRIu64 "/%" PRIu64 " flows\n",
                j, thread[j].stats.files, thread[j].stats.pass.flows,
                thread[j].stats.read.flows);
#endif
    }

  END:
    if (thread) {
        for (i = 0; i < DESTINATION_TYPES; ++i) {
            for (j = 0; j < thread_count; ++j) {
                if (thread[j].recbuf[i]) {
                    free(thread[j].recbuf[i]);
                }
            }
        }
        free(thread);
    }

    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
