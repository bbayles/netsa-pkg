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
**  rwfilter.c
**
**  6/3/2001
**
**  Suresh L. Konda
**
**  Allows for selective extraction of records and fields from a rw
**  packed file.  This version, unlike rwcut, creates a binary file with
**  the filtered records.  A new file type is used.  The header does not
**  contain valid recCount and rejectCount values.  The other fields are
**  taken from the original input file.
**
**  A second header is also created which records the filter rules used
**  for each pass.  Thus this is a variable length header
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwfilter.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwfilter.h"


/* TYPEDEFS AND DEFINES */


/* EXPORTED VARIABLES */

/* information about the destination types (ALL, PASS, FAIL); includes
 * a linked list of destination streams */
dest_type_t dest_type[DESTINATION_TYPES];

/* support for --print-statistics and --print-volume-statistics */
skstream_t *print_stat = NULL;

/* where to print output during a --dry-run; NULL when the switch has
 * not been provided */
FILE *dryrun_fp = NULL;

/* where to print output for --print-filenames; NULL when the switch
 * has not been provided */
FILE *filenames_fp = NULL;

/* input file specified by --input-pipe */
const char *input_pipe = NULL;

/* support for the --xargs switch */
skstream_t *xargs = NULL;

/* index into argv of first option that does not start with a '--'.
 * This assumes getopt rearranges the options, which gnu getopt will
 * do. */
int arg_index;

/* true as long as we are reading records */
int reading_records = 1;

/* whether to print volume statistics */
int print_volume_stats = 0;

/* total number of threads */
uint32_t thread_count = RWFILTER_THREADS_DEFAULT;

/* number of checks to preform */
int checker_count = 0;

/* function pointers to handle checking and or processing */
checktype_t (*checker[MAX_CHECKERS])(rwRec*);



/* LOCAL VARIABLES */

/* read-only cache of argc and argv used for dumping headers */
static int pargc;
static char **pargv;


/* FUNCTION DEFINITIONS */

/*
 *  status = writeHeaders(in_stream);
 *
 *    Create and print the header to each output file; include the
 *    current command line invocation in the header.  If 'in_stream' is
 *    non-null, the file history from that file is also included in
 *    the header.
 */
static int
writeHeaders(
    const skstream_t   *in_stream)
{
    static int did_headers = 0;
    sk_file_header_t *in_hdr = NULL;
    sk_file_header_t *out_hdr;
    destination_t *dest;
    int i;
    int rv = SKSTREAM_OK;

    /* only print headers one time */
    if (did_headers) {
        return rv;
    }
    did_headers = 1;

    /* don't print anything on a dry-run */
    if (dryrun_fp) {
        return rv;
    }

    if (in_stream) {
        in_hdr = skStreamGetSilkHeader(in_stream);
    }

    for (i = 0; i < DESTINATION_TYPES; ++i) {
        for (dest = dest_type[i].dest_list; dest != NULL; dest = dest->next) {
            out_hdr = skStreamGetSilkHeader(dest->stream);

            /* if 'in_stream' is provided, add its command invocation
             * history to each output file's headers */
            if (in_hdr) {
                rv = skHeaderCopyEntries(out_hdr, in_hdr,
                                         SK_HENTRY_INVOCATION_ID);
                if (rv == SKSTREAM_OK) {
                    rv = skHeaderCopyEntries(out_hdr, in_hdr,
                                             SK_HENTRY_ANNOTATION_ID);
                }
            }
            if (rv == SKSTREAM_OK) {
                rv = skHeaderAddInvocation(out_hdr, 1, pargc, pargv);
            }
            if (rv == SKSTREAM_OK) {
                rv = skOptionsNotesAddToStream(dest->stream);
            }
            if (rv == SKSTREAM_OK) {
                rv = skStreamWriteSilkHeader(dest->stream);
            }
            if (rv != SKSTREAM_OK) {
                skStreamPrintLastErr(dest->stream, rv, &skAppPrintErr);
                return rv;
            }
        }
    }

    skOptionsNotesTeardown();

    return rv;
}


/* Write the stats to the program specified by the SILK_STATISTICS envar */
static void
logStats(
    const filter_stats_t   *stats,
    time_t                 *start_time,
    time_t                 *end_time)
{
#define SILK_LOGSTATS_RWFILTER_ENVAR "SILK_LOGSTATS_RWFILTER"
#define SILK_LOGSTATS_ENVAR "SILK_LOGSTATS"
#define SILK_LOGSTATS_VERSION "v0001"
#define SILK_LOGSTATS_DEBUG SILK_LOGSTATS_ENVAR "_DEBUG"
#define NUM_STATS 5
    struct stat st;
    char *cmd_name;
    char param[NUM_STATS][21];
    char **log_argv;
    int debug = 0;
    int p = 0;
    int log_argc = 0;
    pid_t pid;
    int i;

    /* see whether to enable debugging */
    cmd_name = getenv(SILK_LOGSTATS_DEBUG);
    if (cmd_name != NULL && cmd_name[0] != '\0') {
        debug = 1;
    }

    cmd_name = getenv(SILK_LOGSTATS_RWFILTER_ENVAR);
    if (cmd_name == NULL) {
        cmd_name = getenv(SILK_LOGSTATS_ENVAR);
    }
    if (cmd_name == NULL || cmd_name[0] == '\0') {
        if (debug) {
            skAppPrintErr("LOGSTATS value empty or not found in environment");
        }
        return;
    }

    /* Verify that cmd_name represents a path, that it exists, that it
     * is a regular file, and that it is executable */
    if (strchr(cmd_name, '/') == NULL) {
        if (debug) {
            skAppPrintErr("LOGSTATS value does not contain slash '%s'",
                          cmd_name);
        }
        return;
    }
    if (stat(cmd_name, &st) == -1) {
        if (debug) {
            skAppPrintSyserror("LOGSTATS value has no status '%s'", cmd_name);
        }
        return;
    }
    if (S_ISREG(st.st_mode) == 0) {
        if (debug) {
            skAppPrintErr("LOGSTATS value is not a file '%s'", cmd_name);
        }
        return;
    }
    if (access(cmd_name, X_OK) != 0) {
        if (debug) {
            skAppPrintSyserror("LOGSTATS value is not executable '%s'",
                               cmd_name);
        }
        return;
    }

    /* Parent (first rwfilter) program forks */
    pid = fork();
    if (pid == -1) {
        return;
    }
    if (pid != 0) {
        /* Parent reaps Child 1 */
        waitpid(pid, NULL, 0);
        return;
    }

    /* only Child 1 makes it here; Child 1 forks again and immediately
     * exits so that the waiting rwfilter Parent above can continue */
    pid = fork();
    if (pid == -1) {
        _exit(EXIT_FAILURE);
    }
    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }

    /* only Child 2 makes it here.  it now prepares the command line
     * for the log-command. */

    /* magic 4 is log-command-name, app-name, log-version, final NULL */
    log_argv = (char**)calloc((4 + NUM_STATS + pargc), sizeof(char*));
    if (log_argv == NULL) {
        return;
    }

    /* start building the command for the tool */
    log_argv[log_argc++] = cmd_name;
    log_argv[log_argc++] = (char*)"rwfilter";
    log_argv[log_argc++] = (char*)SILK_LOGSTATS_VERSION;

    /* start-time */
    snprintf(param[p], sizeof(param[p]), ("%" PRId64), (int64_t)*start_time);
    ++p;
    /* end-time */
    snprintf(param[p], sizeof(param[p]), ("%" PRId64), (int64_t)*end_time);
    ++p;
    /* files processed */
    snprintf(param[p], sizeof(param[p]), ("%" PRIu32), stats->files);
    ++p;
    /* records read */
    snprintf(param[p], sizeof(param[p]), ("%" PRIu64), stats->read.flows);
    ++p;
    /* records written */
    snprintf(param[p], sizeof(param[p]), ("%" PRIu64),
             ((dest_type[DEST_ALL].count * stats->read.flows)
              + (dest_type[DEST_PASS].count * stats->pass.flows)
              + (dest_type[DEST_FAIL].count
                 * (stats->read.flows - stats->pass.flows))));
    ++p;
    assert(NUM_STATS == p);

    for (i = 0; i < p; ++i) {
        log_argv[log_argc++] = param[i];
    }
    for (i = 0; i < pargc; ++i) {
        log_argv[log_argc++] = pargv[i];
    }
    log_argv[log_argc] = (char*)NULL;

    if (debug) {
        /* for debugging: print command to stderr */
        fprintf(stderr, "%s: LOGSTATS preparing to exec: \"%s\", \"%s",
                skAppName(), cmd_name, log_argv[0]);
        for (i = 1; log_argv[i]; ++i) {
            fprintf(stderr, " %s", log_argv[i]);
        }
        fprintf(stderr, "\"\n");
    }

    execv(cmd_name, log_argv);
    skAppPrintSyserror("Unable to exec '%s'", cmd_name);
    exit(EXIT_FAILURE);
}


/* Write the statistics in 'sum' to the 'buf' */
static void
printStats(
    skstream_t             *stream,
    const filter_stats_t   *stats)
{
    /* check input */
    if (stream == NULL || stats == NULL) {
        return;
    }

    /* detailed or simple statistics? */
    if (print_volume_stats) {
        /* detailed */
        skStreamPrint(stream,
                      ("%5s|%18s|%18s|%20s|%10s|\n"
                       "%5s|%18" PRIu64 "|%18" PRIu64 "|%20" PRIu64 "|%10u|\n"
                       "%5s|%18" PRIu64 "|%18" PRIu64 "|%20" PRIu64 "|%10s|\n"
                       "%5s|%18" PRIu64 "|%18" PRIu64 "|%20" PRIu64 "|%10s|\n"),
                      /* titles */ "", "Recs", "Packets", "Bytes", "Files",

                      "Total",
                      stats->read.flows,
                      stats->read.pkts,
                      stats->read.bytes,
                      (unsigned int)stats->files,

                      "Pass",
                      stats->pass.flows,
                      stats->pass.pkts,
                      stats->pass.bytes,
                      "",

                      "Fail",
                      (stats->read.flows - stats->pass.flows),
                      (stats->read.pkts  - stats->pass.pkts),
                      (stats->read.bytes - stats->pass.bytes),
                      "");
    } else {
        /* simple */
        skStreamPrint(stream,
                      ("Files %5" PRIu32 ".  Read %10" PRIu64 "."
                       "  Pass %10" PRIu64 ". Fail  %10" PRIu64 ".\n"),
                      stats->files, stats->read.flows, stats->pass.flows,
                      (stats->read.flows - stats->pass.flows));
    }
}


/*
 *  closeAllDests();
 *
 *    Close all the output destinations.  Return 0 if they all closed
 *    cleanly, or non-zero if there was an error closing any stream.
 */
int
closeAllDests(
    void)
{
    destination_t *dest;
    destination_t *next_dest;
    int i;
    int rv = 0;
    int io_rv;

    /* close all the output files (pass, fail, all-dest) */
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        for (dest = dest_type[i].dest_list; dest != NULL; dest = next_dest) {
            io_rv = skStreamClose(dest->stream);
            switch (io_rv) {
              case SKSTREAM_OK:
              case SKSTREAM_ERR_NOT_OPEN:
              case SKSTREAM_ERR_CLOSED:
                break;
              default:
                rv |= io_rv;
                if (io_rv) {
                    skStreamPrintLastErr(dest->stream, io_rv, &skAppPrintErr);
                }
            }
            rv |= skStreamDestroy(&dest->stream);
            next_dest = dest->next;
            free(dest);
        }
        dest_type[i].dest_list = NULL;
    }

    return rv;
}


/*
 *  num_output_streams = closeOutputDests(dest_id, quietly);
 *
 *    Close all streams for the specified destination type 'dest_id'
 *    (DEST_PASS, DEST_FAIL, DEST_ALL).
 *
 *    If 'quietly' is non-zero, do not report errors in closing the
 *    file(s).
 *
 *    Return the number of output streams across all destination types
 *    that are still open.
 */
int
closeOutputDests(
    const int           dest_id,
    int                 quietly)
{
    destination_t *next_dest = NULL;
    destination_t *dest;
    int i;
    int rv;
    int num_outs;

    for (dest = dest_type[dest_id].dest_list; dest != NULL; dest = next_dest) {
        next_dest = dest->next;
        rv = skStreamClose(dest->stream);
        if (rv && !quietly) {
            skStreamPrintLastErr(dest->stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&dest->stream);
        free(dest);
    }
    dest_type[dest_id].dest_list = NULL;
    dest_type[dest_id].count = 0;

    /* compute and return the number of output streams that we now
     * have. */
    num_outs = 0;
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        num_outs += dest_type[i].count;
    }
    return num_outs;
}


/*
 *  num_output_streams = closeOneOutput(dest_id, dest);
 *
 *    Quietly close the output stream at 'dest' and free its memory.
 *    'dest_id' specifies which dest_type[] linked list contains
 *    'dest', since 'dest' must be removed from that list.  Return the
 *    new number of output streams.
 */
int
closeOneOutput(
    const int           dest_id,
    destination_t      *dest)
{
    destination_t **dest_prev;
    int num_outs;
    int i;

    /* unwire 'dest' */
    dest_prev = &dest_type[dest_id].dest_list;
    while (*dest_prev != dest) {
        dest_prev = &((*dest_prev)->next);
    }
    *dest_prev = dest->next;

    /* destroy 'dest' */
    skStreamDestroy(&dest->stream);
    free(dest);
    --dest_type[dest_id].count;

    /* compute and return the number of output streams that we now
     * have. */
    num_outs = 0;
    for (i = 0; i < DESTINATION_TYPES; ++i) {
        num_outs += dest_type[i].count;
    }
    return num_outs;
}


/*
 *  ok = filterFile(datafile, ipfile_basename, stats);
 *
 *    This is the actual filtering of the file 'datafile'.  The
 *    function will call the function to write the header if required.
 *    The 'ipfile_basename' parameter is passed to filterCheckFile();
 *    it should be NULL or contain the full-path (minus extension) of the
 *    file that contains Bloom filter or IPset information about the
 *    'datafile'.  The function returns 0 on success; or 1 if the
 *    input file could not be opened.
 *
 *    NOTE: There is a similar function, filterFileThreaded(), in
 *    rwfilterthread.c that is used when running with threads.
 */
static int
filterFile(
    const char         *datafile,
    const char         *ipfile_basename,
    filter_stats_t     *stats)
{
    rwRec rwrec;
    skstream_t *in_stream;
    int i;
    int fail_entire_file = 0;
    int result = RWF_PASS;
    int rv = SKSTREAM_OK;
    int in_rv = SKSTREAM_OK;

    /* print record 'pr_rwrec' to all dest_type streams specified by
     * 'pr_dest_id' */
#define PRINT_REC_TO_DEST_ID(pr_rwrec, pr_dest_id)                      \
    {                                                                   \
        destination_t *dest = dest_type[pr_dest_id].dest_list;          \
        destination_t *dest_next;                                       \
        do {                                                            \
            dest_next = dest->next;                                     \
            rv = skStreamWriteRecord(dest->stream, pr_rwrec);           \
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {                          \
                if (skStreamGetLastErrno(dest->stream) == EPIPE) {      \
                    /* close this one stream */                         \
                    reading_records = closeOneOutput(pr_dest_id, dest); \
                } else {                                                \
                    /* print the error and return */                    \
                    skStreamPrintLastErr(dest->stream, rv, &skAppPrintErr); \
                    reading_records = 0;                                \
                    goto END;                                           \
                }                                                       \
            }                                                           \
        } while ((dest = dest_next) != NULL);                           \
    }


    /* nothing to do in dry-run mode but print the file names */
    if (dryrun_fp) {
        fprintf(dryrun_fp, "%s\n", datafile);
        return 0;
    }

    if (!reading_records) {
        return 0;
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

    if (stats->files == 1) {
        /* first file, print the headers to the output file(s) */
        rv = writeHeaders(in_stream);
        if (rv) {
            goto END;
        }
    }

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
            PRINT_REC_TO_DEST_ID(&rwrec, DEST_ALL);
#if 0 /* dest_type[DEST_ALL].max_records is never set */
            /* close all streams for this destination type if we are
             * at user's requested max.  If max_records is 0, this
             * will never be true, and all records will be
             * processed. */
            if (stats->read.flows == dest_type[DEST_ALL].max_records) {
                reading_records = closeOutputDests(DEST_ALL, 0);
            }
#endif  /* 0 */
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
                PRINT_REC_TO_DEST_ID(&rwrec, DEST_PASS);
                if (stats->pass.flows == dest_type[DEST_PASS].max_records) {
                    /* close all streams for this destination type
                     * since we are at user's specified max. */
                    reading_records = closeOutputDests(DEST_PASS, 0);
                }
            }
            break;

          case RWF_FAIL:
            /* the fail-dest */
            if (dest_type[DEST_FAIL].count) {
                PRINT_REC_TO_DEST_ID(&rwrec, DEST_FAIL);
                if ((stats->read.flows - stats->pass.flows)
                    == dest_type[DEST_FAIL].max_records)
                {
                    /* close all streams for this destination type
                     * since we are at user's specified max. */
                    reading_records = closeOutputDests(DEST_FAIL, 0);
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


char *
appNextInput(
    char               *buf,
    size_t              bufsize)
{
    static int first_call = 1;
    static int i = 0;
    int lc;
    int rv;

    if (!reading_records) {
        return NULL;
    }

    /* Get the files.  Only one of these should be active */
    if (fglobValid()) {
        return fglobNext(buf, bufsize);
    } else if (input_pipe) {
        /* file name given via --input-pipe switch */
        if (first_call) {
            first_call = 0;
            strncpy(buf, input_pipe, bufsize);
            buf[bufsize-1] = '\0';
            return buf;
        }
    } else if (xargs) {
        /* file names from stdin */
        if (first_call) {
            first_call = 0;
            /* open input */
            rv = skStreamOpen(xargs);
            if (rv) {
                skStreamPrintLastErr(xargs, rv, &skAppPrintErr);
                return NULL;
            }
        }
        /* read until end of file */
        while ((rv = skStreamGetLine(xargs, buf, bufsize, &lc))
               != SKSTREAM_ERR_EOF)
        {
            switch (rv) {
              case SKSTREAM_OK:
                /* good, we got our line */
                break;
              case SKSTREAM_ERR_LONG_LINE:
                /* bad: line was longer than sizeof(line) */
                skAppPrintErr("Input line %d too long---ignored", lc);
                continue;
              default:
                /* unexpected error */
                skStreamPrintLastErr(xargs, rv, &skAppPrintErr);
                return NULL;
            }
            return buf;
        }
    } else {
        /* file names from the command line */
        if (first_call) {
            first_call = 0;
            i = arg_index;
        } else {
            ++i;
        }
        if (i < pargc) {
            strncpy(buf, pargv[i], bufsize);
            buf[bufsize-1] = '\0';
            return buf;
        }
    }

    return NULL;
}


int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    char datafile[PATH_MAX];
    filter_stats_t stats;
    int rv_file;
    int rv = 0;
    time_t start_timer;
    time_t end_timer;

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    /* initialize */
    memset(&stats, 0, sizeof(filter_stats_t));


    time(&start_timer);
    appSetup(argc, argv);

    pargc = argc;
    pargv = argv;

#if SK_RWFILTER_THREADED
    if (thread_count > 1) {
        /* must dump the headers first */
        rv = writeHeaders(NULL);
        if (rv == SKSTREAM_OK) {
            rv = threadedFilter(&stats);
        }
    } else
#endif  /* SK_RWFILTER_THREADED */
    {
        /* non-threaded */
        filterIgnoreSigPipe();
        while (appNextInput(datafile, sizeof(datafile)) != NULL) {
            rv_file = filterFile(datafile, NULL, &stats);
            if (rv_file < 0) {
                /* fatal */
                return EXIT_FAILURE;
            }
            /* if (rv_file > 0) there was an error opening/reading
             * input: ignore */
        }
    }

    /*
     * We don't write the header to the destination file(s) until
     * we've read the first record.  However, if no files were read,
     * the destination files are empty, so dump the header to them
     * now.
     */
    if (stats.files == 0) {
        rv_file = writeHeaders(NULL);
        if (rv_file) {
            rv = rv_file;
        }
    }

    /* Print the statistics */
    if (print_stat && !dryrun_fp) {
        printStats(print_stat, &stats);
    }

    time(&end_timer);
    logStats(&stats, &start_timer, &end_timer);

    appTeardown();

    return ((rv == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
