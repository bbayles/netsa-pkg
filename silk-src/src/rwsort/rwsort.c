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
**  rwsort reads SiLK Flow Records from the standard input or from
**  named files and sorts them on one or more user-specified fields.
**
**  rwsort attempts to sort the records in RAM using a buffer whose
**  maximum size is DEFAULT_SORT_BUFFER_SIZE bytes.  The user may
**  choose a different maximum size with the --sort-buffer-size
**  switch.  The buffer rwsort initially allocates is
**  1/SORT_NUM_CHUNKS of this size; when it is full, the buffer is
**  reallocated and grown by another 1/SORT_NUM_CHUNKS.  This
**  continues until all records are read, a realloc() fails, or the
**  maximum buffer size is reached.
**
**  The purpose of gradually increasing the buffer size is twofold:
**  1. So we don't use more memory than we actually need.  2. When
**  allocating a large buffer during start-up, the OS would give us
**  the memory, but if we attempted to use the buffer the OS would
**  kill the rwsort process.
**
**  Records are read and stored in this buffer; if the input ends
**  before the buffer is filled, the records are sorted and printed to
**  standard out or to the named output file.
**
**  However, if the buffer fills before the input is completely read,
**  the records in the buffer are sorted and written to a temporary
**  file on disk; the buffer is cleared, and reading of the input
**  resumes, repeating the process as necessary until all records are
**  read.  We then do an N-way merge-sort on the temporary files,
**  where N is either all the temporary files, MAX_MERGE_FILES, or the
**  maximum number that we can open before running out of file descriptors
**  (EMFILE) or memory.  If we cannot open all temporary files, we
**  merge the N files into a new temporary file, then add it to the
**  list of files to merge.
**
**  When the temporary files are written to the same volume (file
**  system) as the final output, the maximum disk usage will be
**  2-times the number of records read (times the size per record);
**  when different volumes are used, the disk space required for the
**  temporary files will be between 1 and 1.5 times the number of
**  records.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsort.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwsort.h"
#include <silk/skheap.h>


/* EXPORTED VARIABLES */

/* number of fields to sort over; skStringMapParse() sets this */
uint32_t num_fields = 0;

/* IDs of the fields to sort over; skStringMapParse() sets it; values
 * are from the rwrec_printable_fields_t enum and from values that
 * come from plug-ins. */
uint32_t *sort_fields = NULL;

/* the size of a "node".  Because the output from rwsort are SiLK
 * records, the node size includes the complete rwRec, plus any binary
 * fields that we get from plug-ins to use as the key.  This node_size
 * value may increase when we parse the --fields switch. */
size_t node_size = sizeof(rwRec);

/* the columns that make up the key that come from plug-ins */
key_field_t key_fields[MAX_PLUGIN_KEY_FIELDS];

/* the number of these key_fields */
size_t key_num_fields = 0;

/* output stream */
skstream_t *out_stream = NULL;

/* temp file context */
sk_tempfilectx_t *tmpctx;

/* whether the user wants to reverse the sort order */
int reverse = 0;

/* whether to treat the input files as already sorted */
int presorted_input = 0;

/* maximum amount of RAM to attempt to allocate */
size_t sort_buffer_size;


/* FUNCTION DEFINITIONS */

/* How to sort the flows: forward or reverse? */
#define RETURN_SORT_ORDER(val)                  \
    return (reverse ? -(val) : (val))

/* Define our raw sorting functions */
#define RETURN_IF_SORTED(func, rec_a, rec_b)                    \
    {                                                           \
        if (func((rwRec*)(rec_a)) < func((rwRec*)(rec_b))) {    \
            RETURN_SORT_ORDER(-1);                              \
        }                                                       \
        if (func((rwRec*)(rec_a)) > func((rwRec*)(rec_b))) {    \
            RETURN_SORT_ORDER(1);                               \
        }                                                       \
    }

#define RETURN_IF_SORTED_IPS(func, rec_a, rec_b)        \
    {                                                   \
        skipaddr_t ipa, ipb;                            \
        int cmp;                                        \
        func((rwRec*)(rec_a), &ipa);                    \
        func((rwRec*)(rec_b), &ipb);                    \
        cmp = skipaddrCompare(&ipa, &ipb);              \
        if (cmp != 0) {                                 \
            RETURN_SORT_ORDER(cmp);                     \
        }                                               \
    }


static uint8_t
getIcmpType(
    const void         *rec)
{
    if (rwRecIsICMP((rwRec*)rec)) {
        return rwRecGetIcmpType((rwRec*)rec);
    }
    return 0;
}

static uint8_t
getIcmpCode(
    const void         *rec)
{
    if (rwRecIsICMP((rwRec*)rec)) {
        return rwRecGetIcmpCode((rwRec*)rec);
    }
    return 0;
}


/*
 *  rwrecCompare(a, b);
 *
 *     Returns an ordering on the recs pointed to `a' and `b' by
 *     comparing the fields listed in the sort_fields[] array.
 */
static int
rwrecCompare(
    const void         *a,
    const void         *b)
{
    key_field_t *key = key_fields;
    skplugin_err_t err;
    uint32_t i;
    int rv;

    for (i = 0; i < num_fields; ++i) {
        switch (sort_fields[i]) {
          case RWREC_FIELD_SIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetSIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetSIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_DIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetDIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetDIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_NHIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetNhIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetNhIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_SPORT:
            RETURN_IF_SORTED(rwRecGetSPort, a, b);
            break;

          case RWREC_FIELD_DPORT:
            RETURN_IF_SORTED(rwRecGetDPort, a, b);
            break;

          case RWREC_FIELD_PROTO:
            RETURN_IF_SORTED(rwRecGetProto, a, b);
            break;

          case RWREC_FIELD_PKTS:
            RETURN_IF_SORTED(rwRecGetPkts, a, b);
            break;

          case RWREC_FIELD_BYTES:
            RETURN_IF_SORTED(rwRecGetBytes, a, b);
            break;

          case RWREC_FIELD_FLAGS:
            RETURN_IF_SORTED(rwRecGetFlags, a, b);
            break;

          case RWREC_FIELD_STIME:
          case RWREC_FIELD_STIME_MSEC:
            RETURN_IF_SORTED(rwRecGetStartTime, a, b);
            break;

          case RWREC_FIELD_ELAPSED:
          case RWREC_FIELD_ELAPSED_MSEC:
            RETURN_IF_SORTED(rwRecGetElapsed, a, b);
            break;

          case RWREC_FIELD_ETIME:
          case RWREC_FIELD_ETIME_MSEC:
            RETURN_IF_SORTED(rwRecGetEndTime, a, b);
            break;

          case RWREC_FIELD_SID:
            RETURN_IF_SORTED(rwRecGetSensor, a, b);
            break;

          case RWREC_FIELD_INPUT:
            RETURN_IF_SORTED(rwRecGetInput, a, b);
            break;

          case RWREC_FIELD_OUTPUT:
            RETURN_IF_SORTED(rwRecGetOutput, a, b);
            break;

          case RWREC_FIELD_INIT_FLAGS:
            RETURN_IF_SORTED(rwRecGetInitFlags, a, b);
            break;

          case RWREC_FIELD_REST_FLAGS:
            RETURN_IF_SORTED(rwRecGetRestFlags, a, b);
            break;

          case RWREC_FIELD_TCP_STATE:
            RETURN_IF_SORTED(rwRecGetTcpState, a, b);
            break;

          case RWREC_FIELD_APPLICATION:
            RETURN_IF_SORTED(rwRecGetApplication, a, b);
            break;

          case RWREC_FIELD_FTYPE_CLASS:
          case RWREC_FIELD_FTYPE_TYPE:
            RETURN_IF_SORTED(rwRecGetFlowType, a, b);
            break;

          case RWREC_FIELD_ICMP_TYPE:
            RETURN_IF_SORTED(getIcmpType, a, b);
            break;

          case RWREC_FIELD_ICMP_CODE:
            RETURN_IF_SORTED(getIcmpCode, a, b);
            break;

#if 0
          case RWREC_FIELD_SCC:
            {
                uint16_t a_cc = skCountryLookupCode(rwRecGetSIPv4((rwRec*)a));
                uint16_t b_cc = skCountryLookupCode(rwRecGetSIPv4((rwRec*)b));
                if (a_cc < b_cc) {
                    RETURN_SORT_ORDER(-1);
                } else if (b_cc > a_cc) {
                    RETURN_SORT_ORDER(1);
                }
            }
            break;

          case RWREC_FIELD_DCC:
            {
                uint16_t a_cc = skCountryLookupCode(rwRecGetDIPv4((rwRec*)a));
                uint16_t b_cc = skCountryLookupCode(rwRecGetDIPv4((rwRec*)b));
                if (a_cc < b_cc) {
                    RETURN_SORT_ORDER(-1);
                } else if (b_cc > a_cc) {
                    RETURN_SORT_ORDER(1);
                }
            }
            break;
#endif  /* 0 */

          default:
            /* we go through the fields in the same way they were
             * added, and 'key' should always be an index to the
             * current plugin. */
            assert((size_t)(key - key_fields) < key_num_fields);
            err=skPluginFieldRunBinCompareFn(key->kf_field_handle, &rv,
                                             &(((uint8_t*)a)[key->kf_offset]),
                                             &(((uint8_t*)b)[key->kf_offset]));
            if (err != SKPLUGIN_OK) {
                const char **name;
                skPluginFieldName(key->kf_field_handle, &name);
                skAppPrintErr(("Plugin-based field %s failed "
                               "comparing binary values "
                               "with error code %d"), name[0], err);
                exit(EXIT_FAILURE);
            }
            ++key;
            if (rv != 0) {
                RETURN_SORT_ORDER(rv);
            }
            break;
        }
    }

    return 0;
}


/*
 *  status = compHeapNodes(b, a, v_recs);
 *
 *    Callback function used by the heap two compare two heapnodes,
 *    there are just indexes into an array of records.  'v_recs' is
 *    the array of records, where each record is MAX_NODE_SIZE bytes.
 *
 *    Note the order of arguments is 'b', 'a'.
 */
static int
compHeapNodes(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_recs)
{
    uint8_t *recs = (uint8_t*)v_recs;

    return rwrecCompare(&recs[*(uint16_t*)a * MAX_NODE_SIZE],
                        &recs[*(uint16_t*)b * MAX_NODE_SIZE]);
}


/*
 *  status = fillRecordAndKey(stream, buf);
 *
 *    Reads a flow record from 'stream', computes the key based on the
 *    global key_fields[] settings, and fills in the parameter 'buf'
 *    with the record and then the key.  Return 1 if a record was
 *    read, or 0 if it was not.
 */
static int
fillRecordAndKey(
    skstream_t         *stream,
    uint8_t            *buf)
{
    rwRec *rwrec = (rwRec*)buf;
    skplugin_err_t err;
    const char **name;
    size_t i;
    int rv;

    rv = skStreamReadRecord(stream, rwrec);
    if (rv) {
        /* end of file or error getting record */
        if (SKSTREAM_ERR_EOF != rv) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        }
        return 0;
    }

    /* lookup data from plug-in */
    for (i = 0; i < key_num_fields; ++i) {
        err = skPluginFieldRunRecToBinFn(key_fields[i].kf_field_handle,
                                         &(buf[key_fields[i].kf_offset]),
                                         rwrec, NULL);
        if (err != SKPLUGIN_OK) {
            skPluginFieldName(key_fields[i].kf_field_handle, &name);
            skAppPrintErr(("Plugin-based field %s failed "
                           "converting to binary "
                           "with error code %d"), name[0], err);
            appExit(EXIT_FAILURE);
        }
    }
    return 1;
}


/*
 *    Create and return a new temporary file, putting the index of the
 *    file in 'temp_idx'.  Exit the application on failure.
 */
static skstream_t *
sortTempCreate(
    int                *temp_idx)
{
    skstream_t *stream;

    stream = skTempFileCreateStream(tmpctx, temp_idx);
    if (NULL == stream) {
        skAppPrintSyserror("Error creating new temporary file");
        appExit(EXIT_FAILURE);
    }
    return stream;
}

/*
 *    Re-open the existing temporary file indexed by 'temp_idx'.
 *    Return the new stream.  Return NULL if we could not open the
 *    stream due to out-of-memory or out-of-file-handles error.  Exit
 *    the application on any other error.
 */
static skstream_t *
sortTempReopen(
    int                 temp_idx)
{
    skstream_t *stream;

    stream = skTempFileOpenStream(tmpctx, temp_idx);
    if (NULL == stream) {
        if ((errno != EMFILE) && (errno != ENOMEM)) {
            skAppPrintSyserror(("Error opening existing temporary file '%s'"),
                               skTempFileGetName(tmpctx, temp_idx));
            appExit(EXIT_FAILURE);
        }
    }
    return stream;
}

/*
 *    Close a temporary file.  Exit the application if stream was open
 *    for write and closing fails.
 */
static void
sortTempClose(
    skstream_t         *stream)
{
    char errbuf[2 * PATH_MAX];
    ssize_t rv;

    rv = skStreamClose(stream);
    switch (rv) {
      case SKSTREAM_OK:
      case SKSTREAM_ERR_NOT_OPEN:
      case SKSTREAM_ERR_CLOSED:
        skStreamDestroy(&stream);
        return;
      case SKSTREAM_ERR_NULL_ARGUMENT:
        return;
    }

    skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
    skAppPrintErr("Error closing temporary file: %s", errbuf);
    if (skStreamGetMode(stream) == SK_IO_WRITE) {
        appExit(EXIT_FAILURE);
    }
    skStreamDestroy(&stream);
}

/*
 *    Read 'str_size' bytes from 'str_stream' into 'str_buf'.  Return
 *    'str_size' on success or 0 for other condition (end-of-file,
 *    short read, error).
 */
#define sortTempRead(str_stream, str_buf, str_size)                     \
    sortTempReadHelper(str_stream, str_buf, str_size, __FILE__, __LINE__)

static ssize_t
sortTempReadHelper(
    skstream_t         *stream,
    void               *buf,
    size_t              size,
    const char         *file_name,
    int                 file_line)
{
    ssize_t rv;

    rv = skStreamRead(stream, buf, size);
    if (rv == (ssize_t)size) {
        return rv;
    }
#if TRACEMSG_LEVEL == 0
    (void)file_name;
    (void)file_line;
#else
    if (rv == 0) {
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes: EOF on '%s'",
                  file_name, file_line, size, skStreamGetPathname(stream)));
    } else if (rv > 0) {
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes:"
                  " Short read of %" SK_PRIdZ " on '%s'",
                  file_name, file_line, size, rv, skStreamGetPathname(stream)));
    } else {
        char errbuf[2 * PATH_MAX];

        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes: %s",
                  file_name, file_line, size, errbuf));
    }
#endif
    return 0;
}


/*
 *    Write 'stw_size' bytes from 'stw_buf' to 'stw_stream'.  Return
 *    'stw_size' on success and exit the appliation on error or short
 *    write.
 */
#define sortTempWrite(stw_stream, stw_buf, stw_size)                    \
    sortTempWriteHelper(stw_stream, stw_buf, stw_size, __FILE__, __LINE__)

static void
sortTempWriteHelper(
    skstream_t         *stream,
    const void         *buf,
    size_t              size,
    const char         *file_name,
    int                 file_line)
{
    char errbuf[2 * PATH_MAX];
    ssize_t rv;

    rv = skStreamWrite(stream, buf, size);
    if (rv == (ssize_t)size) {
        return;
    }
    skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));

#if TRACEMSG_LEVEL == 0
    (void)file_name;
    (void)file_line;
#else
    if (rv >= 0) {
        TRACEMSG(("%s:%d: Failed to write %" SK_PRIuZ " bytes:"
                  " Short write of %" SK_PRIdZ " on '%s'",
                  file_name, file_line, size, rv, skStreamGetPathname(stream)));
    } else {
        TRACEMSG(("%s:%d: Failed to write %" SK_PRIuZ " bytes: %s",
                  file_name, file_line, size, errbuf));
    }
#endif

    if (rv >= 0) {
        snprintf(errbuf,sizeof(errbuf),
                 "Short write of %" SK_PRIdZ " bytes to '%s'",
                 rv, skStreamGetPathname(stream));
    }
    skAppPrintErr("Error writing to temporary file: %s", errbuf);
    appExit(EXIT_FAILURE);
}

/*
 *    Write the contents of 'rec_buffer' to a new temp file, where
 *    'rec_buffer' contains 'rec_count' records of size 'rec_size'.
 *    Fill 'tmp_idx' with the new temporary file's index.  Exit the
 *    application on error.
 */
static void
sortTempWriteBuffer(
    int                *tmp_idx,
    const void         *rec_buffer,
    uint32_t            rec_size,
    uint32_t            rec_count)
{
    if (skTempFileWriteBufferStream(tmpctx, tmp_idx, rec_buffer,
                                    rec_size, rec_count))
    {
        skAppPrintErr("Error saving sorted buffer to temporary file: %s",
                      strerror(errno));
        appExit(EXIT_FAILURE);
    }
}


/*
 *  mergeFiles(temp_file_idx)
 *
 *    Merge the temporary files numbered from 0 to 'temp_file_idx'
 *    inclusive into the output file 'out_stream', maintaining sorted
 *    order.  Exits the application if an error occurs.
 */
static void
mergeFiles(
    int                 temp_file_idx)
{
    skstream_t *fps[MAX_MERGE_FILES];
    uint8_t recs[MAX_MERGE_FILES][MAX_NODE_SIZE];
    int j;
    uint16_t open_count;
    uint16_t i;
    uint16_t *top_heap;
    uint16_t lowest;
    int tmp_idx_a;
    int tmp_idx_b;
    skstream_t *fp_intermediate = NULL;
    int tmp_idx_intermediate;
    int opened_all_temps = 0;
    skheap_t *heap;
    uint32_t heap_count;
    int rv;

    TRACEMSG(("Merging #%d through #%d into '%s'",
              0, temp_file_idx, skStreamGetPathname(out_stream)));

    heap = skHeapCreate2(compHeapNodes, MAX_MERGE_FILES, sizeof(uint16_t),
                         NULL, recs);
    if (NULL == heap) {
        skAppPrintOutOfMemory("heap");
        appExit(EXIT_FAILURE);
    }

    /* the index of the first temp file to the merge */
    tmp_idx_a = 0;

    /* This loop repeats as long as we haven't read all of the temp
     * files generated in the sorting stage. */
    do {
        assert(SKHEAP_ERR_EMPTY==skHeapPeekTop(heap,(skheapnode_t*)&top_heap));

        /* the index of the last temp file to merge */
        tmp_idx_b = temp_file_idx;

        /* open an intermediate temp file.  The merge-sort will have
         * to write records here if there are not enough file handles
         * available to open all the existing tempoary files. */
        fp_intermediate = sortTempCreate(&tmp_idx_intermediate);

        /* count number of files we open */
        open_count = 0;

        /* Attempt to open up to MAX_MERGE_FILES, though we an open
         * may fail due to lack of resources (EMFILE or ENOMEM) */
        for (j = tmp_idx_a; j <= tmp_idx_b; ++j) {
            fps[open_count] = sortTempReopen(j);
            if (NULL == fps[open_count]) {
                if (0 == open_count) {
                    skAppPrintErr("Unable to open any temporary files");
                    appExit(EXIT_FAILURE);
                }
                /* We cannot open any more files.  Rewind counter by
                 * one to catch this file on the next merge. */
                assert(j > 0);
                tmp_idx_b = j - 1;
                TRACEMSG(
                    ("EMFILE limit hit--merging #%d through #%d into #%d: %s",
                     tmp_idx_a, tmp_idx_b, tmp_idx_intermediate,
                     strerror(errno)));
                break;
            }

            /* read the first record */
            if (sortTempRead(fps[open_count], recs[open_count], node_size)) {
                /* insert the file index into the heap */
                skHeapInsert(heap, &open_count);
                ++open_count;
                if (open_count == MAX_MERGE_FILES) {
                    /* We've reached the limit for this pass.  Set
                     * tmp_idx_b to the file we just opened. */
                    tmp_idx_b = j;
                    TRACEMSG((("MAX_MERGE_FILES limit hit--"
                               "merging #%d through #%d into #%d"),
                              tmp_idx_a, tmp_idx_b, tmp_idx_intermediate));
                    break;
                }
            } else {
                if (skStreamGetLastReturnValue(fps[open_count]) != 0) {
                    skAppPrintSyserror(("Error reading first record from"
                                        " temporary file '%s'"),
                                       skTempFileGetName(tmpctx, j));
                    appExit(EXIT_FAILURE);
                }
                TRACEMSG(("Ignoring empty temporary file '%s'",
                          skTempFileGetName(tmpctx, j)));
                skStreamDestroy(&fps[open_count]);
            }
        }

        /* Here, we check to see if we've opened all temp files.  If
         * so, set a flag so we write data to final destination and
         * break out of the loop after we're done. */
        if (tmp_idx_b == temp_file_idx) {
            opened_all_temps = 1;
            /* no longer need the intermediate temp file */
            sortTempClose(fp_intermediate);
            fp_intermediate = NULL;
        } else {
            /* we could not open all temp files, so merge all opened
             * temp files into the intermediate file.  Add the
             * intermediate file to the list of files to merge */
            temp_file_idx = tmp_idx_intermediate;
        }

        TRACEMSG((("Merging %" PRIu16 " temporary files"), open_count));

        heap_count = skHeapGetNumberEntries(heap);
        assert(heap_count == open_count);

        /* exit this while() once we are only processing a single
         * file */
        while (heap_count > 1) {
            /* entry at the top of the heap has the lowest key */
            skHeapPeekTop(heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;

            /* write the lowest record */
            if (fp_intermediate) {
                /* write record to intermediate tmp file */
                sortTempWrite(fp_intermediate, recs[lowest], node_size);
            } else {
                /* we successfully opened all (remaining) temp files,
                 * write to record to the final destination */
                rv = skStreamWriteRecord(out_stream,(rwRec*)recs[lowest]);
                if (0 != rv) {
                    skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                    if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                        appExit(EXIT_FAILURE);
                    }
                }
            }

            /* replace the record we just wrote */
            if (sortTempRead(fps[lowest], recs[lowest], node_size)) {
                /* read was successful.  "insert" the new entry into
                 * the heap (which has same value as old entry). */
                skHeapReplaceTop(heap, &lowest, NULL);
            } else {
                /* no more data for this file; remove it from the
                 * heap */
                skHeapExtractTop(heap, NULL);
                --heap_count;
                TRACEMSG(("Finished reading file #%u; %u files remain",
                          tmp_idx_a + lowest, heap_count));
            }
        }

        /* get index of the remaining file */
        skHeapExtractTop(heap, &lowest);
        assert(SKHEAP_ERR_EMPTY==skHeapPeekTop(heap,(skheapnode_t*)&top_heap));

        /* read records from the remaining file */
        if (fp_intermediate) {
            do {
                sortTempWrite(fp_intermediate, recs[lowest], node_size);
            } while (sortTempRead(fps[lowest], recs[lowest], node_size));
        } else {
            do {
                rv = skStreamWriteRecord(out_stream, (rwRec*)recs[lowest]);
                if (0 != rv) {
                    skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                    if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                        appExit(EXIT_FAILURE);
                    }
                }
            } while (sortTempRead(fps[lowest], recs[lowest], node_size));
        }

        TRACEMSG(("Finished reading file #%u; 0 files remain", lowest));
        TRACEMSG((("Finished processing #%d through #%d"),
                  tmp_idx_a, tmp_idx_b));

        /* Close all open temp files */
        for (i = 0; i < open_count; ++i) {
            sortTempClose(fps[i]);
        }
        /* Delete all temp files we opened (or attempted to open) this
         * time */
        for (j = tmp_idx_a; j <= tmp_idx_b; ++j) {
            skTempFileRemove(tmpctx, j);
        }

        /* Close the intermediate temp file. */
        if (fp_intermediate) {
            sortTempClose(fp_intermediate);
            fp_intermediate = NULL;
        }

        /* Start the next merge with the next input temp file */
        tmp_idx_a = tmp_idx_b + 1;

    } while (!opened_all_temps);

    skHeapFree(heap);
}


/*
 *  temp_file_idx = sortPresorted();
 *
 *    Assume all input files have been sorted using the exact same
 *    --fields value as those we are using, and simply merge sort
 *    them.
 *
 *    This function is still fairly complicated, because we have to
 *    handle running out of memory or file descriptors as we process
 *    the inputs.  When that happens, we write the records to
 *    temporary files and then use mergeFiles() above to sort those
 *    files.
 *
 *    Exits the application if an error occurs.  On success, this
 *    function returns the index of the final temporary file to use
 *    for the mergeSort().  A return value less than 0 is considered
 *    successful and indicates that no merge-sort is required.
 */
static int
sortPresorted(
    void)
{
    skstream_t *stream[MAX_MERGE_FILES];
    uint8_t recs[MAX_MERGE_FILES][MAX_NODE_SIZE];
    uint16_t i;
    uint16_t open_count;
    uint16_t *top_heap;
    uint16_t lowest;
    skstream_t *fp_intermediate = NULL;
    int temp_file_idx = -1;
    int opened_all_inputs = 0;
    skheap_t *heap;
    uint32_t heap_count;
    int rv;

    memset(stream, 0, sizeof(stream));
    memset(recs, 0, sizeof(recs));

    heap = skHeapCreate2(compHeapNodes, MAX_MERGE_FILES, sizeof(uint16_t),
                         NULL, recs);
    if (NULL == heap) {
        skAppPrintOutOfMemory("heap");
        appExit(EXIT_FAILURE);
    }

    /* This loop repeats as long as we haven't read all of input
     * files */
    do {
        /* open an intermediate temp file.  The merge-sort will have
         * to write records here if there are not enough file handles
         * available to open all the input files. */
        fp_intermediate = sortTempCreate(&temp_file_idx);

        /* Attempt to open up to MAX_MERGE_FILES, though we an open
         * may fail due to lack of resources (EMFILE or ENOMEM) */
        for (open_count = 0; open_count < MAX_MERGE_FILES; ++open_count) {
            rv = appNextInput(&(stream[open_count]));
            if (rv != 0) {
                break;
            }
        }
        switch (rv) {
          case 1:
            /* successfully opened all (remaining) input files */
            opened_all_inputs = 1;
            if (temp_file_idx > 0) {
                TRACEMSG(("Opened all remaining inputs"));
            } else {
                /* we opened all the input files in a single pass.  we
                 * no longer need the intermediate temp file */
                TRACEMSG(("Opened all inputs in a single pass"));
                sortTempClose(fp_intermediate);
                fp_intermediate = NULL;
                temp_file_idx = -1;
            }
            break;
          case -1:
            /* unexpected error opening a file */
            appExit(EXIT_FAILURE);
          case -2:
            /* ran out of memory or file descriptors */
            TRACEMSG((("Unable to open all inputs---"
                       "out of memory or file handles")));
            break;
          case 0:
            if (open_count == MAX_MERGE_FILES) {
                /* ran out of pointers for this run */
                TRACEMSG((("Unable to open all inputs---"
                           "MAX_MERGE_FILES limit reached")));
                break;
            }
            /* no other way that rv == 0 */
            TRACEMSG(("rv == 0 but open_count is %d. Abort.",
                      open_count));
            skAbort();
          default:
            /* unexpected error */
            TRACEMSG(("Got unexpected rv value = %d", rv));
            skAbortBadCase(rv);
        }

        /* Read the first record from each file into the work buffer */
        for (i = 0; i < open_count; ++i) {
            if (fillRecordAndKey(stream[i], recs[i])) {
                /* insert the file index into the heap */
                skHeapInsert(heap, &i);
            }
        }

        heap_count = skHeapGetNumberEntries(heap);

        TRACEMSG((("Merging %" PRIu32 " of %" PRIu16 " open presorted files"),
                  heap_count, open_count));

        /* exit this while() once we are only processing a single
         * file */
        while (heap_count > 1) {
            /* entry at the top of the heap has the lowest key */
            skHeapPeekTop(heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;

            /* write the lowest record */
            if (fp_intermediate) {
                /* we are using the intermediate temp file, so
                 * write the record there. */
                sortTempWrite(fp_intermediate, recs[lowest], node_size);
            } else {
                /* we are not using any temp files, write the
                 * record to the final destination */
                rv = skStreamWriteRecord(out_stream, (rwRec*)recs[lowest]);
                if (0 != rv) {
                    skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                    if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                        appExit(EXIT_FAILURE);
                    }
                }
            }

            /* replace the record we just wrote */
            if (fillRecordAndKey(stream[lowest], recs[lowest])) {
                /* read was successful.  "insert" the new entry into
                 * the heap (which has same value as old entry). */
                skHeapReplaceTop(heap, &lowest, NULL);
            } else {
                /* no more data for this file; remove it from the
                 * heap */
                skHeapExtractTop(heap, NULL);
                --heap_count;
                TRACEMSG(("Finished reading records from file #%u;"
                          " %" PRIu32 " files remain",
                          lowest, heap_count));
            }
        }

        /* read records from the remaining file */
        if (SKHEAP_OK == skHeapExtractTop(heap, &lowest)) {
            if (fp_intermediate) {
                do {
                    sortTempWrite(fp_intermediate, recs[lowest], node_size);
                } while (fillRecordAndKey(stream[lowest], recs[lowest]));
            } else {
                do {
                    rv = skStreamWriteRecord(out_stream, (rwRec*)recs[lowest]);
                    if (0 != rv) {
                        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                        if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                            appExit(EXIT_FAILURE);
                        }
                    }
                } while (fillRecordAndKey(stream[lowest], recs[lowest]));
            }
            TRACEMSG(("Finished reading records from file #%u; 0 files remain",
                      lowest));
        }

        /* Close the input files that we processed this time. */
        for (i = 0; i < open_count; ++i) {
            skStreamDestroy(&stream[i]);
        }

        /* Close the intermediate temp file. */
        if (fp_intermediate) {
            sortTempClose(fp_intermediate);
            fp_intermediate = NULL;
        }
    } while (!opened_all_inputs);

    skHeapFree(heap);

    /* If any temporary files were written, we now have to merge-sort
     * them */
    return temp_file_idx;
}


/*
 *  int = sortRandom();
 *
 *    Don't make any assumptions about the input.  Store the input
 *    records in a large buffer, and sort those in-core records once
 *    all records are processed or the buffer is full.  If the buffer
 *    fills up, store the sorted records into temporary files.  Once
 *    all records are read, use mergeFiles() above to merge-sort the
 *    temporary files.
 *
 *    Exits the application if an error occurs.  On success, this
 *    function returns the index of the final temporary file to use
 *    for the mergeSort().  A return value less than 0 is considered
 *    successful and indicates that no merge-sort is required.
 */
static int
sortRandom(
    void)
{
    int temp_file_idx = -1;
    skstream_t *input_stream;       /* input stream */
    uint8_t *record_buffer = NULL;  /* Region of memory for records */
    uint8_t *cur_node = NULL;       /* Ptr into record_buffer */
    size_t buffer_max_recs;         /* max buffer size (in number of recs) */
    size_t buffer_recs;             /* current buffer size (# records) */
    size_t buffer_chunk_recs;       /* how to grow from current to max buf */
    size_t num_chunks;              /* how quickly to grow buffer */
    size_t record_count = 0;        /* Number of records read */
    int rv;

    /* Determine the maximum number of records that will fit into the
     * buffer if it grows the maximum size */
    buffer_max_recs = sort_buffer_size / node_size;
    TRACEMSG((("sort_buffer_size = %" SK_PRIuZ
               "\nnode_size = %" SK_PRIuZ
               "\nbuffer_max_recs = %" SK_PRIuZ),
              sort_buffer_size, node_size, buffer_max_recs));

    /* We will grow to the maximum size in chunks; do not allocate
     * more than MAX_CHUNK_SIZE at any time */
    num_chunks = NUM_CHUNKS;
    if (num_chunks < 1) {
        num_chunks = 1;
    }
    if (sort_buffer_size / num_chunks > MAX_CHUNK_SIZE) {
        num_chunks = sort_buffer_size / MAX_CHUNK_SIZE;
    }

    /* Attempt to allocate the initial chunk.  If we fail, increment
     * the number of chunks---which will decrease the amount we
     * attempt to allocate at once---and try again. */
    for (;;) {
        buffer_chunk_recs = buffer_max_recs / num_chunks;
        TRACEMSG((("num_chunks = %" SK_PRIuZ
                   "\nbuffer_chunk_recs = %" SK_PRIuZ),
                  num_chunks, buffer_chunk_recs));

        record_buffer = (uint8_t*)calloc(buffer_chunk_recs, node_size);
        if (record_buffer) {
            /* malloc was successful */
            break;
        } else if (buffer_chunk_recs < MIN_IN_CORE_RECORDS) {
            /* give up at this point */
            skAppPrintErr("Error allocating space for %d records",
                          MIN_IN_CORE_RECORDS);
            appExit(EXIT_FAILURE);
        } else {
            /* reduce the amount we allocate at once by increasing the
             * number of chunks and try again */
            TRACEMSG(("malloc() failed"));
            ++num_chunks;
        }
    }

    buffer_recs = buffer_chunk_recs;
    TRACEMSG((("buffer_recs = %" SK_PRIuZ), buffer_recs));

    /* open first file */
    rv = appNextInput(&input_stream);
    if (rv) {
        free(record_buffer);
        if (1 == rv) {
            return temp_file_idx;
        }
        appExit(EXIT_FAILURE);
    }

    record_count = 0;
    cur_node = record_buffer;
    while (input_stream != NULL) {
        /* read record */
        rv = fillRecordAndKey(input_stream, cur_node);
        if (rv == 0) {
            /* close current and open next */
            skStreamDestroy(&input_stream);
            rv = appNextInput(&input_stream);
            if (rv < 0) {
                /* processing these input files one at a time, so we
                 * will not hit the EMFILE limit here */
                free(record_buffer);
                appExit(EXIT_FAILURE);
            }
            continue;
        }

        ++record_count;
        cur_node += node_size;

        if (record_count == buffer_recs) {
            /* Filled the current buffer */

            /* If buffer not at max size, see if we can grow it */
            if (buffer_recs < buffer_max_recs) {
                uint8_t *old_buf = record_buffer;

                /* add a chunk of records.  if we are near the max,
                 * set the size to the max */
                buffer_recs += buffer_chunk_recs;
                if (buffer_recs + buffer_chunk_recs > buffer_max_recs) {
                    buffer_recs = buffer_max_recs;
                }
                TRACEMSG((("Buffer full--attempt to grow to %" SK_PRIuZ
                           " records, %" SK_PRIuZ " bytes"),
                          buffer_recs, node_size * buffer_recs));

                /* attempt to grow */
                record_buffer = (uint8_t*)realloc(record_buffer,
                                                  node_size * buffer_recs);
                if (record_buffer) {
                    /* Success, make certain cur_node points into the
                     * new buffer */
                    cur_node = (record_buffer + (record_count * node_size));
                } else {
                    /* Unable to grow it */
                    TRACEMSG(("realloc() failed"));
                    record_buffer = old_buf;
                    buffer_max_recs = buffer_recs = record_count;
                }
            }

            /* Either buffer at maximum size or attempt to grow it
             * failed. */
            if (record_count == buffer_max_recs) {
                /* Sort */
                TRACEMSG(("Sorting %" SK_PRIuZ " records...", record_count));
                skQSort(record_buffer, record_count, node_size, &rwrecCompare);
                TRACEMSG(("Sorting %" SK_PRIuZ " records...done",
                          record_count));

                /* Write to temp file */
                sortTempWriteBuffer(&temp_file_idx, record_buffer,
                                    node_size, record_count);

                /* Reset record buffer to 'empty' */
                record_count = 0;
                cur_node = record_buffer;
            }
        }
    }

    /* Sort (and maybe store) last batch of records */
    if (record_count > 0) {
        TRACEMSG(("Sorting %" SK_PRIuZ " records...", record_count));
        skQSort(record_buffer, record_count, node_size, &rwrecCompare);
        TRACEMSG(("Sorting %" SK_PRIuZ " records...done", record_count));

        if (temp_file_idx >= 0) {
            /* Write last batch to temp file */
            sortTempWriteBuffer(&temp_file_idx, record_buffer,
                                node_size, record_count);
        }
    }

    /* Generate the output */

    if (record_count > 0 && temp_file_idx == -1) {
        /* No temp files written, just output batch of records */
        size_t c;

        TRACEMSG((("Writing %" SK_PRIuZ " records to '%s'"),
                  record_count, skStreamGetPathname(out_stream)));
        for (c = 0, cur_node = record_buffer;
             c < record_count;
             ++c, cur_node += node_size)
        {
            rv = skStreamWriteRecord(out_stream, (rwRec*)cur_node);
            if (0 != rv) {
                skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                    free(record_buffer);
                    appExit(EXIT_FAILURE);
                }
            }
        }
    }
    /* else a merge sort is required; which gets invoked from main() */

    if (record_buffer) {
        free(record_buffer);
    }

    return temp_file_idx;
}


int main(int argc, char **argv)
{
    int temp_idx = -1;
    int rv;

    appSetup(argc, argv);                 /* never returns on error */

    if (presorted_input) {
        temp_idx = sortPresorted();
    } else {
        temp_idx = sortRandom();
    }
    if (temp_idx >= 0) {
        mergeFiles(temp_idx);
    }

    if (skStreamGetRecordCount(out_stream) == 0) {
        /* No records were read at all; write the header to the output
         * file */
        rv = skStreamWriteSilkHeader(out_stream);
        if (0 != rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
    }

    /* close the file */
    if ((rv = skStreamClose(out_stream))
        || (rv = skStreamDestroy(&out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        appExit(EXIT_FAILURE);
    }
    out_stream = NULL;

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
