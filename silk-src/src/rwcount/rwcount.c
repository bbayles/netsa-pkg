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
 *  rwcount.c
 *
 *    This is a counting application; given the records read from
 *    stdin or named files, it generates counting results for the time
 *    period covered.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcount.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwcount.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* Where to write filenames if --print-file specified */
#define PRINT_FILENAMES_FH  stderr

/* Number of milliseconds in a day */
#define DAY_MILLISEC 86400000

/* Minimum number of bins.  If we cannot allocate this many, give up */
#define BIN_COUNT_MIN 4096

/* Standard number of bins to allocate: 2 million, about enough for a
 * month's worth of one second bins */
#define BIN_COUNT_STD (1 << 21)

/* Maximum possible number of bins */
#define BIN_COUNT_MAX ((uint64_t)(SIZE_MAX / sizeof(count_bin_t)))

/* Convert the sktime_t 'gb_t' to an array index; does not check array
 * bounds; uses the global 'bins' variable. */
#define GET_BIN(gb_t)                                           \
    ((size_t)(((gb_t) - bins.window_min) / bins.size))

/* This macro is TRUE if the time 'toor_t' is too large (or too small)
 * to fit into the current time window; uses the global 'bins' */
#define TIME_OUT_OF_RANGE(toor_t)               \
    (((toor_t) < bins.window_min)               \
     || ((toor_t) >= bins.window_max))

/* This macro is true if the flow whose start time is 'ign_s' and end
 * time is 'ign_e' is outside the range the user is interested in;
 * uses the global 'bins' variable */
#define IGNORE_FLOW(ign_s, ign_e)               \
    (((ign_e) < (bins.start_time))              \
     || ((ign_s) >= (bins.end_time)))


/* EXPORTED VARIABLES */

count_data_t bins;

count_flags_t flags;

sk_options_ctx_t *optctx;


/* FUNCTION DEFINITIONS */

/*
 *  status = initBins(start_time);
 *
 *    Allocates time bins based on an initial 'start_time'.
 *
 *    Returns 0 on success, or -1 for failure.
 */
static int
initBins(
    sktime_t            start_time)
{
    sktime_t end_time;
    uint64_t bin_count;

    /* do not call twice */
    if (bins.data) {
        return 0;
    }

    /* If start_time and end_time are given, do a single allocation
     * to cover the entire range, or fail */
    if ((bins.start_time != RWCO_UNINIT_START)
        && (bins.end_time != RWCO_UNINIT_END))
    {
        assert(bins.end_time >= bins.start_time + bins.size);
        bin_count = ((bins.end_time - bins.start_time) / bins.size);
        /* We should have made end_time fall on a bin boundary when we
         * parsed the user's values */
        assert(bin_count > 0);
        assert((bins.start_time + (sktime_t)(bins.size * bin_count))
               == bins.end_time);
        if (bin_count > BIN_COUNT_MAX) {
            return -1;
        }

        /* Allocate */
        bins.data = (count_bin_t*)calloc(bin_count, sizeof(count_bin_t));
        if (NULL == bins.data) {
            return -1;
        }

        bins.window_min = bins.start_time;
        bins.window_max = bins.end_time;
        bins.count = bin_count;

        return 0;
    }

    /* If the user specified the start_time (but not end_time), use
     * the start_time unconditionally.  Note that this may cause
     * memory problems later if the user's start_time is much earlier
     * than the times on the records she is reading.  Otherwise, set
     * the start_time to something "a bit" earlier than the given
     * start_time, where "a bit" depends on the bin size. */
    if (bins.start_time != RWCO_UNINIT_START) {
        /* set it unconditionally */
        start_time = bins.start_time;
    } else if (bins.size < 1000) {
        /* Move 'start_time' to the start of today */
        start_time = start_time - (start_time % DAY_MILLISEC);
    } else if (bins.size > DAY_MILLISEC) {
        /* Move 'start_time' to last week */
        start_time = (start_time - (start_time % DAY_MILLISEC)
                      - 7 * DAY_MILLISEC);
    } else {
        /* Move 'start_time' to the start of the day before yesterday */
        start_time = (start_time - (start_time % DAY_MILLISEC)
                      - (2 * DAY_MILLISEC));
    }

    if (bins.end_time != RWCO_UNINIT_END) {
        /* When end_time is set but start_time is not, modify the
         * start_time so the end epoch matches exactly */
        end_time = bins.end_time;
        bin_count = 1 + ((end_time - start_time) / bins.size);
        start_time = end_time - bins.size * bin_count;
    } else {
        bin_count = BIN_COUNT_STD;
    }

    /* do not allocate more bins than the maximum */
    if (bin_count > BIN_COUNT_MAX) {
        bin_count = BIN_COUNT_MAX;
    }

    /* Allocate */
    while (NULL == (bins.data = (count_bin_t*)calloc((size_t)bin_count,
                                                     sizeof(count_bin_t))))
    {
        if (bin_count <= BIN_COUNT_MIN) {
            return -1;
        }
        bin_count /= 2;
    }

    bins.window_min = start_time;
    bins.window_max = (sktime_t)start_time + bin_count * bins.size;
    bins.count = bin_count;

    return 0;
}


/*
 *  reallocBins(time);
 *
 *    Reallocate memory for the bins so that the bins will hold 'time'.
 *
 *    Exits application if realloc fails.
 */
static void
reallocBins(
    sktime_t            t)
{
    count_bin_t *new_ptr;
    uint64_t extension_bins;
    uint64_t new_count;
    sktime_t new_window_min;

    assert(TIME_OUT_OF_RANGE(t));

    /* Always extend the rear of array, no matter which end we
     * actually overflow on.  Afterwards, we'll check if it's the
     * front, and shift data around. */

    if (t < bins.window_min) {
        /* To extend front, we want to add enough room to cover the
         * time we're trying to insert. */
        extension_bins = 1 + (bins.window_min - t) / bins.size;
        if (extension_bins < BIN_COUNT_STD) {
            new_count = bins.count + BIN_COUNT_STD;
        } else {
            new_count = bins.count + extension_bins;
        }
        new_window_min = (bins.window_min
                          - ((new_count - bins.count) * bins.size));
    } else {
        /* To extend rear, we want to add enough room to cover the
         * time we're trying to insert, plus an additional 30 days.
         * Slightly different calc since we don't have the
         * window_max. */
        extension_bins = 1 + (t - bins.window_max) / bins.size;
        if (extension_bins < BIN_COUNT_STD) {
            new_count = bins.count + BIN_COUNT_STD;
        } else {
            new_count = bins.count + extension_bins;
        }
        new_window_min = bins.window_min;
    }

    /* When end_time is set, adjust the bin count so it doesn't go
     * beyond the end_time */
    if ((bins.end_time != RWCO_UNINIT_END)
        && (new_window_min + (sktime_t)(bins.size * new_count)) >bins.end_time)
    {
        new_count = 1 + (bins.end_time - new_window_min) / bins.size;
    }

    if (new_count > BIN_COUNT_MAX) {
        new_count = BIN_COUNT_MAX;
        if (new_count - bins.count < extension_bins) {
            goto MEM_FAILURE;
        }
    }

    /* Allocate */
    while (NULL == (new_ptr = (count_bin_t*)realloc(
                        bins.data, (new_count * sizeof(count_bin_t)))))
    {
        if (new_count == bins.count + extension_bins) {
            goto MEM_FAILURE;
        }
        /* reduce the growth factor by 2 */
        new_count -= (new_count - bins.count) / 2;
        if (new_count < (bins.count + extension_bins)) {
            new_count = bins.count + extension_bins;
        }
    }

    /* Compute the number of bins we actually added */
    extension_bins = new_count - bins.count;

    if (t < bins.window_min) {
        /* Shift the data so that the newly allocated empty space is
         * at the front of the array. */
        memmove((new_ptr + extension_bins), new_ptr,
                (bins.count * sizeof(count_bin_t)));
        /* Clear the space that we just moved the data out of */
        memset(new_ptr, 0, (extension_bins * sizeof(count_bin_t)));
    } else {
        /* Clear the newly allocated space */
        memset((new_ptr+bins.count), 0, (extension_bins*sizeof(count_bin_t)));
    }

    /* Adjust the values */
    bins.count = new_count;
    bins.window_min = new_window_min;
    bins.window_max = bins.window_min + bins.size * bins.count;
    bins.data = new_ptr;

    return;

  MEM_FAILURE:
    {
        char buf[SKTIMESTAMP_STRLEN];
        skAppPrintErr(("Cannot allocate %" PRId64 " bins required to hold\n"
                       "\tdata from %s to %s"),
                      extension_bins, sktimestamp_r(buf, new_window_min, 0),
                      sktimestamp(new_window_min + bins.size * new_count, 0));
#if 0
/*
**      if (bins.start_time == RWCO_UNINIT_START) {
**          fprintf(stderr, "\tstart_time:      %20s\n", "DEFAULT");
**      } else {
**          fprintf(stderr, "\tstart_time:      %20" PRId64 " (%s)\n",
**                  (int64_t)bins.start_time,sktimestamp(bins.start_time,0));
**      }
**      if (bins.end_time == RWCO_UNINIT_END) {
**          fprintf(stderr, "\tend_time:        %20s\n", "DEFAULT");
**      } else {
**          fprintf(stderr, "\tend_time:        %20" PRId64 " (%s)\n",
**                  (int64_t)bins.end_time, sktimestamp(bins.end_time, 0));
**      }
**      fprintf(stderr, "\twindow_min:      %20" PRId64 " (%s)\n",
**              (int64_t)bins.window_min, sktimestamp(bins.window_min, 0));
**      fprintf(stderr, "\twindow_max:      %20" PRId64 " (%s)\n",
**              (int64_t)bins.window_max, sktimestamp(bins.window_max, 0));
**      fprintf(stderr, "\tend time (calc): %20" PRId64 " (%s)\n",
**              (int64_t)(bins.window_min + (bins.count * bins.size)),
**              sktimestamp(bins.window_min + (bins.count * bins.size), 0));
**
**      fprintf(stderr, ("\tbin size (ms):   %20" PRId64 "\n"
**                       "\ttotal bins:      %20" PRId64 "\n"),
**              bins.size, bins.count);
*/
#endif
        exit(EXIT_FAILURE);
    }
}


/*
 *  startAdd(rwrec);
 *
 *    Add the record and its byte and packet counts to the first bin
 *    relevant to the record.
 */
static void
startAdd(
    const rwRec        *rwrec)
{
    uint64_t bin;
    sktime_t t = rwRecGetStartTime(rwrec);

    if (IGNORE_FLOW(t, t)) {
        /* user not interested in this flow */
        return;
    }

    if (TIME_OUT_OF_RANGE(t)) {
        reallocBins(t);
    }
    bin = GET_BIN(t);
    bins.data[bin].flows++;
    bins.data[bin].bytes += rwRecGetBytes(rwrec);
    bins.data[bin].pkts += rwRecGetPkts(rwrec);
}


/*
 *  endAdd(rwrec);
 *
 *    Add the record and its byte and packet counts to the final bin
 *    relevant to the record.
 */
static void
endAdd(
    const rwRec        *rwrec)
{
    uint64_t bin;
    sktime_t t = rwRecGetEndTime(rwrec);

    if (IGNORE_FLOW(t, t)) {
        /* user not interested in this flow */
        return;
    }

    if (TIME_OUT_OF_RANGE(t)) {
        reallocBins(t);
    }
    bin = GET_BIN(t);
    bins.data[bin].flows++;
    bins.data[bin].bytes += rwRecGetBytes(rwrec);
    bins.data[bin].pkts += rwRecGetPkts(rwrec);
}


/*
 *  middleAdd(rwrec);
 *
 *    Add the record and its byte and packet counts to the middle bin
 *    relevant to the flow.
 */
static void
middleAdd(
    const rwRec        *rwrec)
{
    uint64_t bin;
    sktime_t t = rwRecGetStartTime(rwrec) + (rwRecGetElapsed(rwrec) / 2);

    if (IGNORE_FLOW(t, t)) {
        /* user not interested in this flow */
        return;
    }

    if (TIME_OUT_OF_RANGE(t)) {
        reallocBins(t);
    }
    bin = GET_BIN(t);
    bins.data[bin].flows++;
    bins.data[bin].bytes += rwRecGetBytes(rwrec);
    bins.data[bin].pkts += rwRecGetPkts(rwrec);
}


/*
 *  meanAdd(rwrec);
 *
 *    Equally distribute the record among all the BINs by adding the
 *    mean of the bytes and packets to each bin.  Note that a
 *    particularly placed 32 second record will be equally distributed
 *    among three 30 second bins.
 */
static void
meanAdd(
    const rwRec        *rwrec)
{
    uint64_t start_bin, end_bin, i;
    uint64_t extra_bins = 0;
    sktime_t sTime = rwRecGetStartTime(rwrec);
    sktime_t eTime = rwRecGetEndTime(rwrec);
    double flows, bytes, pkts;

    if (IGNORE_FLOW(sTime, eTime)) {
        /* user not interested in this flow */
        return;
    }

    if (sTime < bins.start_time) {
        /* the flow started before the time we care about. Increase
         * 'extra_bins' by the number of bins the flow covers before
         * the start_time (==window_min).  To compute 'extra_bins',
         * expand the GET_BIN() macro but reverse the times. */
        start_bin = 0;
        extra_bins += 1 + ((bins.window_min - sTime) / bins.size);
    } else {
        /* maybe grow the bins to allow for the start time */
        if (TIME_OUT_OF_RANGE(sTime)) {
            reallocBins(sTime);
        }
        start_bin = GET_BIN(sTime);
    }

    /* find the ending bin, reallocating the bins if needed */
    if (eTime >= bins.end_time) {
        /* set 'end_bin' to the final bin.  Increase 'extra_bins' by
         * the bins beyond the time window. */
        end_bin = bins.count - 1;
        extra_bins += 1 + ((eTime - bins.window_max) / bins.size);
    } else {
        if (TIME_OUT_OF_RANGE(eTime)) {
            reallocBins(eTime);
        }
        end_bin = GET_BIN(eTime);
    }

    assert(start_bin <= end_bin);
    assert(end_bin < bins.count);

    if ((start_bin == end_bin) && (0 == extra_bins)) {
        /* handle simple case where everything is in one bin */
        bins.data[start_bin].flows++;
        bins.data[start_bin].bytes += rwRecGetBytes(rwrec);
        bins.data[start_bin].pkts += rwRecGetPkts(rwrec);
        return;
    }

    /*
     * Compute the amount of the flow to allocate to each bin.
     * Logically, this value is 1/number-of-bins which is given by the
     * following:
     *
     *     1 / (end_bin - start_bin + extra_bins + 1)
     */
    flows = (1.0 / ((double)(end_bin - start_bin + extra_bins + 1.0)));
    bytes = (double)rwRecGetBytes(rwrec) * flows;
    pkts = (double)rwRecGetPkts(rwrec) * flows;

    for (i = start_bin; i <= end_bin; ++i) {
        bins.data[i].flows += flows;
        bins.data[i].bytes += bytes;
        bins.data[i].pkts += pkts;
    }
}


/*
 *  durationAdd(rwrec);
 *
 *    Divide the flow evenly across each millisecond in the flow, and
 *    then apply that value to each bin according to the number of
 *    millisecond the flow spent in that bin.
 */
static void
durationAdd(
    const rwRec        *rwrec)
{
    uint64_t start_bin, end_bin, i;
    sktime_t sTime = rwRecGetStartTime(rwrec);
    sktime_t eTime = rwRecGetEndTime(rwrec);
    double flows, bytes, pkts;
    double ratio;

    if (IGNORE_FLOW(sTime, eTime)) {
        /* user not interested in this flow */
        return;
    }

    /* find the starting bin, reallocating the bins if needed */
    if (sTime < bins.start_time) {
        /* flow started before the time we care about */
        start_bin = 0;
    } else {
        if (TIME_OUT_OF_RANGE(sTime)) {
            reallocBins(sTime);
        }
        start_bin = GET_BIN(sTime);
    }

    /* find the ending bin, reallocating the bins if needed */
    if (eTime >= bins.end_time) {
        /* put end_bin beyond end of array */
        end_bin = GET_BIN(bins.window_max);
    } else {
        if (TIME_OUT_OF_RANGE(eTime)) {
            reallocBins(eTime);
        }
        end_bin = GET_BIN(eTime);
    }

    /* handle the simple case where everything is in one bin */
    if ((start_bin == end_bin)
        && (sTime >= bins.start_time)
        && (eTime < bins.end_time))
    {
        bins.data[start_bin].flows++;
        bins.data[start_bin].bytes += rwRecGetBytes(rwrec);
        bins.data[start_bin].pkts += rwRecGetPkts(rwrec);
        return;
    }

    /* calculate the amount of data in a fully covered bin by
     * calculating the data per millisecond and multiplying that by
     * the bin size */
    flows = (double)bins.size / (double)(1 + eTime - sTime);
    bytes = (double)rwRecGetBytes(rwrec) * flows;
    pkts = (double)rwRecGetPkts(rwrec) * flows;


    if (sTime >= bins.start_time) {
        /* handle the part of the flow that partially occurs in the
         * start_bin: find the "floating point" start bin, subtract
         * the "integer" start_bin from that, and then subtract that
         * fraction from 1:
         *
         * r = 1.0 - (((sTime - window_min) / bin_size) - start_bin)
         */
        ratio = ((double)start_bin + 1.0
                 - ((double)(sTime - bins.window_min) / (double)bins.size));
        bins.data[start_bin].flows += ratio * flows;
        bins.data[start_bin].bytes += ratio * bytes;
        bins.data[start_bin].pkts += ratio * pkts;

        /* move start_bin to first complete bin */
        ++start_bin;
    }

    if (eTime < bins.end_time) {
        /* handle the part of the flow that partially occurs in the
         * end_bin: calculation is similar to that for start_bin.  Add
         * a millisecond here since at least part of the flow must be
         * active in this bin. */
        ratio = (((double)(eTime + 1 - bins.window_min) / (double)bins.size)
                 - (double)(end_bin));
        bins.data[end_bin].flows += ratio * flows;
        bins.data[end_bin].bytes += ratio * bytes;
        bins.data[end_bin].pkts += ratio * pkts;

        /* don't move end_bin; we'll stop when we get to it */
    }

    if (start_bin == end_bin) {
        /* flow started and ended in adjacent bins */
        return;
    }

    /* Handle the bins that had complete coverage */
    for (i = start_bin; i < end_bin; ++i) {
        bins.data[i].flows += flows;
        bins.data[i].bytes += bytes;
        bins.data[i].pkts += pkts;
    }
}


/*
 *  maximumAdd(rwrec);
 *
 *    Add the flow record and its complete packet and byte count to
 *    EVERY bin where the flow is active.  This will allow one to see
 *    the number of records active during any one time window and the
 *    maximum possible byte and packet counts for each bin.
 */
static void
maximumAdd(
    const rwRec        *rwrec)
{
    uint64_t start_bin, end_bin, i;
    sktime_t sTime = rwRecGetStartTime(rwrec);
    sktime_t eTime = rwRecGetEndTime(rwrec);

    if (IGNORE_FLOW(sTime, eTime)) {
        /* user not interested in this flow */
        return;
    }

    if (sTime < bins.start_time) {
        /* the flow started before the time we care about. */
        start_bin = 0;
    } else {
        /* maybe grow the bins to allow for the start time */
        if (TIME_OUT_OF_RANGE(sTime)) {
            reallocBins(sTime);
        }
        start_bin = GET_BIN(sTime);
    }

    /* find the ending bin, reallocating the bins if needed */
    if (eTime >= bins.end_time) {
        /* flow ended after the time we care about. */
        end_bin = bins.count - 1;
    } else {
        if (TIME_OUT_OF_RANGE(eTime)) {
            reallocBins(eTime);
        }
        end_bin = GET_BIN(eTime);
    }

    assert(start_bin <= end_bin);
    assert(end_bin < bins.count);

    /* add everything to all bins */
    for (i = start_bin; i <= end_bin; ++i) {
        bins.data[i].flows++;
        bins.data[i].bytes += rwRecGetBytes(rwrec);
        bins.data[i].pkts += rwRecGetPkts(rwrec);
    }
}


/*
 *  minimumAdd(rwrec);
 *
 *    Add the flow record to EVERY bin where it is active.  Only add
 *    the flow's packet and byte counts to a bin if the flow is
 *    completely contained within a bin.  This will allow one to see
 *    the number of records active during any one time window and the
 *    minimum possible byte and packet counts for each bin.
 */
static void
minimumAdd(
    const rwRec        *rwrec)
{
    uint64_t start_bin, end_bin, i;
    sktime_t sTime = rwRecGetStartTime(rwrec);
    sktime_t eTime = rwRecGetEndTime(rwrec);

    if (IGNORE_FLOW(sTime, eTime)) {
        /* user not interested in this flow */
        return;
    }

    if (sTime < bins.start_time) {
        /* the flow started before the time we care about. */
        start_bin = 0;
    } else {
        /* maybe grow the bins to allow for the start time */
        if (TIME_OUT_OF_RANGE(sTime)) {
            reallocBins(sTime);
        }
        start_bin = GET_BIN(sTime);
    }

    /* find the ending bin, reallocating the bins if needed */
    if (eTime >= bins.end_time) {
        /* flow ended after the time we care about. */
        end_bin = bins.count - 1;
    } else {
        if (TIME_OUT_OF_RANGE(eTime)) {
            reallocBins(eTime);
        }
        end_bin = GET_BIN(eTime);
    }

    assert(start_bin <= end_bin);
    assert(end_bin < bins.count);

    /* handle the simple case where everything is in one bin */
    if ((start_bin == end_bin)
        && (sTime >= bins.start_time)
        && (eTime < bins.end_time))
    {
        bins.data[start_bin].flows++;
        bins.data[start_bin].bytes += rwRecGetBytes(rwrec);
        bins.data[start_bin].pkts += rwRecGetPkts(rwrec);
        return;
    }

    /* add the flow to every bin; ignore bytes and packets, since flow
     * spans multiple bins */
    for (i = start_bin; i <= end_bin; ++i) {
        bins.data[i].flows++;
    }
}


/*
 *  ok = countFile(stream);
 *
 *    Process the records in 'stream'.  Return 0 on success, or
 *    non-zero on error reading the file.
 */
static int
countFile(
    skstream_t         *stream)
{
    /* protect initBins from multiple calls */
    static int initialized = 0;
    rwRec rwrec;
    int rv = 0;

    /* initialize bins if necessary */
    if (!initialized) {
        initialized = 1;
        rv = skStreamReadRecord(stream, &rwrec);
        if (rv) {
            goto END;
        }
        if (initBins(rwRecGetStartTime(&rwrec))) {
            skAppPrintErr("Cannot allocate space for bins. "
                          "Try a larger bin size or fewer records");
            return 1;
        }
        switch (flags.load_scheme) {
          case LOAD_START:
            startAdd(&rwrec);
            break;
          case LOAD_END:
            endAdd(&rwrec);
            break;
          case LOAD_MIDDLE:
            middleAdd(&rwrec);
            break;
          case LOAD_MEAN:
            meanAdd(&rwrec);
            break;
          case LOAD_DURATION:
            durationAdd(&rwrec);
            break;
          case LOAD_MAXIMUM:
            maximumAdd(&rwrec);
            break;
          case LOAD_MINIMUM:
            minimumAdd(&rwrec);
            break;
        }
    }

    switch (flags.load_scheme) {
      case LOAD_START:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            startAdd(&rwrec);
        }
        break;
      case LOAD_END:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            endAdd(&rwrec);
        }
        break;
      case LOAD_MIDDLE:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            middleAdd(&rwrec);
        }
        break;
      case LOAD_MEAN:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            meanAdd(&rwrec);
        }
        break;
      case LOAD_DURATION:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            durationAdd(&rwrec);
        }
        break;
      case LOAD_MAXIMUM:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            maximumAdd(&rwrec);
        }
        break;
      case LOAD_MINIMUM:
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            minimumAdd(&rwrec);
        }
        break;
    }

  END:
    if (rv == SKSTREAM_ERR_EOF) {
        rv = 0;
    } else {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
    }
    return rv;
}


/*
 *  printBins(output_fh);
 *
 *    Print the contents of the bins to 'output_fh'.
 */
static void
printBins(
    FILE               *output_fh)
{
#define FMT_VALUE "%*s%c%*.2f%c%*.2f%c%*.2f%s\n"
#define FMT_TITLE "%*s%c%*s%c%*s%c%*s%s\n"
#define FMT_WIDTH {23, 15, 20, 17}

    int w[] = FMT_WIDTH;
    uint64_t i;
    uint64_t start_bin = 0;
    uint64_t end_bin = 0;
    char buffer[128];
    sktime_t cur_time = 0;
    char final_delim[] = {'\0', '\0'};

    buffer[0] = '\0';

    /* set up final delimiter */
    if ( !flags.no_final_delimiter ) {
        final_delim[0] = flags.delimiter;
    }

    if (0 == (bins.size % 1000)) {
        flags.timeflags |= SKTIMESTAMP_NOMSEC;
        /* adjust column width */
        w[0] -= 4;
    }

    /* set column widths */
    if (flags.no_columns) {
        memset(w, 0, sizeof(w));
    }

    /* print the titles */
    if ( !flags.no_titles ) {
        fprintf(output_fh, FMT_TITLE,
                w[0], "Date",    flags.delimiter,
                w[1], "Records", flags.delimiter,
                w[2], "Bytes",   flags.delimiter,
                w[3], "Packets", final_delim);
    }

    /* Protect ourselves against no data. */
    if (bins.size == 0 || bins.count == 0 || bins.data == NULL) {
        return;
    }

    /*
     * Determine where to start the output based on the start_time
     * value.  If given an explicit start_time, use that, otherwise
     * skip all initial bins that have no counts.
     */
    if (bins.start_time == RWCO_UNINIT_START) {
        /* No start_time given; find first bin with non-zero byte
         * count. */
        for (start_bin = 0; start_bin < bins.count; ++start_bin) {
            if (bins.data[start_bin].bytes > 0.0) {
                break;
            }
        }
        if (start_bin == bins.count) {
            /* no data? */
            return;
        }

#if 0
        /* The following branch of the "if" never gets called since we
         * set the window_min to the start_time, but leave this here
         * in case we ever decide to change that behavior. */
    } else if (bins.start_time < bins.window_min) {
        /* User wants to start the data before the first bin.  If
         * skip-zeroes is not active, print zero's until we get to the
         * first bin. */
        uint64_t negative_bins;

        start_bin = 0;

        if (flags.skip_zeroes == 0) {
            negative_bins = 1 + (bins.window_min - bins.start_time)/bins.size;
            cur_time = (sktime_t)bins.window_min - (negative_bins * bins.size);

            for (i = 0; i < negative_bins; ++i, cur_time += bins.size) {
                /* figure out the row label */
                if (flags.label_index) {
                    snprintf(buffer, sizeof(buffer), "-%u",
                             (negative_bins - i));
                } else {
                    sktimestamp_r(buffer, cur_time, flags.timeflags);
                }
                fprintf(output_fh, FMT_VALUE,
                        w[0], buffer, flags.delimiter,
                        w[1], 0.0, flags.delimiter,
                        w[2], 0.0, flags.delimiter,
                        w[3], 0.0, final_delim);
            }
        }
#endif /* 0 */
    } else if (bins.start_time
               >= bins.window_min + (sktime_t)(bins.size * bins.count))
    {
        /* User's starting time is greater than the times for which we
         * have data. */
        skAppPrintErr("Epoch start time > time on final record.");
        return;
    } else {
        start_bin = (bins.start_time - bins.window_min) / bins.size;
    }

    /* If end_time is set and count includes it, use it as the
     * final bin */
    if ((bins.end_time != RWCO_UNINIT_END)
        && (bins.window_max >= bins.end_time))
    {
        end_bin = (bins.end_time - bins.window_min) / bins.size;
    } else {
        /* Travel backward from the end to find the final bin that has
         * data. */
        for (end_bin = (bins.count - 1); end_bin > start_bin; --end_bin) {
            if (bins.data[end_bin].bytes > 0.0) {
                break;
            }
        }
        /* add one since we use < in the for loop */
        ++end_bin;
    }

    cur_time = (sktime_t)bins.window_min + (start_bin * bins.size);

    for (i = start_bin; i < end_bin; ++i, cur_time += bins.size) {
        if ((bins.data[i].flows > 0)
            || (flags.skip_zeroes == 0))
        {
            /* figure out the row label */
            if (flags.label_index) {
                snprintf(buffer, sizeof(buffer), ("%" PRIu64), i);
            } else {
                sktimestamp_r(buffer, cur_time, flags.timeflags);
            }
            fprintf(output_fh, FMT_VALUE,
                    w[0], buffer, flags.delimiter,
                    w[1], bins.data[i].flows, flags.delimiter,
                    w[2], bins.data[i].bytes, flags.delimiter,
                    w[3], bins.data[i].pkts, final_delim);
        }
    }

    /* if end epoch was given and skip-zeros is not active, print rows
     * until we reach end_time */
    if (!flags.skip_zeroes && (bins.end_time != RWCO_UNINIT_END)) {
        for ( ; cur_time < bins.end_time; ++i, cur_time += bins.size) {
            /* figure out the row label */
            if (flags.label_index) {
                snprintf(buffer, sizeof(buffer), ("%" PRIu64), i);
            } else {
                sktimestamp_r(buffer, cur_time, flags.timeflags);
            }
            fprintf(output_fh, FMT_VALUE,
                    w[0], buffer, flags.delimiter,
                    w[1], 0.0, flags.delimiter,
                    w[2], 0.0, flags.delimiter,
                    w[3], 0.0, final_delim);
        }
    }

#if 0
    {
        if (bins.start_time == RWCO_UNINIT_START) {
            fprintf(stderr, "\tstart_time:      %20s\n", "DEFAULT");
        } else {
            fprintf(stderr, "\tstart_time:      %20" PRId64 " (%s)\n",
                    (int64_t)bins.start_time,sktimestamp(bins.start_time,0));
        }
        if (bins.end_time == RWCO_UNINIT_END) {
            fprintf(stderr, "\tend_time:        %20s\n", "DEFAULT");
        } else {
            fprintf(stderr, "\tend_time:        %20" PRId64 " (%s)\n",
                    (int64_t)bins.end_time, sktimestamp(bins.end_time, 0));
        }
        fprintf(stderr, "\twindow_min:      %20" PRId64 " (%s)\n",
                (int64_t)bins.window_min, sktimestamp(bins.window_min, 0));
        fprintf(stderr, "\twindow_max:      %20" PRId64 " (%s)\n",
                (int64_t)bins.window_max, sktimestamp(bins.window_max, 0));
        fprintf(stderr, "\tend time (calc): %20" PRId64 " (%s)\n",
                (int64_t)(bins.window_min + (bins.count * bins.size)),
                sktimestamp(bins.window_min + (bins.count * bins.size), 0));

        fprintf(stderr, ("\tbin size (ms):   %20" PRId64 "\n"
                         "\ttotal bins:      %20" PRId64 "\n"
                         "\tstart bin:       %20u\n"
                         "\tend bin:         %20u\n"),
                bins.size, bins.count, start_bin, end_bin);
    }
#endif /* 0 */
}


int main(int argc, char ** argv)
{
    skstream_t *stream;
    FILE *stream_out;
    int rv = 0;

    appSetup(argc, argv);

    /* process input */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        rv = countFile(stream);
        skStreamDestroy(&stream);
        if (rv) {
            exit(EXIT_FAILURE);
        }
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* Print the records */
    stream_out = getOutputHandle();
    printBins(stream_out);

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
