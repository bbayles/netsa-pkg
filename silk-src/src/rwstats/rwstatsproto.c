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

#include <silk/silk.h>

RCSIDENT("$SiLK: rwstatsproto.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwstats.h"
#include "interval.h"

/*
**  rwstatsproto.c
**
**  Functions to compute and print statistics by IP protocol.
**
*/



/*
 * Statistics (min, max, quartiles, intervals) for "continuous" values
 * (bytes, packets, bpp) can be computed over all protocols, and the
 * can be broken out for a limited number of specific protocols.  This
 * defines the size of the data structures to hold these statistics.
 * This is one more that the number of specific protocols allowed.
 */

#define NUM_STATS 3
#define BYTE 0
#define PKT 1
#define BPP 2


/* These arrays hold the statistics.  Position 0 is for the
 * combination of all statistics. */
static uint64_t *count; /* record count per protocol */
static uint32_t *minval;
static uint32_t *maxval;
static uint32_t (*intervals)[NUM_INTERVALS];
static uint32_t **interval_defn;

#define MK_IDX(type, idx) ((type) + (NUM_STATS * (idx)))


/* This maps the protocol number to the index in the above statistics
 * arrays.  If the value for a protocol is 0, the user did not request
 * detailed specs on that protocol. */
static int16_t proto_to_stats_idx[256];


/* OPTIONS */

typedef enum {
    OPT_OVERALL_STATS, OPT_DETAIL_PROTO_STATS
} protoStatsOptionsEnum;

static struct option protoStatsOptions[] = {
    {"overall-stats",       NO_ARG,       0, OPT_OVERALL_STATS},
    {"detail-proto-stats",  REQUIRED_ARG, 0, OPT_DETAIL_PROTO_STATS},
    {0,0,0,0}               /* sentinel entry */
};

static const char *protoStatsHelp[] = {
    ("Print minima, maxima, quartiles, and interval-count\n"
     "\tstatistics for bytes, pkts, bytes/pkt across all flows.  Def. No"),
    ("Print above statistics for each of the specified\n"
     "\tprotocols.  List protocols or ranges separated by commas. Def. No"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  protoStatsSetup(void);
static void protoStatsTeardown(void);
static void protoStatsPrintIntervals(int proto_idx, const char *col_title);
static void
protoStatsUpdateStatistics(
    int                 proto_idx,
    const rwRec        *rwrec);


/* FUNCTION DEFINITIONS */

/*
 * parseProtos
 *      Discover which protos the user wants detailed stats for
 * Arguments:
 *      arg -the command line argument
 * Returns:
 *      0 if OK; 1 if error
 * Side Effects:
 *      Sets values in the global proto_to_stats_idx[]
 */
static int
protoStatsParse(
    const char         *arg)
{
    uint32_t i;
    uint32_t parse_count;
    uint32_t *parsed_list;
    int32_t proto_idx = 1; /* 0 is global stats */
    int rv;

    rv = skStringParseNumberList(&parsed_list, &parse_count, arg, 0, 255, 0);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': %s",
                      protoStatsOptions[OPT_DETAIL_PROTO_STATS].name,
                      arg, skStringParseStrerror(rv));
        return 1;
    }

    for (i = 0; i < parse_count; ++i) {
        if (0 != proto_to_stats_idx[parsed_list[i]]) {
            skAppPrintErr(("Duplicate protocol %" PRIu32 " ignored"),
                          parsed_list[i]);
        } else {
            proto_to_stats_idx[parsed_list[i]] = proto_idx;
            ++proto_idx;
        }
    }

    free(parsed_list);
    return 0;
}


static int
protoStatsSetup(
    void)
{
    int proto_idx = 1; /* ALL stats */
    int i, j;

    for (i = 0; i < 256; ++i) {
        if (proto_to_stats_idx[i]) {
            ++proto_idx;
        }
    }

    /* Allocate space for all the stats */
    count = (uint64_t*)calloc(proto_idx, sizeof(uint64_t));
    minval = (uint32_t*)malloc(NUM_STATS * proto_idx * sizeof(uint32_t));
    maxval = (uint32_t*)calloc(NUM_STATS * proto_idx, sizeof(uint32_t));
    intervals = (uint32_t (*)[10])calloc(NUM_STATS * proto_idx * NUM_INTERVALS,
                                         sizeof(uint32_t*));
    interval_defn = (uint32_t**)calloc(NUM_STATS * proto_idx,
                                       sizeof(uint32_t*));

    if (!minval || !maxval || !intervals || !interval_defn) {
        skAppPrintErr("Cannot allocate space for protocol statistics");
        protoStatsTeardown();
        return 1;
    }

    /* Set the minima to a big value, like INT_MAX */
    for (i = 0; i < proto_idx; ++i) {
        for (j = 0; j < NUM_STATS; ++j) {
            minval[MK_IDX(j, i)] = INT_MAX;
        }
    }

    /* Set the interval definitions for TCP */
    i = proto_to_stats_idx[6];
    if (i != 0) {
        interval_defn[MK_IDX(BYTE, i)] = tcpByteIntervals;
        interval_defn[MK_IDX(PKT,  i)] = tcpPktIntervals;
        interval_defn[MK_IDX(BPP,  i)] = tcpBppIntervals;
    }

    /* Since TCP is dominate protocol; use the TCP interval
     * definitions for stats across ALL protocols. */
    interval_defn[MK_IDX(BYTE, 0)] = tcpByteIntervals;
    interval_defn[MK_IDX(PKT,  0)] = tcpPktIntervals;
    interval_defn[MK_IDX(BPP,  0)] = tcpBppIntervals;

    /* Set all other interval definitions to UDP */
    for (i = 1; i < proto_idx; ++i) {
        if (i != proto_to_stats_idx[6]) {
            interval_defn[MK_IDX(BYTE, i)] = udpByteIntervals;
            interval_defn[MK_IDX(PKT,  i)] = udpPktIntervals;
            interval_defn[MK_IDX(BPP,  i)] = udpBppIntervals;
        }
    }

    return 0;
}


static void
protoStatsTeardown(
    void)
{
    if (count) {
        free(count);
        count = NULL;
    }
    if (minval) {
        free(minval);
        minval = NULL;
    }
    if (maxval) {
        free(maxval);
        maxval = NULL;
    }
    if (intervals) {
        free(intervals);
        intervals = NULL;
    }
    if (interval_defn) {
        free(interval_defn);
        interval_defn = NULL;
    }
}


static int
protoStatsOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    switch ((protoStatsOptionsEnum)opt_index) {
      case OPT_OVERALL_STATS:
        /* combined stats for all protocols */
        proto_stats = 1;
        break;

      case OPT_DETAIL_PROTO_STATS:
        /* detailed stats for specific proto */
        if (0 != protoStatsParse(opt_arg)) {
            return 1;
        }
        proto_stats = 1;
        break;
    }

    return 0;
}


int
protoStatsOptionsRegister(
    void)
{
    assert((sizeof(protoStatsHelp)/sizeof(char *)) ==
           (sizeof(protoStatsOptions)/sizeof(struct option)));

    /* register the options */
    if (skOptionsRegister(protoStatsOptions, &protoStatsOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register protoStats options");
        return 1;
    }

    return 0;
}


void
protoStatsOptionsUsage(
    FILE               *fh)
{
    unsigned int i;

    fprintf(fh, "\nPROTOCOL STATISTICS SWITCHES:\n");
    for (i = 0; protoStatsOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", protoStatsOptions[i].name,
                SK_OPTION_HAS_ARG(protoStatsOptions[i]), protoStatsHelp[i]);
    }
}


/*
 *  ok = protoStatsProcessFile(stream);
 *
 *    Read SiLK Flow records from the stream and update the counters.
 */
static int
protoStatsProcessFile(
    skstream_t         *stream)
{
    rwRec rwrec;
    int proto_idx;
    int rv;

    while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
        /* Statistics across ALL protocols */
        protoStatsUpdateStatistics(0, &rwrec);

        /* Compute statistics for specific protocol if requested */
        proto_idx = proto_to_stats_idx[rwRecGetProto(&rwrec)];
        if (proto_idx) {
            protoStatsUpdateStatistics(proto_idx, &rwrec);
        }

    } /* while skStreamReadRecord() */
    if (SKSTREAM_ERR_EOF != rv) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
    }

    return 0;
}


/*
 * protoStatsUpdateStatistics:
 *      Update the minima, maxima, and intervals for bytes, packets,
 *      and bytes-per-packet for the specified protocol.
 * Arguments:
 *      proto -number of the protocol to be updated.  Used to
 *              determine which intervals to use.  This is equal to
 *              256 for the overall stats
 *      proto_idx -the index---determined by proto---into the
 *              various *_min, *_max, and *_intervals arrays.
 *      rwrecPtr -the rwrec data
 * Returns: NONE.
 * Side Effects:
 *      Global counters, minima, maxima, intervals are modified.
 */
static void
protoStatsUpdateStatistics(
    int                 proto_idx,
    const rwRec        *rwrec)
{
    uint32_t stat_src[NUM_STATS];
    int i;
    int s;

    /* Update count */
    ++count[proto_idx];

    stat_src[BYTE] = rwRecGetBytes(rwrec);
    stat_src[PKT]  = rwRecGetPkts(rwrec);
    stat_src[BPP]  = rwRecGetBytes(rwrec) / rwRecGetPkts(rwrec);

    /* Find min/max/intervals for bytes, packets, bpp */
    for (s = 0; s < NUM_STATS; ++s) {
        if (stat_src[s] < minval[MK_IDX(s, proto_idx)]) {
            minval[MK_IDX(s, proto_idx)] = stat_src[s];
            if (0 == maxval[MK_IDX(s, proto_idx)]) {
                maxval[MK_IDX(s, proto_idx)] = stat_src[s];
            }
        } else if (stat_src[s] > maxval[MK_IDX(s, proto_idx)]) {
            maxval[MK_IDX(s, proto_idx)] = stat_src[s];
        }
        for (i = 0; i < NUM_INTERVALS; ++i) {
            if (stat_src[s] <= interval_defn[MK_IDX(s, proto_idx)][i])
            {
                intervals[s + NUM_STATS * proto_idx][i]++;
                break;
            }
        }
    }
}


/*
 *  protoStatsGenerateOutput()
 *
 *    Generate the output when processing protocols.
 */
static void
protoStatsPrintResults(
    void)
{
    int proto;
    int proto_idx;
    int print_all_protos = 1;

    if (count[0] > 0) {
        /* Check to see if a single protocol has all the flows.  If
         * so, do not print the all-protos stats, since it will be
         * identical to the single-proto stats. */
        for (proto = 0; proto < 256; ++proto) {
            proto_idx = proto_to_stats_idx[proto];
            if (proto_idx == 0) {
                continue;
            }
            if (count[proto_idx] == count[0]) {
                print_all_protos = 0;
                break;
            }
        }
    }

    /* Print all proto stats only when there are multiple protocols. */
    if (print_all_protos) {
        fprintf(output.of_fp, "FLOW STATISTICS--ALL PROTOCOLS:  ");
        protoStatsPrintIntervals(0, "%_of_input");
    }

    /* Return if no records were read */
    if (0 == count[0]) {
        return;
    }

    for (proto = 0; proto < 256; ++proto) {
        proto_idx = proto_to_stats_idx[proto];
        if (proto_idx == 0) {
            /* nothing to do for this protocol */
            continue;
        }

        fprintf(output.of_fp, "\nFLOW STATISTICS--PROTOCOL %d:  ", proto);
        protoStatsPrintIntervals(proto_idx, "%_of_proto");
    }
}


/*
 * protoStatsPrintIntervals
 *      Print min, max, and intervals for bytes, packets, and bpp for
 *      the given protocol
 * Arguments:
 *      proto - the protocol to print
 *      proto_idx - the index to use into the *_min, *_max,
 *              *_interval arrays to access data for this protocol
 * Returns: NONE
 * Side Effects:
 *      Prints output to outstream
 */
static void
protoStatsPrintIntervals(
    int                 proto_idx,
    const char         *col_title)
{
    static const char *stat_name[] = {"BYTES", "PACKETS", "BYTES/PACKET"};
    double *quartiles;
    int i;
    int s;
    double percent;
    double cumul_pct;

    fprintf(output.of_fp, ("%" PRIu64), count[proto_idx]);
    if (proto_idx != 0) {
        fprintf(output.of_fp, ("/%" PRIu64), count[0]);
    }
    fprintf(output.of_fp, " records\n");

    if (0 == count[proto_idx]) {
        /* no records, so no data to print */
        return;
    }

    for (s = 0; s < NUM_STATS; ++s) {
        /* Print title and min, max */
        fprintf(output.of_fp, ("*%s min %" PRIu32 "; max %" PRIu32 "\n"),
                stat_name[s], minval[MK_IDX(s, proto_idx)],
                maxval[MK_IDX(s, proto_idx)]);

        /* Compute and print quartitles */
        quartiles = intervalQuartiles(intervals[MK_IDX(s, proto_idx)],
                                      interval_defn[MK_IDX(s, proto_idx)],
                                      NUM_INTERVALS);
        fprintf(output.of_fp,
                "  quartiles LQ %.5f Med %.5f UQ %.5f UQ-LQ %.5f\n",
                quartiles[0], quartiles[1], quartiles[2],
                (quartiles[2] - quartiles[0]));

        /* Column titles for intervals */
        if (!app_flags.no_titles) {
            fprintf(output.of_fp, "%*s%c%*s%c%*s%c%*s%s\n",
                    width[WIDTH_KEY],   "interval_max", delimiter,
                    width[WIDTH_INTVL], "count<=max", delimiter,
                    width[WIDTH_PCT],   col_title, delimiter,
                    width[WIDTH_PCT],   "cumul_%", final_delim);
        }

        /* Print intervals and percentages */
        cumul_pct = 0.0;
        for (i = 0; i < NUM_INTERVALS; ++i) {
            percent = (100.0 * (double)intervals[MK_IDX(s, proto_idx)][i]
                       / (double)count[proto_idx]);
            cumul_pct += percent;

            fprintf(output.of_fp,
                    ("%*" PRIu32 "%c%*" PRIu32 "%c%*.6f%c%*.6f%s\n"),
                    width[WIDTH_KEY],
                    interval_defn[MK_IDX(s, proto_idx)][i], delimiter,
                    width[WIDTH_INTVL],
                    intervals[MK_IDX(s, proto_idx)][i], delimiter,
                    width[WIDTH_PCT], percent, delimiter,
                    width[WIDTH_PCT], cumul_pct, final_delim);
        }
    }
}


int
protoStatsMain(
    void)
{
    skstream_t *stream;
    int rv = 0;

    rv = protoStatsSetup();
    if (rv) {
        return rv;
    }

    while ((rv = appNextInput(&stream)) == 0) {
        rv = protoStatsProcessFile(stream);
        skStreamDestroy(&stream);
    }
    if (rv > 0) {
        /* processed all files */
        rv = 0;
    } else {
        /* error opening file */
        rv = 1;
    }

    /* enable the pager */
    setOutputHandle();

    /* Generate output */
    protoStatsPrintResults();

    protoStatsTeardown();

    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
