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
 * rwtotal.c
 *
 * This is an analysis package which totals up various values in a
 * packfile, breaking them up by some combination of fields.
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwtotal.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwtotal.h"


/* LOCAL DEFINES AND TYPEDEFS */

/*
 * When generating output, this macro will evaluate to TRUE if the
 * record at position i is within the user-specified limits.  Uses the
 * global 'bounds' variable.
 */
#define IS_RECORD_WITHIN_LIMITS(count_rec, i)                           \
    ((count_rec)[(i) + C_RECS] >= bounds[C_RECS] &&                     \
     (count_rec)[(i) + C_RECS] <= bounds[NUM_TOTALS + C_RECS] &&        \
     (count_rec)[(i) + C_BYTES] >= bounds[C_BYTES] &&                   \
     (count_rec)[(i) + C_BYTES] <= bounds[NUM_TOTALS + C_BYTES] &&      \
     (count_rec)[(i) + C_PKTS] >= bounds[C_PKTS] &&                     \
     (count_rec)[(i) + C_PKTS] <= bounds[NUM_TOTALS + C_PKTS])


/* EXPORTED VARIABLES */

sk_options_ctx_t *optctx;

int count_mode;

int  summation = 0;
int  no_titles = 0;
int  no_columns = 0;
int  no_final_delimiter = 0;
char delimiter = '|';

/* count of records */
uint64_t *count_array = NULL;

/* only print records within these bounds, Lower bounds run from
 * 0--(NUM_TOTALS-1); upper from NUM_TOTALS--(2*NUM_TOTALS-1) */
uint64_t bounds[2 * NUM_TOTALS];


/* LOCAL VARIABLES */

/* number of bins in the array */
static uint32_t total_bins = 0;

/* a mapping from count_mode to the total_bins.
 * This depends on ordering in appOptionsEnum */
static uint32_t count_mode_to_total_bins[] = {
    /* OPT_SIP_FIRST_8    */ (1 <<  8),
    /* OPT_SIP_FIRST_16   */ (1 << 16),
    /* OPT_SIP_FIRST_24   */ (1 << 24),
    /* OPT_SIP_LAST_8     */ (1 <<  8),
    /* OPT_SIP_LAST_16    */ (1 << 16),

    /* OPT_DIP_FIRST_8    */ (1 <<  8),
    /* OPT_DIP_FIRST_16   */ (1 << 16),
    /* OPT_DIP_FIRST_24   */ (1 << 24),
    /* OPT_DIP_LAST_8     */ (1 <<  8),
    /* OPT_DIP_LAST_16    */ (1 << 16),

    /* OPT_SPORT          */ (1 << 16),
    /* OPT_DPORT          */ (1 << 16),
    /* OPT_PROTO          */ (1 <<  8),
    /* OPT_PACKETS        */ (1 << 24),
    /* OPT_BYTES          */ (1 << 24),
    /* OPT_DURATION       */      4096,
    /* OPT_ICMP_CODE      */ (1 << 16)
};



/* FUNCTION DEFINITIONS */


/*
 *  countFile(stream);
 *
 *    Read the records from 'stream' and add their byte, packet,
 *    and flow counts to the appropriate bin.
 */
static void
countFile(
    skstream_t         *stream)
{
    rwRec rwrec;
    uint32_t key = 0;
    int rv;

    /* ignore IPv6 flows when keying on address */
    if (count_mode <= COUNT_MODE_FINAL_ADDR) {
        skStreamSetIPv6Policy(stream, SK_IPV6POLICY_ASV4);
    }

    while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
        switch (count_mode) {
          case OPT_SIP_FIRST_8:
            key = rwRecGetSIPv4(&rwrec) >> 24;
            break;
          case OPT_DIP_FIRST_8:
            key = rwRecGetDIPv4(&rwrec) >> 24;
            break;
          case OPT_SIP_FIRST_16:
            key = rwRecGetSIPv4(&rwrec) >> 16;
            break;
          case OPT_DIP_FIRST_16:
            key = rwRecGetDIPv4(&rwrec) >> 16;
            break;
          case OPT_SIP_FIRST_24:
            key = rwRecGetSIPv4(&rwrec) >> 8;
            break;
          case OPT_DIP_FIRST_24:
            key = rwRecGetDIPv4(&rwrec) >> 8;
            break;
          case OPT_SIP_LAST_8:
            key = rwRecGetSIPv4(&rwrec) & 0xFF;
            break;
          case OPT_DIP_LAST_8:
            key = rwRecGetDIPv4(&rwrec) & 0xFF;
            break;
          case OPT_SIP_LAST_16:
            key = rwRecGetSIPv4(&rwrec) & 0xFFFF;
            break;
          case OPT_DIP_LAST_16:
            key = rwRecGetDIPv4(&rwrec) & 0xFFFF;
            break;
          case OPT_SPORT:
            key = rwRecGetSPort(&rwrec);
            break;
          case OPT_DPORT:
            key = rwRecGetDPort(&rwrec);
            break;
          case OPT_PROTO:
            key = rwRecGetProto(&rwrec);
            break;
          case OPT_PACKETS:
            key = rwRecGetPkts(&rwrec);
            if (key >= total_bins) {
                /* if value is too large, fill final bin */
                key = total_bins - 1;
            }
            break;
          case OPT_BYTES:
            key = rwRecGetBytes(&rwrec);
            if (key >= total_bins) {
                /* if value is too large, fill final bin */
                key = total_bins - 1;
            }
            break;
          case OPT_DURATION:
            key = rwRecGetElapsedSeconds(&rwrec);
            break;
          case OPT_ICMP_CODE:
            key = rwRecGetIcmpTypeAndCode(&rwrec);
            break;
          default:
            skAbortBadCase(count_mode);
        }

        key *= NUM_TOTALS;
        count_array[key + C_RECS]++;
        count_array[key + C_BYTES] += rwRecGetBytes(&rwrec);
        count_array[key + C_PKTS]  += rwRecGetPkts(&rwrec);
    }

    if (rv != SKSTREAM_ERR_EOF) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
    }

    return;
}


/*
 *  dumpCounts(fh);
 *
 *    Print the byte, packet, and flow counts to the named file handle
 *    'fh'.
 */
static void
dumpCounts(
    FILE               *outfp)
{
    /* row-label, records, bytes, packets */
#define FMT_VALUE ("%*s%c%*" PRIu64 "%c%*" PRIu64 "%c%*" PRIu64 "%s\n")
#define FMT_TITLE "%*s%c%*s%c%*s%c%*s%s\n"
#define FMT_WIDTH {11, 15, 20, 17}

    int fmt_width[] = FMT_WIDTH;
    uint32_t i;
    uint32_t t;
    char buf[64];
    char final_delim[] = {'\0', '\0'};
    uint64_t totals[NUM_TOTALS];

    if (!no_final_delimiter) {
        final_delim[0] = delimiter;
    }
    if (no_columns) {
        memset(fmt_width, 0, sizeof(fmt_width));
    }
    memset(totals, 0, sizeof(totals));

    /* Print title */
    if (!no_titles) {
        const char *key_name;

        switch (count_mode) {
          case OPT_SIP_FIRST_8:
            key_name = "sIP_First8";
            break;
          case OPT_DIP_FIRST_8:
            key_name = "dIP_First8";
            break;
          case OPT_SIP_FIRST_16:
            key_name = "sIP_First16";
            break;
          case OPT_DIP_FIRST_16:
            key_name = "dIP_First16";
            break;
          case OPT_SIP_FIRST_24:
            key_name = "sIP_First24";
            break;
          case OPT_DIP_FIRST_24:
            key_name = "dIP_First24";
            break;
          case OPT_SIP_LAST_8:
            key_name =  "sIP_Last8";
            break;
          case OPT_DIP_LAST_8:
            key_name = "dIP_Last8";
            break;
          case OPT_SIP_LAST_16:
            key_name = "sIP_Last16";
            break;
          case OPT_DIP_LAST_16:
            key_name = "dIP_Last16";
            break;
          case OPT_SPORT:
            key_name = "sPort";
            break;
          case OPT_DPORT:
            key_name = "dPort";
            break;
          case OPT_PROTO:
            key_name = "protocol";
            break;
          case OPT_PACKETS:
            key_name = "packets";
            break;
          case OPT_BYTES:
            key_name = "bytes";
            break;
          case OPT_DURATION:
            key_name = "elapsed";
            break;
          case OPT_ICMP_CODE:
            key_name = "icmpTypeCod";
            break;
          default:
            skAbortBadCase(count_mode);
        }

        fprintf(outfp, FMT_TITLE,
                fmt_width[0], key_name,  delimiter,
                fmt_width[1], "Records", delimiter,
                fmt_width[2], "Bytes",   delimiter,
                fmt_width[3], "Packets", final_delim);
    }

    /* print bins */
    for (t = 0, i = 0; t < total_bins; ++t, i += NUM_TOTALS) {
        if (IS_RECORD_WITHIN_LIMITS(count_array, i)) {
            switch (count_mode) {
              case OPT_SIP_FIRST_24:
              case OPT_DIP_FIRST_24:
                sprintf(buf, "%3u.%3u.%3u",
                        (unsigned int)(t >> 16),
                        (unsigned int)((t >> 8) & 0xFF),
                        (unsigned int)(t & 0xFF));
                break;

              case OPT_SIP_FIRST_16:
              case OPT_DIP_FIRST_16:
              case OPT_SIP_LAST_16:
              case OPT_DIP_LAST_16:
                sprintf(buf, "%3u.%3u",
                        (unsigned int)(t >> 8),
                        (unsigned int)(t & 0xFF));
                break;

              case OPT_ICMP_CODE:
                sprintf(buf, "%3u %3u",
                        (unsigned int)(t >> 8),
                        (unsigned int)(t & 0xFF));
                break;

              default:
                sprintf(buf, ("%" PRIu32), t);
                break;
            }

            fprintf(outfp, FMT_VALUE,
                    fmt_width[0], buf,                      delimiter,
                    fmt_width[1], count_array[i + C_RECS],  delimiter,
                    fmt_width[2], count_array[i + C_BYTES], delimiter,
                    fmt_width[3], count_array[i + C_PKTS],  final_delim);
            totals[C_RECS]  += count_array[i + C_RECS];
            totals[C_BYTES] += count_array[i + C_BYTES];
            totals[C_PKTS]  += count_array[i + C_PKTS];
        }
    }

    if (summation) {
        fprintf(outfp, FMT_VALUE,
                fmt_width[0], "TOTALS",        delimiter,
                fmt_width[1], totals[C_RECS],  delimiter,
                fmt_width[2], totals[C_BYTES], delimiter,
                fmt_width[3], totals[C_PKTS],  final_delim);
    }
}


int main(int argc, char **argv)
{
    FILE *stream_out;
    skstream_t *stream;
    int rv;

    appSetup(argc, argv);                       /* never returns on error */

    /* allocate space for the bins */
    assert(count_mode
           < (int)(sizeof(count_mode_to_total_bins) / sizeof(uint32_t)));
    total_bins = count_mode_to_total_bins[count_mode];

    count_array = (uint64_t*)calloc(NUM_TOTALS * total_bins, sizeof(uint64_t));
    if (count_array == NULL) {
        skAppPrintErr("Memory allocation error");
        return 1;
    }

    /* process each input stream/file */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        countFile(stream);
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* get the output handle, which may invoke the pager */
    stream_out = getOutputHandle();

    /* Print results */
    dumpCounts(stream_out);

    /* Done */
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
