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
**  rwstats.c
**
**  Implementation of the rwstats suite application.
**
**  Reads packed files or reads the output from rwfilter and can
**  compute a battery of characterizations and statistics:
**
**  -- Top N or Bottom N SIPs with counts; count of unique SIPs
**  -- Top N or Bottom N DIPs with counts; count of unique DIPs
**  -- Top N or Bottom N SIP/DIP pairs with counts; count of unique
**     SIP/DIP pairs (for a limited number of records)
**  -- Top N or Bottom N Src Ports with counts; count of unique Src Ports
**  -- Top N or Bottom N Dest Ports with counts; count of unique Dest Ports
**  -- Top N or Bottom N Protocols with counts; count of unique protocols
**  -- For more continuous variables (bytes, packets, bytes/packet)
**     provide statistics such as min, max, quartiles, and intervals
**
**  Instead of specifying a Top N or Bottom N as an absolute number N,
**  the user may specify a cutoff threshold.  In this case, the Top N
**  or Bottom N required to print all counts meeting the threshold is
**  computed by the application.
**
**  Instead of specifying the threshold as an absolute count, the user
**  may specify the threshold as percentage of all input records.  For
**  this case, the absolute threshold is calculated and then that is
**  used to calculate the Top N or Bottom N.
**
**  The application will only do calculations and produce output when
**  asked to do so.  At least one argument is required to tell the
**  application what to do.
**
**  Ideas for expansion
**  -- Similarly for other variables, e.g., country code.
**  -- Output each type of data to its own file
**  -- Save intermediate data in files for faster reprocessing by this
**     application
**  -- Save intermediate data in files for processing by other
**     applications
**
*/

/*
**  IMPLEMENTATION NOTES
**
**  For each input type (source ip, dest ip, source port, proto, etc),
**  there are two globals: limit_<type> contains the value the user
**  entered for the input type, and wanted_stat_<type> is a member
**  of the wanted_stat_type and says what the limit_<type> value
**  represents---e.g., the Top N, the bottom threshold percentage, etc.
**
**  The application takes input (either from stdin or as files on
**  command line) and calls processFile() on each.  A count of each
**  unique source IP addresses is stored in the IpCounter hash table
**  counter_src_ip; Destinations IPs in counter_dest_ip; data for
**  flow between a Source IP and Destination IP pair are stored in
**  counter_pair_ip.
**
**  Since there are relatively few ports and protocols, two
**  65536-elements arrays, src_port_array and dest_port_array are
**  used to store a count of the records for each source and
**  destination port, respectively, and a 256-element array,
**  proto_array, is used to store a count of each protocol.
**
**  Minima, maxima, quartile, and interval data are stored for each of
**  bytes, packets, and bytes-per-packet for all flows--regardless of
**  protocol--and detailed for a limited number (RWSTATS_NUM_PROTO-1)
**  of protocols..  The minima and maxima are each stored in arrays
**  for each of bytes, packets, bpp.  For example bytes_min[0]
**  stores the smallest byte count regardless of protocol (ie, over
**  all protocols), and pkts_max[1] stores the largest packet count
**  for the first protocol the user specified.  The mapping from
**  protocol to array index is given by proto_to_stats_idx[], where
**  the index into proto_to_stats_idx[] returns an integer that is
**  the index into bytes_min[].  Data for the intervals is stored in
**  two dimensional arrays, where the first dimension is the same as
**  for the minima and maxima, and the second dimension is the number
**  of intervals, NUM_INTERVALS.
**
**  Once data is collected, it is processed.
**
**  For the IPs, the user is interested the number of unique IPs and
**  the IPs with the topN counts (things are similar for the bottomN,
**  but we use topN in this dicussion to keep things more clear).  In
**  the printTopIps() function, an array with 2*topN elements is
**  created and passed to calcTopIps(); that array will be the result
**  array and it will hold the topN IpAddr and IpCount pairs in sorted
**  order.  In calcTopIps(), a working array of 2*topN elements and a
**  Heap data structure with topN nodes are created.  The topN
**  IpCounts seen are stored as IpCount/IpAddr pairs in the
**  2*topN-element array (but not in sorted order), and the heap
**  stores pointers into that array with the lowest IpCount at the
**  root of the heap.  As the function iterates over the hash table,
**  it compares the IpCount of the current hash-table element with the
**  IpCount at the root of the heap.  When the IpCount of the
**  hash-table element is larger, the root of the heap is removed, the
**  IpCount/IpAddr pair pointed to by the former heap-root is removed
**  from the 2*topN-element array and replaced with the new
**  IpCount/IpAddr pair, and finally a new node is added to the heap
**  that points to the new IpCount/IpAddr pair.  This continues until
**  all hash-table entries are processed.  To get the list of topN IPs
**  from highest to lowest, calcTopIps() removes elements from the
**  heap and stores them in the result array from position N-1 to
**  position 0.
**
**  Finding the topN source ports, topN destination ports, and topN
**  protocols are similar to finding the topN IPs, except the ports
**  and protocols are already stored in an array, so pointers directly
**  into the src_port_array, dest_port_array, and proto_array
**  are stored in the heap.  When generating output, the number of the
**  port or protocol is determined by the diffence between the pointer
**  into the *_port_array or proto_array and its start.
**
**  Instead of specifying a topN, the user may specify a cutoff
**  threshold.  In this case, the topN required to print all counts
**  meeting the threshold is computed by looping over the IP
**  hash-table or port/protocol arrays and finding all entries with at
**  least threshold hits.
**
**  The user may specify a percentage threshold instead of an absolute
**  threshold.  Once all records are read, the total record count is
**  multiplied by the percentage threshold to get the absolute
**  threshold cutoff, and that is used to calculate the topN as
**  described in the preceeding paragraph.
**
**  For the continuous variables bytes, packets, bpp, most of the work
**  was done while reading the data, so processing is minimal.  Only
**  the quartiles must be calculated.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwstats.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skheap.h>
#include "rwstats.h"


/* TYPEDEFS AND DEFINES */

/* Initial number of elements for the heap when using a threshold or
 * percentage cut-off */
#define HEAP_INITIAL_SIZE  512

#define HEAP_PTR_KEY(hp)                        \
    ((uint8_t*)(hp) + heap_offset_key)

#define HEAP_PTR_VALUE(hp)                      \
    ((uint8_t*)(hp) + heap_offset_value)

#define HEAP_PTR_DISTINCT(hp)                                   \
    ((uint8_t*)(hp) + heap_offset_distinct)

/* For output, add an "s" when speaking of values other than 1 */
#define PLURAL(plural_val) (((plural_val) == 1) ? "" : "s")

/*
 *  dir_val_type = DIR_AND_TYPE(direction, value_type);
 *
 *    Return a single integer that encodes the direction (RWSTATS_DIR_TOP,
 *    RWSTATS_DIR_BTM) and the value type to compute (SK_FIELD_RECORDS,...).
 */
#define DIR_AND_TYPE(dat_t_or_b, dat_val_type)  \
    ((dat_t_or_b) | ((dat_val_type) << 1))

#define MEMSET_HEAP_NODE(mhn_buf, key_buf, value_buf, distinct_buf)     \
    do {                                                                \
        memcpy(HEAP_PTR_KEY(mhn_buf), key_buf,                          \
               heap_octets_key);                                        \
        memcpy(HEAP_PTR_VALUE(mhn_buf), value_buf,                      \
               heap_octets_value);                                      \
        memcpy(HEAP_PTR_DISTINCT(mhn_buf), distinct_buf,                \
               heap_octets_distinct);                                   \
    } while(0)


/*
 *  meets = VALUE_MEETS_THRESHOLD(value);
 *
 *    Return true if 'value' meets the threshold value set by the
 *    user.  Uses the global 'limit' and 'direction' variables.
 */
#define VALUE_MEETS_THRESHOLD(vmt_value)                        \
    (((vmt_value) > limit.value[RWSTATS_THRESHOLD].u64)             \
     ? (RWSTATS_DIR_TOP == direction)                           \
     : ((RWSTATS_DIR_BOTTOM == direction)                       \
        || ((vmt_value) == limit.value[RWSTATS_THRESHOLD].u64)))


/* EXPORTED VARIABLES */

/* is this rwstats or rwuniq? */
const statsuniq_program_t this_program = STATSUNIQ_PROGRAM_STATS;


/* LOCAL VARIABLES */

/* the heap data structure */
static skheap_t *heap = NULL;

/* the comparison function to use for the heap */
static skheapcmpfn_t cmp_fn = NULL;

/* for the key, value, and distinct fields used by the heap, the byte
 * lengths of each and the offsets of each when creating a heap
 * node */
static size_t heap_octets_key = 0;
static size_t heap_octets_value = 0;
static size_t heap_octets_distinct = 0;

static size_t heap_offset_key = 0;
static size_t heap_offset_value = 0;
static size_t heap_offset_distinct = 0;

/* the total byte length of a node in the heap */
static size_t heap_octets_node = 0;


/* FUNCTION DEFINITIONS */

/*
 *  topnPrintHeader();
 *
 *    Print the header giving number of unique hash keys seen.  Should
 *    be called even when --no-titles is requested, since it will
 *    print a warning if no records met the threshold.
 */
static void
topnPrintHeader(
    void)
{
    char buf[260];
    const char *direction_name = "";
    const char *above_below = "";

    /* enable the pager */
    setOutputHandle();

    /* handle no titles */
    if (app_flags.no_titles) {
        return;
    }

    switch (direction) {
      case RWSTATS_DIR_TOP:
        direction_name = "Top";
        above_below = "above";
        break;
      case RWSTATS_DIR_BOTTOM:
        direction_name = "Bottom";
        above_below = "below";
        break;
    }

    /* Get a count of unique flows */
    fprintf(output.of_fp, ("INPUT: %" PRIu64 " Record%s for %" PRIu64 " Bin%s"),
            record_count, PLURAL(record_count),
            limit.entries, PLURAL(limit.entries));
    if (value_total) {
        fprintf(output.of_fp, (" and %" PRIu64 " Total %s"),
                value_total, limit.title);
    }
    fprintf(output.of_fp, "\n");

    switch (limit.type) {
      case RWSTATS_COUNT:
        assert(limit.value[RWSTATS_COUNT].u64 > 0);
        /* FALLTHROUGH */
      case RWSTATS_ALL:
        fprintf(output.of_fp, ("OUTPUT: %s %" PRIu64 " Bin%s by %s\n"),
                direction_name, limit.value[RWSTATS_COUNT].u64,
                PLURAL(limit.value[RWSTATS_COUNT].u64), limit.title);
        break;

      case RWSTATS_THRESHOLD:
        if (limit.value[RWSTATS_COUNT].u64 < 1) {
            fprintf(output.of_fp,
                    ("OUTPUT: No bins %s threshold of %" PRIu64 " %s\n"),
                    above_below, limit.value[RWSTATS_THRESHOLD].u64,
                    limit.title);
            return;
        }
        fprintf(output.of_fp,
                "OUTPUT: %s %" PRIu64 " bins by %s (threshold %" PRIu64 ")\n",
                direction_name, limit.value[RWSTATS_COUNT].u64,
                limit.title, limit.value[RWSTATS_THRESHOLD].u64);
        break;

      case RWSTATS_PERCENTAGE:
        if (limit.value[RWSTATS_COUNT].u64 < 1) {
            fprintf(output.of_fp,
                    "OUTPUT: No bins %s threshold of %.4f%% (%" PRIu64 " %s)\n",
                    above_below, limit.value[RWSTATS_PERCENTAGE].d,
                    limit.value[RWSTATS_THRESHOLD].u64, limit.title);
            return;
        }
        fprintf(output.of_fp,
                "OUTPUT: %s %" PRIu64 " bins by %s (%.4f%% == %" PRIu64 ")\n",
                direction_name, limit.value[RWSTATS_COUNT].u64,
                limit.title, limit.value[RWSTATS_PERCENTAGE].d,
                limit.value[RWSTATS_THRESHOLD].u64);
        break;
    }

    if (app_flags.no_titles) {
        return;
    }

    /* print key titles */
    rwAsciiPrintTitles(ascii_str);

    if (!app_flags.no_percents) {
        snprintf(buf, sizeof(buf), "%%%s", limit.title);
        buf[sizeof(buf)-1] = '\0';

        if (app_flags.no_columns) {
            fprintf(output.of_fp, "%c%s%c%s",
                    delimiter, buf, delimiter, "cumul_%");
        } else {
            fprintf(output.of_fp, ("%c%*.*s%c%*.*s"),
                    delimiter, width[WIDTH_PCT], width[WIDTH_PCT], buf,
                    delimiter, width[WIDTH_PCT], width[WIDTH_PCT], "cumul_%");
        }
        fprintf(output.of_fp, "%s\n", final_delim);
    }
}


/*
 *  rwstatsPrintHeap();
 *
 *    Loop over nodes of the heap and print each, as well as the
 *    percentage columns.
 */
static void
rwstatsPrintHeap(
    void)
{
    skheapiterator_t *itheap;
    skheapnode_t heap_ptr;
    uint8_t *outbuf[3] = {NULL, NULL, NULL};
    double cumul_pct = 0.0;
    double percent;
    uint64_t val64;

    /* print the headings and column titles */
    topnPrintHeader();

    skHeapSortEntries(heap);

    itheap = skHeapIteratorCreate(heap, -1);
    if (NULL == itheap) {
        skAppPrintOutOfMemory("iterator");
        return;
    }

    if (app_flags.no_percents) {
        while (skHeapIteratorNext(itheap, &heap_ptr) == SKHEAP_OK) {
            outbuf[0] = HEAP_PTR_KEY(heap_ptr);
            outbuf[1] = HEAP_PTR_VALUE(heap_ptr);
            outbuf[2] = HEAP_PTR_DISTINCT(heap_ptr);
            writeAsciiRecord(outbuf);
        }
    } else if (limit.distinct == 0) {
        switch (limit.fl_id) {
          case SK_FIELD_RECORDS:
          case SK_FIELD_SUM_BYTES:
          case SK_FIELD_SUM_PACKETS:
            while (skHeapIteratorNext(itheap, &heap_ptr) == SKHEAP_OK) {
                outbuf[0] = HEAP_PTR_KEY(heap_ptr);
                outbuf[1] = HEAP_PTR_VALUE(heap_ptr);
                outbuf[2] = HEAP_PTR_DISTINCT(heap_ptr);
                writeAsciiRecord(outbuf);
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry, (uint8_t*)&val64);
                percent = 100.0 * (double)val64 / value_total;
                cumul_pct += percent;
                fprintf(output.of_fp, ("%c%*.6f%c%*.6f%s\n"),
                        delimiter, width[WIDTH_PCT], percent, delimiter,
                        width[WIDTH_PCT], cumul_pct, final_delim);
            }
            break;

          default:
            while (skHeapIteratorNext(itheap, &heap_ptr) == SKHEAP_OK) {
                outbuf[0] = HEAP_PTR_KEY(heap_ptr);
                outbuf[1] = HEAP_PTR_VALUE(heap_ptr);
                outbuf[2] = HEAP_PTR_DISTINCT(heap_ptr);
                writeAsciiRecord(outbuf);
                fprintf(output.of_fp, ("%c%*c%c%*c%s\n"),
                        delimiter, width[WIDTH_PCT], '?', delimiter,
                        width[WIDTH_PCT], '?', final_delim);
            }
        }
    } else {
        union count_un {
            uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
            uint64_t  u64;
            uint32_t  u32;
            uint16_t  u16;
            uint8_t   u8;
        } count;
        size_t len;

        len = skFieldListEntryGetBinOctets(limit.fl_entry);
        while (skHeapIteratorNext(itheap, &heap_ptr) == SKHEAP_OK) {
            outbuf[0] = HEAP_PTR_KEY(heap_ptr);
            outbuf[1] = HEAP_PTR_VALUE(heap_ptr);
            outbuf[2] = HEAP_PTR_DISTINCT(heap_ptr);
            switch (len) {
              case 1:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, &count.u8);
                percent = 100.0 * (double)count.u8 / value_total;
                break;

              case 2:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u16);
                percent = 100.0 * (double)count.u16 / value_total;
                break;

              case 4:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u32);
                percent = 100.0 * (double)count.u32 / value_total;
                break;

              case 8:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u64);
                percent = 100.0 * (double)count.u64 / value_total;
                break;

              case 3:
              case 5:
              case 6:
              case 7:
                count.u64 = 0;
#if SK_BIG_ENDIAN
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             &count.ar[8 - len]);
#else
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, &count.ar[0]);
#endif  /* SK_BIG_ENDIAN */
                percent = 100.0 * (double)count.u64 / value_total;
                break;

              default:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, count.ar);
                percent = 100.0 * (double)count.u64 / value_total;
                break;
            }

            cumul_pct += percent;
            writeAsciiRecord(outbuf);
            fprintf(output.of_fp, ("%c%*.6f%c%*.4f%s\n"),
                    delimiter, width[WIDTH_PCT], percent, delimiter,
                    width[WIDTH_PCT], cumul_pct, final_delim);
        }
     }

    skHeapIteratorFree(itheap);
}


/*
 *  cmp = rwstatsCompareCounts{Top,Btm}{32,64}(node1, node2);
 *
 *    The following 4 functions are invoked by the skHeap library to
 *    compare counters.  'node1' and 'node2' are pointers to an
 *    integer value (either a uint32_t or a uint64_t).
 *
 *    For the *Top* functions, return 1, 0, -1 depending on whether
 *    the value in 'node1' is <, ==, > the value in 'node2'.
 *
 *    For the *Btm* functions, return -1, 0, 1 depending on whether
 *    the value in 'node1' is <, ==, > the value in 'node2'.
 */

#define COMPARE(cmp_a, cmp_b)                                   \
    (((cmp_a) < (cmp_b)) ? -1 : (((cmp_a) > (cmp_b)) ? 1 : 0))

#define CMP_INT_HEAP_VALUES(cmp_out, cmp_type, cmp_a, cmp_b)    \
    {                                                           \
        cmp_type val_a;                                         \
        cmp_type val_b;                                         \
        skFieldListExtractFromBuffer(value_fields,              \
                                     HEAP_PTR_VALUE(cmp_a),     \
                                     limit.fl_entry,            \
                                     (uint8_t*)&val_a);         \
        skFieldListExtractFromBuffer(value_fields,              \
                                     HEAP_PTR_VALUE(cmp_b),     \
                                     limit.fl_entry,            \
                                     (uint8_t*)&val_b);         \
        cmp_out = COMPARE(val_a, val_b);                        \
    }

#define CMP_INT_HEAP_DISTINCTS(cmp_out, cmp_type, cmp_a, cmp_b) \
    {                                                           \
        cmp_type val_a;                                         \
        cmp_type val_b;                                         \
        skFieldListExtractFromBuffer(distinct_fields,           \
                                     HEAP_PTR_DISTINCT(cmp_a),  \
                                     limit.fl_entry,            \
                                     (uint8_t*)&val_a);         \
        skFieldListExtractFromBuffer(distinct_fields,           \
                                     HEAP_PTR_DISTINCT(cmp_b),  \
                                     limit.fl_entry,            \
                                     (uint8_t*)&val_b);         \
        cmp_out = COMPARE(val_a, val_b);                        \
    }

static int
rwstatsCompareValuesTop64(
    const skheapnode_t  node1,
    const skheapnode_t  node2)
{
    int rv;
    CMP_INT_HEAP_VALUES(rv, uint64_t, node1, node2);
    return -rv;
}

static int
rwstatsCompareValuesBottom64(
    const skheapnode_t  node1,
    const skheapnode_t  node2)
{
    int rv;
    CMP_INT_HEAP_VALUES(rv, uint64_t, node1, node2);
    return rv;
}

static int
rwstatsComparePluginAny(
    const skheapnode_t  node1,
    const skheapnode_t  node2)
{
    skplugin_err_t err;
    int cmp;

    err = skPluginFieldRunBinCompareFn(limit.pi_field, &cmp,
                                       (const uint8_t*)node1,
                                       (const uint8_t*)node2);
    if (err != SKPLUGIN_OK) {
        const char **name;
        skPluginFieldName(limit.pi_field, &name);
        skAppPrintErr(("Plugin-based field %s failed "
                       "binary comparison with error code %d"), name[0], err);
        appExit(EXIT_FAILURE);
    }
    return ((RWSTATS_DIR_TOP == direction) ? -cmp : cmp);
}

static int
rwstatsCompareDistinctsAny(
    const skheapnode_t  node1,
    const skheapnode_t  node2)
{
    union value_un {
        uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
        uint64_t  u64;
    } count1, count2;
    size_t len;
    int cmp;

    len = skFieldListEntryGetBinOctets(limit.fl_entry);
    switch (len) {
      case 1:
        CMP_INT_HEAP_DISTINCTS(cmp, uint8_t, node1, node2);
        break;
      case 2:
        CMP_INT_HEAP_DISTINCTS(cmp, uint16_t, node1, node2);
        break;
      case 4:
        CMP_INT_HEAP_DISTINCTS(cmp, uint32_t, node1, node2);
        break;
      case 8:
        CMP_INT_HEAP_DISTINCTS(cmp, uint64_t, node1, node2);
        break;

      case 3:
      case 5:
      case 6:
      case 7:
#if SK_BIG_ENDIAN
        cmp = memcmp(HEAP_PTR_DISTINCT(node1), HEAP_PTR_DISTINCT(node2), len);
#else
        count1.u64 = 0;
        count2.u64 = 0;
        skFieldListExtractFromBuffer(distinct_fields, HEAP_PTR_DISTINCT(node1),
                                     limit.fl_entry, count1.ar);
        skFieldListExtractFromBuffer(distinct_fields, HEAP_PTR_DISTINCT(node2),
                                     limit.fl_entry, count2.ar);
        cmp = COMPARE(count1.u64, count2.u64);
#endif  /* #else of #if SK_BIG_ENDIAN */
        break;

      default:
        skFieldListExtractFromBuffer(distinct_fields, HEAP_PTR_DISTINCT(node1),
                                     limit.fl_entry, count1.ar);
        skFieldListExtractFromBuffer(distinct_fields, HEAP_PTR_DISTINCT(node2),
                                     limit.fl_entry, count2.ar);
        cmp = COMPARE(count1.u64, count2.u64);
        break;
    }

    return ((RWSTATS_DIR_TOP == direction) ? -cmp : cmp);
}


/*
 *  rwstatsHeapMemory(newnode);
 *
 *    Function called when an attempt to use a variable-sized heap
 *    fails due to lack of memory.
 */
static void
rwstatsHeapMemory(
    uint8_t            *newnode)
{
    uint8_t *top_heap;

    switch (limit.type) {
      case RWSTATS_COUNT:
        skAbortBadCase(limit.type);
      case RWSTATS_ALL:
        skAppPrintErr(("Out of memory when attempting to sort all bins;"
                       " using an absolute bin count of %" PRIu64 " instead"),
                      limit.value[RWSTATS_COUNT].u64);
        break;
      case RWSTATS_THRESHOLD:
        skAppPrintErr(("Out of memory when attempting to use a threshold"
                       "of %" PRIu64 ";"
                       " using an absolute bin count of %" PRIu64 " instead"),
                      limit.value[RWSTATS_THRESHOLD].u64,
                      limit.value[RWSTATS_COUNT].u64);
        break;
      case RWSTATS_PERCENTAGE:
        skAppPrintErr(("Out of memory when attempting to use a threshold"
                       "of %" PRIu64 " (%.4f%%);"
                       " using an absolute bin count of %" PRIu64 " instead"),
                      limit.value[RWSTATS_THRESHOLD].u64,
                      limit.value[RWSTATS_PERCENTAGE].d,
                      limit.value[RWSTATS_COUNT].u64);
        break;
    }

    /* Add this record assuming a fixed heap size */

    /* Get the node at the top of heap and its value.  This is the
     * smallest value in the topN. */
    skHeapPeekTop(heap, (skheapnode_t*)&top_heap);

    if (cmp_fn(top_heap, newnode) > 0) {
        /* The skUnique element we just read is "better" (for topN,
         * higher than current heap-root's value; for bottomN, lower
         * than current heap-root's value). */
        skHeapReplaceTop(heap, newnode, NULL);
    }
}


/*
 *  ok = statsRandom();
 *
 *    Main control function that processes unsorted input (from files
 *    or from stdin) and fills the heap.  Returns 0 on success, -1 on
 *    failure.
 */
static int
statsRandom(
    void)
{
    uint8_t *top_heap;
    uint8_t newnode[HASHLIB_MAX_KEY_WIDTH + HASHLIB_MAX_VALUE_WIDTH];
    sk_unique_iterator_t *iter;
    uint8_t *outbuf[3] = {NULL, NULL, NULL};
    skstream_t *stream;
    rwRec rwrec;
    int rv = 0;
    size_t len;
    union count_un {
        uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
        uint64_t  u64;
        uint32_t  u32;
        uint16_t  u16;
        uint8_t   u8;
    } count;

    /* read SiLK Flow records and insert into the skunique data structure */
    while (0 == (rv = appNextInput(&stream))) {
        while (SKSTREAM_OK == (rv = readRecord(stream, &rwrec))) {
            if (0 != skUniqueAddRecord(uniq, &rwrec)) {
                return -1;
            }
        }
        if (rv != SKSTREAM_ERR_EOF) {
            /* corrupt record in file */
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            return -1;
        }
        skStreamDestroy(&stream);
    }
    if (rv == -1) {
        /* error opening file */
        return -1;
    }

    /* no more input; prepare for output */
    skUniquePrepareForOutput(uniq);

    if (limit.distinct) {
        value_total = skUniqueGetTotalDistinctCount(uniq);
    }

    if (RWSTATS_PERCENTAGE == limit.type) {
        /* the limit is a percentage of the sum of bytes, of packets,
         * or of flows for all bins; compute the threshold given that
         * we now know the total */
        limit.value[RWSTATS_THRESHOLD].u64
            = limit.value[RWSTATS_PERCENTAGE].d * value_total / 100.0;
    }

    /* create the iterator over skUnique's bins */
    rv = skUniqueIteratorCreate(uniq, &iter);
    if (rv) {
        skAppPrintErr("Unable to create iterator; err = %d", rv);
        return -1;
    }

    /* branch based on type of limit and type of value */
    if (RWSTATS_COUNT == limit.type) {
        /* fixed-size heap; this is easy to handle */
        uint32_t heap_num_entries;

        /* put the first topn entries into the heap */
        for (heap_num_entries = 0;
             ((heap_num_entries < limit.value[RWSTATS_COUNT].u64)
              && (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2],&outbuf[1])
                  == SK_ITERATOR_OK));
             ++heap_num_entries)
        {
            ++limit.entries;
            MEMSET_HEAP_NODE(newnode, outbuf[0], outbuf[1], outbuf[2]);
            skHeapInsert(heap, newnode);
        }

        /* drop to code below where we handle adding more entries to a
         * fixed size heap */

    } else if (RWSTATS_ALL == limit.type) {
        while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
               == SK_ITERATOR_OK)
        {
            ++limit.entries;
            MEMSET_HEAP_NODE(newnode, outbuf[0], outbuf[1], outbuf[2]);
            if (skHeapInsert(heap, newnode) == SKHEAP_ERR_FULL) {
                /* Cannot grow the heap any more; process remaining
                 * records using this fixed heap size */
                rwstatsHeapMemory(newnode);
                break;
            }
            /* else insert was successful */
            ++limit.value[RWSTATS_COUNT].u64;
        }

    } else if (limit.distinct) {
        /* handling a distinct field */
        len = skFieldListEntryGetBinOctets(limit.fl_entry);
        while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
               == SK_ITERATOR_OK)
        {
            ++limit.entries;
            switch (len) {
              case 1:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, &count.u8);
                if (!VALUE_MEETS_THRESHOLD(count.u8)) {
                    continue;
                }
                break;

              case 2:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u16);
                if (!VALUE_MEETS_THRESHOLD(count.u16)) {
                    continue;
                }
                break;

              case 4:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u32);
                if (!VALUE_MEETS_THRESHOLD(count.u32)) {
                    continue;
                }
                break;

              case 8:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u64);
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;

              case 3:
              case 5:
              case 6:
              case 7:
                count.u64 = 0;
#if SK_BIG_ENDIAN
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry,
                                             &count.ar[8 - len]);
#else
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, &count.ar[0]);
#endif  /* SK_BIG_ENDIAN */
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;

              default:
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             limit.fl_entry, count.ar);
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;
            }

            /* record meets threshold; insert it */
            MEMSET_HEAP_NODE(newnode, outbuf[0], outbuf[1], outbuf[2]);
            if (skHeapInsert(heap, newnode) == SKHEAP_ERR_FULL) {
                /* Cannot grow the heap any more; process remaining
                 * records using this fixed heap size */
                rwstatsHeapMemory(newnode);
                break;
            }
            /* else insert was successful */
            ++limit.value[RWSTATS_COUNT].u64;
        }

    } else {
        /* handling an aggregate value field */
        len = skFieldListEntryGetBinOctets(limit.fl_entry);
        while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
               == SK_ITERATOR_OK)
        {
            ++limit.entries;
            switch (len) {
              case 1:
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry, &count.u8);
                if (!VALUE_MEETS_THRESHOLD(count.u8)) {
                    continue;
                }
                break;

              case 2:
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u16);
                if (!VALUE_MEETS_THRESHOLD(count.u16)) {
                    continue;
                }
                break;

              case 4:
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u32);
                if (!VALUE_MEETS_THRESHOLD(count.u32)) {
                    continue;
                }
                break;

              case 8:
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry,
                                             (uint8_t*)&count.u64);
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;

              case 3:
              case 5:
              case 6:
              case 7:
                count.u64 = 0;
#if SK_BIG_ENDIAN
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry,
                                             &count.ar[8 - len]);
#else
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry, &count.ar[0]);
#endif  /* SK_BIG_ENDIAN */
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;

              default:
                skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                             limit.fl_entry, count.ar);
                if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                    continue;
                }
                break;
            }

            /* record meets threshold; insert it */
            MEMSET_HEAP_NODE(newnode, outbuf[0], outbuf[1], outbuf[2]);
            if (skHeapInsert(heap, newnode) == SKHEAP_ERR_FULL) {
                /* Cannot grow the heap any more; process remaining
                 * records using this fixed heap size */
                rwstatsHeapMemory(newnode);
                break;
            }
            /* else insert was successful */
            ++limit.value[RWSTATS_COUNT].u64;
        }
    }

    /* Get the node at the top of heap and its value.  This is the
     * smallest value in the topN. */
    skHeapPeekTop(heap, (skheapnode_t*)&top_heap);

    /* At this point the size of the heap is fixed.  Process the
     * remaining entries in the skUnique hash table---if any */
    while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
           == SK_ITERATOR_OK)
    {
        ++limit.entries;

        MEMSET_HEAP_NODE(newnode, outbuf[0], outbuf[1], outbuf[2]);
        if (cmp_fn(top_heap, newnode) > 0) {
            /* The skUnique element we just read is "better" (for
             * topN, higher than current heap-root's value; for
             * bottomN, lower than current heap-root's value). */
            skHeapReplaceTop(heap, newnode, NULL);

            /* the top may have changed; get the new top */
            skHeapPeekTop(heap, (skheapnode_t*)&top_heap);
        }
    }

    skUniqueIteratorDestroy(&iter);
    return 0;
}


/*
 *  presortedEntryCallback(key, distinct, value, top_heap);
 *
 *    This function is invoked by the skPresortedUnique* library code
 *    to process a key/distinct/value triplet when handling presorted
 *    input.
 */
static int
presortedEntryCallback(
    const uint8_t      *key,
    const uint8_t      *distinct,
    const uint8_t      *value,
    void               *top_heap)
{
    uint8_t newnode[HASHLIB_MAX_KEY_WIDTH + HASHLIB_MAX_VALUE_WIDTH];
    size_t len;
    union count_un {
        uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
        uint64_t  u64;
        uint32_t  u32;
        uint16_t  u16;
        uint8_t   u8;
    } count;
    static uint32_t heap_num_entries = 0;

    ++limit.entries;

    if (NULL != *(skheapnode_t*)top_heap) {
        /* heap is now full.  exchange entries if the current node is
         * better than the worst node in the heap, which is at the
         * root */
        MEMSET_HEAP_NODE(newnode, key, value, distinct);
        if (cmp_fn(*(skheapnode_t*)top_heap, newnode) > 0) {
            skHeapReplaceTop(heap, newnode, NULL);

            /* the top may have changed; get the new top */
            skHeapPeekTop(heap, (skheapnode_t*)top_heap);
        }

    } else if (RWSTATS_COUNT == limit.type) {
        /* there is still room in the heap */
        MEMSET_HEAP_NODE(newnode, key, value, distinct);
        skHeapInsert(heap, newnode);
        ++heap_num_entries;
        if (heap_num_entries == limit.value[RWSTATS_COUNT].u64) {
            /* we have filled the heap; get the top element */
            skHeapPeekTop(heap, (skheapnode_t*)top_heap);
        }

    } else if (RWSTATS_ALL == limit.type) {
        MEMSET_HEAP_NODE(newnode, key, value, distinct);
        if (skHeapInsert(heap, newnode) == SKHEAP_OK) {
            ++limit.value[RWSTATS_COUNT].u64;
        } else {
            /* Cannot grow the heap any more; process remaining
             * records using this fixed heap size */
            rwstatsHeapMemory(newnode);
            /* no more room; get the top element */
            skHeapPeekTop(heap, (skheapnode_t*)top_heap);
        }

    } else if (limit.distinct) {
        /* handling a distinct field */
        len = skFieldListEntryGetBinOctets(limit.fl_entry);

        switch (len) {
          case 1:
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry, &count.u8);
            if (!VALUE_MEETS_THRESHOLD(count.u8)) {
                return 0;
            }
            break;

          case 2:
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u16);
            if (!VALUE_MEETS_THRESHOLD(count.u16)) {
                return 0;
            }
            break;

          case 4:
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u32);
            if (!VALUE_MEETS_THRESHOLD(count.u32)) {
                return 0;
            }
            break;

          case 8:
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u64);
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;

          case 3:
          case 5:
          case 6:
          case 7:
            count.u64 = 0;
#if SK_BIG_ENDIAN
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry,
                                         &count.ar[8 - len]);
#else
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry, &count.ar[0]);
#endif  /* SK_BIG_ENDIAN */
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;

          default:
            skFieldListExtractFromBuffer(distinct_fields, distinct,
                                         limit.fl_entry, count.ar);
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;
        }

        /* record meets threshold; insert it */
        MEMSET_HEAP_NODE(newnode, key, value, distinct);
        if (skHeapInsert(heap, newnode) == SKHEAP_OK) {
            ++limit.value[RWSTATS_COUNT].u64;
        } else {
            /* Cannot grow the heap any more; process remaining
             * records using this fixed heap size */
            rwstatsHeapMemory(newnode);
            /* no more room; get the top element */
            skHeapPeekTop(heap, (skheapnode_t*)top_heap);
        }

    } else {
        /* handling an aggregate value field */
        len = skFieldListEntryGetBinOctets(limit.fl_entry);

        switch (len) {
          case 1:
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry, &count.u8);
            if (!VALUE_MEETS_THRESHOLD(count.u8)) {
                return 0;
            }
            break;

          case 2:
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u16);
            if (!VALUE_MEETS_THRESHOLD(count.u16)) {
                return 0;
            }
            break;

          case 4:
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u32);
            if (!VALUE_MEETS_THRESHOLD(count.u32)) {
                return 0;
            }
            break;

          case 8:
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry,
                                         (uint8_t*)&count.u64);
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;

          case 3:
          case 5:
          case 6:
          case 7:
            count.u64 = 0;
#if SK_BIG_ENDIAN
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry,
                                         &count.ar[8 - len]);
#else
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry, &count.ar[0]);
#endif  /* SK_BIG_ENDIAN */
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;

          default:
            skFieldListExtractFromBuffer(value_fields, value,
                                         limit.fl_entry, count.ar);
            if (!VALUE_MEETS_THRESHOLD(count.u64)) {
                return 0;
            }
            break;
        }

        /* record meets threshold; insert it */
        MEMSET_HEAP_NODE(newnode, key, value, distinct);
        if (skHeapInsert(heap, newnode) == SKHEAP_OK) {
            ++limit.value[RWSTATS_COUNT].u64;
        } else {
            /* Cannot grow the heap any more; process remaining
             * records using this fixed heap size */
            rwstatsHeapMemory(newnode);
            /* no more room; get the top element */
            skHeapPeekTop(heap, (skheapnode_t*)top_heap);
        }
    }

    return 0;
}


/*
 *  ok = statsPresorted();
 *
 *    Main control function that reads presorted flow records from
 *    files or stdin and fills the heap.  Returns 0 on success, -1 on
 *    failure.
 */
static int
statsPresorted(
    void)
{
    skheapnode_t top_heap = NULL;

    if (skPresortedUniqueProcess(ps_uniq, presortedEntryCallback, &top_heap)) {
        skAppPrintErr("Unique processing failed");
        return -1;
    }
    if (limit.distinct) {
        value_total = skPresortedUniqueGetTotalDistinctCount(ps_uniq);
    }

    return 0;
}


/*
 *  topnMain();
 *
 *    Function used when the user requests a top-N or bottom-N
 *    calculation.  This function initializes parameters used by the
 *    heap, creates the heap, invokes a function to handle the input
 *    and filling of the heap, and finally prints the heap, and
 *    destroys it.
 */
static void
topnMain(
    void)
{
    uint32_t initial_entries;
    int rv;

    /* set comparison function */
    if (limit.distinct) {
        cmp_fn = &rwstatsCompareDistinctsAny;
    } else {
        switch (DIR_AND_TYPE(direction, limit.fl_id)) {
          case DIR_AND_TYPE(RWSTATS_DIR_TOP, SK_FIELD_RECORDS):
          case DIR_AND_TYPE(RWSTATS_DIR_TOP, SK_FIELD_SUM_BYTES):
          case DIR_AND_TYPE(RWSTATS_DIR_TOP, SK_FIELD_SUM_PACKETS):
            cmp_fn = &rwstatsCompareValuesTop64;
            break;

          case DIR_AND_TYPE(RWSTATS_DIR_BOTTOM, SK_FIELD_RECORDS):
          case DIR_AND_TYPE(RWSTATS_DIR_BOTTOM, SK_FIELD_SUM_BYTES):
          case DIR_AND_TYPE(RWSTATS_DIR_BOTTOM, SK_FIELD_SUM_PACKETS):
            cmp_fn = &rwstatsCompareValuesBottom64;
            break;

          case DIR_AND_TYPE(RWSTATS_DIR_TOP, SK_FIELD_CALLER):
          case DIR_AND_TYPE(RWSTATS_DIR_BOTTOM, SK_FIELD_CALLER):
            cmp_fn = &rwstatsComparePluginAny;
            break;

          default:
            skAbortBadCase(DIR_AND_TYPE(direction, limit.fl_id));
        }
    }

    /* set up the byte lengths and offsets for the heap */
    heap_octets_key = skFieldListGetBufferSize(key_fields);
    heap_octets_value = skFieldListGetBufferSize(value_fields);
    heap_octets_distinct = skFieldListGetBufferSize(distinct_fields);

    heap_octets_node = heap_octets_key+heap_octets_value+heap_octets_distinct;

    /* heap node contains (VALUE, DISTINCT, KEY) */
    heap_offset_value = 0;
    heap_offset_distinct = heap_offset_value + heap_octets_value;
    heap_offset_key = heap_offset_distinct + heap_octets_distinct;

    /* get the initial size of the heap */
    if (RWSTATS_COUNT == limit.type) {
        /* fixed size */
        initial_entries = limit.value[RWSTATS_COUNT].u64;
    } else {
        /* guess the initial size of the heap and allow the heap to
         * grow if the guess is too small */
        initial_entries = HEAP_INITIAL_SIZE;
    }

    /* create the heap */
    heap = skHeapCreate(cmp_fn, initial_entries, heap_octets_node, NULL);
    if (NULL == heap) {
        skAppPrintErr(("Unable to create heap of %" PRIu32
                       " %" PRIu32 "-byte elements"),
                      initial_entries, (uint32_t)heap_octets_node);
        exit(EXIT_FAILURE);
    }

    /* read the flow records and fill the heap */
    if (app_flags.presorted_input) {
        rv = statsPresorted();
    } else {
        rv = statsRandom();
    }
    if (rv) {
        skHeapFree(heap);
        appExit(EXIT_FAILURE);
    }

    /* print the results */
    rwstatsPrintHeap();

    skHeapFree(heap);
}


int main(int argc, char **argv)
{
    int rv = 0;

    /* Global setup */
    appSetup(argc, argv);

    if (proto_stats) {
        rv = protoStatsMain();
    } else {
        topnMain();
    }

    /* Done, do cleanup */
    appTeardown();
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
