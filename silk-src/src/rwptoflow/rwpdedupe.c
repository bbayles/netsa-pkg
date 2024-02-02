/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  rwpdedupe.c
**
**  Detects and eliminates duplicate records.  Duplicate records are
**  defined as having the same 5-tuple and payload, and whose
**  timestamps are within a user-configurable amount of time of each
**  other.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpdedupe.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwppacketheaders.h"
#include <silk/skdllist.h>


/* LOCAL DEFINES AND TYPEDEFS */

#define USAGE_FH stdout

typedef struct pcap_pkt_st {
    struct pcap_pkthdr hdr;
    const u_char *data;
} pcap_pkt_t;

typedef struct input_st {
    struct timeval *min; /* cache of earliest timestamp on list */
    struct timeval *max; /* cache of latest timestamp on list */
    sk_dllist_t    *head; /* list of packets buffered from input */
    int eof; /* if 0, keep reading.  otherwise, done with stream */
} input_t;

/*
 * Provide timeradd and timercmp macros, in case they are not defined
 * on a particular platform.
 */

/* struct timeval 'vvp' = struct timeval 'tvp' + struct timeval 'uvp' */
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                 \
    do {                                                        \
        (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
        (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
        if ((vvp)->tv_usec >= 1000000) {                        \
            (vvp)->tv_sec++;                                    \
            (vvp)->tv_usec -= 1000000;                          \
        }                                                       \
    } while (0)
#endif

#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                 \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?         \
     ((tvp)->tv_usec cmp (uvp)->tv_usec) :      \
     ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif


#define ASSERT_MEM(mem_object)                  \
    if (NULL != (mem_object)) { } else {        \
        skAppPrintOutOfMemory(#mem_object);     \
        exit(EXIT_FAILURE);                     \
    }

#ifdef NDEBUG
#  define ASSERT_DLL(dll_call)   dll_call
#else
#  define ASSERT_DLL(dll_call)                  \
    do {                                        \
        int dll_call_rv = (dll_call);           \
        assert(0 == dll_call_rv);               \
    } while (0)
#endif  /* #else of #ifdef NDEBUG */


/* LOCAL VARIABLES */

enum selectionHeuristic {
    DUPE_SELECT_INVALID,
    DUPE_SELECT_FIRST,
    DUPE_SELECT_RANDOM
};

static struct timeval g_duplicate_margin;
static pcap_t **g_inputs = NULL;
static int g_input_count = 0;
static pcap_t *g_output = NULL;
static pcap_dumper_t *g_output_dumper = NULL;
static int g_selection_heuristic = DUPE_SELECT_INVALID;


/* OPTION SETUP */

enum appOptionEnum {
    RWPTOFLOW_OPT_THRESHOLD,
    RWPTOFLOW_OPT_SELECT_FIRST,
    RWPTOFLOW_OPT_SELECT_RANDOM
};

static struct option appOptions[] = {
    {"threshold",        REQUIRED_ARG, 0, RWPTOFLOW_OPT_THRESHOLD},
    {"first-duplicate",  NO_ARG,       0, RWPTOFLOW_OPT_SELECT_FIRST},
    {"random-duplicate", OPTIONAL_ARG, 0, RWPTOFLOW_OPT_SELECT_RANDOM},
    {0,0,0,0}            /* sentinel entry */
};

static const char *appHelp[] = {
    ("Millisecond timeframe in which duplicate packets are\n"
     "\tdetected. Def. 0"),
    "Select earliest timestamp among duplicates.  Default",
    ("Select random timestamp among duplicates.\n"
     "\tOptionally takes a value as a random number seed"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void
bufferInputList(
    input_t            *buffer,
    int                 idx);
static void
checkDuplicates(
    input_t            *buffer,
    int                 basis_index);
static struct timeval *
getListMinTimestamp(
    input_t            *buffers,
    int                 idx);
static struct timeval *
getListMaxTimestamp(
    input_t            *buffers,
    int                 idx);
static int
isDuplicatePacket(
    pcap_pkt_t         *early,
    pcap_pkt_t         *later);
static pcap_pkt_t *
selectDuplicate(
    sk_dllist_t        *dupes);


/* FUNCTION DEFINITIONS */

/*
 *  appUsageLong();
 *
 *    Print complete usage information to USAGE_FH.  Pass this
 *    function to skOptionsSetUsageCallback(); skOptionsParse() will
 *    call this funciton and then exit the program when the --help
 *    option is given.
 */
static void
appUsageLong(
    void)
{
#define USAGE_MSG                                                       \
    ("<SWITCHES>\n"                                                     \
     "\tDetects and eliminates duplicate records.  Duplicate\n"         \
     "\trecords are defined as having the same 5-tuple and payload,\n"  \
     "\tand whose timestamps are within a user-configurable amount\n"   \
     "\tof time of each other.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
}


/*
 *  appTeardown()
 *
 *    Teardown all modules, close all files, and tidy up all
 *    application state.
 *
 *    This function is idempotent.
 */
static void
appTeardown(
    void)
{
    static uint8_t teardownFlag = 0;
    int i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close inputs */
    if (g_inputs) {
        for (i = 0; i < g_input_count; ++i) {
            if (g_inputs[i]) {
                pcap_close(g_inputs[i]);
            }
        }
        free(g_inputs);
    }

    /* close output */
    if (g_output_dumper) {
        pcap_dump_close(g_output_dumper);
    }

    skAppUnregister();
}


/*
 *  appSetup(argc, argv);
 *
 *    Perform all the setup for this application include setting up
 *    required modules, parsing options, etc.  This function should be
 *    passed the same arguments that were passed into main().
 *
 *    Returns to the caller if all setup succeeds.  If anything fails,
 *    this function will cause the application to exit with a FAILURE
 *    exit status.
 */
static void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int i;
    int j;
    char errbuf[PCAP_ERRBUF_SIZE];
    int arg_index;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char*)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize duplicate margin */
    memset(&g_duplicate_margin, 0, sizeof (struct timeval));

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse options */
    if ((arg_index = skOptionsParse(argc, argv)) < 0) {
        skAppUsage(); /* never returns */
    }

    if (g_selection_heuristic == DUPE_SELECT_INVALID) {
        skAppPrintErr("Must select either --first-duplicate or "
                      "--random-duplicate");
        exit(EXIT_FAILURE);
    }

    /*
     * Open input files
     */
    g_input_count = argc - arg_index;
    if (g_input_count < 2) {
        skAppPrintErr("Two or more inputs required");
        exit(EXIT_FAILURE);
    }
    g_inputs = (pcap_t **)malloc(sizeof (pcap_t *) * g_input_count);
    ASSERT_MEM(g_inputs);

    for (i = arg_index, j = 0; i < arg_index + g_input_count; ++i, ++j) {
        g_inputs[j] = pcap_open_offline(argv[i], errbuf);
        if (g_inputs[j] == NULL) {
            skAppPrintErr("Error opening input %s: %s", argv[i],
                          errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /*
     * Open output file
     */
    if (FILEIsATty(stdout)) {
        skAppPrintErr("stdout is connected to a terminal");
        exit(EXIT_FAILURE);
    }


    /* XXX - we should probably check all the datalink and snaplens of
       input files and make sure they match up.  if they don't, throw
       an error?  or somehow pick the 'correct' or l.c.d. value? */
    g_output = pcap_open_dead(pcap_datalink(g_inputs[0]),
                              pcap_snapshot(g_inputs[0]));
    if (g_output == NULL) {
        skAppPrintErr("Error opening stdout: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    g_output_dumper = pcap_dump_open(g_output, "-");
    if (g_output_dumper == NULL) {
        skAppPrintErr("Error opening stdout: %s", pcap_geterr(g_output));
        exit(EXIT_FAILURE);
    }

    return; /* OK */
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    This function is passed to skOptionsRegister(); it will be called
 *    by skOptionsParse() for each user-specified switch that the
 *    application has registered; it should handle the switch as
 *    required---typically by setting global variables---and return 1
 *    if the switch processing failed or 0 if it succeeded.  Returning
 *    a non-zero from from the handler causes skOptionsParse() to return
 *    a negative value.
 *
 *    The clientData in 'cData' is typically ignored; 'opt_index' is
 *    the index number that was specified as the last value for each
 *    struct option in appOptions[]; 'opt_arg' is the user's argument
 *    to the switch for options that have a REQUIRED_ARG or an
 *    OPTIONAL_ARG.
 */
static int
appOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    int rv;
    uint32_t temp;

    switch (opt_index) {
      case RWPTOFLOW_OPT_THRESHOLD:
        rv = skStringParseUint32(&temp, opt_arg, 0, 1000000);
        if (rv) {
            goto PARSE_ERROR;
        }
        /* convert to microseconds */
        temp *= 1000;
        g_duplicate_margin.tv_sec = temp / 1000000;
        g_duplicate_margin.tv_usec = temp % 1000000;
        break;

      case RWPTOFLOW_OPT_SELECT_FIRST:
        if (g_selection_heuristic != DUPE_SELECT_INVALID) {
            skAppPrintErr("Only one duplicate selection option allowed.");
            return 1;
        }
        g_selection_heuristic = DUPE_SELECT_FIRST;
        break;

      case RWPTOFLOW_OPT_SELECT_RANDOM:
        if (g_selection_heuristic != DUPE_SELECT_INVALID) {
            skAppPrintErr("Only one duplicate selection option allowed.");
            return 1;
        }
        g_selection_heuristic = DUPE_SELECT_RANDOM;
        if (opt_arg) {
            rv = skStringParseUint32(&temp, opt_arg, 0, 0);
            if (rv != 0) {
                goto PARSE_ERROR;
            }
            srandom(temp);
        } else {
            int r;
            r = rand();
            srandom((u_int) r);
        }
        break;
    }

    return 0; /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 * read packets from g_inputs[index] into buffer inputs[index].  fill
 * the buffer until we run out of records, or the last packet read is
 * later than the first packet in the buffer plus the duplicate
 * margin.
 *
 * Note: we malloc() space for every new packet in the buffer.  If
 * performance gets slow, use a circular buffer instead.
 */
static void
bufferInputList(
    input_t            *buffer,
    int                 idx)
{
    int f_read_packets = 1;

    struct timeval cutoff; /* new cutoff to read packets until */
    struct timeval *min_ts = NULL; /* earliest timestamp on list */
    struct timeval *max_ts = NULL; /* latest timestamp on list */

    assert(buffer != NULL);
    assert(idx >= 0);
    assert(idx < g_input_count);

    /* do nothing if the stream has dried up or failed in some way */
    if (buffer[idx].eof == 1) {
        return;
    }

    /* read more packets until the last packet read is past the cutoff */
    while (f_read_packets) {

        /* calculate the cutoff point for packets to be read */
        min_ts = getListMinTimestamp(buffer, idx);

        f_read_packets = 0;
        if (min_ts == NULL) {
            f_read_packets = 1;
        } else {
            timeradd(min_ts, &g_duplicate_margin, &cutoff);
            max_ts = getListMaxTimestamp(buffer, idx);
            if (max_ts && timercmp(&cutoff, max_ts, <)) {
                f_read_packets = 1;
            }
        }

        if (f_read_packets == 1) {
            pcap_pkt_t *cur_pkt;
            cur_pkt = (pcap_pkt_t *) malloc(sizeof(pcap_pkt_t));
            ASSERT_MEM(cur_pkt);
            cur_pkt->data = pcap_next(g_inputs[idx], &cur_pkt->hdr);
            if (cur_pkt->data == NULL) {
                /* cannot read more records from input */
                buffer[idx].eof = 1;
                free(cur_pkt);
                return; /* do not read any more packets for this input */
            } else {
                if (skDLListPushTail(buffer[idx].head, (void *) cur_pkt)) {
                    skAppPrintOutOfMemory("list entry");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}


static void
checkDuplicates(
    input_t            *buffer,
    int                 basis_index)
{
    sk_dllist_t *dupes = NULL;

    pcap_pkt_t *basis;

    sk_dll_iter_t comp_node;
    pcap_pkt_t *comp;

    int i;

    /* get the packet to be used as the basis for comparison */
    ASSERT_DLL(skDLListPopHead(buffer[basis_index].head, (void **)&basis));

    comp = NULL;
    for (i = 0; i < g_input_count; ++i) {
        /* do not check for duplicates on the same input stream */
        if (i == basis_index) {
            continue;
        }

        /* compare and get next packet, continue until out of
           packets */
        skDLLAssignIter(&comp_node, buffer[i].head);
        while (skDLLIterForward(&comp_node, (void **)&comp) == 0) {
            if (isDuplicatePacket(basis, comp)) {
                /* allocate list to track duplicates if one doesn't
                   exist */
                if (dupes == NULL) {
                    dupes = skDLListCreate(free);
                    ASSERT_MEM(dupes);

                    /* add basis packet to new list */
                    if (skDLListPushTail(dupes, (void *) basis)) {
                        skAppPrintOutOfMemory("list entry");
                        exit(EXIT_FAILURE);
                    }
                }

                /* add duplicate packet to list */
                if (skDLListPushTail(dupes, (void *) comp)) {
                    skAppPrintOutOfMemory("list entry");
                    exit(EXIT_FAILURE);
                }

                /* remove duplicate from its buffer */
                ASSERT_DLL(skDLLIterDel(&comp_node));
            }
        }
    }

    /*
     * Remove the basis-for-comparison list node
     */
    buffer[basis_index].min = NULL;

    /*
     * Output the appropriate packet
     */
    if (dupes == NULL) {
        /* no duplicates, output the basis packet */
        pcap_dump((u_char *) g_output_dumper, &basis->hdr, basis->data);

        /*
         * Free the data for the basis-for-comparison packet
         */
        free(basis);
    } else {
        pcap_pkt_t *selected = selectDuplicate(dupes);
        pcap_dump((u_char *) g_output_dumper, &selected->hdr,
                  selected->data);
        skDLListDestroy(dupes);
        /* The basis data is freed as part of this, since it is on the
           dupes list */
    }

}



/*
 * Get the minimum timestamp for a particular input buffer.  Caches
 * the timestamp in list->min.  Returns NULL if the timestamp cannot
 * be found (for example, if the list is empty).
 */
static struct timeval *
getListMinTimestamp(
    input_t            *buffers,
    int                 idx)
{
    pcap_pkt_t *pkt;

    assert(buffers != NULL);
    assert(idx >= 0);
    assert(idx < g_input_count);

    if (skDLListPeekHead(buffers[idx].head, (void **)&pkt)) {
        return NULL;
    }

    return &pkt->hdr.ts;
}


/*
 * Same as getListMinTimestamp(), except that it gets the latest
 * timestamp for a particular input buffer.
 */
static struct timeval *
getListMaxTimestamp(
    input_t            *buffers,
    int                 idx)
{
    pcap_pkt_t *pkt;

    assert(buffers != NULL);
    assert(idx >= 0);
    assert(idx < g_input_count);

    if (skDLListPeekTail(buffers[idx].head, (void **)&pkt)) {
        return NULL;
    }

    return &pkt->hdr.ts;
}



/*
 * Determines if two packets are duplicates of one another.  Two
 * packets are considered duplicates if:
 *
 * * Their timestamps occur within 'g_duplicate_margin' of each
 * other.
 *
 * * Their ethernet headers match.
 *
 * * If they aren't IP packets, then the entire ethernet payload
 * matches.
 *
 * * If they are IP packets, then their source addresses, destination
 * addresses, protocols, and IP payloads match.
 */
static int
isDuplicatePacket(
    pcap_pkt_t         *early,
    pcap_pkt_t         *later)
{
    struct timeval ts;
    eth_header_t *eh_early;
    eth_header_t *eh_later;
    ip_header_t *ih_early;
    ip_header_t *ih_later;

    u_int ip_offset_early;
    u_int ip_offset_later;
    u_int ip_size_early;
    u_int ip_size_later;

    const u_char *payload_early;
    const u_char *payload_later;

    /*
     * If the timestamp is not within g_duplicate_margin, then it is
     * not a duplicate.
     */
    timeradd(&early->hdr.ts, &g_duplicate_margin, &ts);
    if (timercmp(&ts, &later->hdr.ts, <)) {
        return 0;
    }

    /*
     * compare ethernet header
     */
    eh_early = (eth_header_t *) early->data;
    eh_later = (eth_header_t *) later->data;
    if (0 != memcmp(eh_early, eh_later, sizeof (eth_header_t))) {
        return 0;
    }

    if (ntohs(eh_early->ether_type) != 0x0800) {
        /* it is a non-IP packet */
        /* make sure the packets are the same length. */
        if (early->hdr.len != later->hdr.len) {
            return 0;
        }

        /* compare as much of each packet captured as we can */
        if (0 != memcmp(early->data, later->data,
                        ((early->hdr.caplen < later->hdr.caplen)
                         ? early->hdr.caplen
                         : later->hdr.caplen)))
        {
            return 0;
        }
    } else {
        /* it is an IP packet */

        /* retrieve the position of the ip header (add length of
           ethernet header) */
        ih_early = (ip_header_t *) (early->data +
                                    sizeof (eth_header_t));
        ih_later = (ip_header_t *) (later->data +
                                    sizeof (eth_header_t));

        /* compare size, saddr, daddr, proto */
        if ((ih_early->saddr != ih_later->saddr) ||
            (ih_early->daddr != ih_later->daddr) ||
            (ih_early->proto != ih_later->proto))
        {
            return 0;
        }

        /* compare IP payloads */
        ip_offset_early = (ih_early->ver_ihl & 0xf) * 4;
        ip_offset_later = (ih_later->ver_ihl & 0xf) * 4;
        payload_early = (early->data + sizeof (eth_header_t) +
                         ip_offset_early);
        payload_later = (later->data + sizeof (eth_header_t) +
                         ip_offset_later);
        ip_size_early = (early->hdr.caplen -
                         (u_int) sizeof (eth_header_t) -
                         ip_offset_early);
        ip_size_later = (later->hdr.caplen -
                         (u_int) sizeof (eth_header_t) -
                         ip_offset_later);

        if (0 != memcmp((void *) payload_early, (void *) payload_later,
                        ((ip_size_early < ip_size_later)
                         ? ip_size_early
                         : ip_size_later)))
        {
            return 0;
        }
    }

    return 1;
}



static pcap_pkt_t *
selectDuplicate(
    sk_dllist_t        *dupes)
{
    sk_dll_iter_t node;
    pcap_pkt_t *pkt;
    double chance;
    double value;
    int count;
    int r;

    switch (g_selection_heuristic) {
      case DUPE_SELECT_FIRST:
        /* default to selecting the first packet */
        ASSERT_DLL(skDLListPeekHead(dupes, (void **)&pkt));
        break;

      case DUPE_SELECT_RANDOM:
        skDLLAssignIter(&node, dupes);
        count = 0;
        while (skDLLIterForward(&node, NULL) == 0) {
            count++;
            chance = 1.0 / count;

            r = rand();
            value = (double)r / RAND_MAX;

            if (value <= chance) {
                ASSERT_DLL(skDLLIterValue(&node, (void **)&pkt));
            }
        }
        assert(count > 0);
        break;

      default:
        skAbortBadCase(g_selection_heuristic);
    }

    return pkt;
}


int main(int argc, char **argv)
{
    int i;
    int j;

    /*
     * 'candidates' is an array where each element corresponds to a
     * particular input source (each input source should be a
     * different sensor).  Each element is a list which is a buffer of
     * packets read from that input source, sorted by time.
     *
     * In order to detect duplicates for a packet, all packets within
     * 'g_duplicate_margin' (the user-defined duplicate detection
     * window) must be loaded onto the list for comparison.
     *
     * In addition, 'candidates' contains metadata on each stream, for
     * example, an EOF flag indicating if more records should be read.
     */
    input_t *candidates;

    /* 'min_index' is the file index in the range [0,g_input_count) of
     * the data stream containing the packet with the earliest
     * timestamp which has not yet been written to output or discarded
     * as a duplicate.  A value of -1 means that the earliest packet
     * has not been calculated yet (because we are just starting, or
     * because the last "earliest packet" was written).
     */
    int min_index;

    appSetup(argc, argv);

    /* Allocate the duplicate packet candidate array and lists */
    candidates = (input_t *) malloc(sizeof (input_t) * g_input_count);
    if (candidates == NULL) {
        skAppPrintErr("Memory error creating input buffer");
        exit(EXIT_FAILURE);
    }
    memset(candidates, 0, sizeof (input_t) * g_input_count);
    for (i = 0; i < g_input_count; ++i) {
        candidates[i].head = skDLListCreate(free);
        if (candidates[i].head == NULL) {
            skAppPrintErr("Memory error creating buffer %d", i);
            exit(EXIT_FAILURE);
        }
    }

    /* loop until no minimum packet is found (when there are no more
       packets), and then break. */
    for (;;) {
        min_index = -1;
        for (j = 0; j < g_input_count; ++j) {
            struct timeval *cur;

            /* Step 1: Read all packets within 'g_duplicate_margin'
               for each input source.  It is okay to have extra
               packets which fall outside the margin, but it is not
               okay to load too few packets.  When an input stream
               runs out of packets, set its EOF flag so we skip it
               from there on out. */
            bufferInputList(candidates, j);

            /*
             * Step 2: Get the earliest packet among all lists.
             */
            cur = getListMinTimestamp(candidates, j);
            if (cur != NULL) {
                if (min_index == -1) {
                    min_index = j;
                } else {
                    struct timeval *min;
                    min = getListMinTimestamp(candidates, min_index);
                    if (timercmp(cur, min, <)) {
                        min_index = j;
                    }
                }
            }
        }

        /*
         * If there are no more packets in any buffers, and all input
         * streams have flagged EOF, then we are done.
         */
        if (min_index == -1) {
            break;
        }


        /*
         * Step 3: Using the earliest packet as the basis for
         * comparison, check all other input streams for duplicate
         * packets.  If no duplicate packets are found, output the
         * basis packet.  If duplicate packets are found, select one
         * according to the user-selected heuristic and output it.
         * Remove all duplicate packets from their input stream
         * (including the one used as a basis for the comparison)
         */
        checkDuplicates(candidates, min_index);
    }

    free(candidates);

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
