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
**  rwpmatch.c
**
**  Filter a tcpdump file by outputting only packets whose 5-tuple and
**  timestamp match corresponding flows in a rw-file.  Outputs the
**  filtered tcpdump file to stdout.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpmatch.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skstream.h>
#include "rwppacketheaders.h"


/* LOCAL DEFINES AND TYPEDEFS */

#define USAGE_FH stdout


/* LOCAL VARIABLES */

static pcap_t *packet_input = NULL;
static skstream_t *flow_input = NULL;
static pcap_dumper_t *packet_match = NULL;

/* Whether to use millisecond precision */
static int use_msec  = 0;

/* Whether to compare the port fields */
static int use_ports = 0;


/* OPTION SETUP */

typedef enum {
    OPT_FLOW_FILE, OPT_USE_MSEC, OPT_USE_PORTS
} appOptionsEnum;


static struct option appOptions[] = {
    {"flow-file",     REQUIRED_ARG, 0, OPT_FLOW_FILE},
    {"msec-compare",  NO_ARG,       0, OPT_USE_MSEC},
    {"ports-compare", NO_ARG,       0, OPT_USE_PORTS},
    {0, 0, 0, 0}  /* sentinel entry */
};


static const char *appHelp[] = {
    "Flow file to use to filter the tcpdump data",
    "Compare flows to the millisecond (instead of second)",
    "Do not consider port data when comparing flows",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData  cData, int opt_index, char *opt_arg);

static int
timecmp_pkt_flow(
    struct timeval     *pkt,
    const rwRec        *flow);
static int
tuples_match(
    struct pcap_pkthdr *hdr,
    const u_char       *pkt,
    const rwRec        *flow);


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
#define USAGE_MSG                                                         \
    ("--flow-file=FILE [SWITCHES]\n"                                      \
     "\tFilter a tcpdump file by writing, to the standard output, the\n"  \
     "\tpackets whose source and destination IP, protocol, timestamp\n"   \
     "\t(and optionally source and destination ports) match SiLK Flow\n"  \
     "\trecords read from the specified file.\n")

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
    static int teardownFlag = 0;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* Close all files */

    if (packet_match) {
        if (-1 == pcap_dump_flush(packet_match)) {
            skAppPrintErr("Error finalizing output file");
        }
        pcap_dump_close(packet_match);
        packet_match = NULL;
    }

    if (packet_input) {
        pcap_close(packet_input);
        packet_input = NULL;
    }

    if (flow_input) {
        skStreamDestroy(&flow_input);
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
    char errbuf[PCAP_ERRBUF_SIZE];
    int arg_index;
    const char *packet_input_path;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char*)) ==
            (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

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
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage(); /* never returns */
    }

    /* must have a flow file */
    if (flow_input == NULL) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_FLOW_FILE].name);
        exit(EXIT_FAILURE);
    }

    /* Will not write binary data to a terminal */
    if (FILEIsATty(stdout)) {
        skAppPrintErr("Will not write binary data to stdout\n"
                      "\twhen it is connected to a terminal");
        exit(EXIT_FAILURE);
    }

    /* verify one and only one PCAP input file; allow "stdin" to have
     * pcap read from the standard input */
    if (argc - arg_index != 1) {
        skAppPrintErr("Must have one and only one input file");
        skAppUsage();           /* never returns */
    }
    if ((0 == strcmp(argv[arg_index], "stdin"))
        || (0 == strcmp(argv[arg_index], "-")))
    {
        if (FILEIsATty(stdin)) {
            skAppPrintErr("Will not read binary data from stdin\n"
                          "\twhen it is connected to a terminal");
            exit(EXIT_FAILURE);
        }
        if ((strcmp(skStreamGetPathname(flow_input), "-") == 0)
            || (strcmp(skStreamGetPathname(flow_input), "stdin") == 0))
        {
            skAppPrintErr("Cannot read both pcap and flow data from stdin");
            exit(EXIT_FAILURE);
        }
        packet_input_path = "-";
    } else {
        packet_input_path = argv[arg_index];
    }

    /* open packet-input file; verify it contains ethernet data */
    packet_input = pcap_open_offline(packet_input_path, errbuf);
    if (packet_input == NULL) {
        skAppPrintErr("Unable to open input file %s: %s", packet_input_path,
                      errbuf);
        exit(EXIT_FAILURE);
    }
    if (DLT_EN10MB != pcap_datalink(packet_input)) {
        skAppPrintErr("Input file %s does not contain Ethernet data",
                      packet_input_path);
        exit(EXIT_FAILURE);
    }

    /* open output */
    packet_match = pcap_dump_open(packet_input, "-");
    if (packet_match == NULL) {
        skAppPrintErr("Error opening stdout for pcap data: %s",
                      pcap_geterr(packet_input));
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

    switch ((appOptionsEnum)opt_index) {
      case OPT_FLOW_FILE:
        /* the input-pipe must be 'stdin' or it must be an existing
         * FIFO.  If 'stdin', stdin must not be a TTY, since we expect
         * binary. */
        if (strcmp(opt_arg, "stdin") == 0) {
            if (FILEIsATty(stdin)) {
                skAppPrintErr("stdin is connected to a terminal.");
                return -1;
            }
        }
        rv = skStreamOpenSilkFlow(&flow_input, opt_arg, SK_IO_READ);
        if (rv) {
            skStreamPrintLastErr(flow_input, rv, &skAppPrintErr);
            skStreamDestroy(&flow_input);
            exit(EXIT_FAILURE);
        }
        break;

      case OPT_USE_MSEC:
        use_msec = 1;
        break;

      case OPT_USE_PORTS:
        use_ports = 1;
        break;
    }

    return 0; /* OK */
}


/*
 * returns:
 *   -1 if packet is earlier than flow
 *   0 if packet and flow occurred at the same time
 *   1 if packet is later than flow
 */
static int
timecmp_pkt_flow(
    struct timeval     *pkt_time,
    const rwRec        *flow)
{
    /* should never get negative entries in timeval, but better safe
       than sorry */
    assert(pkt_time->tv_sec >= 0);
    assert(pkt_time->tv_usec >= 0);

    if (use_msec) {
        sktime_t pkt_msec = sktimeCreateFromTimeval(pkt_time);

        if (pkt_msec < rwRecGetStartTime(flow)) {
            return -1;
        }
        if (pkt_msec > rwRecGetStartTime(flow)) {
            return 1;
        }
    } else {
        /* compare seconds */
        time_t flow_sec = (time_t)(rwRecGetStartTime(flow) / 1000);

        if (pkt_time->tv_sec < flow_sec) {
            return -1;
        }
        if (pkt_time->tv_sec > flow_sec) {
            return 1;
        }
    }

    return 0;
}


/*
 *    Determines if a packet was aggregated into a flow using
 *    rwptoflow.  Returns a true value if they match, a false value
 *    otherwise.
 *
 *    This function assumes that the times have already been found to
 *    be equal.
 */
static int
tuples_match(
    struct pcap_pkthdr *pcaph,
    const uint8_t      *pkt,
    const rwRec        *flow)
{
    /* pointer to the ethernet header inside of 'pkt' */
    eth_header_t *ethh;
    /* pointer to the IP header inside of 'pkt' */
    ip_header_t *iph;
    /* pointer to the tcp-specific header in 'pkt' */
    tcp_header_t *tcph;
    /* the advertised length of the IP header */
    uint32_t iph_len;
    uint32_t len;

    /* Calling code should have checked timestamp */
    assert(timecmp_pkt_flow(&pcaph->ts, flow) == 0);

    /* verify packet is Ethernet */
    len = pcaph->caplen;
    if (len < sizeof(eth_header_t)) {
        return 0;
    }
    ethh = (eth_header_t*)pkt;
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    /*
     * FUTURE: we don't store the ethernet identification field in the
     * flow record, so we can't compare it when going backwards.  we
     * might want to consider storing it in the future.
     */

    /* get the IP header; verify that we have the entire IP header
     * that the version is 4. */
    iph = (ip_header_t*)(pkt + sizeof(eth_header_t));
    len -= sizeof(eth_header_t);
    if (len < sizeof(ip_header_t)) {
        /* short packet */
        return 0;
    }
    if ((iph->ver_ihl >> 4) != 4) {
        /* ignoring non IPv4 packet */
        return 0;
    }

    /* compare saddr, daddr, proto */
    if ((iph->saddr != htonl(rwRecGetSIPv4(flow))) ||
        (iph->daddr != htonl(rwRecGetDIPv4(flow))) ||
        (iph->proto != rwRecGetProto(flow)))
    {
        return 0;
    }

    /* compare the ports for TCP and UDP if requested on unfragmented
     * datagrams or on the zero-packet of fragmented datagrams */
    if (use_ports
        && (iph->proto == 6 || iph->proto == 17)
        && ((ntohs(iph->flags_fo) & IPHEADER_FO_MASK) == 0))
    {
        /* the protocol-specific header begins after the advertised
         * length of the IP header */
        iph_len = (iph->ver_ihl & 0x0F) << 2;
        if (len > iph_len) {
            tcph = (tcp_header_t*)(((u_char*)iph) + iph_len);
            len -= iph_len;
            if (len >= 4) {
                if ((tcph->sport != htons(rwRecGetSPort(flow))) ||
                    (tcph->dport != htons(rwRecGetDPort(flow))))
                {
                    return 0;
                }
            }
        }
    }

    return 1;
}


int main(int argc, char **argv)
{
    /*
     * Flag to tell whether or not we should continue processing
     * files.  0 if processing should continue, 1 if packet flow
     * reached EOF, 2 if flow file reached EOF.  -1 on an error
     * condition.
     */
    int done = 0;

    /*
     * Flag to determine if the latest packet data has been consumed,
     * and a new packet must be read from file.
     */
    int load_next_pkt = 1;

    /*
     * Flag to determine if the latest flow data has been consumed,
     * and a new flow must be read from file.
     */
    int load_next_flow = 1;

    /*
     * Latest packet read from file.
     */
    struct pcap_pkthdr pkt_hdr;
    const u_char *pkt_data = NULL;

    /*
     * Latest flow read from file.
     */
    rwRec flow;

    /*
     * -1 if pkt < flow, 0 if pkt == flow, 1 if pkt > flow
     */
    int ts_compare;


    appSetup(argc, argv);

    while (!done) {
        /* If the current packet data is stale, load the next packet */
        if (load_next_pkt) {
            load_next_pkt = 0;
            pkt_data = pcap_next(packet_input, &pkt_hdr);
            if (pkt_data == NULL) {
                done = 1;
            }
        }

        /* If the current flow data is stale, load the next flow */
        if (load_next_flow) {
            load_next_flow = 0;
            if (SKSTREAM_OK != skStreamReadRecord(flow_input, &flow)) {
                done = 2;
                continue; /* drops out of while loop */
            }
        }

        /*
         * At this point, we are guaranteed that both the packet and
         * flow data is fresh, so compare the records.
         */

        /*
         * If the current packet matches the flow characteristics
         * (5-tuple and timestamp), output the packet.
         */
        ts_compare = timecmp_pkt_flow(&pkt_hdr.ts, &flow);
        if ((ts_compare == 0)
            && tuples_match(&pkt_hdr, pkt_data, &flow))
        {
            pcap_dump((u_char*)packet_match, &pkt_hdr, pkt_data);
            load_next_pkt = 1;
            load_next_flow = 1;
            continue;
        }

        /*
         * The packet and flow didn't match.
         */
        if (ts_compare <= 0) {
            /*
             * If the packet data has an earlier timestamp (or equal,
             * but the 5-tuple didn't match), then the current packet
             * does not exist in the flow file, so it can be skipped.
             * Keep the same flow record, and try the next packet.
             */
            load_next_pkt = 1;
        } else {
            /*
             * If the packet data has a later timestamp, then the flow
             * contains an entry which was not derived from this
             * packet data.  Report an error, and exit.
             */
            skAppPrintErr("Found a flow which does not have "
                           "corresponding packet data.  Exitting.");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
