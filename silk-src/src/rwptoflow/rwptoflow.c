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
**  rwptoflow.c
**
**    Generates a flow for every IP packet.  Since IP packets can
**    arrive out of order, though, some fragments are collapsed into a
**    single flow.  (In particular, all fragments before the "zero"
**    fragment are lumped into the "zero" fragment's flow.  Later
**    fragments are output as their own flows.  We do this so that we
**    can add OSI layer 4 information to the flows we generate, like
**    source and destination ports.)
**
**    Future development:
**
**    In the event that the zero fragment is too small to contain TCP
**    flags, attempt to get them from the next fragment.  This will
**    require more sophisticated fragment reassembly.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwptoflow.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skplugin.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include "rwppacketheaders.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* where to print the statistics */
#define STATS_STREAM stderr


/* LOCAL VARIABLES */

/*
 * rwptoflow hands the packet to the plugin as an "extra argument".
 * rwptoflow and its plugins must agree on the name of this argument.
 * The extra argument is specified in a NULL-terminated array of
 * argument names defined in rwppacketheaders.h.
 */
static const char *plugin_extra_args[] = RWP2F_EXTRA_ARGUMENTS;

/* the packet file to read */
static const char *packet_input_path = NULL;
static pcap_t *packet_input = NULL;

/* the flow file to write */
static skstream_t *flow_output = NULL;

/* the compression method to use when writing the flow_output file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* the optional packet file to write for packets that pass */
static const char *packet_pass_path = NULL;
static pcap_dumper_t *packet_pass = NULL;

/* the optional packet file to write for packets that reject */
static const char *packet_reject_path = NULL;
static pcap_dumper_t *packet_reject = NULL;

/* time window over which to process data */
static struct time_window_st {
    struct timeval tw_begin;
    struct timeval tw_end;
} time_window;

/* default values to insert into each SiLK Flow */
static rwRec default_flow_values;

/* whether to ignore all fragmented packets; whether to ignore
 * fragmented packets other than the initial one */
static int reject_frags_all = 0;
static int reject_frags_subsequent = 0;

/* whether to ignore packets where either the fragment or the capture
 * size is too small to gather the port information for TCP, UPD,
 * ICMP---and the flags information for TCP. */
static int reject_incomplete = 0;

/* statistics counters and whether to print them */
static struct statistics_st {
    /* total number of packets read */
    uint64_t    s_total;
    /* packets that were too short to get any information from */
    uint64_t    s_short;
    /* packets that were not Ethernet_IP or non-IPv4 packets */
    uint64_t    s_nonipv4;
    /* packets that occurred outside the time window */
    uint64_t    s_prewindow;
    uint64_t    s_postwindow;
    /* packets that were fragmented */
    uint64_t    s_fragmented;
    /* packets that were the initial packet of a fragment */
    uint64_t    s_zerofrag;
    /* packets that the user's plug-in ignored and rejected */
    uint64_t    s_plugin_ign;
    uint64_t    s_plugin_rej;
    /* packets that were long enough to get most info but too short to
     * get the ports---and/or flags for TCP */
    uint64_t    s_incomplete;
} statistics;

static int print_statistics = 0;

/* value passed to pcap_open for stdin/stdout */
static const char *pcap_stdio = "-";

/* buffer for pcap error messages */
static char errbuf[PCAP_ERRBUF_SIZE];


/* OPTION SETUP */

typedef enum {
    OPT_PLUGIN,
    OPT_ACTIVE_TIME,
    OPT_FLOW_OUTPUT,
    OPT_PACKET_PASS_OUTPUT,
    OPT_PACKET_REJECT_OUTPUT,
    OPT_REJECT_ALL_FRAGMENTS,
    OPT_REJECT_NONZERO_FRAGMENTS,
    OPT_REJECT_INCOMPLETE,
    OPT_SET_SENSORID,
    OPT_SET_INPUTINDEX,
    OPT_SET_OUTPUTINDEX,
    OPT_SET_NEXTHOPIP,
    OPT_PRINT_STATISTICS
} appOptionsEnum;


static struct option appOptions[] = {
    {"plugin",                  REQUIRED_ARG, 0, OPT_PLUGIN},
    {"active-time",             REQUIRED_ARG, 0, OPT_ACTIVE_TIME},
    {"flow-output",             REQUIRED_ARG, 0, OPT_FLOW_OUTPUT},
    {"packet-pass-output",      REQUIRED_ARG, 0, OPT_PACKET_PASS_OUTPUT},
    {"packet-reject-output",    REQUIRED_ARG, 0, OPT_PACKET_REJECT_OUTPUT},
    {"reject-all-fragments",    NO_ARG,       0, OPT_REJECT_ALL_FRAGMENTS},
    {"reject-nonzero-fragments",NO_ARG,       0, OPT_REJECT_NONZERO_FRAGMENTS},
    {"reject-incomplete",       NO_ARG,       0, OPT_REJECT_INCOMPLETE},
    {"set-sensorid",            REQUIRED_ARG, 0, OPT_SET_SENSORID},
    {"set-inputindex",          REQUIRED_ARG, 0, OPT_SET_INPUTINDEX},
    {"set-outputindex",         REQUIRED_ARG, 0, OPT_SET_OUTPUTINDEX},
    {"set-nexthopip",           REQUIRED_ARG, 0, OPT_SET_NEXTHOPIP},
    {"print-statistics",        NO_ARG,       0, OPT_PRINT_STATISTICS},
    {0,0,0,0}                   /* sentinel entry */
};


static const char *appHelp[] = {
    "Use given plug-in. Def. None",
    ("Only generate flows for packets whose time falls within\n"
     "\tthe specified range.  Def. Generate flows for all packets\n"
     "\tYYYY/MM/DD:hh:dd:mm:ss.uuuuuu-YYYY/MM/DD:hh:dd:mm:ss.uuuuuu"),
    ("Write the generated SiLK Flow records to the specified\n"
     "\tstream or file path. Def. stdout"),
    ("For each generated flow, write its corresponding\n"
     "\tpacket to the specified path.  Def. No"),
    ("Write each packet that occurs within the\n"
     "\tactive-time window but for which a SiLK Flow is NOT generated to\n"
     "\tthe specified path. Def. No"),
    ("Do not generate a SiLK Flow when the packet is\n"
     "\tfragmented. Def. All packets"),
    ("Do not generate SiLK Flows for packets where\n"
     "\tthe fragment-offset is non-zero. Def. All packets"),
    ("Do not generate SiLK Flows for zero-fragment or\n"
     "\tunfragmented packets when the flow cannot be completely filled\n"
     "\t(missing ICMP type&code, TCP/UDP ports, TCP flags). Def. All packets"),
    "Set sensor ID for all flows, 0-65534. Def. 0",
    "Set SNMP input index for all flows, 0-65535. Def. 0",
    "Set SNMP output index for all flows, 0-65535. Def. 0",
    "Set next hop IP address for all flows. Def. 0.0.0.0",
    ("Print the count of packets read, packets processed,\n"
     "\tand bad packets to the standard error"),
    (char*)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);


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
    ("[SWITCHES] TCPDUMP_FILE\n"                                        \
     "\tRead packet capture data from TCPDUMP_FILE and attempt to generate\n" \
     "\ta SiLK Flow record for every packet; use \"stdin\" to read the\n" \
     "\tpackets from the standard input.  Write the SiLK Flows to the\n" \
     "\tnamed flow-output path or to the standard output if it is not\n" \
     "\tconnected to a terminal.\n")

    FILE *fh = USAGE_FH;
    int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);

    skPluginOptionsUsage(fh);
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
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    skPluginRunCleanup(SKPLUGIN_APP_TRANSFORM);
    skPluginTeardown();

    /*
     * Close all files
     */

    /* flow output */
    if (flow_output) {
        rv = skStreamClose(flow_output);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(flow_output, rv, &skAppPrintErr);
        }
        skStreamDestroy(&flow_output);
    }

    /* packet output */
    if (packet_pass) {
        if (-1 == pcap_dump_flush(packet_pass)) {
            skAppPrintErr("Error finalizing %s file '%s'",
                          appOptions[OPT_PACKET_PASS_OUTPUT].name,
                          packet_pass_path);
        }
        pcap_dump_close(packet_pass);
        packet_pass = NULL;
    }
    if (packet_reject) {
        if (-1 == pcap_dump_flush(packet_reject)) {
            skAppPrintErr("Error finalizing %s file '%s'",
                          appOptions[OPT_PACKET_REJECT_OUTPUT].name,
                          packet_reject_path);
        }
        pcap_dump_close(packet_reject);
        packet_reject = NULL;
    }

    /* packet input */
    if (packet_input) {
        pcap_close(packet_input);
        packet_input = NULL;
    }

    skOptionsNotesTeardown();
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
    int rv;
    int arg_index;
    int stdout_used = 0;
    sk_file_header_t *hdr;
#ifdef SILK_CLOBBER_ENVAR
    const char *clobber_env = getenv(SILK_CLOBBER_ENVAR);
#endif

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&statistics, 0, sizeof(statistics));
    memset(&time_window, 0, sizeof(time_window));
    memset(&default_flow_values, 0, sizeof(default_flow_values));
    rwRecSetPkts(&default_flow_values, 1);
    rwRecSetSensor(&default_flow_values, SK_INVALID_SENSOR);

    skPluginSetup(1, SKPLUGIN_APP_TRANSFORM);
    skPluginSetAppExtraArgs(plugin_extra_args);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method))
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
        skAppUsage();           /* never returns */
    }

    /* verify one and only one input file; allow "stdin" to have pcap
     * read from the standard input */
    if ((argc - arg_index) != 1) {
        skAppPrintErr("Must have one and only one input file");
        skAppUsage();           /* never returns */
    }
    packet_input_path = argv[arg_index];
    if ((0 == strcmp(packet_input_path, "stdin"))
        || (0 == strcmp(packet_input_path, "-")))
    {
        if (FILEIsATty(stdin)) {
            skAppPrintErr("Will not read binary data from stdin\n"
                          "\twhen it is connected to a terminal");
            exit(EXIT_FAILURE);
        }
        packet_input_path = pcap_stdio;
    }

    /* verify that multiple outputs are not using stdout */
    if (flow_output == NULL) {
        ++stdout_used;
        if ((rv = skStreamCreate(&flow_output, SK_IO_WRITE,
                                 SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(flow_output, "stdout")))
        {
            skStreamPrintLastErr(flow_output, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }
    if (packet_pass_path) {
        if ((0 == strcmp(packet_pass_path, "stdout"))
            || (0 == strcmp(packet_pass_path, "-")))
        {
            ++stdout_used;
            packet_pass_path = pcap_stdio;
#ifdef SILK_CLOBBER_ENVAR
        } else if (clobber_env != NULL && *clobber_env && *clobber_env != '0'){
            /* overwrite existing files */
#endif
        } else if (skFileExists(packet_pass_path)) {
            skAppPrintErr("The %s '%s' exists.  Will not overwrite it.",
                          appOptions[OPT_PACKET_PASS_OUTPUT].name,
                          packet_pass_path);
            exit(EXIT_FAILURE);
        }
    }
    if (packet_reject_path) {
        if ((0 == strcmp(packet_reject_path, "stdout"))
            || (0 == strcmp(packet_reject_path, "-")))
        {
            ++stdout_used;
            packet_reject_path = pcap_stdio;
#ifdef SILK_CLOBBER_ENVAR
        } else if (clobber_env != NULL && *clobber_env && *clobber_env != '0'){
            /* overwrite existing files */
#endif
        } else if (skFileExists(packet_reject_path)) {
            skAppPrintErr("The %s '%s' exists.  Will not overwrite it.",
                          appOptions[OPT_PACKET_REJECT_OUTPUT].name,
                          packet_reject_path);
            exit(EXIT_FAILURE);
        }
    }
    if (stdout_used > 1) {
        skAppPrintErr("Multiple binary outputs are using standard output");
        exit(EXIT_FAILURE);
    }
    if (stdout_used && FILEIsATty(stdout)) {
        skAppPrintErr("Will not write binary data to stdout\n"
                      "\twhen it is connected to a terminal");
        exit(EXIT_FAILURE);
    }

    if (skPluginRunInititialize(SKPLUGIN_APP_TRANSFORM) != SKPLUGIN_OK) {
        skAppPrintErr("Unable to initialize plugins");
        exit(EXIT_FAILURE);
    }

    /* open packet-input file; verify it contains ethernet data */
    packet_input = pcap_open_offline(packet_input_path, errbuf);
    if (packet_input == NULL) {
        skAppPrintErr("Error opening input %s: %s",
                      packet_input_path, errbuf);
        exit(EXIT_FAILURE);
    }
    if (DLT_EN10MB != pcap_datalink(packet_input)) {
        skAppPrintErr("Input file %s does not contain Ethernet data",
                      packet_input_path);
        exit(EXIT_FAILURE);
    }

    /* open the packet output file(s), if any */
    if (packet_pass_path) {
        packet_pass = pcap_dump_open(packet_input, packet_pass_path);
        if (packet_pass == NULL) {
            skAppPrintErr("Error opening %s file '%s': %s",
                          appOptions[OPT_PACKET_PASS_OUTPUT].name,
                          packet_pass_path,
                          pcap_geterr(packet_input));
            exit(EXIT_FAILURE);
        }
    }
    if (packet_reject_path) {
        packet_reject = pcap_dump_open(packet_input, packet_reject_path);
        if (packet_reject == NULL) {
            skAppPrintErr("Error opening %s file '%s': %s",
                          appOptions[OPT_PACKET_REJECT_OUTPUT].name,
                          packet_reject_path,
                          pcap_geterr(packet_input));
            exit(EXIT_FAILURE);
        }
    }

    /* open the flow-output file */
    hdr = skStreamGetSilkHeader(flow_output);
    rv = skHeaderSetCompressionMethod(hdr, comp_method);
    if (rv == SKSTREAM_OK) {
        rv = skOptionsNotesAddToStream(flow_output);
    }
    if (rv == SKSTREAM_OK) {
        rv = skHeaderAddInvocation(hdr, 1, argc, argv);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamOpen(flow_output);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamWriteSilkHeader(flow_output);
    }
    if (rv != SKSTREAM_OK) {
        skStreamPrintLastErr(flow_output, rv, &skAppPrintErr);
        skStreamDestroy(&flow_output);
        exit(EXIT_FAILURE);
    }

    return;                     /* OK */
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
    sktime_t begin_time;
    sktime_t end_time;
    skipaddr_t ip;
    imaxdiv_t t_div;
    uint32_t temp;
    unsigned int precision;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1)) {
            skAppPrintErr("Fatal error loading plug-in '%s'", opt_arg);
            return 1;
        }
        break;

      case OPT_ACTIVE_TIME:
        /* parse the time */
        rv = skStringParseDatetimeRange(&begin_time, &end_time, opt_arg,
                                        NULL, &precision);
        if (rv) {
            goto PARSE_ERROR;
        }
        /* set the begin time */
        t_div = imaxdiv(begin_time, 1000);
        time_window.tw_begin.tv_sec = t_div.quot;
        time_window.tw_begin.tv_usec = t_div.rem * 1000;

        /* adjust the maximum if required */
        if (end_time != INT64_MAX
            && (0 == (SK_PARSED_DATETIME_EPOCH & precision))
            && (SK_PARSED_DATETIME_GET_PRECISION(precision)
                < SK_PARSED_DATETIME_SECOND))
        {
            /* the max date precision is less than (courser than) second
             * resolution, so "round" the date up */
            if (skDatetimeCeiling(&end_time, &end_time, precision)) {
                return 1;
            }
        }

        /* set the end time */
        t_div = imaxdiv(end_time, 1000);
        time_window.tw_end.tv_sec = t_div.quot;
        time_window.tw_end.tv_usec = t_div.rem * 1000;
        break;

      case OPT_FLOW_OUTPUT:
        if (flow_output) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&flow_output, SK_IO_WRITE,
                                 SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(flow_output, opt_arg)))
        {
            skStreamPrintLastErr(flow_output, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
        break;

      case OPT_PACKET_PASS_OUTPUT:
        if (packet_pass_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        packet_pass_path = opt_arg;
        break;

      case OPT_PACKET_REJECT_OUTPUT:
        if (packet_reject_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        packet_reject_path = opt_arg;
        break;

      case OPT_REJECT_ALL_FRAGMENTS:
        reject_frags_all = 1;
        break;

      case OPT_REJECT_NONZERO_FRAGMENTS:
        reject_frags_subsequent = 1;
        break;

      case OPT_REJECT_INCOMPLETE:
        reject_incomplete = 1;
        break;

      case OPT_SET_SENSORID:
        rv = skStringParseUint32(&temp, opt_arg, 0, (SK_INVALID_SENSOR-1));
        if (rv) {
            goto PARSE_ERROR;
        }
        rwRecSetSensor(&default_flow_values, (sk_sensor_id_t)temp);
        break;

      case OPT_SET_INPUTINDEX:
        rv = skStringParseUint32(&temp, opt_arg, 0, UINT16_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        rwRecSetInput(&default_flow_values, (uint16_t)temp);
        break;

      case OPT_SET_OUTPUTINDEX:
        rv = skStringParseUint32(&temp, opt_arg, 0, UINT16_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        rwRecSetOutput(&default_flow_values, (uint16_t)temp);
        break;

      case OPT_SET_NEXTHOPIP:
        rv = skStringParseIP(&ip, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
#if SK_ENABLE_IPV6
        if (skipaddrIsV6(&ip)) {
            skAppPrintErr("Invalid %s '%s': IPv6 addresses not supported",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
#endif /* SK_ENABLE_IPV6 */
        rwRecSetNhIPv4(&default_flow_values, skipaddrGetV4(&ip));
        break;

      case OPT_PRINT_STATISTICS:
        print_statistics = 1;
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
 *  status = packetsToFlows();
 *
 *    For every packet in the global 'packet_input' file, try to
 *    produce a SiLK flow record, and write that record to the
 *    'flow_output' stream.  In addition, print the packets to
 *    the 'packet_pass' and/or 'packet_fail' dump files if requested.
 *    Update the global 'statistics' struct.  Return 0 on success, or
 *    -1 if writing a flow to the 'flow_output' stream fails.
 */
static int
packetsToFlows(
    void)
{
#define DUMP_REJECT_PACKET                                        \
    if ( !packet_reject) { /* no-op */}                           \
    else {pcap_dump((u_char*)packet_reject, &pcaph, data);}

    sk_pktsrc_t pktsrc;
    struct pcap_pkthdr pcaph;
    const u_char *data;
    rwRec flow;
    /* pointer to the ethernet header inside of 'data' */
    eth_header_t *ethh;
    /* pointer to the IP header inside of 'data' */
    ip_header_t *iph;
    /* pointer to the protocol-specific header in 'data' */
    u_char *protoh;
    /* the advertised length of the IP header */
    uint32_t iph_len;
    uint32_t len;
    int rv;
    void *pktptr;
    skplugin_err_t err;

    /* set up the sk_pktsrc_t for communicating with the plugins */
    pktsrc.pcap_src = packet_input;
    pktsrc.pcap_hdr = &pcaph;

    while (NULL != (data = pcap_next(packet_input, &pcaph))) {
        ++statistics.s_total;

        /* see if the packet's time is within our time window */
        if (time_window.tw_end.tv_sec) {
            if (pcaph.ts.tv_sec < time_window.tw_begin.tv_sec
                || (pcaph.ts.tv_sec == time_window.tw_begin.tv_sec
                    && pcaph.ts.tv_usec < time_window.tw_begin.tv_usec))
            {
                /* packet's time is before window */
                ++statistics.s_prewindow;
                continue;
            }
            if (pcaph.ts.tv_sec > time_window.tw_end.tv_sec
                || (pcaph.ts.tv_sec == time_window.tw_end.tv_sec
                    && pcaph.ts.tv_usec > time_window.tw_end.tv_usec))
            {
                /* packet's time is after window */
                ++statistics.s_postwindow;
                continue;
            }
        }

        /* make certain we captured the ethernet header */
        len = pcaph.caplen;
        if (len < sizeof(eth_header_t)) {
            /* short packet */
            ++statistics.s_short;
            DUMP_REJECT_PACKET;
            continue;
        }

        /* get the ethernet header; goto next packet if not Ethernet. */
        ethh = (eth_header_t*)data;
        if (ntohs(ethh->ether_type) != ETHERTYPE_IP) {
            /* ignoring non IP packet */
            ++statistics.s_nonipv4;
            DUMP_REJECT_PACKET;
            continue;
        }

        /* get the IP header; verify that we have the entire IP header
         * that the version is 4. */
        iph = (ip_header_t*)(data + sizeof(eth_header_t));
        len -= sizeof(eth_header_t);
        if (len < sizeof(ip_header_t)) {
            ++statistics.s_short;
            DUMP_REJECT_PACKET;
            continue;
        }
        if ((iph->ver_ihl >> 4) != 4) {
            /* ignoring non IPv4 packet */
            ++statistics.s_nonipv4;
            DUMP_REJECT_PACKET;
            continue;
        }

        /* the protocol-specific header begins after the advertised
         * length of the IP header */
        iph_len = (iph->ver_ihl & 0x0F) << 2;
        if (len > iph_len) {
            protoh = (u_char*)(((u_char*)iph) + iph_len);
            len -= iph_len;
        } else {
            protoh = NULL;
        }

        /* check for fragmentation */
        if (ntohs(iph->flags_fo) & (IP_MF | IPHEADER_FO_MASK)) {
            ++statistics.s_fragmented;

            if (reject_frags_all) {
                DUMP_REJECT_PACKET;
                continue;
            }
            if ((ntohs(iph->flags_fo) & IPHEADER_FO_MASK) == 0) {
                ++statistics.s_zerofrag;
            } else if (reject_frags_subsequent) {
                DUMP_REJECT_PACKET;
                continue;
            }
        }

        /* we have enough data to generate a flow; fill it in with
         * what we know so far. */
        memcpy(&flow, &default_flow_values, sizeof(rwRec));

        rwRecSetSIPv4(&flow, ntohl(iph->saddr));
        rwRecSetDIPv4(&flow, ntohl(iph->daddr));
        rwRecSetProto(&flow, iph->proto);
        rwRecSetBytes(&flow, ntohs(iph->tlen));
        rwRecSetStartTime(&flow, sktimeCreateFromTimeval(&pcaph.ts));

        /* Get the port information from unfragmented datagrams or
         * from the zero-packet of fragmented datagrams. */
        if (protoh && ((ntohs(iph->flags_fo) & IPHEADER_FO_MASK) == 0)) {

            /* Set ports and flags based on the IP protocol */
            switch (iph->proto) {
              case 1: /* ICMP */
                /* did we capture enough to get ICMP data? */
                if (len < 2) {
                    ++statistics.s_incomplete;
                    if (reject_incomplete) {
                        DUMP_REJECT_PACKET;
                        continue;
                    }
                } else {
                    icmp_header_t *icmphdr = (icmp_header_t*)protoh;
                    rwRecSetDPort(&flow,
                                  ((icmphdr->type << 8) | icmphdr->code));
                }
                break;

              case 6: /* TCP */
                /* did we capture enough to get the TCP flags? */
                if (len < 14) {
                    ++statistics.s_incomplete;
                    if (reject_incomplete) {
                        DUMP_REJECT_PACKET;
                        continue;
                    }
                    /* can we at least get the ports? */
                    if (len >= 4) {
                        tcp_header_t *tcphdr = (tcp_header_t*)protoh;
                        rwRecSetSPort(&flow, ntohs(tcphdr->sport));
                        rwRecSetDPort(&flow, ntohs(tcphdr->dport));
                    }
                } else {
                    tcp_header_t *tcphdr = (tcp_header_t*)protoh;
                    rwRecSetSPort(&flow, ntohs(tcphdr->sport));
                    rwRecSetDPort(&flow, ntohs(tcphdr->dport));
                    rwRecSetFlags(&flow, tcphdr->flags);
                }
                break;

              case 17: /* UDP */
                /* did we capture enough to get UDP sport and dport? */
                if (len < 4) {
                    ++statistics.s_incomplete;
                    if (reject_incomplete) {
                        DUMP_REJECT_PACKET;
                        continue;
                    }
                } else {
                    udp_header_t *udphdr = (udp_header_t*)protoh;
                    rwRecSetSPort(&flow, ntohs(udphdr->sport));
                    rwRecSetDPort(&flow, ntohs(udphdr->dport));
                }
                break;
            }
        }

        /* If the user provided plug-in(s), call it(them) */
        pktsrc.pcap_data = data;
        pktptr = &pktsrc;
        err = skPluginRunTransformFn(&flow, &pktptr);
        switch (err) {
          case SKPLUGIN_FILTER_PASS:
            /* success, but no opinion; try next plug-in */
            break;

          case SKPLUGIN_FILTER_PASS_NOW:
            /* success, immediately write flow */
            goto WRITE_FLOW;

          case SKPLUGIN_FILTER_FAIL:
            /* success, but immediately reject the flow */
            ++statistics.s_plugin_rej;
            DUMP_REJECT_PACKET;
            goto NEXT_PACKET;

          case SKPLUGIN_FILTER_IGNORE:
            /* success, immediately ignore the flow */
            ++statistics.s_plugin_ign;
            goto NEXT_PACKET;

          default:
            /* an error */
            skAppPrintErr("Quitting on error code %d from plug-in",
                          err);
            return -1;
        }

      WRITE_FLOW:
        /* FINALLY, write the record to the SiLK Flow file and write
         * the packet to the packet-pass-output file */
        rv = skStreamWriteRecord(flow_output, &flow);
        if (rv) {
            skStreamPrintLastErr(flow_output, rv, &skAppPrintErr);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                return -1;
            }
        }
        if (packet_pass) {
            pcap_dump((u_char*)packet_pass, &pcaph, data);
        }

      NEXT_PACKET:
        ; /* empty */
    }

    return 0;
}


/*
 *  printStatistics(fh);
 *
 *    Print statistics about the number of packets read, ignored,
 *    rejected, and written to the specified file handle.
 */
static void
printStatistics(
    FILE               *fh)
{
    uint64_t count = statistics.s_total;

    fprintf(fh,
            ("Packet count statistics for %s\n"
             "\t%20" PRIu64 " read\n"),
            packet_input_path, statistics.s_total);

    if (time_window.tw_end.tv_sec) {
        fprintf(fh,
                ("\t%20" PRIu64 " ignored: before active-time\n"
                 "\t%20" PRIu64 " ignored: after active-time\n"),
                statistics.s_prewindow, statistics.s_postwindow);
        count -= (statistics.s_prewindow + statistics.s_postwindow);
    }

    fprintf(fh,
            ("\t%20" PRIu64 " rejected: too short to get information\n"
             "\t%20" PRIu64 " rejected: not IPv4\n"),
            statistics.s_short, statistics.s_nonipv4);
    count -= (statistics.s_short + statistics.s_nonipv4);

    if (reject_frags_all) {
        fprintf(fh, ("\t%20" PRIu64 " rejected: fragmented\n"),
                statistics.s_fragmented);
        count -= statistics.s_fragmented;
    }

    if (reject_incomplete) {
        fprintf(fh, ("\t%20" PRIu64 " rejected: incomplete\n"),
                statistics.s_fragmented);
        count -= statistics.s_fragmented;
    }

    if (reject_frags_subsequent) {
        fprintf(fh, ("\t%20" PRIu64 " rejected: non-zero fragment\n"),
                (statistics.s_fragmented - statistics.s_zerofrag));
        count -= (statistics.s_fragmented - statistics.s_zerofrag);
    }

    if (statistics.s_plugin_ign || statistics.s_plugin_rej) {
        fprintf(fh,
                ("\t%20" PRIu64 " ignored: by plug-in\n"
                 "\t%20" PRIu64 " rejected: by plug-in\n"),
                statistics.s_plugin_ign, statistics.s_plugin_rej);
        count -= (statistics.s_plugin_ign + statistics.s_plugin_rej);
    }

    fprintf(fh, ("\n\t%20" PRIu64 " total written\n"),
            count);

    if ( !reject_frags_all) {
        if ( !reject_frags_subsequent) {
            fprintf(fh, ("\t%20" PRIu64 " total fragmented packets\n"),
                    statistics.s_fragmented);
        }
        fprintf(fh, ("\t%20" PRIu64 " zero-packet of a fragment\n"),
                statistics.s_zerofrag);
    }

    if ( !reject_incomplete) {
        fprintf(fh, ("\t%20" PRIu64 " incomplete (no ports and/or flags)\n"),
                statistics.s_incomplete);
    }
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);

    if (packetsToFlows()) {
        exit(EXIT_FAILURE);
    }

    if (print_statistics) {
        printStatistics(STATS_STREAM);
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
