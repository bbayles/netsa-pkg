/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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
**  Quick application to print the IPs in a set file
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsetcat.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sknetstruct.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* Where to print usage (--help) */
#define USAGE_FH stdout

/*
 *    setcat_range_state_t is used when computing ranges of IPs
 */
struct setcat_range_state_st {
    /* start of the current range */
    skipaddr_t  start;
    /* end of the current range */
    skipaddr_t  end;
    /* number of IPs in the current range; [0] contains the upper
     * 64-bits of the count, [1] the lower 64-bits */
    uint64_t    count[2];
    /* column widths (count, start, end) */
    int         widths[3];
    /* final delimiter */
    char        final_delim[2];
};
typedef struct setcat_range_state_st setcat_range_state_t;


/* LOCAL VARIABLES */

/* where to send output */
static skstream_t *outstream;

/* index of first option that is not handled by the options handler.
 * If this is equal to argc, then input is from stdin. */
static int arg_index = 0;

/* output delimiter for network structure */
static char output_delimiter = '|';

/* type of network structure to print */
static const char *net_structure = NULL;

/* where to write the output; set by --output-path */
static const char *output_path = NULL;

/* paging program to use for output; set by --pager */
static const char *pager = NULL;

/* how to print IPs from silk_types.h: enum skipaddr_flags_t */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS
     | SK_OPTION_IP_FORMAT_UNMAP_V6);

/* option flags */
static struct opt_flags_st {
    /* whether to output network breakdown of set contents */
    unsigned    network_structure   :1;
    /* whether to print IP ranges as LOW|HIGH| */
    unsigned    ip_ranges           :1;
    /* whether the user specified the --cidr-block switch */
    unsigned    user_cidr           :1;
    /* whether user wants to print IPs as CIDR blocks */
    unsigned    cidr_blocks         :1;
    /* whether to surpress fixed-width columnar network structure output */
    unsigned    no_columns          :1;
    /* whether to suppress the final delimiter */
    unsigned    no_final_delimiter  :1;
    /* whether user explicitly gave the print-ips option */
    unsigned    print_ips           :1;
    /* whether to count IPs: default no */
    unsigned    count_ips           :1;
    /* whether to print statistics; default no */
    unsigned    statistics          :1;
    /* whether to print file names; default is normally no; however,
     * the default becomes yes when --count-ips or --print-statistics
     * is specified and there are multiple input files. */
    unsigned    print_filenames     :1;
    /* whether user provided --print-filenames */
    unsigned    print_filenames_user:1;
} opt_flags = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* OPTIONS SETUP */

typedef enum {
    OPT_COUNT_IPS,
    OPT_PRINT_STATISTICS,
    OPT_PRINT_IPS,
    OPT_NETWORK_STRUCTURE,
    OPT_CIDR_BLOCKS,
    OPT_IP_RANGES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_PRINT_FILENAMES,
    OPT_OUTPUT_PATH,
    OPT_PAGER
} appOptionsEnum;

static struct option appOptions[] = {
    {"count-ips",           NO_ARG,       0, OPT_COUNT_IPS},
    {"print-statistics",    NO_ARG,       0, OPT_PRINT_STATISTICS},
    {"print-ips",           NO_ARG,       0, OPT_PRINT_IPS},
    {"network-structure",   OPTIONAL_ARG, 0, OPT_NETWORK_STRUCTURE},
    {"cidr-blocks",         OPTIONAL_ARG, 0, OPT_CIDR_BLOCKS},
    {"ip-ranges",           NO_ARG,       0, OPT_IP_RANGES},
    {"no-columns",          NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",  NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",           OPTIONAL_ARG, 0, OPT_DELIMITED},
    {"print-filenames",     OPTIONAL_ARG, 0, OPT_PRINT_FILENAMES},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"pager",               REQUIRED_ARG, 0, OPT_PAGER},
    {0,0,0,0}               /* sentinel entry */
};


static const char *appHelp[] = {
    "Print the number of IP in each IPset listed on the command\n"
    "\tline; disables default printing of IPs. Def. No",
    "Print statistics about the IPset (min-/max-ip, etc);\n"
    "\tdisable default printing of IPs. Def. No",
    "Also print IPs when count or statistics switch is given",
    NULL,
    ("Print IPs in CIDR block notation when no argument given\n"
     "\tor argument is 1; otherwise, print individual IPs.\n"
     "\tDef. Individual IPs for IPv4 IPsets, CIDR blocks for IPv6 IPsets"),
    "Print IPs as ranges of count|low|high|. Def. No",
    ("When printing network-structure or ip-ranges, disable\n"
     "\tfixed-width columnar output. Def. Columnar"),
    ("When printing network-structure or ip-ranges, use\n"
     "\tspecified character between columns. Def. '|'"),
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
    ("Print the name of each filename. 0 = no; 1 = yes.\n"
     "\tDefault is no unless multiple input files are provided and output\n"
     "\tis --count-ips or --print-statistics"),
    "Write the output to this stream or file. Def. stdout",
    "Invoke this program to page output. Def. $SILK_PAGER or $PAGER",
    (char *)NULL /* sentinel entry */
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
#define USAGE_MSG                                                             \
    ("[SWITCHES] [IPSET_FILES]\n"                                             \
     "\tBy default, prints the IPs in the specified IPSET_FILES.  Use\n"      \
     "\tswitches to control format of the outout and to optionally or\n"      \
     "\tadditionally print the number of IPs in the file, the network\n"      \
     "\tstructure, or other statistics.  If no IPSET_FILEs are given on\n"    \
     "\tthe command line, the IPset will be read from the standard input.\n")

    /* network-structure help string is longer than allowed by C90 */
#define NETWORK_STRUCT_HELP1                                                  \
    ("Print the number of hosts for each specified CIDR\n"                    \
     "\tblock in the comma-separed list of CIDR block sizes (0--32) and/or\n" \
     "\tletters (T=0,A=8,B=16,C=24,X=27,H=32). If argument contains 'S' or\n" \
     "\t'/', for each CIDR block print host counts and number of occupied\n")
#define NETWORK_STRUCT_HELP2                                                  \
    ("\tsmaller CIDR blocks. Additional CIDR blocks to summarize can be\n"    \
     "\tspecified by listing them after the '/'. Def. v4:TS/8,16,24,27.\n"    \
     "\tA leading 'v6:' treats IPset as being IPv6, allows range 0--128,\n"   \
     "\tdisallows A,B,C,X, sets H to 128, and sets default to TS/48,64")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ",
                appOptions[i].name, SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_NETWORK_STRUCTURE:
            fprintf(fh, "%s%s\n", NETWORK_STRUCT_HELP1, NETWORK_STRUCT_HELP2);
            break;
          case OPT_IP_RANGES:
            fprintf(fh, "%s\n", appHelp[i]);
            /* insert the --ip-format switches */
            skOptionsIPFormatUsage(fh);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }
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

    skStreamDestroy(&outstream);
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

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    outstream = NULL;

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags))
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
        skAppUsage();             /* never returns */
    }

    /* either need name of set file(s) after options or a set file on stdin */
    if ((arg_index == argc) && (FILEIsATty(stdin))) {
        skAppPrintErr("No files on the command line and"
                      " stdin is connected to a terminal");
        skAppUsage();
    }

    /* determine whether to print file names */
    if (!opt_flags.print_filenames_user
        && (argc - arg_index > 1)
        && (opt_flags.count_ips || opt_flags.statistics))
    {
        opt_flags.print_filenames = 1;
    }

    /* network structure output conflicts with most other output */
    if (opt_flags.network_structure) {
        if (opt_flags.user_cidr) {
            skAppPrintErr("Cannot combine the --%s and --%s switches.",
                          appOptions[OPT_NETWORK_STRUCTURE].name,
                          appOptions[OPT_CIDR_BLOCKS].name);
            skAppUsage();
        }
        if (opt_flags.print_ips) {
            skAppPrintErr("Cannot combine the --%s and --%s switches.",
                          appOptions[OPT_NETWORK_STRUCTURE].name,
                          appOptions[OPT_PRINT_IPS].name);
            skAppUsage();
        }
        if (opt_flags.count_ips) {
            skAppPrintErr("Cannot combine the --%s and --%s switches.",
                          appOptions[OPT_NETWORK_STRUCTURE].name,
                          appOptions[OPT_COUNT_IPS].name);
            skAppUsage();
        }
        if (opt_flags.ip_ranges) {
            skAppPrintErr("Cannot combine the --%s and --%s switches.",
                          appOptions[OPT_NETWORK_STRUCTURE].name,
                          appOptions[OPT_IP_RANGES].name);
            skAppUsage();
        }
        /* disable mapping of ::ffff:0:0/96 to IPv4 */
        ip_format = ip_format & ~SKIPADDR_UNMAP_V6;
    }

    /* cannot use --ip-ranges with --cidr-blocks */
    if (opt_flags.ip_ranges) {
        if (opt_flags.user_cidr) {
            skAppPrintErr("Cannot combine the --%s and --%s switches.",
                          appOptions[OPT_IP_RANGES].name,
                          appOptions[OPT_CIDR_BLOCKS].name);
            skAppUsage();
        }
        opt_flags.print_ips = 0;
    }

    /* If no output was specified, print the ips */
    if (!opt_flags.statistics && !opt_flags.count_ips
        && !opt_flags.network_structure && !opt_flags.print_ips
        && !opt_flags.ip_ranges)
    {
        opt_flags.print_ips = 1;
    }

    /* If an output_path is set, bypass the pager by setting it to the
     * empty string.  if no output_path was set, use stdout */
    if (output_path) {
        pager = "";
    } else {
        output_path = "-";
    }
    /* If the only output is count_ips, do not use the pager */
    if (opt_flags.count_ips
        && !opt_flags.print_filenames && !opt_flags.print_ips
        && !opt_flags.network_structure && !opt_flags.ip_ranges
        && !opt_flags.statistics)
    {
        pager = "";
    }

    /* Create the output stream */
    if ((rv = skStreamCreate(&outstream, SK_IO_WRITE, SK_CONTENT_TEXT))
        || (rv = skStreamBind(outstream, output_path))
        || (rv = skStreamPageOutput(outstream, pager))
        || (rv = skStreamOpen(outstream)))
    {
        skStreamPrintLastErr(outstream, rv, &skAppPrintErr);
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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    SK_UNUSED_PARAM(cData);

    switch ((appOptionsEnum)opt_index) {
      case OPT_PRINT_STATISTICS:
        opt_flags.statistics = 1;
        break;

      case OPT_COUNT_IPS:
        opt_flags.count_ips = 1;
        break;

      case OPT_NETWORK_STRUCTURE:
        net_structure = opt_arg;
        opt_flags.network_structure = 1;
        break;

      case OPT_PRINT_IPS:
        opt_flags.print_ips = 1;
        break;

      case OPT_CIDR_BLOCKS:
        opt_flags.print_ips = 1;
        opt_flags.user_cidr = 1;
        if (NULL == opt_arg) {
            opt_flags.cidr_blocks = 1;
        } else if (0 == strcmp(opt_arg, "1")) {
            opt_flags.cidr_blocks = 1;
        } else if (0 != strcmp(opt_arg, "0")) {
            skAppPrintErr("Invalid %s: Value must be 0 or 1",
                          appOptions[opt_index].name);
            return -1;
        }
        break;

      case OPT_IP_RANGES:
        opt_flags.ip_ranges = 1;
        break;

      case OPT_NO_COLUMNS:
        opt_flags.no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        opt_flags.no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        output_delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        opt_flags.no_columns = 1;
        opt_flags.no_final_delimiter = 1;
        if (opt_arg) {
            output_delimiter = opt_arg[0];
        }
        break;

      case OPT_PRINT_FILENAMES:
        opt_flags.print_filenames_user = 1;
        if (NULL == opt_arg) {
            opt_flags.print_filenames = 1;
        } else if (0 == strcmp(opt_arg, "1")) {
            opt_flags.print_filenames = 1;
        } else if (0 != strcmp(opt_arg, "0")) {
            skAppPrintErr("Invalid %s: Value must be 0 or 1",
                          appOptions[opt_index].name);
            return -1;
        }
        break;

      case OPT_OUTPUT_PATH:
        if (output_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        output_path = opt_arg;
        break;

      case OPT_PAGER:
        pager = opt_arg;
        break;
    }

    return 0;                   /* OK */
}


/*
 *    Callback function invoked by either skIPSetWalk() or
 *    skIPSetProcessStream() with printing the IPs in an IPset.
 *
 *    Print a textual representation of the 'ip' and 'prefix'.
 */
static int
printIPsCallback(
    skipaddr_t         *ip,
    uint32_t            prefix,
    void               *dummy)
{
    char ipbuf[SKIPADDR_CIDR_STRLEN];

    SK_UNUSED_PARAM(dummy);

    /* do not print the prefix when it represents a single IP */
    if (
#if SK_ENABLE_IPV6
        (128 == prefix || (32 == prefix && !skipaddrIsV6(ip)))
#else
        (32 == prefix)
#endif
        )
    {
        /* a single address */
        skipaddrString(ipbuf, ip, ip_format);
    } else {
        /* a block */
        skipaddrCidrString(ipbuf, ip, prefix, ip_format);
    }
    skStreamPrint(outstream, "%s\n", ipbuf);
    return SKIPSET_OK;
}

/*
 *    Initialization function when printing the IPs in an IPset.  May
 *    be called directly or by skIPSetProcessStream().
 */
static int
printIPsInitialize(
    const skipset_t            *ipset,
    const sk_file_header_t     *hdr,
    void                       *cb_init_func_ctx,
    skipset_procstream_parm_t  *proc_stream_settings)
{
    SK_UNUSED_PARAM(hdr);
    SK_UNUSED_PARAM(cb_init_func_ctx);

    proc_stream_settings->visit_cidr = (opt_flags.user_cidr
                                        ? opt_flags.cidr_blocks
                                        : skIPSetIsV6(ipset));
    return SKIPSET_OK;
}

/*
 *    Print the IPs in either the IPset 'ipset' or in the IPset
 *    that exists in the stream 'setstream'.
 *
 *    Use the function printIPsCallback() to print an entry from the
 *    IPset; use the function printIPsInitialize() to initialize
 *    printing.
 */
static void
printIPs(
    const skipset_t    *ipset,
    skstream_t         *setstream)
{
    char errbuf[2 * PATH_MAX];
    skipset_procstream_parm_t param;
    ssize_t rv;

    memset(&param, 0, sizeof(param));
    param.v6_policy = SK_IPV6POLICY_MIX;
    param.cb_entry_func = printIPsCallback;
    param.cb_entry_func_ctx = NULL;

    if (ipset) {
        printIPsInitialize(ipset, NULL, NULL, &param);
        rv = skIPSetWalk(ipset, param.visit_cidr, param.v6_policy,
                         param.cb_entry_func, param.cb_entry_func_ctx);
    } else {
        rv = skIPSetProcessStream(setstream, printIPsInitialize, NULL, &param);
    }
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamLastErrMessage(setstream,
                                   skStreamGetLastReturnValue(setstream),
                                   errbuf, sizeof(errbuf));
        } else {
            strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
            errbuf[sizeof(errbuf) - 1] = '\0';
        }
        skAppPrintErr("Error while reading IPset from '%s': %s",
                      skStreamGetPathname(setstream), errbuf);
    }
}


/*
 *    Callback function for printNetwork().  This is invoked by either
 *    skIPSetWalk() or skIPSetProcessStream().
 *
 *    Add the data for the current 'ipaddr' and 'prefix' to the
 *    network structure object in 'v_ns'.
 */
static int
printNetworkAdd(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ns)
{
    skNetStructureAddCIDR((sk_netstruct_t *)v_ns, ipaddr, prefix);
    return SKIPSET_OK;
}


/*
 *    Print the network structure of the IPset in 'ipset' or of the
 *    IPset that exists in the stream 'setstream'.
 *
 *    Use the function printNetworkAdd() to add an entry from the
 *    IPset to the network structure object.
 */
static void
printNetwork(
    const skipset_t    *ipset,
    skstream_t         *setstream)
{
    char errbuf[2 * PATH_MAX];
    sk_netstruct_t *ns = NULL;
    skipset_procstream_parm_t param;
    ssize_t rv;

    /* Set up the skNetStruct */
    if (skNetStructureCreate(&ns, 0 /*no counts*/)) {
        skAppPrintErr("Error creating network-structure");
        return;
    }
    if (skNetStructureParse(ns, net_structure)) {
        goto END;
    }
    skNetStructureSetOutputStream(ns, outstream);
    skNetStructureSetDelimiter(ns, output_delimiter);
    if (opt_flags.no_columns) {
        skNetStructureSetNoColumns(ns);
    }
    skNetStructureSetIpFormat(ns, ip_format);

    memset(&param, 0, sizeof(param));
    param.v6_policy = SK_IPV6POLICY_MIX;
    param.visit_cidr = 1;
    param.cb_entry_func = printNetworkAdd;
    param.cb_entry_func_ctx = ns;

    if (ipset) {
        rv = skIPSetWalk(ipset, param.visit_cidr, param.v6_policy,
                         param.cb_entry_func, param.cb_entry_func_ctx);
    } else {
        rv = skIPSetProcessStream(setstream, NULL, NULL, &param);
    }
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamLastErrMessage(setstream,
                                   skStreamGetLastReturnValue(setstream),
                                   errbuf, sizeof(errbuf));
        } else {
            strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
            errbuf[sizeof(errbuf) - 1] = '\0';
        }
        skAppPrintErr("Error while reading IPset from '%s': %s",
                      skStreamGetPathname(setstream), errbuf);
    }

    /* set the last key flag and call it once more, for good measure.
     * (that way, it closes out blocks after the last key.) */
    skNetStructurePrintFinalize(ns);

  END:
    skNetStructureDestroy(&ns);
}


/*
 *    Helper for printRanges(), printRangesCallbackV4() and
 *    printRangesCallbackV6().
 *
 *    Print a single range (count, start, end).
 */
static void
printRangesSingle(
    const setcat_range_state_t *state)
{
    char ip1[SKIPADDR_STRLEN+1];
    char ip2[SKIPADDR_STRLEN+1];

#if SK_ENABLE_IPV6
    if (state->count[0]) {
        char countbuf[64];
        uint64_t count[2];
        uint8_t count_ipv6[16];
        skipaddr_t count_ipaddr;

        /* display the count by putting it into an IPv6 address and
         * getting its decimal presentation */
        count[0] = ntoh64(state->count[0]);
        count[1] = ntoh64(state->count[1]);
        memcpy(&count_ipv6[0], &count[0], sizeof(count[0]));
        memcpy(&count_ipv6[8], &count[1], sizeof(count[1]));
        skipaddrSetV6(&count_ipaddr, count_ipv6);
        skipaddrString(countbuf, &count_ipaddr, SKIPADDR_DECIMAL);

        skStreamPrint(outstream, ("%*s%c%*s%c%*s%s\n"),
                      state->widths[0], countbuf, output_delimiter,
                      state->widths[1],
                      skipaddrString(ip1, &state->start, ip_format),
                      output_delimiter,
                      state->widths[2],
                      skipaddrString(ip2, &state->end, ip_format),
                      state->final_delim);
        return;
    }
#endif  /* SK_ENABLE_IPV6 */

    skStreamPrint(outstream, ("%*" PRIu64 "%c%*s%c%*s%s\n"),
                  state->widths[0], state->count[1], output_delimiter,
                  state->widths[1],
                  skipaddrString(ip1, &state->start, ip_format),
                  output_delimiter,
                  state->widths[2],
                  skipaddrString(ip2, &state->end, ip_format),
                  state->final_delim);
}


#if SK_ENABLE_IPV6
/*
 *    Callback function for printRanges().  This is invoked either by
 *    skIPSetWalk() or skIPSetProcessStream().
 *
 *    Update the range information in 'state' with the current
 *    'ipaddr' and 'prefix'.  If 'ipaddr' is not contiguous with the
 *    current range, the current range is printed and a new range is
 *    started.
 */
static int
printRangesCallbackV6(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_state)
{
    setcat_range_state_t *state = (setcat_range_state_t*)v_state;
    skipaddr_t contig;

    if (state->count[0] || state->count[1]) {
        /* check whether this range is continuous with previous */
        skipaddrCopy(&contig, &state->end);
        skipaddrIncrement(&contig);
        if (0 == skipaddrCompare(&contig, ipaddr)) {
            /* it is contiguous */
            skCIDR2IPRange(ipaddr, prefix, ipaddr, &state->end);
            if (prefix <= 64) {
                state->count[0] += (UINT64_C(1) << (64 - prefix));
            } else {
                uint64_t tmp = (UINT64_C(1) << (128 - prefix));
                if ((UINT64_MAX - tmp) > state->count[1]) {
                    state->count[1] += tmp;
                } else {
                    ++state->count[0];
                    state->count[1] -= ((UINT64_MAX - tmp) + 1);
                }
            }
            return SKIPSET_OK;
        }

        printRangesSingle(state);
    }

    /* begin a new range */
    skCIDR2IPRange(ipaddr, prefix, &state->start, &state->end);
    if (prefix <= 64) {
        state->count[0] = (UINT64_C(1) << (64 - prefix));
        state->count[1] = 0;
    } else {
        state->count[0] = 0;
        state->count[1] = (UINT64_C(1) << (128 - prefix));
    }
    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Callback function for printRanges().  This is invoked either by
 *    skIPSetWalk() or skIPSetProcessStream().
 *
 *    Update the range information in 'state' with the current
 *    'ipaddr' and 'prefix'.  If 'ipaddr' is not contiguous with the
 *    current range, the current range is printed and a new range is
 *    started.
 */
static int
printRangesCallbackV4(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_state)
{
    setcat_range_state_t *state = (setcat_range_state_t*)v_state;
    skipaddr_t contig;

    if (state->count[1]) {
        /* check whether this range is continuous with previous */
        skipaddrCopy(&contig, &state->end);
        skipaddrIncrement(&contig);
        if (0 == skipaddrCompare(&contig, ipaddr)) {
            /* it is contiguous */
            skCIDR2IPRange(ipaddr, prefix, ipaddr, &state->end);
            state->count[1] += (1 << (32 - prefix));
            return SKIPSET_OK;
        }

        /* print current range */
        printRangesSingle(state);
    }

    /* start a new range */
    skCIDR2IPRange(ipaddr, prefix, &state->start, &state->end);
    state->count[1] = (UINT64_C(1) << (32 - prefix));
    return SKIPSET_OK;
}


/*
 *    Initialization function when printing ranges in an IPset.  May
 *    be called directly or by skIPSetProcessStream().
 */
static int
printRangesInitialize(
    const skipset_t            *ipset,
    const sk_file_header_t     *hdr,
    void                       *cb_init_func_ctx,
    skipset_procstream_parm_t  *proc_stream_settings)
{
    setcat_range_state_t *state;

    SK_UNUSED_PARAM(hdr);
    SK_UNUSED_PARAM(cb_init_func_ctx);

    /* choose callback function based on type of IPset */
#if SK_ENABLE_IPV6
    if (skIPSetIsV6(ipset)) {
        proc_stream_settings->v6_policy = SK_IPV6POLICY_FORCE;
        proc_stream_settings->cb_entry_func = printRangesCallbackV6;
    } else
#endif
    {
        proc_stream_settings->v6_policy = SK_IPV6POLICY_ASV4;
        proc_stream_settings->cb_entry_func = printRangesCallbackV4;
    }

    /* Initialize the state object */
    state = (setcat_range_state_t*)proc_stream_settings->cb_entry_func_ctx;

    if (!opt_flags.no_final_delimiter) {
        state->final_delim[0] = output_delimiter;
    }
    if (!opt_flags.no_columns) {
        state->widths[0]
            = skipaddrStringMaxlen(skIPSetIsV6(ipset), SKIPADDR_DECIMAL);
        state->widths[1] = state->widths[2]
            = skipaddrStringMaxlen(skIPSetIsV6(ipset), ip_format);
    }

    return SKIPSET_OK;
}

/*
 *    Print the ranges in either the IPset 'ipset' or in the IPset
 *    that exists in the stream 'setstream'.
 *
 *    The output appears in three output columns; where the first is
 *    the number of IPs in the range, the second is the starting IP,
 *    the third is the ending IP.
 *
 *     COUNT| LOW| HIGH|
 *
 *    Use printRanges
 */
static void
printRanges(
    const skipset_t    *ipset,
    skstream_t         *setstream)
{
    char errbuf[2 * PATH_MAX];
    setcat_range_state_t state;
    skipset_procstream_parm_t param;
    ssize_t rv;

    memset(&param, 0, sizeof(param));
    memset(&state, 0, sizeof(state));
    param.v6_policy = SK_IPV6POLICY_MIX;
    param.visit_cidr = 1;
    param.cb_entry_func = NULL;
    param.cb_entry_func_ctx = &state;

    if (ipset) {
        printRangesInitialize(ipset, NULL, NULL, &param);
        rv = skIPSetWalk(ipset, param.visit_cidr, param.v6_policy,
                         param.cb_entry_func, param.cb_entry_func_ctx);
    } else {
        rv = skIPSetProcessStream(setstream, printRangesInitialize,
                                  NULL, &param);
    }
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamLastErrMessage(setstream,
                                   skStreamGetLastReturnValue(setstream),
                                   errbuf, sizeof(errbuf));
        } else {
            strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
            errbuf[sizeof(errbuf) - 1] = '\0';
        }
        skAppPrintErr("Error while reading IPset from '%s': %s",
                      skStreamGetPathname(setstream), errbuf);
    }

    if (state.count[0] || state.count[1]) {
        printRangesSingle(&state);
    }
}


#if SK_ENABLE_IPV6
/*
 *  printStatisticsV6
 *
 *    Prints, to outF, statistics of the IPSet ipset.  Statistics
 *    printed are the minimum IP, the maximum IP, a count of the
 *    number of every /N from where N is an integer mulitple of 8
 *    between 8 and 120 inclusive.
 */
static void
printStatisticsV6(
    const skipset_t    *ipset)
{
#define NUM_LEVELS_V6 15

    const unsigned int cidr[NUM_LEVELS_V6] = {
        8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120
    };
    struct count_st {
        uint64_t upper;
        uint64_t lower;
    } count[NUM_LEVELS_V6];
    skipset_iterator_t iter;
    skipaddr_t ipaddr;
    skipaddr_t min_ip;
    skipaddr_t max_ip;
    uint8_t old_ip[16];
    uint8_t ipv6[16];
    uint32_t prefix;
    char ip_str1[SKIPADDR_STRLEN+1];
    char ip_str2[SKIPADDR_STRLEN+1];
    uint32_t local_fmt;
    int width;
    uint64_t tmp;
    double d_count;
    int i;

    memset(count, 0, sizeof(count));

    if (skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_FORCE)) {
        return;
    }

    /* Get first IP */
    if (skIPSetIteratorNext(&iter, &ipaddr, &prefix) != SK_ITERATOR_OK) {
        /* empty ipset */
        skStreamPrint(outstream,
                      ("Network Summary\n"
                       "\tminimumIP = %s\n"
                       "\tmaximumIP = %s\n"),
                      "-", "-");
        for (i = 0; i < NUM_LEVELS_V6; ++i) {
            skStreamPrint(outstream, ("\t%39" PRIu64 " occupied /%u%s\n"),
                          count[i].lower, cidr[i],
                          ((count[i].lower > 1) ? "s" : ""));
        }
        tmp = 0;
        skStreamPrint(outstream, ("\t%39" PRIu64 " host%s\n"),
                      tmp, ((tmp == 1) ? " (/128)" : "s (/128s)"));
        return;
    }

    /* first IP */
    skipaddrCopy(&min_ip, &ipaddr);
    skipaddrGetV6(&ipaddr, old_ip);
    old_ip[0] = ~old_ip[0];

    do {
        skipaddrGetV6(&ipaddr, ipv6);

        for (i = 0; i < 16; ++i) {
            if (ipv6[i] != old_ip[i]) {
                for ( ; i < NUM_LEVELS_V6 && prefix >= cidr[i]; ++i) {
                    if (count[i].lower < UINT64_MAX) {
                        ++count[i].lower;
                    } else {
                        ++count[i].upper;
                        count[i].lower = 0;
                    }
                }
                for ( ; i < NUM_LEVELS_V6 && (cidr[i] - prefix < 64); ++i) {
                    tmp = UINT64_C(1) << (cidr[i] - prefix);
                    if (UINT64_MAX - tmp > count[i].lower) {
                        count[i].lower += tmp;
                    } else {
                        ++count[i].upper;
                        count[i].lower -= (UINT64_MAX - tmp) + 1;
                    }
                }
                for ( ; i < NUM_LEVELS_V6; ++i) {
                    count[i].upper += UINT64_C(1) << (cidr[i] - prefix - 64);
                }
                break;
            }
        }

        memcpy(old_ip, ipv6, sizeof(ipv6));
    } while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK);

    /* get max IP */
    skCIDR2IPRange(&ipaddr, prefix, &ipaddr, &max_ip);

    /* ignore the unmap-v6 ip_format here since we are printing the data
     * for an IPv6 IPset */
    local_fmt = ip_format & ~SKIPADDR_UNMAP_V6;
    width = skipaddrStringMaxlen(1, local_fmt);
    skStreamPrint(outstream,
                  ("Network Summary\n"
                   "\tminimumIP = %*s\n"
                   "\tmaximumIP = %*s\n"),
                  width, skipaddrString(ip_str1, &min_ip, local_fmt),
                  width, skipaddrString(ip_str2, &max_ip, local_fmt));

    for (i = 0; i < NUM_LEVELS_V6; ++i) {
        if (0 == count[i].upper) {
            skStreamPrint(outstream, ("\t%39" PRIu64 " occupied /%u%s\n"),
                          count[i].lower, cidr[i],
                          ((count[i].lower == 1) ? "" : "s"));
        } else {
            d_count = ((double)count[i].upper * ((double)UINT64_MAX + 1.0)
                       + (double)count[i].lower);
            skStreamPrint(outstream, ("\t%39.f occupied /%us\n"),
                          d_count, cidr[i]);
        }
    }
    skIPSetCountIPsString(ipset, ip_str1, sizeof(ip_str1));
    tmp = (0 == strcmp("1", ip_str1));
    skStreamPrint(outstream, ("\t%39s host%s\n"),
                  ip_str1, ((tmp == 1) ? " (/128)" : "s (/128s)"));
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  printStatisticsV4
 *
 *    Prints, to outF, statistics of the IPSet ipset.  Statistics
 *    printed are the minimum IP, the maximum IP, a count of the class
 *    A blocks, class B blocks (number of nodes), class C blocks, and
 *    a count of the addressBlocks (/27's) used.  If integerIP is 0,
 *    the min and max IPs are printed in dotted-quad form; otherwise
 *    they are printed as integers.
 */
static void
printStatisticsV4(
    const skipset_t    *ipset)
{
#define PLURAL_COMMA(count, prefix)             \
    ((count == 1)                               \
     ? ((prefix < 10) ? ",  " : ", ")           \
     : ((prefix < 10) ? "s, " : "s,"))
#define NUM_LEVELS_V4 5

    const unsigned int cidr[NUM_LEVELS_V4] = {32, 8, 16, 24, 27};
    const uint32_t mask[NUM_LEVELS_V4] = {0x0000001F, 0xFF000000, 0x00FF0000,
                                          0x0000FF00, 0x000000E0};
    uint64_t count[NUM_LEVELS_V4];
    skipset_iterator_t iter;
    skipaddr_t ipaddr;
    skipaddr_t min_ip;
    skipaddr_t max_ip;
    uint32_t prefix;
    uint32_t old_addr;
    uint32_t xor_ips;
    char ip_str1[SKIPADDR_STRLEN+1];
    char ip_str2[SKIPADDR_STRLEN+1];
    uint32_t local_fmt;
    int width;
    int i;

    memset(count, 0, sizeof(count));

    if (skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_MIX)) {
        return;
    }

    /* Get first IP */
    if (skIPSetIteratorNext(&iter, &ipaddr, &prefix) != SK_ITERATOR_OK) {
        /* empty ipset */
        skStreamPrint(outstream,
                      ("Network Summary\n"
                       "\tminimumIP = %15s\n"
                       "\tmaximumIP = %15s\n"),
                      "-", "-");
        skStreamPrint(outstream,
                      ("\t%10" PRIu64 " host%s  %10.6f%% of 2^32\n"),
                      count[0], ((count[0] == 1) ? " (/32),  " : "s (/32s),"),
                      100.0 *((double)count[0]) / pow(2.0, cidr[0]));

        for (i = 1; i < NUM_LEVELS_V4; ++i) {
            skStreamPrint(outstream,
                          ("\t%10" PRIu64 " occupied /%u%s %10.6f%% of 2^%u\n"),
                          count[i], cidr[i], PLURAL_COMMA(count[i], cidr[i]),
                          100.0 * (double)count[i]/pow(2.0, cidr[i]), cidr[i]);
        }
        return;
    }

    /* first IP */
    skipaddrCopy(&min_ip, &ipaddr);
    old_addr = ~(skipaddrGetV4(&ipaddr));

    do {
        /* find most significant bit where they differ */
        xor_ips = old_addr ^ skipaddrGetV4(&ipaddr);

        count[0] += (1 << (32 - prefix));
        for (i = 1; i < NUM_LEVELS_V4; ++i) {
            if (xor_ips & mask[i]) {
                for ( ; i < NUM_LEVELS_V4 && prefix >= cidr[i]; ++i) {
                    ++count[i];
                }
                for ( ; i < NUM_LEVELS_V4; ++i) {
                    count[i] += (1 << (cidr[i] - prefix));
                }
                break;
            }
        }

        old_addr = skipaddrGetV4(&ipaddr);
    } while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK);

    /* get max IP */
    skCIDR2IPRange(&ipaddr, prefix, &ipaddr, &max_ip);

    /* ignore the map-v4 ip_format here since we are printing the data
     * for an IPv4 IPset */
    local_fmt = ip_format & ~SKIPADDR_MAP_V4;
    width = skipaddrStringMaxlen(0, local_fmt);
    skStreamPrint(outstream,
                  ("Network Summary\n"
                   "\tminimumIP = %*s\n"
                   "\tmaximumIP = %*s\n"),
                  width, skipaddrString(ip_str1, &min_ip, local_fmt),
                  width, skipaddrString(ip_str2, &max_ip, local_fmt));

    skStreamPrint(outstream,
                  ("\t%10" PRIu64 " host%s  %10.6f%% of 2^32\n"),
                  count[0], ((count[0] == 1) ? " (/32),  " : "s (/32s),"),
                  100.0 *((double)count[0]) / pow(2.0, cidr[0]));

    for (i = 1; i < NUM_LEVELS_V4; ++i) {
        skStreamPrint(outstream,
                      ("\t%10" PRIu64 " occupied /%u%s %10.6f%% of 2^%u\n"),
                      count[i], cidr[i], PLURAL_COMMA(count[i], cidr[i]),
                      100.0 * (double)count[i] / pow(2.0, cidr[i]), cidr[i]);
    }
}

static void
printStatistics(
    const skipset_t    *ipset)
{
#if SK_ENABLE_IPV6
    if (skIPSetIsV6(ipset)) {
        printStatisticsV6(ipset);
        return;
    }
#endif  /* SK_ENABLE_IPV6 */
    printStatisticsV4(ipset);
}


/*
 *  setcatProcessFile(filename);
 *
 *    Read the IPset from 'file' and print the output requested by the
 *    user to the global stream 'outstream'.
 */
static void
setcatProcessFile(
    const char         *filename)
{
    char errbuf[2 * PATH_MAX];
    skstream_t *stream = NULL;
    char count[64];
    skipset_t *ipset = NULL;
    int rv;

    /* Open the stream containing the IPset */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        skAppPrintErr("Unable to read IPset from '%s': %s",
                      filename, errbuf);
        goto END;
    }

    /* Read the IPset into memory if we must */
    if (opt_flags.statistics
        || (opt_flags.count_ips
            && (opt_flags.print_ips
                || opt_flags.network_structure
                || opt_flags.ip_ranges)))
    {
        rv = skIPSetRead(&ipset, stream);
        if (rv) {
            if (SKIPSET_ERR_FILEIO == rv) {
                skStreamLastErrMessage(stream,
                                       skStreamGetLastReturnValue(stream),
                                       errbuf, sizeof(errbuf));
            } else {
                strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
                errbuf[sizeof(errbuf) - 1] = '\0';
            }
            skAppPrintErr("Unable to read IPset from '%s': %s",
                          filename, errbuf);
            goto END;
        }
        skStreamDestroy(&stream);
    }

    assert((ipset && !stream) || (stream && !ipset));

    /* Print count and/or print file name if requested */
    if (opt_flags.count_ips) {
        if (opt_flags.print_filenames) {
            skStreamPrint(outstream, "%s:", filename);
        }
        if (ipset) {
            skStreamPrint(outstream, "%s\n",
                          skIPSetCountIPsString(ipset, count, sizeof(count)));
        } else {
            rv = skIPSetProcessStreamCountIPs(stream, count, sizeof(count));
            if (SKIPSET_OK == rv) {
                skStreamPrint(outstream, "%s\n", count);
            } else {
                if (SKIPSET_ERR_FILEIO == rv) {
                    skStreamLastErrMessage(stream,
                                           skStreamGetLastReturnValue(stream),
                                           errbuf, sizeof(errbuf));
                    skAppPrintErr("Unable to read IPset from '%s': %s",
                                  filename, errbuf);
                } else {
                    strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
                    errbuf[sizeof(errbuf) - 1] = '\0';
                    skAppPrintErr("Unable to count IPs in IPset from '%s': %s",
                                  filename, errbuf);
                }
                goto END;
            }
        }
    } else if (opt_flags.print_filenames) {
        skStreamPrint(outstream, "%s:\n", filename);
    }

    /* Print contents of the IPset */
    if (opt_flags.print_ips) {
        printIPs(ipset, stream);
    }
    else if (opt_flags.network_structure) {
        printNetwork(ipset, stream);
    }
    else if (opt_flags.ip_ranges) {
        printRanges(ipset, stream);
    }

    /* Print statistics */
    if (opt_flags.statistics) {
        assert(ipset);
        printStatistics(ipset);
    }

  END:
    skIPSetDestroy(&ipset);
    skStreamDestroy(&stream);
}


int main(int argc, char **argv)
{
    int i;

    appSetup(argc, argv);                       /* never returns on error */

    if (arg_index == argc) {
        setcatProcessFile("stdin");
    } else {
        for (i = arg_index; i < argc; ++i) {
            setcatProcessFile(argv[i]);
        }
    }

    /* done */
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
