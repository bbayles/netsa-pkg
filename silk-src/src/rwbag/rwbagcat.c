/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
 *    rwbagcat reads a binary bag, converts it to text, and outputs it
 *    to stdout.  It can also print various statistics and summary
 *    information about the bag.  It attempts to read the bag(s) from
 *    stdin or from any arguments.
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwbagcat.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skbag.h>
#include <silk/skcountry.h>
#include <silk/skheap.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/sknetstruct.h>
#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* return 1 if 'm_arg' refers to the standard input */
#define IS_STDIN(m_arg)                                                 \
    (0 == strcmp((m_arg), "-") || 0 == strcmp((m_arg), "stdin"))

/* width of count fields in columnar output */
#define COUNT_WIDTH 20

/* the minimum counter allowed by the --mincounter switch */
#define BAGCAT_MIN_COUNTER  UINT64_C(1)

/* mask for the key_format to determine which of these values it has */
#define KEY_FORMAT_MASK     UINT32_C(0xF0000000)

/* for the --key-format, value to indicate an IP address */
#define KEY_FORMAT_IP       UINT32_C(0x80000000)

/* for the --key-format, value to indicate a timestamp */
#define KEY_FORMAT_TIME     UINT32_C(0x40000000)

/* for --sort-counter, the initial size of the heap */
#define BAGCAT_HEAP_INITIAL_SIZE  (1u << 20)


/* return a non-zero value if a record's 'key' and 'counter' values
 * are within the global limits and if the key is in the global
 * 'mask_set' if specified */
#define CHECK_LIMITS_IPADDR(k, c)                                       \
    (((c)->val.u64 >= limits.mincounter)                                \
     && ((c)->val.u64 <= limits.maxcounter)                             \
     && ((0 == limits.key_is_min)                                       \
         || (skipaddrCompare(&limits.minkey_ip, &(k)->val.addr) <= 0))  \
     && ((0 == limits.key_is_max)                                       \
         || (skipaddrCompare(&limits.maxkey_ip, &(k)->val.addr) >= 0))  \
     && ((NULL == limits.mask_set)                                      \
         || skIPSetCheckAddress(limits.mask_set, &(k)->val.addr)))

#define CHECK_LIMITS_UINT32(k, c)                       \
    (((c)->val.u64 >= limits.mincounter)                \
     && ((c)->val.u64 <= limits.maxcounter)             \
     && ((0 == limits.key_is_min)                       \
         || ((k)->val.u32 >= limits.minkey_u32))        \
     && ((0 == limits.key_is_max)                       \
         || ((k)->val.u32 <= limits.maxkey_u32)))

/* Allow paging of the output */
#define INVOKE_PAGER()                          \
    if (pager_invoked) { /* no-op */ } else {   \
        pager_invoked = 1;                      \
        skStreamPageOutput(output, pager);      \
    }

typedef enum bin_scheme_en {
    BINSCHEME_NONE=0,
    BINSCHEME_LINEAR=1,
    BINSCHEME_BINARY=2,
    BINSCHEME_DECIMAL=3
} bin_scheme_t;


typedef enum bagcat_fmt_en {
    BAGCAT_FMT_ATTRIBUTES,
    BAGCAT_FMT_COUNTRY,
    BAGCAT_FMT_IPADDR,
    BAGCAT_FMT_PMAP,
    BAGCAT_FMT_SENSOR,
    BAGCAT_FMT_TCPFLAGS,
    BAGCAT_FMT_TIME
} bagcat_fmt_t;

struct bagcat_key_st {
    skBagKeyType_t      key_type;
    bagcat_fmt_t        formatter;
    uint32_t            formatter_flags;
    int                 width;
    size_t              buflen;
};
typedef struct bagcat_key_st bagcat_key_t;

/* printing state */
struct state_st {
    const bagcat_key_t *bc_key;
    char                end_of_line[2];
    int                 width[2];
    size_t              buflen;
    char               *buf;
};
typedef struct state_st state_t;

/* bagcat_heapnode_t is how key/counter pairs are stored in the heap
 * that is used to implement the --sort-counter switch */
struct bagcat_heapnode_st {
    uint64_t            counter;
    skBagTypedKey_t     key;
};
typedef struct bagcat_heapnode_st bagcat_heapnode_t;



/* LOCAL VARIABLES */

/* global I/O state */
sk_options_ctx_t *optctx = NULL;
static skstream_t *output = NULL;
static skstream_t *stats_stream = NULL;
static int print_statistics = 0;
static int print_network = 0;
static int sort_counters = 0;
static bin_scheme_t bin_scheme = BINSCHEME_NONE;
static const char *net_structure = NULL;

/* delimiter between output columns for hosts/counts */
static char output_delimiter = '|';

/* whether key/counter output is in columns (0) or scrunched together (1) */
static int no_columns = 0;

/* whether to suppress the final delimiter; default no (i.e. end with '|') */
static int no_final_delimiter = 0;

/* how to format the keys.  Value is set by the --key-format switch.
 * Possible values include an skipaddr_flags_t value from silk_types.h
 * or an sktimestamp_flags_t value from utils.h.  The default format
 * is determined by the type of Bag, or it is SKIPADDR_CANONICAL for
 * CUSTOM keys (including SiLK-2 Bag files) or SKIPADDR_DECIMAL
 * otherwise. */
static uint32_t key_format = 0;

/* the caller's key format argument; for error messages */
static const char *key_format_arg = NULL;

/* prefix map to use for keys in bags whose key is a pmap dictionary */
static skPrefixMap_t *prefix_map = NULL;

/* print out keys whose counter is zero---requires a mask_set or that
 * both --minkey and --maxkey are specified */
static int print_zero_counts = 0;

/* the limits for determining which entries get printed. */
static struct limits_st {
    /* the {min,max}counter entered */
    uint64_t        mincounter;
    uint64_t        maxcounter;

    /* only print keys that appear in this set */
    skipset_t      *mask_set;

    /* the {min,max}key entered */
    skipaddr_t      minkey_ip;
    skipaddr_t      maxkey_ip;

    /* the {min,max}key as a uint32_t */
    uint32_t        minkey_u32;
    uint32_t        maxkey_u32;

    /* true when any limit switch or mask-set was specified */
    unsigned        active     :1;

    /* true when minkey or maxkey was given */
    unsigned        key_is_min :1;
    unsigned        key_is_max :1;

} limits;

/* name of program to run to page output */
static char *pager = NULL;

/* whether the pager has been invoked.  this is set to true when the
 * --output-path switch is specified to bypass the pager */
static int pager_invoked = 0;

/* values provided to min-key and max-key switches; for errros */
static char *min_key = NULL;
static char *max_key = NULL;

/* possible key formats */
static const sk_stringmap_entry_t key_format_names[] = {
    {"canonical",       KEY_FORMAT_IP | SKIPADDR_CANONICAL,
     "canonical IP format (192.0.2.1, 2001:db8::1, ::ffff:127.0.0.1)", NULL},
    {"decimal",         KEY_FORMAT_IP | SKIPADDR_DECIMAL,
     "integer number in decimal format", NULL},
    {"hexadecimal",     KEY_FORMAT_IP | SKIPADDR_HEXADECIMAL,
     "integer number in hexadecimal format", NULL},
    {"no-mixed",        KEY_FORMAT_IP | SKIPADDR_NO_MIXED,
     "canonical IP format but no mixed IPv4/IPv6 for IPv6 IPs", NULL},
    {"zero-padded",     KEY_FORMAT_IP | SKIPADDR_ZEROPAD,
     "pad IP result to its maximum width with zeros", NULL},
    {"map-v4",          KEY_FORMAT_IP | SKIPADDR_MAP_V4,
     "map IPv4 to ::ffff:0:0/96 netblock prior to formatting", NULL},
    {"unmap-v6",        KEY_FORMAT_IP | SKIPADDR_UNMAP_V6,
     "convert IPv6 in ::ffff:0:0/96 to IPv4 prior to formatting", NULL},
    {"force-ipv6",      KEY_FORMAT_IP | SKIPADDR_FORCE_IPV6,
     "alias equivalent to \"map-v4,no-mixed\"", NULL},
    {"timestamp",       KEY_FORMAT_TIME | 0,
     "time in yyyy/mm/ddThh:mm:ss format", NULL},
    {"iso-time",        KEY_FORMAT_TIME | SKTIMESTAMP_ISO,
     "time in yyyy-mm-dd hh:mm:ss format", NULL},
    {"m/d/y",           KEY_FORMAT_TIME | SKTIMESTAMP_MMDDYYYY,
     "time in mm/dd/yyyy hh:mm:ss format", NULL},
    {"utc",             KEY_FORMAT_TIME | SKTIMESTAMP_UTC,
     "print as time using UTC", NULL},
    {"localtime",       KEY_FORMAT_TIME | SKTIMESTAMP_LOCAL,
     "print as time and use TZ environment variable or local timezone", NULL},
    {"epoch",           KEY_FORMAT_TIME | SKTIMESTAMP_EPOCH,
     "seconds since UNIX epoch (equivalent to decimal)", NULL},
    SK_STRINGMAP_SENTINEL
};

/* the stringmap that contains those formats */
static sk_stringmap_t *key_format_map = NULL;

/* whether stdin has been used */
static int stdin_used = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_NETWORK_STRUCTURE,
    OPT_BIN_IPS,
    OPT_SORT_COUNTERS,
    OPT_PRINT_STATISTICS,
    OPT_MASK_SET,
    OPT_MINKEY,
    OPT_MAXKEY,
    OPT_MINCOUNTER,
    OPT_MAXCOUNTER,
    OPT_ZERO_COUNTS,
    OPT_PMAP_FILE,
    OPT_KEY_FORMAT,
    OPT_INTEGER_KEYS,
    OPT_ZERO_PAD_IPS,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_OUTPUT_PATH,
    OPT_PAGER
} appOptionsEnum;


static struct option appOptions[] = {
    {"network-structure",   OPTIONAL_ARG, 0, OPT_NETWORK_STRUCTURE},
    {"bin-ips",             OPTIONAL_ARG, 0, OPT_BIN_IPS},
    {"sort-counters" ,      OPTIONAL_ARG, 0, OPT_SORT_COUNTERS},
    {"print-statistics",    OPTIONAL_ARG, 0, OPT_PRINT_STATISTICS},
    {"mask-set",            REQUIRED_ARG, 0, OPT_MASK_SET},
    {"minkey",              REQUIRED_ARG, 0, OPT_MINKEY},
    {"maxkey",              REQUIRED_ARG, 0, OPT_MAXKEY},
    {"mincounter",          REQUIRED_ARG, 0, OPT_MINCOUNTER},
    {"maxcounter",          REQUIRED_ARG, 0, OPT_MAXCOUNTER},
    {"zero-counts",         NO_ARG,       0, OPT_ZERO_COUNTS},
    {"pmap-file",           REQUIRED_ARG, 0, OPT_PMAP_FILE},
    {"key-format",          REQUIRED_ARG, 0, OPT_KEY_FORMAT},
    {"integer-keys",        NO_ARG,       0, OPT_INTEGER_KEYS},
    {"zero-pad-ips",        NO_ARG,       0, OPT_ZERO_PAD_IPS},
    {"no-columns",          NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",  NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",           OPTIONAL_ARG, 0, OPT_DELIMITED},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"pager",               REQUIRED_ARG, 0, OPT_PAGER},
    {0,0,0,0 }              /* sentinel entry */
};


static const char *appHelp[] = {
    NULL,
    ("Invert the bag and count by distinct volume values.  May not\n"
     "\tbe combined with --network-structure or --sort-counters. Choices:\n"
     "\tlinear   - volume => count(KEYS) [default when no argument]\n"
     "\tbinary   - log2(volume) => count(KEYS)\n"
     "\tdecimal  - variation on log10(volume) => count(KEYS)"),
    ("Sort the output by counters instead of by keys.  May\n"
     "\tnot be combined with --network-structure or --bin-ips. Choices:\n"
     "\tdecreasing - print highest counter first [default when no argument]\n"
     "\tincreasing - print lowest counter first"),
    ("Print statistics about the bag.  Def. no. Write\n"
     "\toutput to the standard output unless an argument is given.\n"
     "\tUse 'stderr' to send the output to the standard error"),
    ("Output records that appear in this IPset. Def. Records\n"
     "\twith non-zero counters"),
    NULL,
    NULL,
    NULL,
    NULL,
    ("Print keys with a counter of zero. Def. No\n"
     "\t(requires --mask-set or both --minkey and --maxkey)"),
    ("Use this prefix map as the mapping file when Bag's key\n"
     "\twas generated by a pmap. May be specified as MAPNAME:PATH, but the\n"
     "\tmapname is currently ignored."),
    NULL,
    "DEPRECATED. Equivalent to --key-format=decimal",
    "DEPRECATED. Equivalent to --key-format=zero-padded",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
    "Write the output to this stream or file. Def. stdout",
    "Invoke this program to page output. Def. $SILK_PAGER or $PAGER",
    (char *) NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  setOutput(const char* filename, skstream_t **stream_out);
static int  parsePmapFileOption(const char *opt_arg);
static int  keyFormatParse(const char *format);
static void keyFormatUsage(FILE *fh);


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
#define USAGE_MSG                                                            \
    ("[SWITCHES] [BAG_FILES]\n"                                              \
     "\tPrint binary Bag files as text.  When multiple files are given,\n"   \
     "\tthe bags are processed sequentially---specifically, their entries\n" \
     "\tare not merged.\n")

    /* network-structure help string is longer than allowed by C90 */
#define NETWORK_STRUCT_HELP1                                                  \
    ("Print the sum of counters for each specified CIDR\n"                    \
     "\tblock in the comma-separed list of CIDR block sizes (0--32) and/or\n" \
     "\tletters (T=0,A=8,B=16,C=24,X=27,H=32). If argument contains 'S' or\n" \
     "\t'/', for each CIDR block print host counts and number of occupied\n")
#define NETWORK_STRUCT_HELP2                                                 \
    ("\tsmaller CIDR blocks.  Additional CIDR blocks to summarize can be\n"  \
     "\tspecified by listing them after the '/'. Def. v4:TS/8,16,24,27.\n"   \
     "\tA leading 'v6:' treats Bag's keys as IPv6, allows range 0--128,\n"   \
     "\tdisallows A,B,C,X, sets H to 128, and sets default to TS/48,64.\n"   \
     "\tMay not be combined with --bin-ips or --sort-counters")

    FILE *fh = USAGE_FH;
    unsigned int i;
#if SK_ENABLE_IPV6
    const char *v4_or_v6 = "v6";
#else
    const char *v4_or_v6 = "v4";
#endif

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_NETWORK_STRUCTURE:
            fprintf(fh, "%s%s\n", NETWORK_STRUCT_HELP1, NETWORK_STRUCT_HELP2);
            break;
          case OPT_MINKEY:
            fprintf(fh,
                    ("Output records whose key is at least VALUE,"
                     " an IP%s address\n\tor an integer between"
                     " %" PRIu64 " and %" PRIu64 ", inclusive."
                     " Def. Records with\n\tnon-zero counters\n"),
                    v4_or_v6,
                    (uint64_t)SKBAG_KEY_MIN, (uint64_t)SKBAG_KEY_MAX);
            break;
          case OPT_MAXKEY:
            fprintf(fh,
                    ("Output records whose key is not more than VALUE,"
                     " an IP%s\n\taddress or an integer."
                     " Def. Records with non-zero counters\n"),
                    v4_or_v6);
            break;
          case OPT_MINCOUNTER:
            fprintf(fh,
                    ("Output records whose counter is at least VALUE,"
                     " an integer\n\tbetween %" PRIu64 " and %" PRIu64
                     ", inclusive. Def. %" PRIu64 "\n"),
                    BAGCAT_MIN_COUNTER, SKBAG_COUNTER_MAX, BAGCAT_MIN_COUNTER);
            break;
          case OPT_MAXCOUNTER:
            fprintf(fh,
                    ("Output records whose counter is not more than VALUE,"
                     " an\n\tinteger.  Def. %" PRIu64 "\n"),
                    SKBAG_COUNTER_MAX);
            break;
          case OPT_KEY_FORMAT:
            keyFormatUsage(fh);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    sksiteOptionsUsage(fh);
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

    if (stats_stream != output) {
        skStreamDestroy(&stats_stream);
    }
    skStreamDestroy(&output);

    skPrefixMapDelete(prefix_map);
    skStringMapDestroy(key_format_map);

    skOptionsCtxDestroy(&optctx);
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
    unsigned int optctx_flags;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
            (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&limits, 0, sizeof(limits));
    limits.mincounter = SKBAG_COUNTER_MIN;
    limits.maxcounter = SKBAG_COUNTER_MAX;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_BINARY | SK_OPTIONS_CTX_ALLOW_STDIN);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
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

    /* create the string map of the possible key formats */
    if ((skStringMapCreate(&key_format_map) != SKSTRINGMAP_OK)
        || (skStringMapAddEntries(key_format_map, -1, key_format_names)
            != SKSTRINGMAP_OK))
    {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    if (print_network) {
        /* may not have --print-network and --bin-scheme */
        if (bin_scheme != BINSCHEME_NONE) {
            skAppPrintErr("Cannot specify both --%s and --%s",
                          appOptions[OPT_NETWORK_STRUCTURE].name,
                          appOptions[OPT_BIN_IPS].name);
            exit(EXIT_FAILURE);
        }
        /* ensure key-format is an IP */
        if (key_format && !(key_format & KEY_FORMAT_IP)) {
            skAppPrintErr("Invalid %s: May only use an IP format with --%s",
                          appOptions[OPT_KEY_FORMAT].name,
                          appOptions[OPT_NETWORK_STRUCTURE].name);
            exit(EXIT_FAILURE);
        }
        /* disable mapping of ::ffff:0:0/96 to IPv4 */
        key_format = key_format & ~SKIPADDR_UNMAP_V6;
    }

    /* when printing of entries with counters of 0 is requested,
     * either --mask-set or both --minkey and --maxkey must be
     * given */
    if (print_zero_counts
        && (NULL == limits.mask_set)
        && (0 == limits.key_is_min || 0 == limits.key_is_max))
    {
        skAppPrintErr("To use --%s, either --%s or both --%s and --%s"
                      " must be specified",
                      appOptions[OPT_ZERO_COUNTS].name,
                      appOptions[OPT_MASK_SET].name,
                      appOptions[OPT_MINKEY].name,
                      appOptions[OPT_MAXKEY].name);
        skAppUsage();           /* never returns */
    }

    /* write an error message and exit when a minimum is greater than
     * a maximum */
    if (limits.mincounter > limits.maxcounter) {
        skAppPrintErr(("Minimum counter greater than maximum: "
                       "%" PRIu64 " > %" PRIu64),
                      limits.mincounter, limits.maxcounter);
        exit(EXIT_FAILURE);
    }
    if (limits.key_is_min && limits.key_is_max) {
        if (skipaddrCompare(&limits.maxkey_ip, &limits.minkey_ip) < 0) {
            skAppPrintErr("Minimum key greater than maximum: %s > %s",
                          min_key, max_key);
            exit(EXIT_FAILURE);
        }
    }

    /* when an output-path was given, disable the pager.  If no
     * output-path was given, set it to the default */
    if (output) {
        /* do not page the output */
        pager_invoked = 1;
    } else {
        if (setOutput("stdout", &output)) {
            skAppPrintErr("Unable to print to standard output");
            exit(EXIT_FAILURE);
        }
    }

    /* set stream and pager for --print-statistics */
    if (print_statistics) {
        if (NULL == stats_stream) {
            /* Set the --print-stat output stream to stdout if the
             * user did not set it */
            if (setOutput("stdout", &stats_stream)) {
                skAppPrintErr("Unable to print to standard output");
                exit(EXIT_FAILURE);
            }
        } else if (bin_scheme == BINSCHEME_NONE
                   && !sort_counters && !print_network)
        {
            /* Disable the pager when the only output is --print-stat
             * and an explicit stream was specified */
            pager_invoked = 1;
        }
    }

    rv = skStreamOpen(output);
    if (rv) {
        skStreamPrintLastErr(output, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    if (stats_stream != NULL && stats_stream != output) {
        rv = skStreamOpen(stats_stream);
        if (rv) {
            skStreamPrintLastErr(stats_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    return; /* OK */
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Called by skOptionsParse(), this handles a user-specified switch
 *    that the application has registered, typically by setting global
 *    variables.  Returns 1 if the switch processing failed or 0 if it
 *    succeeded.  Returning a non-zero from from the handler causes
 *    skOptionsParse() to return a negative value.
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
    skstream_t *stream = NULL;
    uint64_t val64;
    size_t len;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_NETWORK_STRUCTURE:
        net_structure = opt_arg;
        print_network = 1;
        break;

      case OPT_PMAP_FILE:
        if (prefix_map) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (IS_STDIN(opt_arg)) {
            stdin_used = 1;
        }
        if (parsePmapFileOption(opt_arg)) {
            return 1;
        }
        break;

      case OPT_BIN_IPS:
        if (NULL == opt_arg) {
            bin_scheme = BINSCHEME_LINEAR;
        } else if (0 == (len = strlen(opt_arg))) {
            skAppPrintErr("Invalid %s: Switch requires an argument",
                          appOptions[opt_index].name);
            return 1;
        } else if (strncmp(opt_arg, "linear", len) == 0) {
            bin_scheme = BINSCHEME_LINEAR;
        } else if (strncmp(opt_arg, "binary", len) == 0) {
            bin_scheme = BINSCHEME_BINARY;
        } else if (strncmp(opt_arg, "decimal", len) == 0) {
            bin_scheme = BINSCHEME_DECIMAL;
        } else {
            skAppPrintErr(
                "Illegal %s '%s'. Valid schemes: linear, binary, decimal",
                appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_SORT_COUNTERS:
        if (NULL == opt_arg) {
            sort_counters = 1;
        } else if (0 == (len = strlen(opt_arg))) {
            skAppPrintErr("Invalid %s: Switch requires an argument",
                          appOptions[opt_index].name);
            return 1;
        } else if (0 == strncmp("decreasing", opt_arg, len)) {
            sort_counters = 1;
        } else if (0 == strncmp("increasing", opt_arg, len)) {
            sort_counters = -1;
        } else {
            skAppPrintErr(
                "Invalid %s '%s': Valid values: decreasing, increasing",
                appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_PRINT_STATISTICS:
        if (opt_arg != NULL) {
            if (stats_stream) {
                skAppPrintErr("Invalid %s: Switch used multiple times",
                              appOptions[opt_index].name);
                return 1;
            }
            if (setOutput(opt_arg, &stats_stream)) {
                skAppPrintErr("Invalid %s '%s'",
                              appOptions[opt_index].name, opt_arg);
                return 1;
            }
        }
        print_statistics = 1;
        break;

      case OPT_MINCOUNTER:
        rv = skStringParseUint64(&val64, opt_arg,
                                 BAGCAT_MIN_COUNTER, SKBAG_COUNTER_MAX);
        if (rv == SKUTILS_ERR_MINIMUM) {
            skAppPrintErr(("Invalid %s: Smallest allowable value is %" PRIu64
                           ".\n"
                           "\tUse --%s to print records whose counters are 0"),
                          appOptions[opt_index].name, BAGCAT_MIN_COUNTER,
                          appOptions[OPT_ZERO_COUNTS].name);
            return 1;
        }
        if (rv) {
            goto PARSE_ERROR;
        }
        limits.mincounter = val64;
        limits.active = 1;
        break;

      case OPT_MAXCOUNTER:
        rv = skStringParseUint64(&val64, opt_arg,
                                 BAGCAT_MIN_COUNTER, SKBAG_COUNTER_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        limits.maxcounter = val64;
        limits.active = 1;
        break;

      case OPT_MINKEY:
        rv = skStringParseIP(&limits.minkey_ip, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (skipaddrGetAsV4(&limits.minkey_ip, &limits.minkey_u32)) {
#if SK_ENABLE_IPV6
            limits.minkey_u32 = 1;
#endif  /* SK_ENABLE_IPV6 */
        }
        min_key = opt_arg;
        limits.key_is_min = 1;
        limits.active = 1;
        break;

      case OPT_MAXKEY:
        rv = skStringParseIP(&limits.maxkey_ip, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (skipaddrGetAsV4(&limits.maxkey_ip, &limits.maxkey_u32)) {
#if SK_ENABLE_IPV6
            limits.maxkey_u32 = UINT32_MAX;
#endif  /* SK_ENABLE_IPV6 */
        }
        max_key = opt_arg;
        limits.key_is_max = 1;
        limits.active = 1;
        break;

      case OPT_MASK_SET:
        if (limits.mask_set) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, opt_arg))
            || (rv = skStreamOpen(stream)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            return 1;
        }
        rv = skIPSetRead(&limits.mask_set, stream);
        if (rv) {
            if (SKIPSET_ERR_FILEIO == rv) {
                skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                     &skAppPrintErr);
            } else {
                skAppPrintErr("Unable to read IPset from '%s': %s",
                              opt_arg, skIPSetStrerror(rv));
            }
            skStreamDestroy(&stream);
            return 1;
        }
        skStreamDestroy(&stream);
        limits.active = 1;
        break;

      case OPT_OUTPUT_PATH:
        if (output) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (setOutput(opt_arg, &output)) {
            skAppPrintErr("Invalid %s '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_NO_COLUMNS:
        no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        output_delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        no_columns = 1;
        no_final_delimiter = 1;
        if (opt_arg) {
            output_delimiter = opt_arg[0];
        }
        break;

      case OPT_KEY_FORMAT:
        key_format_arg = opt_arg;
        if (keyFormatParse(opt_arg)) {
            return 1;
        }
        break;

      case OPT_INTEGER_KEYS:
        if (keyFormatParse("decimal")) {
            skAbort();
        }
        break;

      case OPT_ZERO_PAD_IPS:
        if (keyFormatParse("zero-padded")) {
            skAbort();
        }
        break;

      case OPT_ZERO_COUNTS:
        print_zero_counts = 1;
        break;

      case OPT_PAGER:
        pager = opt_arg;
        break;
    }

    return 0;                   /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  status = keyFormatParse(format_string);
 *
 *    Parse the key-format value contained in 'format_string'.  Return
 *    0 on success, or -1 if parsing of the value fails.
 */
static int
keyFormatParse(
    const char         *format)
{
    const unsigned format_timezone = (SKTIMESTAMP_UTC | SKTIMESTAMP_LOCAL);
    const unsigned format_ip_mapping = (SKIPADDR_MAP_V4 | SKIPADDR_UNMAP_V6);
    char *errmsg;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *found_entry;
    int rv = -1;

    /* attempt to match the user's format */
    if (skStringMapParse(
            key_format_map, format, SKSTRINGMAP_DUPES_ERROR, &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_KEY_FORMAT].name, errmsg);
        goto END;
    }

    /* determine which value(s) the user specified and check for
     * conflicting values. The only multiple-value possibility that is
     * allowed is a timezone with a time format. */
    while (skStringMapIterNext(iter, &found_entry, NULL) == SK_ITERATOR_OK) {
        if (!key_format) {
            key_format = found_entry->id;
        } else if ((KEY_FORMAT_MASK & key_format)
                   != (KEY_FORMAT_MASK & found_entry->id))
        {
            skAppPrintErr("Invalid %s '%s': Combination is nonsensical",
                          appOptions[OPT_KEY_FORMAT].name, format);
            goto END;
        } else if ((KEY_FORMAT_MASK & key_format) == KEY_FORMAT_IP) {
            if (found_entry->id == (KEY_FORMAT_IP | SKIPADDR_ZEROPAD)) {
                key_format |= found_entry->id;
            } else if ((key_format & format_ip_mapping)
                       && (found_entry->id & format_ip_mapping))
            {
                skAppPrintErr(
                    "Invalid %s '%s': May only specify one IP mapping option",
                    appOptions[OPT_KEY_FORMAT].name, format);
                goto END;
            } else if (0 == ((format_ip_mapping | SKIPADDR_ZEROPAD)
                             & (key_format | found_entry->id)))
            {
                skAppPrintErr("Invalid %s '%s': May only specify one IP format",
                              appOptions[OPT_KEY_FORMAT].name, format);
                goto END;
            } else {
                key_format |= found_entry->id;
            }
        } else if (SKTIMESTAMP_EPOCH & (key_format | found_entry->id)) {
            skAppPrintErr(
                "Invalid %s '%s': May not use another time format with '%s'",
                appOptions[OPT_KEY_FORMAT].name, format,
                skStringMapGetFirstName(
                    key_format_map, (KEY_FORMAT_TIME | SKTIMESTAMP_EPOCH)));
            goto END;
        } else if ((key_format & format_timezone)
                   && (found_entry->id & format_timezone))
        {
            skAppPrintErr(
                "Invalid %s '%s': May only specify one timezone format",
                appOptions[OPT_KEY_FORMAT].name, format);
            goto END;
        } else if (0 == (format_timezone & (key_format | found_entry->id))) {
            skAppPrintErr(
                "Invalid %s '%s': May only specify one time format",
                appOptions[OPT_KEY_FORMAT].name, format);
            goto END;
        } else {
            key_format |= found_entry->id;
        }
    }

    rv = 0;

  END:
    skStringMapIterDestroy(iter);
    return rv;
}


/*
 *  keyFormatUsage(fh);
 *
 *    Print the description of the argument to the --key-format
 *    switch to the 'fh' file handle.
 */
static void
keyFormatUsage(
    FILE               *fh)
{
    char bagtype[SKBAG_MAX_FIELD_BUFLEN];

    fprintf(
        fh, ("Print keys in specified format. Default is determined by\n"
             "\tthe type of key in the bag;"
             " the '%s' format is used when bag's\n"
             "\tkey is %s or has no type, '%s' format otherwise. Choices:\n"),
        skStringMapGetFirstName(
            key_format_map, KEY_FORMAT_IP | SKIPADDR_CANONICAL),
        skBagFieldTypeAsString(SKBAG_FIELD_CUSTOM, bagtype, sizeof(bagtype)),
        skStringMapGetFirstName(
            key_format_map, KEY_FORMAT_IP | SKIPADDR_DECIMAL));
    skStringMapPrintDetailedUsage(key_format_map, fh);
}


/*
 *    Parse the [MAPNAME:]PMAP_PATH option and set the result in the
 *    global 'prefix_map'.  Return 0 on success or -1 on error.
 */
static int
parsePmapFileOption(
    const char         *opt_arg)
{
    skPrefixMapErr_t rv_map;
    skstream_t *stream;
    const char *sep;
    const char *filename;
    int rv;

    /* check for a leading mapname */
    sep = strchr(opt_arg, ':');
    if (NULL == sep) {
        /* no mapname; check for one in the pmap once we read it */
        filename = opt_arg;
    } else if (sep == opt_arg) {
        /* treat a 0-length mapname on the command as having none.
         * Allows use of default mapname for files that contain the
         * separator. */
        filename = sep + 1;
    } else {
        /* a mapname was supplied on the command line */
        filename = sep + 1;
#if 0
        /* no need to keep the mapname */
        size_t namelen;
        char *mapname;

        if (memchr(opt_arg, ',', sep - opt_arg) != NULL) {
            skAppPrintErr("Invalid %s: The map-name may not include a comma",
                          appOptions[OPT_PMAP_FILE].name);
            goto END;
        }
        namelen = sep - opt_arg;
        mapname = (char *)malloc(namelen + 1);
        if (NULL == mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
        strncpy(mapname, opt_arg, namelen);
        mapname[namelen] = '\0';
#endif  /* 0 */
    }

    /* open the file and read the prefix map */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }
    rv_map = skPrefixMapRead(&prefix_map, stream);
    if (SKPREFIXMAP_OK != rv_map) {
        if (SKPREFIXMAP_ERR_IO == rv_map) {
            skStreamPrintLastErr(
                stream, skStreamGetLastReturnValue(stream), &skAppPrintErr);
        } else {
            skAppPrintErr("Failed to read the prefix map file '%s': %s",
                          filename, skPrefixMapStrerror(rv_map));
        }
        skStreamDestroy(&stream);
        return -1;
    }
    skStreamDestroy(&stream);

#if 0
    /* get the mapname from the file when none on command line */
    if (NULL == mapname) {
        if (NULL == skPrefixMapGetMapName(prefix_map)) {
            skAppPrintErr(("Invalid %s '%s': Prefix map file does not contain"
                           " a map-name and none provided on the command line"),
                appOptions[OPT_PMAP_FILE].name, filename);
            goto END;
        }
        mapname = strdup(skPrefixMapGetMapName(prefix_map));
        if (NULL == mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }
#endif  /* 0 */

    return 0;
}


/*
 *  status = setOutput(name, &stream);
 *
 *    Set stream's output to 'name'.  If 'name' is the standard output
 *    and an existing stream is already open to the standard output,
 *    set 'stream' to that existing stream.  Return 0 on success, -1
 *    otherwise.
 */
static int
setOutput(
    const char         *filename,
    skstream_t        **stream)
{
    int rv;

    assert(stream);

    if (filename == NULL || filename[0] == '\0') {
        skAppPrintErr("Empty filename");
        return -1;
    }

    /* compare 'filename' with known streams */
    if (output) {
        if ((0 == strcmp(skStreamGetPathname(output), filename))
            || (0 == strcmp(filename, "stdout")
                && 0 == strcmp(skStreamGetPathname(output), "-"))
            || (0 == strcmp(filename, "-")
                && 0 == strcmp(skStreamGetPathname(output), "stdout")))
        {
            *stream = output;
            return 0;
        }
    }
    if (stats_stream) {
        if ((0 == strcmp(skStreamGetPathname(stats_stream), filename))
            || (0 == strcmp(filename, "stdout")
                && 0 == strcmp(skStreamGetPathname(stats_stream), "-"))
            || (0 == strcmp(filename, "-")
                && 0 == strcmp(skStreamGetPathname(stats_stream), "stdout")))
        {
            *stream = stats_stream;
            return 0;
        }
    }

    if ((rv = skStreamCreate(stream, SK_IO_WRITE, SK_CONTENT_TEXT))
        || (rv = skStreamBind(*stream, filename)))
    {
        skStreamPrintLastErr(*stream, rv, &skAppPrintErr);
        skStreamDestroy(stream);
        return -1;
    }

    return 0;
}


/*
 *    Create and print a temporary bag whose keys are related to the
 *    counters of the input bag and the counters are the number of
 *    unique keys in the input bag.
 */
static int
bagcatInvertBag(
    const skBag_t      *bag)
{
    skBag_t *inverted_bag = NULL;
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skBagTypedKey_t bin;
    char s_label[64];
    char final_delim[] = {'\0', '\0'};
    int rv = 1;

    INVOKE_PAGER();

    if (!no_final_delimiter) {
        final_delim[0] = output_delimiter;
    }

    /* Create an inverted bag */
    if (skBagCreate(&inverted_bag) != SKBAG_OK) {
        goto END;
    }
    if (skBagIteratorCreate(bag, &iter) != SKBAG_OK) {
        goto END;
    }

    /* get key from bag as an ip address */
    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    bin.type = SKBAG_KEY_U32;

    /* loop over the entries, check whether they are in limits, and if
     * so, add the inverted entry to the bag */
    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        if (!CHECK_LIMITS_IPADDR(&key, &counter)) {
            continue;
        }
        switch (bin_scheme) {
          case BINSCHEME_LINEAR:
            bin.val.u32 = (uint32_t)((counter.val.u64 < UINT32_MAX)
                                     ? counter.val.u64
                                     : UINT32_MAX);
            break;
          case BINSCHEME_BINARY:
            bin.val.u32 = skIntegerLog2(counter.val.u64);
            break;
          case BINSCHEME_DECIMAL:
            if (counter.val.u64 < 100) {
                bin.val.u32 = (uint32_t)counter.val.u64;
            } else {
                bin.val.u32
                    = (uint32_t)floor((log10((double)counter.val.u64) - 1.0)
                                      * 100.0);
            }
            break;
          case BINSCHEME_NONE:
            skAbortBadCase(bin_scheme);
        }
        if (skBagCounterIncrement(inverted_bag, &bin) != SKBAG_OK) {
            goto END;
        }
    }

    skBagIteratorDestroy(iter);
    iter = NULL;

    /* iterate over inverted bag to print entries */
    if (skBagIteratorCreate(inverted_bag, &iter) != SKBAG_OK) {
        goto END;
    }

    while (skBagIteratorNextTyped(iter, &bin, &counter) == SKBAG_OK) {
        switch (bin_scheme) {
          case BINSCHEME_LINEAR:
            /* label is just bin number */
            snprintf(s_label, sizeof(s_label), ("%" PRIu32), bin.val.u32);
            break;

          case BINSCHEME_BINARY:
            /* label is range of values "2^03 to 2^04-1" */
            snprintf(s_label, sizeof(s_label),
                     ("2^%02" PRIu32 " to 2^%02" PRIu32 "-1"),
                     bin.val.u32, (bin.val.u32 + 1));
            break;

          case BINSCHEME_DECIMAL:
            /* label is the median value of possible keys in that bin */
            if (bin.val.u32 < 100) {
                snprintf(s_label, sizeof(s_label), ("%" PRIu32),bin.val.u32);
            } else {
                double min, max, mid;
                min = ceil(pow(10, (((double)bin.val.u32 / 100.0) + 1.0)));
                max = floor(pow(10, ((((double)bin.val.u32 + 1.0)/100.0)+1.0)));
                mid = floor((min + max) / 2.0);
                snprintf(s_label, sizeof(s_label), "%.0f", mid);
            }
            break;

          case BINSCHEME_NONE:
            skAbortBadCase(bin_scheme);
        }

        if (!no_columns) {
            skStreamPrint(output, ("%*s%c%*" PRIu64 "%s\n"),
                          COUNT_WIDTH, s_label, output_delimiter,
                          COUNT_WIDTH, counter.val.u64, final_delim);
        } else {
            skStreamPrint(output, ("%s%c%" PRIu64 "%s\n"),
                          s_label, output_delimiter,
                          counter.val.u64, final_delim);
        }
    }

    rv = 0;

  END:
    skBagDestroy(&inverted_bag);
    skBagIteratorDestroy(iter);

    return rv;
}


/*
 *    Print a single key-counter pair.  Used when the key is printed
 *    as a non-IP and non-number.
 *
 *    Helper for bagcatPrintBag().
 */
static void
bagcatPrintBagRow(
    const state_t              *state,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter)
{
    switch (state->bc_key->formatter) {
      case BAGCAT_FMT_ATTRIBUTES:
        skTCPStateString(key->val.u32, state->buf,
                         state->bc_key->formatter_flags);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_COUNTRY:
        skCountryCodeToName(key->val.u32, state->buf, state->buflen);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_IPADDR:
        skipaddrString(state->buf, &key->val.addr,
                       state->bc_key->formatter_flags);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_PMAP:
        skPrefixMapDictionaryGetEntry(prefix_map, key->val.u32, state->buf,
                                      state->buflen);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_SENSOR:
        sksiteSensorGetName(state->buf, state->buflen, key->val.u32);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_TCPFLAGS:
        skTCPFlagsString(key->val.u32, state->buf,
                         state->bc_key->formatter_flags);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;

      case BAGCAT_FMT_TIME:
        sktimestamp_r(state->buf, sktimeCreate(key->val.u32, 0),
                      state->bc_key->formatter_flags);
        skStreamPrint(output, "%*s%c%*" PRIu64 "%s\n",
                      state->width[0], state->buf, output_delimiter,
                      state->width[1], counter->val.u64, state->end_of_line);
        break;
    }
}

/*
 *    Print the contents of a bag file when the key is being displayed
 *    as something other than an IP address or a number.
 */
static int
bagcatPrintBag(
    const state_t      *state,
    const skBag_t      *bag)
{
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;

    INVOKE_PAGER();

    /* set type for key and counter */
    key.type = SKBAG_KEY_U32;
    counter.type = SKBAG_COUNTER_U64;

    if (!limits.active) {
        /* print contents of the bag */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            return 1;
        }
        while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK) {
            bagcatPrintBagRow(state, &key, &counter);
        }
        skBagIteratorDestroy(b_iter);

    } else if (0 == print_zero_counts) {
        /* print contents of the bag, subject to limits */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            return 1;
        }
        while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK) {
            if (CHECK_LIMITS_UINT32(&key, &counter)) {
                bagcatPrintBagRow(state, &key, &counter);
            }
        }
        skBagIteratorDestroy(b_iter);

    } else {
        /* print keys between two key values, subject to maximum
         * counter limit */

        /* handle first key */
        key.val.u32 = limits.minkey_u32;
        skBagCounterGet(bag, &key, &counter);
        if (counter.val.u64 <= limits.maxcounter) {
            bagcatPrintBagRow(state, &key, &counter);
        }
        /* handle remaining keys */
        while (key.val.u32 < limits.maxkey_u32) {
            ++key.val.u32;
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatPrintBagRow(state, &key, &counter);
            }
        }
    }

    return 0;
}


/*
 *    Print a single key-counter pair.  Used when the key is printed
 *    as either an IP or as a decimal or hexadecimal number.
 *
 *    Helper for bagcatPrintNetwork().
 */
static void
bagcatPrintNetworkRow(
    sk_netstruct_t             *ns,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter)
{
    skNetStructureAddKeyCounter(ns, &key->val.addr, &counter->val.u64);
}

/*
 *    Print the contents of a bag file using the print-network code
 *    from libsilk.
 */
static int
bagcatPrintNetwork(
    sk_netstruct_t     *ns,
    const skBag_t      *bag)
{
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;

    /* set type for key and counter */
    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    if (!limits.active) {
        /* print all entries in the bag */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            return 1;
        }
        while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK) {
            bagcatPrintNetworkRow(ns, &key, &counter);
        }
        skBagIteratorDestroy(b_iter);

    } else if (0 == print_zero_counts) {
        /* print entries in the bag that meet the limits */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            return 1;
        }
        while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK) {
            if (CHECK_LIMITS_IPADDR(&key, &counter)) {
                bagcatPrintNetworkRow(ns, &key, &counter);
            }
        }
        skBagIteratorDestroy(b_iter);

    } else if (NULL == limits.mask_set) {
        /* print entries whose keys are between two key values,
         * subject to maximum counter limit */

        /* handle first key */
        skipaddrCopy(&key.val.addr, &limits.minkey_ip);
        skBagCounterGet(bag, &key, &counter);
        if (counter.val.u64 <= limits.maxcounter) {
            bagcatPrintNetworkRow(ns, &key, &counter);
        }

        /* handle remaining keys */
        while (skipaddrCompare(&key.val.addr, &limits.maxkey_ip) < 0) {
            skipaddrIncrement(&key.val.addr);
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatPrintNetworkRow(ns, &key, &counter);
            }
        }

    } else if (0 == limits.key_is_min && 0 == limits.key_is_max) {
        /* print entries whose keys appear in the IPset, subject to
         * the maximum counter limit */
        skipset_iterator_t s_iter;
        uint32_t cidr;

        skIPSetIteratorBind(&s_iter, limits.mask_set, 0, SK_IPV6POLICY_MIX);
        while (skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr)
               == SK_ITERATOR_OK)
        {
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatPrintNetworkRow(ns, &key, &counter);
            }
        }

    } else {
        /* print entries whose keys appear in the IPset and are within
         * the --minkey and --maxkey range, subject to the maximum
         * counter limit */
        skipset_iterator_t s_iter;
        uint32_t cidr;
        int s_rv;

        skIPSetIteratorBind(&s_iter, limits.mask_set, 0, SK_IPV6POLICY_MIX);
        /* ignore IPs less then --minkey */
        while (((s_rv = skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr))
                == SK_ITERATOR_OK)
               && (skipaddrCompare(&key.val.addr, &limits.minkey_ip) < 0))
            ;                   /* empty */
        if (SK_ITERATOR_OK == s_rv) {
            do {
                skBagCounterGet(bag, &key, &counter);
                if (counter.val.u64 <= limits.maxcounter) {
                    bagcatPrintNetworkRow(ns, &key, &counter);
                }
            } while ((skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr)
                      == SK_ITERATOR_OK)
                     && (skipaddrCompare(&key.val.addr, &limits.maxkey_ip)
                         < 0));
        }
    }

    skNetStructurePrintFinalize(ns);

    return 0;
}


/*
 *    Comparison function used by the heap that is used to implement
 *    the --sort-counters switch.  Return a positive value if 'a'
 *    should be closer to the root of the tree.
 *
 *    To have a decreasing sort order, the root of the tree should
 *    contain the smallest value.  'sort_counters' is 1 for decreasing
 *    sort order and -1 for increasing order.
 */
static int
bagcatHeapCompare(
    const skheapnode_t  a,
    const skheapnode_t  b)
{
    const bagcat_heapnode_t *a_node = (bagcat_heapnode_t *)a;
    const bagcat_heapnode_t *b_node = (bagcat_heapnode_t *)b;

    if (a_node->counter != b_node->counter) {
        return ((a_node->counter < b_node->counter)
                ? sort_counters
                : -sort_counters);
    }
    if (SKBAG_KEY_IPADDR == a_node->key.type) {
        return (skipaddrCompare(&a_node->key.val.addr, &b_node->key.val.addr));
    }
    return ((b_node->key.val.u32 < a_node->key.val.u32)
            ? -1
            : (b_node->key.val.u32 > a_node->key.val.u32));
}


/*
 *    Add a 'key' and 'counter' pair to 'heap'.
 */
static void
bagcatHeapAdd(
    skheap_t                   *heap,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter)
{
    static int not_full = 1;
    static bagcat_heapnode_t *top_heap;
    bagcat_heapnode_t heap_entry;

    /* the new entry */
    heap_entry.counter = counter->val.u64;
    memcpy(&heap_entry.key, key, sizeof(*key));

    if (not_full) {
        if (skHeapInsert(heap, &heap_entry) == SKHEAP_OK) {
            return;
        }
        not_full = 0;

        /* Cannot grow the heap any more; process remaining
         * records using this fixed heap size */
        skAppPrintErr("Cannot grow heap; limiting to %u entries",
                      skHeapGetNumberEntries(heap));

        /* Get the node at the top of heap and its value.  For
         * decreasing sort order, this is the smallest value. */
        skHeapPeekTop(heap, (skheapnode_t *)&top_heap);
    }

    if (bagcatHeapCompare(top_heap, &heap_entry) > 0) {
        /* The element we just read is "better" */
        skHeapReplaceTop(heap, &heap_entry, NULL);

        /* the top may have changed; get the new top */
        skHeapPeekTop(heap, (skheapnode_t*)&top_heap);
    }
}


/*
 *    Provide implementation of --sort-counters.
 *
 *    Process the entries in 'bag', adding each key/value pair that
 *    meets the limits to a heap data structure.  Once all entries are
 *    process, sort the heap and print the results.
 */
static int
bagcatSortCounters(
    const skBag_t      *bag,
    const bagcat_key_t *bc_key)
{
    uint32_t count;
    state_t state;
    skBagFieldType_t key_field;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skheap_t *heap;
    skheapiterator_t *itheap;
    bagcat_heapnode_t *heap_entry;
    int rv = 1;

    heap = NULL;
    itheap = NULL;

    memset(&key, 0, sizeof(key));

    memset(&state, 0, sizeof(state));
    state.bc_key = bc_key;
    if (!no_final_delimiter) {
        state.end_of_line[0] = output_delimiter;
    }
    if (!no_columns) {
        state.width[0] = bc_key->width;
        state.width[1] = COUNT_WIDTH;
    }
    state.buflen = bc_key->buflen;
    state.buf = (char *)malloc(state.buflen);
    state.buf[0] = '\0';

    switch (skBagKeyFieldLength(bag)) {
      case 1:
        count = (1u << 8);
        break;
      case 2:
        count = (1u << 16);
        break;
      default:
        count = BAGCAT_HEAP_INITIAL_SIZE;
        break;
    }

    /* create the heap */
    while (NULL == (heap = skHeapCreate(bagcatHeapCompare, count,
                                        sizeof(bagcat_heapnode_t), NULL)))
    {
        count >>= 1;
        if (count < UINT8_MAX) {
            skAppPrintOutOfMemory("creating heap");
            exit(EXIT_FAILURE);
        }
    }

    key_field = skBagKeyFieldType(bag);

    /* set type for key and counter */
    counter.type = SKBAG_COUNTER_U64;
    switch (key_field) {
      case SKBAG_FIELD_CUSTOM:
      case SKBAG_FIELD_SIPv4:
      case SKBAG_FIELD_DIPv4:
      case SKBAG_FIELD_NHIPv4:
      case SKBAG_FIELD_ANY_IPv4:
      case SKBAG_FIELD_SIPv6:
      case SKBAG_FIELD_DIPv6:
      case SKBAG_FIELD_NHIPv6:
      case SKBAG_FIELD_ANY_IPv6:
        key.type = SKBAG_KEY_IPADDR;
        break;
      default:
        key.type = SKBAG_KEY_U32;
        break;
    }

    /* Process the bag */
    if (!limits.active) {
        /* handle all entries in the bag */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            goto END;
        }
        while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK) {
            bagcatHeapAdd(heap, &key, &counter);
        }
        skBagIteratorDestroy(b_iter);

    } else if (0 == print_zero_counts) {
        /* handle entries in the bag that meet the limits */
        skBagIterator_t *b_iter;

        if (skBagIteratorCreate(bag, &b_iter) != SKBAG_OK) {
            goto END;
        }
        if (SKBAG_KEY_U32 == key.type) {
            while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK){
                if (CHECK_LIMITS_UINT32(&key, &counter)) {
                    bagcatHeapAdd(heap, &key, &counter);
                }
            }
        } else {
            while (skBagIteratorNextTyped(b_iter, &key, &counter) == SKBAG_OK){
                if (CHECK_LIMITS_IPADDR(&key, &counter)) {
                    bagcatHeapAdd(heap, &key, &counter);
                }
            }
        }
        skBagIteratorDestroy(b_iter);

    } else if (SKBAG_KEY_U32 == key.type) {
        /* handle entries whose (numeric) keys are between two values,
         * subject to maximum counter limit */

        /* handle first key */
        key.val.u32 = limits.minkey_u32;
        skBagCounterGet(bag, &key, &counter);
        if (counter.val.u64 <= limits.maxcounter) {
            bagcatHeapAdd(heap, &key, &counter);
        }
        /* handle remaining keys */
        while (key.val.u32 < limits.maxkey_u32) {
            ++key.val.u32;
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatHeapAdd(heap, &key, &counter);
            }
        }

    } else if (NULL == limits.mask_set) {
        /* handle entries whose (IP) keys are between two values,
         * subject to maximum counter limit */

        /* handle first key */
        skipaddrCopy(&key.val.addr, &limits.minkey_ip);
        skBagCounterGet(bag, &key, &counter);
        if (counter.val.u64 <= limits.maxcounter) {
            bagcatHeapAdd(heap, &key, &counter);
        }
        /* handle remaining keys */
        while (skipaddrCompare(&key.val.addr, &limits.maxkey_ip) < 0) {
            skipaddrIncrement(&key.val.addr);
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatHeapAdd(heap, &key, &counter);
            }
        }

    } else if (0 == limits.key_is_min && 0 == limits.key_is_max) {
        /* handle entries whose keys appear in the IPset, subject to
         * the maximum counter limit */
        skipset_iterator_t s_iter;
        uint32_t cidr;

        skIPSetIteratorBind(&s_iter, limits.mask_set, 0, SK_IPV6POLICY_MIX);
        while (skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr)
               == SK_ITERATOR_OK)
        {
            skBagCounterGet(bag, &key, &counter);
            if (counter.val.u64 <= limits.maxcounter) {
                bagcatHeapAdd(heap, &key, &counter);
            }
        }

    } else {
        /* handle entries whose keys appear in the IPset and are
         * within the --minkey and --maxkey range, subject to the
         * maximum counter limit */
        skipset_iterator_t s_iter;
        uint32_t cidr;
        int s_rv;

        /* ensure minimum counter is 0*/
        limits.mincounter = SKBAG_COUNTER_MIN;

        skIPSetIteratorBind(&s_iter, limits.mask_set, 0, SK_IPV6POLICY_MIX);
        while (((s_rv = skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr))
                == SK_ITERATOR_OK)
               && (skipaddrCompare(&key.val.addr, &limits.minkey_ip) < 0))
            ;                   /* empty */
        if (SK_ITERATOR_OK == s_rv) {
            do {
                skBagCounterGet(bag, &key, &counter);
                if (counter.val.u64 <= limits.maxcounter) {
                    bagcatHeapAdd(heap, &key, &counter);
                }
            } while ((skIPSetIteratorNext(&s_iter, &key.val.addr, &cidr)
                      == SK_ITERATOR_OK)
                     && (skipaddrCompare(&key.val.addr, &limits.maxkey_ip)< 0));
        }
    }

    INVOKE_PAGER();

    /* output the values in the heap */
    skHeapSortEntries(heap);

    itheap = skHeapIteratorCreate(heap, -1);
    while (skHeapIteratorNext(itheap, (skheapnode_t *)&heap_entry)
           == SKHEAP_OK)
    {
        counter.val.u64 = heap_entry->counter;
        bagcatPrintBagRow(&state, &heap_entry->key, &counter);
    }

    rv = 0;

  END:
    skHeapIteratorFree(itheap);
    skHeapFree(heap);
    free(state.buf);

    return rv;
}


/*
 *    Output bag using current state of options
 */
static int
bagcatProcessBag(
    const skBag_t      *bag,
    const bagcat_key_t *bc_key)
{
    char field_name[SKBAG_MAX_FIELD_BUFLEN];
    skBagFieldType_t key_field;
    const char *this_net_structure;
    state_t state;
    sk_netstruct_t *ns;
    int rv = 0;

    /* structures that contain state to use while printing */
    memset(&state, 0, sizeof(state));
    ns = NULL;

    key_field = skBagKeyFieldName(bag, field_name, sizeof(field_name));

    /* it is an error when --network-structure is given and the bag
     * does not contain IP addresses */
    switch (key_field) {
      case SKBAG_FIELD_CUSTOM:
      case SKBAG_FIELD_SIPv4:
      case SKBAG_FIELD_DIPv4:
      case SKBAG_FIELD_NHIPv4:
      case SKBAG_FIELD_ANY_IPv4:
      case SKBAG_FIELD_SIPv6:
      case SKBAG_FIELD_DIPv6:
      case SKBAG_FIELD_NHIPv6:
      case SKBAG_FIELD_ANY_IPv6:
        if (net_structure) {
            this_net_structure = net_structure;
        } else if (print_network) {
            if (16 == skBagKeyFieldLength(bag)) {
                this_net_structure = "v6:";
            } else {
                this_net_structure = "v4:";
            }
        } else if (16 == skBagKeyFieldLength(bag)) {
            this_net_structure = "v6:H";
        } else {
            this_net_structure = "v4:H";
        }
        break;
      default:
        /* set 'this_net_structure' in case bagcatPrintNetwork() is
         * used to print values in decimal or hex */
        this_net_structure = "v4:H";
        if (print_network) {
            skAppPrintErr("Cannot use --%s with a Bag containing %s keys",
                          appOptions[OPT_NETWORK_STRUCTURE].name, field_name);
            rv = 1;
            goto END;
        }
        break;
    }

    if (BAGCAT_FMT_IPADDR == bc_key->formatter) {
        /* Set up the skNetStruct */
        if (skNetStructureCreate(&ns, 1)) {
            skAppPrintErr("Error creating network-structure");
            rv = 1;
            goto END;
        }
        skNetStructureSetCountWidth(ns, COUNT_WIDTH);
        if (skNetStructureParse(ns, this_net_structure)) {
            rv = 1;
            goto END;
        }
        skNetStructureSetOutputStream(ns, output);
        skNetStructureSetDelimiter(ns, output_delimiter);
        if (no_columns) {
            skNetStructureSetNoColumns(ns);
        }
        if (no_final_delimiter) {
            skNetStructureSetNoFinalDelimiter(ns);
        }
        skNetStructureSetIpFormat(ns, bc_key->formatter_flags);

        INVOKE_PAGER();

        if (bagcatPrintNetwork(ns, bag) != 0) {
            rv = 1;
            goto END;
        }

    } else {
        /* state is the print state used by bagcatPrintBag() */
        state.bc_key = bc_key;
        if (!no_final_delimiter) {
            state.end_of_line[0] = output_delimiter;
        }
        if (!no_columns) {
            state.width[0] = bc_key->width;
            state.width[1] = COUNT_WIDTH;
        }
        state.buflen = bc_key->buflen;
        state.buf = (char *)malloc(state.buflen);
        state.buf[0] = '\0';

        if (bagcatPrintBag(&state, bag)) {
            rv = 1;
            goto END;
        }
    }

  END:
    skNetStructureDestroy(&ns);
    free(state.buf);
    return rv;
}


static int
printStatistics(
    const skBag_t      *bag,
    const bagcat_key_t *bc_key,
    skstream_t         *stream_out)
{
    double counter_temp =  0.0;
    double counter_mult =  0.0;
    double sum =  0.0; /* straight sum */
    double sum2 = 0.0; /* sum of squares */
    double sum3 = 0.0; /* sum of cubes */

    double key_count = 0.0;
    double mean = 0.0;
    double stddev = 0.0;
    double temp = 0.0;
    double variance = 0.0;
    double skew = 0.0;
    double kurtosis = 0.0;

    skBagIterator_t *iter;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;

    skipaddr_t min_max_key[2];
    uint64_t min_seen_counter, max_seen_counter;
    char *key_buf[2];
    skBagErr_t rv;
    size_t i;

#define SUMS_OF_COUNTERS(soc_count)                     \
    {                                                   \
        /* straight sum */                              \
        counter_temp = (double)(soc_count);             \
        sum += counter_temp;                            \
        /* sum of squares */                            \
        counter_mult = counter_temp * counter_temp;     \
        sum2 += counter_mult;                           \
        /* sum of cubes */                              \
        counter_mult *= counter_temp;                   \
        sum3 += counter_mult;                           \
    }

    INVOKE_PAGER();

    assert(bag != NULL);
    assert(stream_out != NULL);

    if (skBagIteratorCreateUnsorted(bag, &iter) != SKBAG_OK) {
        return 1;
    }

    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    /* find first entry within limits */
    while ((rv = skBagIteratorNextTyped(iter, &key, &counter))
           == SKBAG_OK)
    {
        if (CHECK_LIMITS_IPADDR(&key, &counter)) {
            break;
        }
        ++key_count;
    }

    if (SKBAG_ERR_KEY_NOT_FOUND == rv) {
        /* reached end of bag */
        skStreamPrint(stream_out, "\nStatistics\n");
        if (key_count < 1.0) {
            skStreamPrint(stream_out, "  No entries in bag.\n");
        } else {
            skStreamPrint(stream_out,
                          "  No entries in bag within limits.\n");
        }
        skBagIteratorDestroy(iter);
        return 0;
    }
    if (SKBAG_OK != rv) {
        /* some other unexpected error */
        skAppPrintErr("Error iterating over bag: %s",
                      skBagStrerror(rv));
        skBagIteratorDestroy(iter);
        return 1;
    }

    key_count = 1;
    skipaddrCopy(&min_max_key[0], &key.val.addr);
    skipaddrCopy(&min_max_key[1], &key.val.addr);
    min_seen_counter = max_seen_counter = counter.val.u64;
    SUMS_OF_COUNTERS(counter.val.u64);

    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        if (!CHECK_LIMITS_IPADDR(&key, &counter)) {
            continue;
        }

        ++key_count;
        SUMS_OF_COUNTERS(counter.val.u64);

        if (counter.val.u64 < min_seen_counter) {
            min_seen_counter = counter.val.u64;
        } else if (counter.val.u64 > max_seen_counter) {
            max_seen_counter = counter.val.u64;
        }
        if (skipaddrCompare(&key.val.addr, &min_max_key[0]) < 0) {
            skipaddrCopy(&min_max_key[0], &key.val.addr);
        } else if (skipaddrCompare(&key.val.addr, &min_max_key[1]) > 0) {
            skipaddrCopy(&min_max_key[1], &key.val.addr);
        }
    }

    if (skBagIteratorDestroy(iter) != SKBAG_OK) {
        return 1;
    }

    /* convert min/max keys to strings */
    for (i = 0; i < 2; ++i) {
        uint32_t u32;

        key_buf[i] = (char *)malloc(bc_key->buflen);
        if (NULL == key_buf[i]) {
            skAppPrintOutOfMemory(NULL);
            exit(EXIT_FAILURE);
        }
        if (bc_key->formatter == BAGCAT_FMT_IPADDR) {
            skipaddrString(key_buf[i], &min_max_key[i],
                           bc_key->formatter_flags);

        } else if (skipaddrGetAsV4(&min_max_key[i], &u32)) {
#if SK_ENABLE_IPV6
            skAppPrintErr("Cannot convert IP to 32bit number");
            skipaddrString(key_buf[i], &min_max_key[i], SKIPADDR_DECIMAL);
#endif  /* SK_ENABLE_IPV6 */
        } else {
            switch (bc_key->formatter) {
              case BAGCAT_FMT_ATTRIBUTES:
                skTCPStateString(u32, key_buf[i], bc_key->formatter_flags);
                break;

              case BAGCAT_FMT_COUNTRY:
                skCountryCodeToName(u32, key_buf[i], bc_key->buflen);
                break;

              case BAGCAT_FMT_IPADDR:
                skAbortBadCase(bc_key->formatter);

              case BAGCAT_FMT_PMAP:
                skPrefixMapDictionaryGetEntry(prefix_map, u32, key_buf[i],
                                              bc_key->buflen);
                break;

              case BAGCAT_FMT_SENSOR:
                sksiteSensorGetName(key_buf[i], bc_key->buflen, u32);
                break;

              case BAGCAT_FMT_TCPFLAGS:
                skTCPFlagsString(u32, key_buf[i], bc_key->formatter_flags);
                break;

              case BAGCAT_FMT_TIME:
                sktimestamp_r(key_buf[i], sktimeCreate(u32, 0),
                              bc_key->formatter_flags);
                break;
            }
        }
    }

    skStreamPrint(stream_out, "\nStatistics\n");

    /* formulae derived from HyperStat Online - David M. Lane */

    /* http://davidmlane.com/hyperstat/A15885.html (mean) */
    mean = sum / key_count;

    /* http://davidmlane.com/hyperstat/A16252.html (variance) */

    temp = (sum2
            - (2.0 * mean * sum)
            + (key_count * mean * mean));

    variance = temp / (key_count - 1.0);

    /* http://davidmlane.com/hyperstat/A16252.html (standard deviation) */
    stddev = sqrt(variance);

    /* http://davidmlane.com/hyperstat/A11284.html (skew) */
    skew = ((sum3
             - (3.0 * mean * sum2)
             + (3.0 * mean * mean * sum)
             - (key_count * mean * mean * mean))
            / (key_count * variance * stddev));

    /* http://davidmlane.com/hyperstat/A53638.html (kurtosis) */
    kurtosis = (temp * temp) / (key_count * variance * variance);

    skStreamPrint(stream_out, ("%18s:  %" PRIu64 "\n"
                               "%18s:  %" PRIu64 "\n"
                               "%18s:  %s\n"
                               "%18s:  %s\n"
                               "%18s:  %" PRIu64 "\n"
                               "%18s:  %" PRIu64 "\n"
                               "%18s:  %.4g\n"
                               "%18s:  %.4g\n"
                               "%18s:  %.4g\n"
                               "%18s:  %.4g\n"
                               "%18s:  %.4g\n"),
                  "number of keys",     (uint64_t)key_count,
                  "sum of counters",    (uint64_t)sum,
                  "minimum key",        key_buf[0],
                  "maximum key",        key_buf[1],
                  "minimum counter",    (uint64_t)min_seen_counter,
                  "maximum counter",    (uint64_t)max_seen_counter,
                  "mean",               mean,
                  "variance",           variance,
                  "standard deviation", stddev,
                  "skew",               skew,
                  "kurtosis",           kurtosis);
    skBagPrintTreeStats(bag, stream_out);

    free(key_buf[0]);
    free(key_buf[1]);

    return 0;
}


/*
 *    Verify that the bag key-format makes sense for the bag we
 *    loaded; determine the number of bytes necessary to hold the key.
 */
static int
bagcatCheckKeyFormat(
    const skBag_t          *bag,
    bagcat_key_t           *bc_key)
{
    char field_name[SKBAG_MAX_FIELD_BUFLEN];
    skBagFieldType_t key_field;
    int bad_format = 0;
    int as_integer = 0;
    int as_ipv6 = 0;
    int as_ipv4 = 0;
    int as_time = 0;

    memset(bc_key, 0, sizeof(*bc_key));
    key_field = skBagKeyFieldName(bag, field_name, sizeof(field_name));
    switch (key_field) {
      case SKBAG_FIELD_SIPv6:
      case SKBAG_FIELD_DIPv6:
      case SKBAG_FIELD_NHIPv6:
      case SKBAG_FIELD_ANY_IPv6:
        as_ipv6 = 1;
        break;

      case SKBAG_FIELD_SIPv4:
      case SKBAG_FIELD_DIPv4:
      case SKBAG_FIELD_NHIPv4:
      case SKBAG_FIELD_ANY_IPv4:
        as_ipv4 = 1;
        break;

      case SKBAG_FIELD_STARTTIME:
      case SKBAG_FIELD_ENDTIME:
      case SKBAG_FIELD_ANY_TIME:
        as_time = 1;
        break;

      case SKBAG_FIELD_FLAGS:
      case SKBAG_FIELD_INIT_FLAGS:
      case SKBAG_FIELD_REST_FLAGS:
        bc_key->key_type = SKBAG_KEY_U32;
        if (0 == key_format) {
            bc_key->buflen = 1 + SK_TCPFLAGS_STRLEN;
            bc_key->formatter = BAGCAT_FMT_TCPFLAGS;
            bc_key->formatter_flags = 0;
            bc_key->width = 8;
        } else {
            as_integer = 1;
        }
        break;

      case SKBAG_FIELD_TCP_STATE:
        bc_key->key_type = SKBAG_KEY_U32;
        if (0 == key_format) {
            bc_key->buflen = 1 + SK_TCP_STATE_STRLEN;
            bc_key->formatter = BAGCAT_FMT_ATTRIBUTES;
            bc_key->formatter_flags = 0;
            bc_key->width = 8;
        } else {
            as_integer = 1;
        }
        break;

      case SKBAG_FIELD_SID:
        bc_key->key_type = SKBAG_KEY_U32;
        if (0 == key_format) {
            /* set key-column width */
            sksiteConfigure(0);
            bc_key->width = sksiteSensorGetMaxNameStrLen();
            bc_key->buflen = 1 + bc_key->width;
            bc_key->formatter = BAGCAT_FMT_SENSOR;
            bc_key->formatter_flags = 0;
        } else {
            as_integer = 1;
        }
        break;

      case SKBAG_FIELD_SIP_COUNTRY:
      case SKBAG_FIELD_DIP_COUNTRY:
      case SKBAG_FIELD_ANY_COUNTRY:
        if (0 == key_format) {
            bc_key->key_type = SKBAG_KEY_U32;
            bc_key->buflen = 3;
            bc_key->formatter = BAGCAT_FMT_COUNTRY;
            bc_key->formatter_flags = 0;
            bc_key->width = 2;
        } else {
            bad_format = 1;
        }
        break;

      case SKBAG_FIELD_SIP_PMAP:
      case SKBAG_FIELD_DIP_PMAP:
      case SKBAG_FIELD_ANY_IP_PMAP:
      case SKBAG_FIELD_SPORT_PMAP:
      case SKBAG_FIELD_DPORT_PMAP:
      case SKBAG_FIELD_ANY_PORT_PMAP:
        if (0 == key_format) {
            bc_key->width = skPrefixMapDictionaryGetMaxWordSize(prefix_map);
            bc_key->key_type = SKBAG_KEY_U32;
            bc_key->buflen = 1 + bc_key->width;
            bc_key->formatter = BAGCAT_FMT_PMAP;
            bc_key->formatter_flags = 0;
        } else {
            bad_format = 1;
        }
        break;

      case SKBAG_FIELD_CUSTOM:
        if ((0 == key_format) || (key_format & KEY_FORMAT_IP)) {
            if (16 == skBagKeyFieldLength(bag)) {
                as_ipv6 = 1;
            } else {
                as_ipv4 = 1;
            }
        } else if (16 == skBagKeyFieldLength(bag)) {
            skAppPrintErr(("Invalid %s '%s':"
                           " Bag's key length is too long for format"),
                          appOptions[OPT_KEY_FORMAT].name, key_format_arg);
            return -1;
        } else {
            assert(key_format & KEY_FORMAT_TIME);
            as_time = 1;
        }
        break;

      default:
        as_integer = 1;
    }

    if (as_ipv4 || as_ipv6) {
        bc_key->key_type = SKBAG_KEY_IPADDR;
        bc_key->buflen = 1 + SKIPADDR_STRLEN;
        bc_key->formatter = BAGCAT_FMT_IPADDR;
        if (0 != key_format && !(key_format & KEY_FORMAT_IP)) {
            bad_format = 1;
        } else {
            if (0 == key_format) {
                bc_key->formatter_flags = SKIPADDR_CANONICAL;
            } else {
                bc_key->formatter_flags = key_format & ~KEY_FORMAT_MASK;
            }
            bc_key->width = skipaddrStringMaxlen(as_ipv6,
                                                 bc_key->formatter_flags);
        }
    }

    if (as_time) {
        bc_key->key_type = SKBAG_KEY_U32;
        bc_key->buflen = 1 + SKTIMESTAMP_STRLEN;
        bc_key->formatter = BAGCAT_FMT_TIME;
        if (0 != key_format && !(key_format & KEY_FORMAT_TIME)) {
            bad_format = 1;
        } else {
            if (0 == key_format) {
                assert(SKBAG_FIELD_CUSTOM != key_format);
                bc_key->formatter_flags = SKTIMESTAMP_NOMSEC;
            } else {
                bc_key->formatter_flags
                    = (SKTIMESTAMP_NOMSEC | (key_format & ~KEY_FORMAT_MASK));
            }
            bc_key->width
                = ((SKTIMESTAMP_EPOCH & bc_key->formatter_flags) ? 10 : 19);
        }
    }

    if (as_integer) {
        bc_key->key_type = SKBAG_KEY_U32;
        bc_key->buflen = 1 + SKIPADDR_STRLEN;
        bc_key->formatter = BAGCAT_FMT_IPADDR;
        if (0 == key_format) {
            bc_key->formatter_flags = SKIPADDR_DECIMAL;
            bc_key->width = 10;
        } else {
            switch (key_format) {
              case KEY_FORMAT_IP | SKIPADDR_DECIMAL:
              case KEY_FORMAT_IP | SKIPADDR_DECIMAL | SKIPADDR_ZEROPAD:
                bc_key->formatter_flags = key_format & ~KEY_FORMAT_IP;
                bc_key->width = 10;
                break;
              case KEY_FORMAT_IP | SKIPADDR_HEXADECIMAL:
              case KEY_FORMAT_IP | SKIPADDR_HEXADECIMAL | SKIPADDR_ZEROPAD:
                bc_key->formatter_flags = key_format & ~KEY_FORMAT_IP;
                bc_key->width = 8;
                break;
              case KEY_FORMAT_IP | SKIPADDR_ZEROPAD:
                bc_key->formatter_flags = SKIPADDR_DECIMAL | SKIPADDR_ZEROPAD;
                bc_key->width = 10;
                break;
              default:
                bad_format = 1;
                break;
            }
        }
    }

    if (bad_format) {
        skAppPrintErr("Invalid %s '%s': Nonsensical for Bag containing %s keys",
                      appOptions[OPT_KEY_FORMAT].name, key_format_arg,
                      field_name);
        return -1;
    }
    return 0;
}


/*
 *    Verify we have a prefix map and that the prefix map is the
 *    correct type for the type of bag.
 */
static int
bagcatCheckPrefixMap(
    const skBag_t      *bag)
{
    char field_name[SKBAG_MAX_FIELD_BUFLEN];
    skBagFieldType_t key_field;
    int key_is_ip_pmap = 0;

    key_field = skBagKeyFieldName(bag, field_name, sizeof(field_name));

    switch (key_field) {
      case SKBAG_FIELD_SIP_PMAP:
      case SKBAG_FIELD_DIP_PMAP:
      case SKBAG_FIELD_ANY_IP_PMAP:
        key_is_ip_pmap = 1;
        /* FALLTHROUGH */
      case SKBAG_FIELD_SPORT_PMAP:
      case SKBAG_FIELD_DPORT_PMAP:
      case SKBAG_FIELD_ANY_PORT_PMAP:
        break;

      default:
        return 0;
    }

    if (!prefix_map) {
        skAppPrintErr("The --%s switch is required for Bags containing %s keys",
                      appOptions[OPT_PMAP_FILE].name, field_name);
        return -1;
    }
    if ((skPrefixMapGetContentType(prefix_map) == SKPREFIXMAP_CONT_PROTO_PORT)
        ? key_is_ip_pmap
        : !key_is_ip_pmap)
    {
        skAppPrintErr("Cannot use %s prefix map for Bag containing %s keys",
                      skPrefixMapGetContentName(
                          skPrefixMapGetContentType(prefix_map)), field_name);
        return -1;
    }

    return 0;
}


/*
 *    Verify that the bag contains IP keys when the the --mask-set
 *    switch is provided.
 */
static int
bagcatCheckMaskSet(
    const skBag_t      *bag)
{
    char field_name[SKBAG_MAX_FIELD_BUFLEN];
    skBagFieldType_t key_field;

    if (limits.mask_set) {
        key_field = skBagKeyFieldName(bag, field_name, sizeof(field_name));

        switch (key_field) {
          case SKBAG_FIELD_CUSTOM:
          case SKBAG_FIELD_SIPv4:
          case SKBAG_FIELD_DIPv4:
          case SKBAG_FIELD_NHIPv4:
          case SKBAG_FIELD_ANY_IPv4:
          case SKBAG_FIELD_SIPv6:
          case SKBAG_FIELD_DIPv6:
          case SKBAG_FIELD_NHIPv6:
          case SKBAG_FIELD_ANY_IPv6:
            break;
          default:
            skAppPrintErr("Cannot use --%s with a Bag containing %s keys",
                          appOptions[OPT_NETWORK_STRUCTURE].name, field_name);
            return -1;
        }
    }
    return 0;
}


int main(int argc, char **argv)
{
    skBagErr_t err;
    skBag_t *bag = NULL;
    char *filename;
    bagcat_key_t bagcat_key;
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    while ((rv = skOptionsCtxNextArgument(optctx, &filename)) == 0) {
        if (IS_STDIN(filename)) {
            if (stdin_used) {
                skAppPrintErr("Multiple streams attempt"
                              " to read from the standard input");
            }
            stdin_used = 1;
        }
        err = skBagLoad(&bag, filename);
        if (err != SKBAG_OK) {
            skAppPrintErr("Error reading bag from input stream '%s': %s",
                          filename, skBagStrerror(err));
            exit(EXIT_FAILURE);
        }

        /* --mask-set only allowed with IP bag */
        if (bagcatCheckMaskSet(bag)) {
            skBagDestroy(&bag);
            exit(EXIT_FAILURE);
        }

        /* check features needed when producing output other than
         * inverting the bag. */
        if (sort_counters || print_statistics || bin_scheme == BINSCHEME_NONE){
            /* check for a valid prefix map if needed */
            if (bagcatCheckPrefixMap(bag)) {
                skBagDestroy(&bag);
                exit(EXIT_FAILURE);
            }

            /* verify that the key-format makes sense */
            if (bagcatCheckKeyFormat(bag, &bagcat_key)) {
                skBagDestroy(&bag);
                exit(EXIT_FAILURE);
            }
        }

        /* handle --bin-ips */
        if (bin_scheme != BINSCHEME_NONE) {
            if (bagcatInvertBag(bag)) {
                skAppPrintErr("Error inverting bag '%s'", filename);
                skBagDestroy(&bag);
                exit(EXIT_FAILURE);
            }
        } else if (sort_counters) {
            bagcatSortCounters(bag, &bagcat_key);
        } else if (print_network || !print_statistics) {
            /* either --network-structure explicitly given or there
             * was no other output selected */
            if (bagcatProcessBag(bag, &bagcat_key)) {
                skAppPrintErr("Error processing bag '%s'", filename);
                skBagDestroy(&bag);
                exit(EXIT_FAILURE);
            }
        }
        if (print_statistics) {
            printStatistics(bag, &bagcat_key, stats_stream);
        }
        skBagDestroy(&bag);
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
