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
**  rwpmaplookup.c
**
**    Read the prefix map file provided on the command line (which may
**    indicate rwpmaplookup should read the default country code or
**    addrtype mapping files).  Then read textual input from files or
**    from command line arguments, parse the text as either IP
**    addresses or as protocol/port pairs depending on the type of
**    prefix map specified, lookup the IP or proto/port pair in the
**    prefix map, and print the results as textual columns.
**
**    When --no-files is specified, the command line arguments are
**    treated as the text to parse and look-up.  Otherwise, read input
**    from the named files, from standard input, or from the files
**    specified by --xargs.
**
**  Mark Thomas
**  June 2011
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpmaplookup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* max expected length of a pmap dictionary entry */
#define DICTIONARY_ENTRY_BUFLEN 2048

/* value indicating an unset IP address */
#define ADDRESS_UNSET 0xFFFFFFFF

/* maximum number of output fields */
#define PMAPLOOKUP_MAX_FIELD_COUNT  8

/* for columnar output, the minimum width for the value field */
#define PMAPLOOKUP_VALUE_WIDTH_MINIMUM   5

/* for columnar output, the default width for the value field when no
 * other value can be determined */
#define PMAPLOOKUP_VALUE_WIDTH_DEFAULT  22

/* identifiers for the type of prefix map */
typedef enum pmaplookup_type_en {
    PMAPLOOKUP_TYPE_NONE          = 0x00,
    PMAPLOOKUP_TYPE_PROTOPORT     = 0x80, /* 1000 0000 */
    PMAPLOOKUP_TYPE_IPV4          = 0x01, /* 1000 0001 */
    PMAPLOOKUP_TYPE_IPV6          = 0x02, /* 0000 0010 */
    PMAPLOOKUP_TYPE_COUNTRY_IPV4  = 0x05, /* 0000 0101 */
    PMAPLOOKUP_TYPE_COUNTRY_IPV6  = 0x06, /* 0000 0110 */
    PMAPLOOKUP_TYPE_ADDRTYPE_IPV4 = 0x09, /* 0000 1001 */
    PMAPLOOKUP_TYPE_ADDRTYPE_IPV6 = 0x0A  /* 0000 1010 */
} pmaplookup_type_t;

/* if 'pii_pt' is a value from the 'pmaplookup_type_t' enum, determine
 * whether the type represents an IPv6 prefix map */
#define PMAPLOOKUP_TYPE_CHECK_IPV6(pii_pt)  (0x02 & (int)(pii_pt))

/* identifiers of the fields to print */
typedef enum pmap_find_field_en {
    PMAPLOOKUP_FIELD_KEY, PMAPLOOKUP_FIELD_VALUE,
    PMAPLOOKUP_FIELD_INPUT, PMAPLOOKUP_FIELD_BLOCK,
    PMAPLOOKUP_FIELD_START_BLOCK, PMAPLOOKUP_FIELD_END_BLOCK
} pmap_find_field_t;

/* default output fields */
#define PMAPLOOKUP_DEFAULT_FIELDS  "key,value"


/* LOCAL VARIABLES */

/* string map used to get field names from user */
static const sk_stringmap_entry_t field_map_entries[] = {
    {"key",          PMAPLOOKUP_FIELD_KEY,                 NULL, NULL},
    {"value",        PMAPLOOKUP_FIELD_VALUE,               NULL, NULL},
    {"input",        PMAPLOOKUP_FIELD_INPUT,               NULL, NULL},
    {"block",        PMAPLOOKUP_FIELD_BLOCK,               NULL, NULL},
    {"start-block",  PMAPLOOKUP_FIELD_START_BLOCK,         NULL, NULL},
    {"end-block",    PMAPLOOKUP_FIELD_END_BLOCK,           NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* fields to print, in the order in which to print them */
static pmap_find_field_t fields[PMAPLOOKUP_MAX_FIELD_COUNT];

/* number of fields in list */
static size_t num_fields;

/* width of the columns, where index is an pmap_find_field_t. */
static int col_width[PMAPLOOKUP_MAX_FIELD_COUNT];

/* the type of prefix map */
static pmaplookup_type_t pmaplookup_type = PMAPLOOKUP_TYPE_NONE;

/* the prefix map file */
static skPrefixMap_t *map = NULL;

/* whether 'fields[]' contains the PMAPLOOKUP_FIELD_INPUT field */
static int printing_input = 0;

/* whether 'fields[]' contains any of PMAPLOOKUP_FIELD_START_BLOCK,
 * PMAPLOOKUP_FIELD_END_BLOCK, or PMAPLOOKUP_FIELD_BLOCK */
static int printing_block = 0;

/* when non-zero, do not print errors.  set by --no-errors */
static int no_errors = 0;

/* when non-zero, treat arguments as values to look-up.  set by --no-files */
static int no_files = 0;

/* when non-zero, treat arguments as names of IPset files.  set by
 * --ipset-files */
static int ipset_files = 0;

/* the output stream, set by --output-path or --pager */
static sk_fileptr_t output;

/* paging program */
static const char *pager;

/* flags used to print IPs */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);

/* delimiter */
static char column_separator = '|';

/* how to format output */
static int no_columns;
static int no_final_delimiter;
static int no_titles;

/* final delimiter */
static char final_delim[] = {'\0', '\0'};

/* for processing input */
static sk_options_ctx_t *optctx;


/* OPTIONS SETUP */

typedef enum {
    OPT_MAP_FILE, OPT_ADDRESS_TYPES, OPT_COUNTRY_CODES,
    OPT_FIELDS,
#if 0
    OPT_INPUT_FIELDS, OPT_INPUT_DELIMITER,
#endif
    OPT_NO_FILES, OPT_NO_ERRORS, OPT_IPSET_FILES,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS, OPT_COLUMN_SEPARATOR, OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_OUTPUT_PATH, OPT_PAGER
} appOptionsEnum;

static struct option appOptions[] = {
    {"map-file",            REQUIRED_ARG, 0, OPT_MAP_FILE},
    {"address-types",       OPTIONAL_ARG, 0, OPT_ADDRESS_TYPES},
    {"country-codes",       OPTIONAL_ARG, 0, OPT_COUNTRY_CODES},
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
#if 0
    {"input-fields",        REQUIRED_ARG, 0, OPT_INPUT_FIELDS},
    {"input-delimiter",     REQUIRED_ARG, 0, OPT_INPUT_DELIMITER},
#endif
    {"no-files",            NO_ARG,       0, OPT_NO_FILES},
    {"no-errors",           NO_ARG,       0, OPT_NO_ERRORS},
    {"ipset-files",         NO_ARG,       0, OPT_IPSET_FILES},

    {"no-titles",           NO_ARG,       0, OPT_NO_TITLES},
    {"no-columns",          NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",  NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",           OPTIONAL_ARG, 0, OPT_DELIMITED},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"pager",               REQUIRED_ARG, 0, OPT_PAGER},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    ("Find the IPs or the protocol/port pairs in the named\n"
     "\t prefix map file"),
    ("Find IPs in the named address types mapping file, or\n"
     "\tin the default file when no argument is provided"),
    ("Find IPs in the named country code mapping file, or\n"
     "\tin the default file when no argument is provided"),
    NULL,  /* generated dynamically */
#if 0
    "Names of input columns",
    "Character separating input columns",
#endif  /* 0 */
    ("Do not read from files and instead treat the command\n"
     "\tline arguments as the IPs or proto/port pairs to find. Def. No"),
    "Do not report errors parsing the input. Def. No",
    ("Treat the command line arguments as binary IPset files to\n"
     "\tread. Def. Treat command line arguments as names of text files"),

    "Do not print column headers. Def. Print titles.",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
    "Write the output to this stream or file. Def. stdout",
    "Invoke this program to page output. Def. $SILK_PAGER or $PAGER",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void usageFields(FILE *fh);
static int  parseFields(const char *field_string);


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
    /* usage string is longer than allowed by C90 */
#define USAGE_MSG1                                                            \
    ("<SWITCHES>\n"                                                           \
     "\tMap textual IPs, textual protocol/port pairs, or addresses in a\n"    \
     "\tbinary IPset file to entries in a binary prefix map and print the\n"  \
     "\tresults in a columnar, |-delimited format.\n"                         \
     "\tExactly one of --map-file, --address-types, or --country-codes must\n")
#define USAGE_MSG2                                                            \
    ("\tbe specified, where --map-file requires a prefix map argument and\n"  \
     "\tthe other switches use the default map unless an argument is\n"       \
     "\tprovided to the switch.  The textual input is read from files\n"      \
     "\tspecified on the command line, or you may specify the --no-files\n"   \
     "\tswitch and specify the IP(s) or protocol/port pair(s) on the\n"       \
     "\tcommand line.  Use --ipset-files to process data from IPset files.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s%s", skAppName(), USAGE_MSG1, USAGE_MSG2);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_FIELDS:
            /* Dynamically build the help */
            usageFields(fh);
            break;
          case OPT_IPSET_FILES:
            fprintf(fh, "%s\n", appHelp[i]);
            /* insert the --ip-format switches */
            skOptionsIPFormatUsage(fh);
            break;
          default:
            /* Simple static help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
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

    /* close the output file or process */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }

    switch (pmaplookup_type) {
      case PMAPLOOKUP_TYPE_COUNTRY_IPV4:
      case PMAPLOOKUP_TYPE_COUNTRY_IPV6:
        skCountryTeardown();
        break;
      case PMAPLOOKUP_TYPE_ADDRTYPE_IPV4:
      case PMAPLOOKUP_TYPE_ADDRTYPE_IPV6:
        skAddressTypesTeardown();
        break;
      case PMAPLOOKUP_TYPE_IPV4:
      case PMAPLOOKUP_TYPE_IPV6:
      case PMAPLOOKUP_TYPE_PROTOPORT:
        if (map) {
            skPrefixMapDelete(map);
        }
        break;
      case PMAPLOOKUP_TYPE_NONE:
        break;
    }
    map = NULL;

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
    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    optctx_flags = (SK_OPTIONS_CTX_ALLOW_STDIN | SK_OPTIONS_CTX_XARGS);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown hanlder */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* ensure we have a pmap */
    if (PMAPLOOKUP_TYPE_NONE == pmaplookup_type) {
        skAppPrintErr("Must specify the prefix map to use");
        exit(EXIT_FAILURE);
    }

    /* do not query a protocol/port map for IPs */
    if (PMAPLOOKUP_TYPE_PROTOPORT == pmaplookup_type && ipset_files) {
        skAppPrintErr("May not use a %s prefix map with --%s",
                      skPrefixMapGetContentName(pmaplookup_type),
                      appOptions[OPT_IPSET_FILES].name);
        exit(EXIT_FAILURE);
    }

    /* when --no-files is specified, ensure we have arguments on the
     * command line */
    if (no_files && 0 == skOptionsCtxCountArgs(optctx)) {
        skAppPrintErr("Must provide command line arguments when --%s is used",
                      appOptions[OPT_NO_FILES].name);
        exit(EXIT_FAILURE);
    }

    /* set default fields */
    if (0 == num_fields) {
        rv = parseFields(PMAPLOOKUP_DEFAULT_FIELDS);
        assert(0 == rv);
    }

    /* set variables for formatting the output */
    if (!no_final_delimiter) {
        final_delim[0] = column_separator;
    }
    memset(col_width, 0, sizeof(col_width));
    if (!no_columns) {
        col_width[PMAPLOOKUP_FIELD_INPUT] = PMAPLOOKUP_VALUE_WIDTH_DEFAULT;
        col_width[PMAPLOOKUP_FIELD_VALUE] = PMAPLOOKUP_VALUE_WIDTH_DEFAULT;

        switch (pmaplookup_type) {
          case PMAPLOOKUP_TYPE_COUNTRY_IPV4:
          case PMAPLOOKUP_TYPE_COUNTRY_IPV6:
            col_width[PMAPLOOKUP_FIELD_VALUE] = PMAPLOOKUP_VALUE_WIDTH_MINIMUM;
            break;
          case PMAPLOOKUP_TYPE_ADDRTYPE_IPV4:
          case PMAPLOOKUP_TYPE_ADDRTYPE_IPV6:
          case PMAPLOOKUP_TYPE_IPV4:
          case PMAPLOOKUP_TYPE_IPV6:
          case PMAPLOOKUP_TYPE_PROTOPORT:
            if (skPrefixMapDictionaryGetWordCount(map) > 0) {
                col_width[PMAPLOOKUP_FIELD_VALUE]
                    = (int)skPrefixMapDictionaryGetMaxWordSize(map);
                if (col_width[PMAPLOOKUP_FIELD_VALUE]
                    < PMAPLOOKUP_VALUE_WIDTH_MINIMUM)
                {
                    col_width[PMAPLOOKUP_FIELD_VALUE]
                        = PMAPLOOKUP_VALUE_WIDTH_MINIMUM;
                }
            }
            break;
          case PMAPLOOKUP_TYPE_NONE:
            skAbortBadCase(pmaplookup_type);
        }

        if (PMAPLOOKUP_TYPE_PROTOPORT == pmaplookup_type) {
            /* max column: "255/65535" */
            col_width[PMAPLOOKUP_FIELD_KEY] = 3 + 1 + 5;
            col_width[PMAPLOOKUP_FIELD_BLOCK] =
                1 + (2 * col_width[PMAPLOOKUP_FIELD_KEY]);
        } else if (PMAPLOOKUP_TYPE_CHECK_IPV6(pmaplookup_type)) {
            col_width[PMAPLOOKUP_FIELD_KEY]
                = skipaddrStringMaxlen(1, ip_format);
            col_width[PMAPLOOKUP_FIELD_BLOCK]
                = skipaddrCidrStringMaxlen(1, ip_format);
            col_width[PMAPLOOKUP_FIELD_INPUT] = 39;
        } else {
            col_width[PMAPLOOKUP_FIELD_KEY]
                = skipaddrStringMaxlen(0, ip_format);
            col_width[PMAPLOOKUP_FIELD_BLOCK]
                = skipaddrCidrStringMaxlen(0, ip_format);
        }
        col_width[PMAPLOOKUP_FIELD_START_BLOCK]
            = col_width[PMAPLOOKUP_FIELD_END_BLOCK]
            = col_width[PMAPLOOKUP_FIELD_KEY];
    }

    /* create the output stream. */
    /* open the --output-path.  the 'of_name' member is NULL if user
     * didn't get an output-path.  do not page when no_files is active
     * or when an explicit output-path is given */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Unable to open %s '%s': %s",
                          appOptions[OPT_OUTPUT_PATH].name,
                          output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }
    } else if (!no_files) {
        /* Invoke the pager */
        rv = skFileptrOpenPager(&output, pager);
        if (rv && rv != SK_FILEPTR_PAGER_IGNORED) {
            skAppPrintErr("Unable to invoke pager");
        }
    }

    return;  /* OK */
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
      case OPT_MAP_FILE:
        if (pmaplookup_type != PMAPLOOKUP_TYPE_NONE) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return -1;
        }
        rv = skPrefixMapLoad(&map, opt_arg);
        if (rv) {
            return -1;
        }
        switch (skPrefixMapGetContentType(map)) {
          case SKPREFIXMAP_CONT_PROTO_PORT:
            pmaplookup_type = PMAPLOOKUP_TYPE_PROTOPORT;
            break;
          case SKPREFIXMAP_CONT_ADDR_V4:
            pmaplookup_type = PMAPLOOKUP_TYPE_IPV4;
            break;
          case SKPREFIXMAP_CONT_ADDR_V6:
            pmaplookup_type = PMAPLOOKUP_TYPE_IPV6;
            break;
          default:
            skAbortBadCase(skPrefixMapGetContentType(map));
        }
        break;

      case OPT_COUNTRY_CODES:
        if (pmaplookup_type != PMAPLOOKUP_TYPE_NONE) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return -1;
        }
        /* find and load the map file */
        if (skCountrySetup(opt_arg, &skAppPrintErr)) {
            return -1;
        }
        if (skCountryIsV6() == 1) {
            pmaplookup_type = PMAPLOOKUP_TYPE_COUNTRY_IPV6;
        } else {
            pmaplookup_type = PMAPLOOKUP_TYPE_COUNTRY_IPV4;
        }
        break;

      case OPT_ADDRESS_TYPES:
        if (pmaplookup_type != PMAPLOOKUP_TYPE_NONE) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return -1;
        }
        /* find and load the map file */
        if (skAddressTypesSetup(opt_arg, &skAppPrintErr)) {
            return -1;
        }
        map = skAddressTypesGetPmap();
        switch (skPrefixMapGetContentType(map)) {
          case SKPREFIXMAP_CONT_ADDR_V4:
            pmaplookup_type = PMAPLOOKUP_TYPE_ADDRTYPE_IPV4;
            break;
          case SKPREFIXMAP_CONT_ADDR_V6:
            pmaplookup_type = PMAPLOOKUP_TYPE_ADDRTYPE_IPV6;
            break;
          default:
            skAbortBadCase(skPrefixMapGetContentType(map));
        }
        break;

      case OPT_FIELDS:
        if (parseFields(opt_arg)) {
            return -1;
        }
        break;

#if 0
      case OPT_INPUT_FIELDS:
        break;

      case OPT_INPUT_DELIMITER:
        break;
#endif  /* 0 */

      case OPT_IPSET_FILES:
        if (no_files) {
            skAppPrintErr("Invalid %s: May not be combined with --%s",
                          appOptions[opt_index].name,
                          appOptions[OPT_NO_FILES].name);
            return -1;
        }
        ipset_files = 1;
        break;

      case OPT_NO_FILES:
        if (ipset_files) {
            skAppPrintErr("Invalid %s: May not be combined with --%s",
                          appOptions[opt_index].name,
                          appOptions[OPT_IPSET_FILES].name);
            return -1;
        }
        no_files = 1;
        break;

      case OPT_NO_ERRORS:
        no_errors = 1;
        break;

      case OPT_NO_TITLES:
        no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        no_columns = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        column_separator = opt_arg[0];
        break;

      case OPT_NO_FINAL_DELIMITER:
        no_final_delimiter = 1;
        break;

      case OPT_DELIMITED:
        no_columns = 1;
        no_final_delimiter = 1;
        if (opt_arg) {
            column_separator = opt_arg[0];
        }
        break;

      case OPT_OUTPUT_PATH:
        if (output.of_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        output.of_name = opt_arg;
        break;

      case OPT_PAGER:
        pager = opt_arg;
        break;
    }

    return 0;  /* OK */
}


/*
 *  stringmap = createStringmap();
 *
 *    Create the string map that is used to parse the --fields
 *    paramater.
 */
static sk_stringmap_t *
createStringmap(
    void)
{
    sk_stringmap_t *field_map;

    /* Create the map if necessary */
    if (SKSTRINGMAP_OK != skStringMapCreate(&field_map)) {
        return NULL;
    }

    /* add entries */
    if (skStringMapAddEntries(field_map, -1, field_map_entries)
        != SKSTRINGMAP_OK)
    {
        skStringMapDestroy(field_map);
        return NULL;
    }

    return field_map;
}


/*
 *  usageFields(fh);
 *
 *    Print the usage (help) message for --fields to the 'fh' file
 *    pointer.
 */
static void
usageFields(
    FILE               *fh)
{
    sk_stringmap_t *field_map;

    /* Create the string map for --fields */
    field_map = createStringmap();
    if (NULL == field_map) {
        fprintf(fh, "Field(s) to print.\n");
        return;
    }

    fprintf(fh, ("Fields(s) to print. Def. " PMAPLOOKUP_DEFAULT_FIELDS "\n"
                 "\tList field names or IDs separated by commas."
                 "Supported fields:\n"));
    skStringMapPrintUsage(field_map, fh, 8);
    skStringMapDestroy(field_map);
}


/*
 *  ok = parseFields(string);
 *
 *    Parse the output fields listed in 'string' and set the global
 *    fields[] array to the pmap_find_field_t IDs.  Return 0 on
 *    success, or non-zero on failure.
 */
static int
parseFields(
    const char         *field_string)
{
    sk_stringmap_t *field_map = NULL;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    char *errmsg;
    int rv = -1;

    if (field_string == NULL || field_string[0] == '\0') {
        skAppPrintErr("Invalid %s: Value is empty",
                      appOptions[OPT_FIELDS].name);
        return rv;
    }
    field_map = createStringmap();
    if (NULL == field_map) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* parse the field-list */
    if (skStringMapParse(field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_FIELDS].name, errmsg);
        goto END;
    }

    /* add the selected fields to the 'fields[]' array */
    for (num_fields = 0;
         skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK;
         ++num_fields)
    {
        assert(num_fields < PMAPLOOKUP_MAX_FIELD_COUNT);
        fields[num_fields] = (pmap_find_field_t)entry->id;
        switch (fields[num_fields]) {
          case PMAPLOOKUP_FIELD_INPUT:
            printing_input = 1;
            break;
          case PMAPLOOKUP_FIELD_START_BLOCK:
          case PMAPLOOKUP_FIELD_END_BLOCK:
          case PMAPLOOKUP_FIELD_BLOCK:
            printing_block = 1;
            break;
          default:
            break;
        }
    }

    rv = 0;

  END:
    if (iter != NULL) {
        skStringMapIterDestroy(iter);
    }
    if (field_map != NULL) {
        skStringMapDestroy(field_map);
    }
    return rv;
}


/*
 *  printTitles();
 *
 *    Print the column headings unless --no-titles was specified.
 */
static void
printTitles(
    void)
{
    size_t i;

    if (no_titles) {
        return;
    }

    if (no_columns) {
        i = 0;
        fprintf(output.of_fp, "%s", field_map_entries[fields[i]].name);
        for (++i; i < num_fields; ++i) {
            fprintf(output.of_fp, "%c%s",
                    column_separator, field_map_entries[fields[i]].name);
        }
    } else {
        for (i = 0; i < num_fields; ++i) {
            if (i > 0) {
                fprintf(output.of_fp, "%c", column_separator);
            }
            fprintf(output.of_fp, "%*.*s",
                    col_width[fields[i]], col_width[fields[i]],
                    field_map_entries[fields[i]].name);
        }
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  printInputOnly(input_string);
 *
 *    Print a row where all columns are empty except for the 'input'
 *    column.  This function is used when --fields includes 'input'
 *    and a line of the input is empty or does not parse correctly.
 */
static void
printInputOnly(
    const char         *input_string)
{
    size_t i;

    assert(printing_input);

    for (i = 0; i < num_fields; ++i) {
        if (i > 0) {
            fprintf(output.of_fp, "%c", column_separator);
        }
        switch (fields[i]) {
          case PMAPLOOKUP_FIELD_KEY:
          case PMAPLOOKUP_FIELD_VALUE:
          case PMAPLOOKUP_FIELD_START_BLOCK:
          case PMAPLOOKUP_FIELD_END_BLOCK:
          case PMAPLOOKUP_FIELD_BLOCK:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], "");
            break;
          case PMAPLOOKUP_FIELD_INPUT:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], input_string);
            break;
        }
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  printAddress(ip, input_string);
 *
 *    Find the IP Address 'ip' in the prefix map file and print the
 *    row.
 */
static void
printAddress(
    const skipaddr_t   *ip,
    const char         *input_string)
{
    char buf[SKIPADDR_CIDR_STRLEN];
    char label[DICTIONARY_ENTRY_BUFLEN];
    skipaddr_t start_ip;
    skipaddr_t end_ip;
    size_t i;

    /* get the label for the IP */
    switch (pmaplookup_type) {
      case PMAPLOOKUP_TYPE_COUNTRY_IPV4:
      case PMAPLOOKUP_TYPE_COUNTRY_IPV6:
        skCountryLookupName(ip, label, sizeof(label));
        if (printing_block) {
            skCountryLookupCodeAndRange(ip, &start_ip, &end_ip);
        }
        break;
      case PMAPLOOKUP_TYPE_ADDRTYPE_IPV4:
      case PMAPLOOKUP_TYPE_ADDRTYPE_IPV6:
      case PMAPLOOKUP_TYPE_IPV4:
      case PMAPLOOKUP_TYPE_IPV6:
        skPrefixMapFindString(map, ip, label, sizeof(label));
        if (printing_block) {
            skPrefixMapFindRange(map, ip, &start_ip, &end_ip);
        }
        break;
      case PMAPLOOKUP_TYPE_PROTOPORT:
      case PMAPLOOKUP_TYPE_NONE:
        skAbortBadCase(pmaplookup_type);
    }

    for (i = 0; i < num_fields; ++i) {
        if (i > 0) {
            fprintf(output.of_fp, "%c", column_separator);
        }
        switch (fields[i]) {
          case PMAPLOOKUP_FIELD_KEY:
            skipaddrString(buf, ip, ip_format);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_VALUE:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], label);
            break;

          case PMAPLOOKUP_FIELD_INPUT:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], input_string);
            break;

          case PMAPLOOKUP_FIELD_START_BLOCK:
            skipaddrString(buf, &start_ip, ip_format);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_END_BLOCK:
            skipaddrString(buf, &end_ip, ip_format);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_BLOCK:
            skipaddrCidrString(buf, &start_ip,
                               skCIDRComputePrefix(&start_ip, &end_ip, NULL),
                               ip_format);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;
        }
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  printProtoPort(pp);
 *
 *    Find the protocol/port pair 'pp' in the prefix map file and
 *    print the row.
 */
static void
printProtoPort(
    const skPrefixMapProtoPort_t   *pp,
    const char                     *input_string)
{
    char buf[128];
    char label[DICTIONARY_ENTRY_BUFLEN];
    skPrefixMapProtoPort_t start_pp;
    skPrefixMapProtoPort_t end_pp;
    size_t i;

    assert(PMAPLOOKUP_TYPE_PROTOPORT == pmaplookup_type);

    /* get the label for the proto/port pair */
    skPrefixMapFindString(map, pp, label, sizeof(label));
    if (printing_block) {
        skPrefixMapFindRange(map, pp, &start_pp, &end_pp);
    }

    for (i = 0; i < num_fields; ++i) {
        if (i > 0) {
            fprintf(output.of_fp, "%c", column_separator);
        }
        switch (fields[i]) {
          case PMAPLOOKUP_FIELD_KEY:
            snprintf(buf, sizeof(buf), "%u/%u", pp->proto, pp->port);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_VALUE:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], label);
            break;

          case PMAPLOOKUP_FIELD_INPUT:
            fprintf(output.of_fp, "%*s", col_width[fields[i]], input_string);
            break;

          case PMAPLOOKUP_FIELD_START_BLOCK:
            assert(printing_block);
            snprintf(buf, sizeof(buf), "%u/%u", start_pp.proto, start_pp.port);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_END_BLOCK:
            assert(printing_block);
            snprintf(buf, sizeof(buf), "%u/%u", end_pp.proto, end_pp.port);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;

          case PMAPLOOKUP_FIELD_BLOCK:
            assert(printing_block);
            snprintf(buf, sizeof(buf), "%u/%u %u/%u",
                     start_pp.proto, start_pp.port,
                     end_pp.proto, end_pp.port);
            fprintf(output.of_fp, "%*s", col_width[fields[i]], buf);
            break;
        }
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  status = processAddress(string, filename, linenum);
 *
 *    Parse 'string' as an IP address, find the IP address in the
 *    prefix map, and print the resulting columns specified in
 *    --fields.
 *
 *    If an error occurs in parsing, report an error unless
 *    --no-errors was specified.  The parameters 'filename' and
 *    'linenum' specify the source of 'string' and will be used when
 *    reporting the error.  If 'filename' is NULL, it is assumed the
 *    string was read off the command line.
 */
static void
processAddress(
    const char         *string,
    const char         *filename,
    int                 linenum)
{
    skipaddr_t ip;
    int rv;

    /* parse the line */
    rv = skStringParseIP(&ip, string);
    if (rv) {
        if (no_errors || SKUTILS_ERR_EMPTY == rv) {
            /* nothing to report */
        } else if (filename) {
            skAppPrintErr("Invalid IP '%s' at %s:%d: %s",
                          string, filename, linenum, skStringParseStrerror(rv));
        } else {
            skAppPrintErr("Invalid IP '%s' on command line: %s",
                          string, skStringParseStrerror(rv));
        }
        if (printing_input) {
            printInputOnly(string);
        }
#if SK_ENABLE_IPV6
    } else if (PMAPLOOKUP_TYPE_CHECK_IPV6(pmaplookup_type)) {
        if (!skipaddrIsV6(&ip)) {
            /* force IP to be IPv6 when querying an IPv6 prefix map so
             * that the key reflects the type of pmap */
            skipaddrV4toV6(&ip, &ip);
        }
        printAddress(&ip, string);
    } else if (skipaddrIsV6(&ip)) {
        /* must try to force the key to IPv4 before querying the
         * prefix map */
        skipaddr_t ipaddrv4;
        if (0 == skipaddrV6toV4(&ip, &ipaddrv4)) {
            printAddress(&ipaddrv4, string);
        } else if (printing_input) {
            printInputOnly(string);
        }
#endif /* SK_ENABLE_IPV6 */
    } else {
        printAddress(&ip, string);
    }
}


/*
 *  status = processProtoPort(string, filename, linenum);
 *
 *    Parse 'string' as a protocol/port pair, find the pair in the
 *    prefix map, and print the resulting columns specified in
 *    --fields.
 *
 *    If an error occurs in parsing, report an error unless
 *    --no-errors was specified.  The parameters 'filename' and
 *    'linenum' specify the source of 'string' and will be used when
 *    reporting the error.  If 'filename' is NULL, it is assumed the
 *    string was read off the command line.
 */
static void
processProtoPort(
    const char         *string,
    const char         *filename,
    int                 linenum)
{
    skPrefixMapProtoPort_t pp;
    const char *port_string;
    uint32_t proto;
    uint32_t port;
    int rv;

    /* protocol */
    rv = skStringParseUint32(&proto, string, 0, UINT8_MAX);
    if (rv < 0) {
        if (no_errors || SKUTILS_ERR_EMPTY == rv) {
            /* nothing to report */
        } else if (filename) {
            skAppPrintErr("Invalid protocol '%s' at %s:%d: %s",
                          string, filename, linenum,
                          skStringParseStrerror(rv));
        } else {
            skAppPrintErr("Invalid protocol '%s' on command line: %s",
                          string, skStringParseStrerror(rv));
        }
        if (printing_input) {
            printInputOnly(string);
        }
        return;
    }
    if (rv == 0) {
        if (no_errors) {
            /* nothing to report */
        } else if (filename) {
            skAppPrintErr(("Invalid proto/port '%s' at %s:%d:"
                           " Missing '/' delimiter"),
                          string, filename, linenum);
        } else {
            skAppPrintErr(("Invalid proto/port '%s' on command line:"
                           " Missing '/' delimiter"),
                          string);
        }
        if (printing_input) {
            printInputOnly(string);
        }
        return;
    }

    /* rv is location of the '/' */
    port_string = string + rv + 1;

    /* port */
    rv = skStringParseUint32(&port, port_string, 0, UINT16_MAX);
    if (rv) {
        if (no_errors) {
            /* nothing to report */
        } else if (filename) {
            skAppPrintErr("Invalid port '%s' at %s:%d: %s",
                          port_string, filename, linenum,
                          skStringParseStrerror(rv));
        } else {
            skAppPrintErr("Invalid port '%s' on command line: %s",
                          port_string, skStringParseStrerror(rv));
        }
        if (printing_input) {
            printInputOnly(string);
        }
        return;
    }

    pp.proto = proto;
    pp.port = port;
    printProtoPort(&pp, string);
}


/*
 *  status = processInputFile(f_name);
 *
 *    For every line in the text file 'f_name', invoke
 *    processAddress() or processProtoPort() as appropriate.
 */
static int
processInputFile(
    const char         *f_name)
{
    char line[2048];
    skstream_t *stream = NULL;
    int retval = 1;
    int rv;
    int lc = 0;

    /* open input */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_TEXT))
        || (rv = skStreamBind(stream, f_name))
        || (rv = skStreamSetCommentStart(stream, "#"))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        goto END;
    }

    if (PMAPLOOKUP_TYPE_PROTOPORT == pmaplookup_type) {
        /* read until end of file */
        while ((rv = skStreamGetLine(stream, line, sizeof(line), &lc))
               != SKSTREAM_ERR_EOF)
        {
            switch (rv) {
              case SKSTREAM_OK:
                processProtoPort(line, f_name, lc);
                break;
              case SKSTREAM_ERR_LONG_LINE:
                /* bad: line was longer than sizeof(line) */
                if (!no_errors) {
                    skAppPrintErr("Input line %s:%d too long. ignored",
                                  f_name, lc);
                }
                break;
              default:
                /* unexpected error */
                skStreamPrintLastErr(stream, rv, &skAppPrintErr);
                goto END;
            }
        }
    } else {
        while ((rv = skStreamGetLine(stream, line, sizeof(line), &lc))
               != SKSTREAM_ERR_EOF)
        {
            switch (rv) {
              case SKSTREAM_OK:
                processAddress(line, f_name, lc);
                break;
              case SKSTREAM_ERR_LONG_LINE:
                /* bad: line was longer than sizeof(line) */
                skAppPrintErr("Input line %s:%d too long. ignored",
                              f_name, lc);
                break;
              default:
                /* unexpected error */
                skStreamPrintLastErr(stream, rv, &skAppPrintErr);
                goto END;
            }
        }
    }

    retval = 0;

  END:
    skStreamDestroy(&stream);
    return retval;
}


/*
 *  status = processIPSetFile(f_name);
 *
 *    Print the addresses that appear in the IPset file named by the
 *    'f_name' parameter.
 */
static int
processIPSetFile(
    const char         *f_name)
{
    char buf[SKIPADDR_STRLEN];
    skstream_t *stream = NULL;
    skipset_iterator_t iter;
    skipset_t *ipset;
    skipaddr_t ip;
    uint32_t prefix;
    int rv;

    /* Read the IPset file from the input */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, f_name))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return 1;
    }
    rv = skIPSetRead(&ipset, stream);
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Unable to read IPset from '%s': %s",
                          f_name, skIPSetStrerror(rv));
        }
        skStreamDestroy(&stream);
        return 1;
    }
    skStreamDestroy(&stream);

    skIPSetIteratorBind(&iter, ipset, 0, SK_IPV6POLICY_MIX);

#if !SK_ENABLE_IPV6
    if (!printing_input) {
        while (skIPSetIteratorNext(&iter, &ip, &prefix) == SK_ITERATOR_OK) {
            printAddress(&ip, NULL);
        }
    } else {
        while (skIPSetIteratorNext(&iter, &ip, &prefix) == SK_ITERATOR_OK) {
            skipaddrString(buf, &ip, SKIPADDR_CANONICAL);
            printAddress(&ip, buf);
        }
    }

#else  /* SK_ENABLE_IPV6 */

    if (!printing_input) {
        if (PMAPLOOKUP_TYPE_IPV4 == pmaplookup_type) {
            /* Tell the iterator to skip any IPv6 addresses */
            skIPSetIteratorBind(&iter, ipset, 0, SK_IPV6POLICY_ASV4);
        }
        while (skIPSetIteratorNext(&iter, &ip, &prefix) == SK_ITERATOR_OK) {
            printAddress(&ip, NULL);
        }
    } else if (PMAPLOOKUP_TYPE_IPV4 == pmaplookup_type
               && skIPSetContainsV6(ipset))
    {
        /* Need to visit every address and only query the prefix
         * map for IPv4 addresses */
        skipaddr_t ipaddrv4;
        while (skIPSetIteratorNext(&iter, &ip, &prefix) == SK_ITERATOR_OK) {
            skipaddrString(buf, &ip, SKIPADDR_CANONICAL);
            if (!skipaddrIsV6(&ip)) {
                printAddress(&ip, buf);
            } else if (0 == skipaddrV6toV4(&ip, &ipaddrv4)) {
                printAddress(&ipaddrv4, buf);
            } else {
                printInputOnly(buf);
            }
        }
    } else {
        if (PMAPLOOKUP_TYPE_IPV4 == pmaplookup_type
            && skIPSetIsV6(ipset))
        {
            skIPSetIteratorBind(&iter, ipset, 0, SK_IPV6POLICY_ASV4);
        }
        while (skIPSetIteratorNext(&iter, &ip, &prefix) == SK_ITERATOR_OK) {
            skipaddrString(buf, &ip, SKIPADDR_CANONICAL);
            printAddress(&ip, buf);
        }
    }
#endif  /* #else of #if !SK_ENABLE_IPV6 */

    skIPSetDestroy(&ipset);

    return 0;
}


int main(int argc, char **argv)
{
    char *arg;
    int rv = 0;

    appSetup(argc, argv);                       /* never returns on error */

    printTitles();
    while (skOptionsCtxNextArgument(optctx, &arg) == 0 && rv == 0) {
        if (ipset_files) {
            rv = processIPSetFile(arg);
        } else if (!no_files) {
            rv = processInputFile(arg);
        } else if (PMAPLOOKUP_TYPE_PROTOPORT == pmaplookup_type) {
            processProtoPort(arg, NULL, 0);
        } else {
            processAddress(arg, NULL, 0);
        }
    }

    /* done */
    appTeardown();

    return ((0 == rv) ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
