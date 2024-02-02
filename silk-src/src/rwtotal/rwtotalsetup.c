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
**  rwtotalsetup.c
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwtotalsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwtotal.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* where to write output */
static sk_fileptr_t output;

/* name of program to run to page output */
static char *pager;


/* OPTIONS SETUP */

static struct option appOptions[] = {
    {"sip-first-8",         NO_ARG,       0, OPT_SIP_FIRST_8},
    {"sip-first-16",        NO_ARG,       0, OPT_SIP_FIRST_16},
    {"sip-first-24",        NO_ARG,       0, OPT_SIP_FIRST_24},
    {"sip-last-8",          NO_ARG,       0, OPT_SIP_LAST_8},
    {"sip-last-16",         NO_ARG,       0, OPT_SIP_LAST_16},

    {"dip-first-8",         NO_ARG,       0, OPT_DIP_FIRST_8},
    {"dip-first-16",        NO_ARG,       0, OPT_DIP_FIRST_16},
    {"dip-first-24",        NO_ARG,       0, OPT_DIP_FIRST_24},
    {"dip-last-8",          NO_ARG,       0, OPT_DIP_LAST_8},
    {"dip-last-16",         NO_ARG,       0, OPT_DIP_LAST_16},

    {"sport",               NO_ARG,       0, OPT_SPORT},
    {"dport",               NO_ARG,       0, OPT_DPORT},
    {"proto",               NO_ARG,       0, OPT_PROTO},
    {"packets",             NO_ARG,       0, OPT_PACKETS},
    {"bytes",               NO_ARG,       0, OPT_BYTES},
    {"duration",            NO_ARG,       0, OPT_DURATION},
    {"icmp-code",           NO_ARG,       0, OPT_ICMP_CODE},

    {"summation",           NO_ARG,       0, OPT_SUMMATION},
    {"min-bytes",           REQUIRED_ARG, 0, OPT_MIN_BYTES},
    {"min-packets",         REQUIRED_ARG, 0, OPT_MIN_PACKETS},
    {"min-records",         REQUIRED_ARG, 0, OPT_MIN_RECORDS},
    {"max-bytes",           REQUIRED_ARG, 0, OPT_MAX_BYTES},
    {"max-packets",         REQUIRED_ARG, 0, OPT_MAX_PACKETS},
    {"max-records",         REQUIRED_ARG, 0, OPT_MAX_RECORDS},
    {"skip-zeroes",         NO_ARG,       0, OPT_SKIP_ZEROES},
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
    "Key on the first 8 bits of the source IP address",
    "Key on the first 16 bits of the source IP address",
    "Key on the first 24 bits of the source IP address",
    "Key on the last 8 bits of the source IP address",
    "Key on the last 16 bits of the source IP address",

    "Key on the first 8 bits of the destination IP address",
    "Key on the first 16 bits of the destination IP address",
    "Key on the first 24 bits of the destination IP address",
    "Key on the last 8 bits of the destination IP address",
    "Key on the last 16 bits of the  destination  IP address",

    "Key on the source port",
    "Key on the destination port",
    "Key on the protocol",
    "Key on the number of packets",
    "Key on the number of bytes",
    "Key on duration",
    ("Key on icmp type and code (DOES NOT check to see\n"
     "\t if the record is ICMP)"),

    "Print a summation row that totals all columns. Def. No",
    ("Do not print bins having fewer than this many bytes.\n"
     "\tDef. 0"),
    ("Do not print bins having fewer than this many packets.\n"
     "\tDef. 0"),
    ("Do not print bins having fewer than this many records.\n"
     "\tDef. 0"),
    ("Do not print bins having more than this many bytes.\n"
     "\tDef. 18446744073709551615"),
    ("Do not print bins having more than this many packets.\n"
     "\tDef. 18446744073709551615"),
    ("Do not print bins having more than this many records.\n"
     "\tDef. 18446744073709551615"),
    "Do not print bins having zero records. Def. Print all",
    "Do not print column titles. Def. Print titles",
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
    ("<KEY> [SWITCHES] [FILES]\n"                                             \
     "\tSummarize SiLK Flow records by a specified key and print the byte,\n" \
     "\tpacket, and flow counts for flows matching the key.  When no files\n" \
     "\tare given on the command line, flows are read from STDIN.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nKEY:\n");
    for (i = 0; appOptions[i].name && i <= COUNT_MODE_MAX_OPTION; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for ( ; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
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
void
appTeardown(
    void)
{
    static uint8_t teardownFlag = 0;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* free our RAM */
    if (count_array) {
        free(count_array);
    }

    /* close output file or process */
    if (output.of_name) {
        skFileptrClose(&output, skAppPrintErr);
    }

    /* close copy-input stream */
    skOptionsCtxCopyStreamClose(optctx, &skAppPrintErr);

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
void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    unsigned int optctx_flags;
    int rv;
    int i;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize variables */
    count_mode = COUNT_MODE_UNSET;
    for (i = 0; i < NUM_TOTALS; ++i) {
        bounds[i] = 0;
        bounds[NUM_TOTALS + i] = UINT64_MAX;
    }

    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES
                    | SK_OPTIONS_CTX_COPY_INPUT);

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

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();         /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* make certain we have something to count */
    if (count_mode == COUNT_MODE_UNSET) {
        skAppPrintErr("No key specified,\n"
                      "\t Please choose a summarization key.\n");
        skAppUsage();
    }

    /* verify our bounds */
    for (i = 0; i < NUM_TOTALS; ++i) {
        if (bounds[i] > bounds[NUM_TOTALS + i]) {
            const char *field = ((i == C_BYTES)
                                 ? "bytes"
                                 : ((i == C_PKTS)
                                    ? "packets"
                                    : "records"));
            skAppPrintErr(("The min-%s value is greater than max-%s: "
                           "%" PRIu64 " > %" PRIu64),
                          field, field, bounds[i], bounds[NUM_TOTALS + i]);
            exit(EXIT_FAILURE);
        }
    }

    /* make certain stdout is not being used for multiple outputs */
    if (skOptionsCtxCopyStreamIsStdout(optctx)) {
        if ((NULL == output.of_name)
            || (0 == strcmp(output.of_name, "-"))
            || (0 == strcmp(output.of_name, "stdout")))
        {
            skAppPrintErr("May not use stdout for multiple output streams");
            exit(EXIT_FAILURE);
        }
    }

    /* open the --ouptut-path: the 'of_name' member is non-NULL when
     * the switch is given */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Cannot open '%s': %s",
                          output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }
    }

    /* looks good, open the --copy-input destination */
    if (skOptionsCtxOpenStreams(optctx, &skAppPrintErr)) {
        exit(EXIT_FAILURE);
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
    int i;
    int rv;

    /* handle the switches that set the key/count-mode */
    if (opt_index <= COUNT_MODE_MAX_OPTION) {
        if (count_mode != COUNT_MODE_UNSET) {
            skAppPrintErr("Only one summarization key may be specified");
            return 1;
        }
        count_mode = opt_index;
        return 0;
    }

    switch (opt_index) {
      case OPT_SUMMATION:
        summation = 1;
        break;

      case OPT_MIN_BYTES:
        rv = skStringParseUint64(&(bounds[C_BYTES]), opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MIN_PACKETS:
        rv = skStringParseUint64(&(bounds[C_PKTS]), opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MIN_RECORDS:
        rv = skStringParseUint64(&(bounds[C_RECS]), opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MAX_BYTES:
        rv = skStringParseUint64(&(bounds[NUM_TOTALS + C_BYTES]), opt_arg,0,0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MAX_PACKETS:
        rv = skStringParseUint64(&(bounds[NUM_TOTALS + C_PKTS]), opt_arg, 0,0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MAX_RECORDS:
        rv = skStringParseUint64(&(bounds[NUM_TOTALS + C_RECS]), opt_arg, 0,0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SKIP_ZEROES:
        /* set lower bound to 1 unless it is already set. */
        for (i = 0; i < NUM_TOTALS; ++i) {
            if (bounds[i] == 0) {
                bounds[i] = 1;
            }
        }
        break;

      case OPT_NO_TITLES:
        no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        no_columns = 1;
        no_final_delimiter = 1;
        if (opt_arg) {
            delimiter = opt_arg[0];
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

      default:
        skAbortBadCase(opt_index);
    } /* switch */

    return 0;                     /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


FILE *
getOutputHandle(
    void)
{
    int rv;

    /* only invoke the pager when the user has not specified the
     * output-path, even if output-path is stdout */
    if (NULL == output.of_name) {
        /* invoke the pager */
        rv = skFileptrOpenPager(&output, pager);
        if (rv && rv != SK_FILEPTR_PAGER_IGNORED) {
            skAppPrintErr("Unable to invoke pager");
        }
    }

    return output.of_fp;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
