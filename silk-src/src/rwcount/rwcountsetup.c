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
 *  rwcountsetup.c
 *
 *    Routines for setting up rwcount
 *
 *    Michael P. Collins
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcountsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstringmap.h>
#include "rwcount.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to send --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* start and end time strings that user entered */
static const char *start_time;
static const char *end_time;

/* where to write output */
static sk_fileptr_t output;

static char *pager;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags =
    (SK_OPTION_TIMESTAMP_ALWAYS_MSEC | SK_OPTION_TIMESTAMP_OPTION_EPOCH_NAME
     | SK_OPTION_TIMESTAMP_OPTION_LEGACY);

/* load-schemes */
static const sk_stringmap_entry_t load_schemes[] = {
    {"time-proportional",       LOAD_DURATION,  NULL,
     "split volume proportional to time active in bin"},
    {"bin-uniform",             LOAD_MEAN,      NULL,
     "split volume evenly across the bins"},
    {"start-spike",             LOAD_START,     NULL,
     "add complete volume to bin at start time"},
    {"middle-spike",            LOAD_MIDDLE,    NULL,
     "add complete volume to bin at midpoint (by time)"},
    {"end-spike",               LOAD_END,       NULL,
     "add complete volume to bin at end time"},
    {"maximum-volume",          LOAD_MAXIMUM,   NULL,
     "add complete volume to every bin"},
    {"minimum-volume",          LOAD_MINIMUM,   NULL,
     "add volume only when record in is single bin"},
    SK_STRINGMAP_SENTINEL
};


/* OPTIONS SETUP */

typedef enum {
    OPT_BIN_SIZE, OPT_LOAD_SCHEME,
    OPT_START_TIME, OPT_END_TIME, OPT_SKIP_ZEROES,
    OPT_BIN_SLOTS,
    OPT_NO_TITLES, OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR, OPT_NO_FINAL_DELIMITER, OPT_DELIMITED,
    OPT_OUTPUT_PATH, OPT_PAGER
} appOptionsEnum;

static const struct option appOptions[] = {
    {"bin-size",            REQUIRED_ARG, 0, OPT_BIN_SIZE},
    {"load-scheme",         REQUIRED_ARG, 0, OPT_LOAD_SCHEME},
    {"start-time",          REQUIRED_ARG, 0, OPT_START_TIME},
    {"end-time",            REQUIRED_ARG, 0, OPT_END_TIME},
    {"skip-zeroes",         NO_ARG,       0, OPT_SKIP_ZEROES},
    {"bin-slots",           NO_ARG,       0, OPT_BIN_SLOTS},
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
    "Set size of bins in seconds; may be fractional. Def. 30.000",
    NULL, /* generated dynamically */
    "Print bins from this time forward. Def. First nonzero bin",
    "Print bins until this time. Def. Last nonzero bin",
    "Do not print bins that have no flows. Def. Print all",
    "Print bin labels using the internal bin index. Def. No",
    "Do not print column titles. Def. Print titles",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
    "Write the output to this stream or file. Def. stdout",
    "Invoke this program to page output. Def. $SILK_PAGER or $PAGER",
    (char *)NULL
};

static const struct option deprecatedOptions[] = {
    {"start-epoch",         REQUIRED_ARG, 0, OPT_START_TIME},
    {"end-epoch",           REQUIRED_ARG, 0, OPT_END_TIME},
    {0,0,0,0}               /* sentinel entry */
};

static const char *deprecatedHelp[] = {
    "DEPRECATED. Alias for --start-time",
    "DEPRECATED. Alias for --end-time",
    (char *)NULL
};

/* Allow any abbreviation of "--start-" and "--end-" to work */
static const struct option deprecatedOptionsShort[] = {
    {"start-",              REQUIRED_ARG, 0, OPT_START_TIME},
    {"start",               REQUIRED_ARG, 0, OPT_START_TIME},
    {"star",                REQUIRED_ARG, 0, OPT_START_TIME},
    {"sta",                 REQUIRED_ARG, 0, OPT_START_TIME},
    {"st",                  REQUIRED_ARG, 0, OPT_START_TIME},
    /* "--s" can be --start-time or --skip-zeroes */
    {"end-",                REQUIRED_ARG, 0, OPT_END_TIME},
    {"end",                 REQUIRED_ARG, 0, OPT_END_TIME},
    {"en",                  REQUIRED_ARG, 0, OPT_END_TIME},
    /* "--e" can be --end-time or --epoch-slots */
    {0,0,0,0}               /* sentinel entry */
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  loadschemeParse(const char *format, bin_load_scheme_enum_t *ls);
static void loadschemeUsage(FILE *fh);


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
    ("[SWITCHES] [FILES]\n"                                                   \
     "\tSummarize SiLK Flow records across time, producing textual output\n"  \
     "\twith counts of bytes, packets, and flow records for each time bin.\n" \
     "\tWhen no files given on command line, flows are read from STDIN.\n")

    FILE *fh = USAGE_FH;
    int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_LOAD_SCHEME:
            loadschemeUsage(fh);
            break;
          case OPT_BIN_SLOTS:
            fprintf(fh, "%s\n", appHelp[i]);
            skOptionsTimestampFormatUsage(fh);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }
    for (i = 0; deprecatedOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", deprecatedOptions[i].name,
                SK_OPTION_HAS_ARG(deprecatedOptions[i]), deprecatedHelp[i]);
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
    static int teardownFlag = 0;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* free our memory */
    if (bins.data) {
        free(bins.data);
    }

    /* close the output file or process */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }

    /* close the copy-stream */
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
    sktime_t t;
    unsigned int end_precision;
    unsigned int is_epoch;
    int64_t bin_count;
    int rv;

    /* make sure count of option's declarations and help-strings match */
    assert((sizeof(appOptions)/sizeof(struct option)) ==
           (sizeof(appHelp)/sizeof(char *)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&flags, 0, sizeof(flags));
    flags.delimiter = '|';
    flags.load_scheme = DEFAULT_LOAD_SCHEME;

    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    memset(&bins, 0, sizeof(bins));
    bins.start_time = RWCO_UNINIT_START;
    bins.end_time = RWCO_UNINIT_END;
    bins.size = DEFAULT_BINSIZE;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES
                    | SK_OPTIONS_CTX_COPY_INPUT);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(deprecatedOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(deprecatedOptionsShort, &appOptionsHandler, NULL)
        || skOptionsTimestampFormatRegister(&flags.timeflags,
                                            time_register_flags, "epoch-slots")
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

    /* parse options; print usage if error */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* parse the times */
    if (start_time) {
        rv = skStringParseDatetime(&bins.start_time, start_time, NULL);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[OPT_START_TIME].name, start_time,
                          skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
    }

    if (end_time) {
        rv = skStringParseDatetime(&t, end_time, &end_precision);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[OPT_END_TIME].name, end_time,
                          skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
        /* get the precision; treat epoch time as seconds resolution
         * unless its precision is already seconds or milliseconds */
        is_epoch = SK_PARSED_DATETIME_EPOCH & end_precision;
        end_precision &= SK_PARSED_DATETIME_MASK_PRECISION;
        if (is_epoch && end_precision < SK_PARSED_DATETIME_SECOND) {
            end_precision = SK_PARSED_DATETIME_SECOND;
        }

        if (start_time) {
            /* move end-time to its ceiling */
            skDatetimeCeiling(&t, &t, end_precision);
            ++t;

            /* verify times */
            if (t <= bins.start_time) {
                char buf_s[SKTIMESTAMP_STRLEN];
                char buf_e[SKTIMESTAMP_STRLEN];
                skAppPrintErr("The %s is less than %s: %s < %s",
                              appOptions[OPT_END_TIME].name,
                              appOptions[OPT_START_TIME].name,
                              sktimestamp_r(buf_e, t, SKTIMESTAMP_NOMSEC),
                              sktimestamp_r(buf_s, bins.start_time,
                                            SKTIMESTAMP_NOMSEC));
                exit(EXIT_FAILURE);
            }

            /* make certain end-time fails on a boundary by computing
             * the number of bins required to hold the end-time.  we
             * subtract 1 then add 1 to get a valid count whether or
             * not the division would have a remainder. */
            bin_count = 1 + ((t - bins.start_time - 1) / bins.size);
            bins.end_time = bins.start_time + bins.size * bin_count;
        } else {
            /* when only end_time is given, create bins up to its
             * ceiling value */
            bins.end_time = t;
            skDatetimeCeiling(&t, &t, end_precision);
            ++t;
            /* determine the number of bins between the end-time
             * specified by the user and the ceiling of that end-time,
             * then increase the end time by that number of bins */
            bin_count = 1 + ((t - bins.end_time - 1) / bins.size);
            bins.end_time += bin_count * bins.size;
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

    /* open the --output-path: the 'of_name' member is non-NULL when
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

    return;                     /* OK */
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
    double opt_double;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_LOAD_SCHEME:
        if (loadschemeParse(opt_arg, &flags.load_scheme)) {
            return 1;
        }
        break;

      case OPT_BIN_SIZE:
        rv = skStringParseDouble(&opt_double, opt_arg, 0.001, INT32_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        bins.size = (sktime_t)(1000.0 * opt_double);
        break;

      case OPT_BIN_SLOTS:
        flags.label_index = 1;
        break;

      case OPT_START_TIME:
        if (start_time != NULL) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
        }
        start_time = opt_arg;
        break;

      case OPT_END_TIME:
        if (end_time != NULL) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
        }
        end_time = opt_arg;
        break;

      case OPT_SKIP_ZEROES:
        flags.skip_zeroes = 1;
        break;

      case OPT_NO_TITLES:
        flags.no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        flags.no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        flags.no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        flags.delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        flags.no_columns = 1;
        flags.no_final_delimiter = 1;
        if (opt_arg) {
            flags.delimiter = opt_arg[0];
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

    return 0;                     /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  status = loadschemeParse(scheme_name, load_scheme);
 *
 *    Parse the load-scheme name in 'scheme_name' and set
 *    'load_scheme' to the result of parsing the string.  Return 0 on
 *    success, or -1 if parsing of the value fails.
 */
static int
loadschemeParse(
    const char             *scheme_name,
    bin_load_scheme_enum_t *load_scheme)
{
    char buf[128];
    sk_stringmap_entry_t new_entry;
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t sm_err;
    sk_stringmap_entry_t *sm_entry;
    const sk_stringmap_entry_t *e;
    int rv = -1;

    memset(&new_entry, 0, sizeof(new_entry));
    new_entry.name = buf;

    /* create a stringmap of the available load-scheme names */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, load_schemes) != SKSTRINGMAP_OK){
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* allow the integer ID of each load-scheme to work */
    for (e = load_schemes; e->name; ++e) {
        new_entry.id = e->id;
        snprintf(buf, sizeof(buf), "%u", e->id);
        if (skStringMapAddEntries(str_map, 1, &new_entry) != SKSTRINGMAP_OK) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }

    /* attempt to match */
    sm_err = skStringMapGetByName(str_map, scheme_name, &sm_entry);
    switch (sm_err) {
      case SKSTRINGMAP_OK:
        *load_scheme = (bin_load_scheme_enum_t)sm_entry->id;
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s: '%s' is ambiguous",
                      appOptions[OPT_LOAD_SCHEME].name, scheme_name);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s: '%s' is not recognized",
                      appOptions[OPT_LOAD_SCHEME].name, scheme_name);
        break;

      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      sm_err);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/*
 *  loadschemeUsage(fh);
 *
 *    Print the description of the argument to the --load-scheme
 *    switch to the 'fh' file handle.
 */
static void
loadschemeUsage(
    FILE               *fh)
{
    const sk_stringmap_entry_t *e;
    char buf[128];

    /* Find name of the default load-scheme */
    for (e = load_schemes; e->name; ++e) {
        if (DEFAULT_LOAD_SCHEME == e->id) {
            break;
        }
    }
    if (NULL == e->name) {
        skAbort();
    }

    fprintf(fh, "Split a record's volume (bytes & packets) among the\n"
            "\tbins it spans using this scheme. Def. %s. Choices:\n",
            e->name);
    for (e = load_schemes; e->name; ++e) {
        if (e->userdata) {
            snprintf(buf, sizeof(buf), "%s,%u", e->name, e->id);
            fprintf(fh, "\t  %-19s - %s\n",
                    buf, (const char*)e->userdata);
        }
    }
}


/*
 *  fp = getOutputHandle();
 *
 *    Return the file handle to use for output.
 */
FILE *
getOutputHandle(
    void)
{
    int rv;

    /* only invoke the pager when the user has not specified the
     * output-path, even if output-path is stdout */
    if (NULL == output.of_name) {
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
