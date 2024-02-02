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
** rwcutsetup.c
**      utility routines in support of rwcut.
** Suresh Konda
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcutsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silkpython.h>
#include <silk/skcountry.h>
#include <silk/skdllist.h>
#include <silk/skplugin.h>
#include <silk/skprefixmap.h>
#include <silk/skstringmap.h>
#include "rwcut.h"


/* TYPEDEFS AND MACROS */

/* where to write --help output */
#define USAGE_FH stdout

/* The last field printed by default. */
#define RWCUT_LAST_DEFAULT_FIELD  RWREC_FIELD_SID

/* User options */
typedef struct cut_opt_flags_st {
    unsigned no_titles          :1;
    unsigned no_final_delimiter :1;
    unsigned no_columns         :1;
    unsigned icmp_type_and_code :1;
    unsigned integer_sensors    :1;
    unsigned integer_tcp_flags  :1;
    unsigned dry_run            :1;
} cut_opt_flags_t;


/* LOCAL VARIABLES */

/* start and end record number */
static uint64_t start_rec_num = 0;
static uint64_t end_rec_num = 0;
/* num_recs and tail_recs are globals */

/* The output stream: where to print the records */
static sk_fileptr_t output;

/* name of program to run to page output */
static char *pager = NULL;

/* user's options */
static cut_opt_flags_t cut_opts;

/* delimiter between columns */
static char delimiter;

/* how to print IP addresses */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);

/* how to print timestamps */
static uint32_t time_flags = 0;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags =
    (SK_OPTION_TIMESTAMP_OPTION_EPOCH | SK_OPTION_TIMESTAMP_OPTION_LEGACY);

/* the text the user entered for the --fields switch */
static char *fields_arg = NULL;

/* whether the --all-fields switch was given */
static int all_fields = 0;

/* available fields */
static sk_stringmap_t *key_field_map;

/* fields that get defined just like plugins */
static const struct app_static_plugins_st {
    const char         *name;
    skplugin_setup_fn_t setup_fn;
} app_static_plugins[] = {
    {"addrtype",        skAddressTypesAddFields},
    {"ccfilter",        skCountryAddFields},
    {"pmapfilter",      skPrefixMapAddFields},
#if SK_ENABLE_PYTHON
    {"silkpython",      skSilkPythonAddFields},
#endif
    {NULL, NULL}        /* sentinel */
};

/* List of plugins to attempt to open at startup */
static const char *app_plugin_names[] = {
    NULL /* sentinel */
};


/* OPTIONS SETUP */

typedef enum {
    /* Keep this list in sync with appOptions[] */
    OPT_HELP_FIELDS,
    OPT_FIELDS,
    OPT_ALL_FIELDS,
    OPT_NUM_RECS,
    OPT_START_REC_NUM,
    OPT_END_REC_NUM,
    OPT_TAIL_RECS,
    OPT_DRY_RUN,
    OPT_PLUGIN,
    OPT_ICMP_TYPE_AND_CODE,
    OPT_INTEGER_SENSORS,
    OPT_INTEGER_TCP_FLAGS,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_OUTPUT_PATH,
    OPT_PAGER
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {"all-fields",          NO_ARG,       0, OPT_ALL_FIELDS},
    {"num-recs",            REQUIRED_ARG, 0, OPT_NUM_RECS},
    {"start-rec-num",       REQUIRED_ARG, 0, OPT_START_REC_NUM},
    {"end-rec-num",         REQUIRED_ARG, 0, OPT_END_REC_NUM},
    {"tail-recs",           REQUIRED_ARG, 0, OPT_TAIL_RECS},
    {"dry-run",             NO_ARG,       0, OPT_DRY_RUN},
    {"plugin",              REQUIRED_ARG, 0, OPT_PLUGIN},
    {"icmp-type-and-code",  NO_ARG,       0, OPT_ICMP_TYPE_AND_CODE},
    {"integer-sensors",     NO_ARG,       0, OPT_INTEGER_SENSORS},
    {"integer-tcp-flags",   NO_ARG,       0, OPT_INTEGER_TCP_FLAGS},
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
    "Describe each field and exit. Def. no",
    NULL, /* generated dynamically */
    "Print all known fields to the output",
    "Print no more than this number of records. Def. Unlimited",
    ("Start printing with this record number, where 1 is the\n"
     "\tfirst record.  Def. 1.  Conflicts with --tail-recs"),
    ("End printing with this record number; must be greater\n"
     "\tthan --start-rec-num.  Def. Final record. Conflicts with --tail-recs"),
    ("Start printing this number of records from the end of the\n"
     "\tinput. Def. None. Conflicts with --start-rec-num and --end-rec-num"),
    "Parse options and print column titles only. Def. No",
    ("Load given plug-in to add fields. Switch may be repeated to\n"
     "\tload multiple plug-ins. Def. None"),
    ("Print the ICMP type/code in the sPort/dPort fields.\n"
     "\tDef. No. DEPRECATED. Use the explicit iType and iCode fields instead"),
    "Print sensor as an integer. Def. Sensor name",
    "Print TCP Flags as an integer. Def. No",
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
static void helpFields(FILE *fh);
static int  createStringmaps(void);
static int  selectFieldsDefault(void);
static int  selectFieldsAll(void);
static int  parseFields(const char* opt_arg);
static int  appAddPluginField(const sk_stringmap_entry_t *map_entry);


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
     "\tPrint SiLK Flow records in a |-delimited, columnar, human-readable\n" \
     "\tformat.  Use --fields to select columns to print. When no files are\n"\
     "\tgiven on the command line, flows are read from the standard input.\n")

    FILE *fh = USAGE_FH;
    int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_FIELDS:
            /* Dynamically build the help */
            usageFields(fh);
            break;
          case OPT_ICMP_TYPE_AND_CODE:
            /* Simple static help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
            /* Print the IPv6 usage next */
            skIPv6PolicyUsage(fh);
            /* Print the timestamp format usage */
            skOptionsTimestampFormatUsage(fh);
            /* Print the IP address format usage */
            skOptionsIPFormatUsage(fh);
            break;
          default:
            /* Simple static help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    sksiteOptionsUsage(fh);
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
void
appTeardown(
    void)
{
    static uint8_t teardownFlag = 0;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* Plugin teardown */
    skPluginRunCleanup(SKPLUGIN_APP_CUT);
    skPluginTeardown();

    /* close copy input stream */
    skOptionsCtxCopyStreamClose(optctx, skAppPrintErr);

    /* close the output file or process */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }

    /* destroy output */
    rwAsciiStreamDestroy(&ascii_str);

    /* destroy field map */
    if (key_field_map != NULL) {
        skStringMapDestroy(key_field_map);
        key_field_map = NULL;
    }

    if (tail_buf) {
        free(tail_buf);
        tail_buf = NULL;
    }

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
    int j;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&cut_opts, 0, sizeof(cut_opts));
    delimiter = '|';

    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES
                    | SK_OPTIONS_CTX_COPY_INPUT);

    /* Initialize plugin library */
    skPluginSetup(1, SKPLUGIN_APP_CUT);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE)
        || skOptionsTimestampFormatRegister(&time_flags, time_register_flags)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags)
        || skIPv6PolicyOptionsRegister(&ipv6_policy))
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

    /* try to load hard-coded plugins */
    for (j = 0; app_static_plugins[j].name; ++j) {
        skPluginAddAsPlugin(app_static_plugins[j].name,
                            app_static_plugins[j].setup_fn);
    }
    for (j = 0; app_plugin_names[j]; ++j) {
        skPluginLoadPlugin(app_plugin_names[j], 0);
    }

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();         /* never returns */
    }

    /* Not having site config is allowed */
    sksiteConfigure(0);

    /* Create the --fields */
    if (createStringmaps()) {
        exit(EXIT_FAILURE);
    }

    /* Create the ascii stream */
    if (rwAsciiStreamCreate(&ascii_str)) {
        skAppPrintErr("Unable to create ascii stream");
        exit(EXIT_FAILURE);
    }

    /* Parse the --fields or --all-fields argument, or use the default
     * fields */
    if (fields_arg != NULL) {
        if (parseFields(fields_arg)) {
            exit(EXIT_FAILURE);
        }
    } else if (all_fields) {
        if (selectFieldsAll()) {
            exit(EXIT_FAILURE);
        }
    } else if (selectFieldsDefault()) {
        skAppPrintErr("Cannot set default output fields");
        exit(EXIT_FAILURE);
    }

    /* check limits; main loop uses 'num_recs' with either 'skip_recs'
     * or 'tail_recs' */
    if (tail_recs) {
        if (start_rec_num || end_rec_num) {
            skAppPrintErr("May not use --%s when --%s or --%s is specified",
                          appOptions[OPT_TAIL_RECS].name,
                          appOptions[OPT_START_REC_NUM].name,
                          appOptions[OPT_END_REC_NUM].name);
            exit(EXIT_FAILURE);
        }
        if (num_recs >= tail_recs) {
            /* cannot print more than 'tail_recs' records */
            num_recs = 0;
        }
    }
    if (start_rec_num) {
        skip_recs = start_rec_num - 1;
    }
    if (end_rec_num) {
        if (end_rec_num < start_rec_num) {
            skAppPrintErr(("The %s is less than the %s: "
                           "%" PRIu64 " < %" PRIu64),
                          appOptions[OPT_END_REC_NUM].name,
                          appOptions[OPT_START_REC_NUM].name,
                          end_rec_num, start_rec_num);
            exit(EXIT_FAILURE);
        }
        if (start_rec_num) {
            /* unconditionally set num_recs to their difference */
            num_recs = end_rec_num - skip_recs;
        } else if ((num_recs > 0) && (num_recs < end_rec_num)) {
            skip_recs = end_rec_num - num_recs;
        } else {
            num_recs = end_rec_num;
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

    /* set properties on the ascii-stream */
    rwAsciiSetDelimiter(ascii_str, delimiter);
    rwAsciiSetIPv6Policy(ascii_str, ipv6_policy);
    rwAsciiSetIPFormatFlags(ascii_str, ip_format);
    rwAsciiSetTimestampFlags(ascii_str, time_flags);

    if (cut_opts.no_titles) {
        rwAsciiSetNoTitles(ascii_str);
    }
    if (cut_opts.no_columns) {
        rwAsciiSetNoColumns(ascii_str);
    }
    if (cut_opts.integer_sensors) {
        rwAsciiSetIntegerSensors(ascii_str);
    }
    if (cut_opts.integer_tcp_flags) {
        rwAsciiSetIntegerTcpFlags(ascii_str);
    }
    if (cut_opts.no_final_delimiter) {
        rwAsciiSetNoFinalDelimiter(ascii_str);
    }
    if (cut_opts.icmp_type_and_code) {
        rwAsciiSetIcmpTypeCode(ascii_str);
    }

    /* allocate the buffer for 'tail_recs' */
    if (tail_recs) {
        tail_buf = (rwRec*)malloc(tail_recs * sizeof(rwRec));
        if (NULL == tail_buf) {
            skAppPrintErr("Unable to create buffer for %" PRIu64 " records",
                          tail_recs);
            exit(EXIT_FAILURE);
        }
    }

    /* open the --output-path.  the 'of_name' member is NULL if user
     * didn't get an output-path.  only invoke the pager when an
     * explicit --output-path was not given. */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Cannot open '%s': %s",
                          output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }
    } else {
        /* Invoke the pager */
        rv = skFileptrOpenPager(&output, pager);
        if (rv && rv != SK_FILEPTR_PAGER_IGNORED) {
            skAppPrintErr("Unable to invoke pager");
        }
    }

    rwAsciiSetOutputHandle(ascii_str, output.of_fp);

    /* if dry-run, print the column titles and exit */
    if (cut_opts.dry_run) {
        rwAsciiPrintTitles(ascii_str);
        appTeardown();
        exit(EXIT_SUCCESS);
    }

    /* open the --copy-input stream */
    if ((rv = skOptionsCtxOpenStreams(optctx, &skAppPrintErr))) {
        exit(EXIT_FAILURE);
    }

    return;                       /* OK */
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
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_FIELDS:
        if (fields_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (all_fields) {
            skAppPrintErr("Invalid %s: The --%s switch was already given",
                          appOptions[opt_index].name,
                          appOptions[OPT_ALL_FIELDS].name);
            return 1;
        }
        fields_arg = opt_arg;
        break;

      case OPT_ALL_FIELDS:
        if (fields_arg) {
            skAppPrintErr("Invalid %s: The --%s switch was already given",
                          appOptions[opt_index].name,
                          appOptions[OPT_FIELDS].name);
            return 1;
        }
        all_fields = 1;
        break;

      case OPT_NUM_RECS:
        rv = skStringParseUint64(&num_recs, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_START_REC_NUM:
        rv = skStringParseUint64(&start_rec_num, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_END_REC_NUM:
        rv = skStringParseUint64(&end_rec_num, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_TAIL_RECS:
        rv = skStringParseUint64(&tail_recs, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_NO_TITLES:
        cut_opts.no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        cut_opts.no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        cut_opts.no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        cut_opts.no_columns = 1;
        cut_opts.no_final_delimiter = 1;
        if (opt_arg) {
            delimiter = opt_arg[0];
        }
        break;

      case OPT_ICMP_TYPE_AND_CODE:
        cut_opts.icmp_type_and_code = 1;
        break;

      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1) != 0) {
            skAppPrintErr("Unable to load %s as a plugin", opt_arg);
            return 1;
        }
        break;

      case OPT_INTEGER_SENSORS:
        cut_opts.integer_sensors = 1;
        break;

      case OPT_INTEGER_TCP_FLAGS:
        cut_opts.integer_tcp_flags = 1;
        break;

      case OPT_DRY_RUN:
        cut_opts.dry_run = 1;
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
 *  status = selectFieldsDefault();
 *
 *    Set the global ascii-stream to print rwcut's default columns.
 *    Return 0 on success or -1 on memory error.
 */
static int
selectFieldsDefault(
    void)
{
    uint32_t default_fields[1+RWCUT_LAST_DEFAULT_FIELD];
    const uint32_t count = 1+RWCUT_LAST_DEFAULT_FIELD;
    uint32_t i;

    /* set up the default fields for rwcut */
    for (i = 0; i < count; ++i) {
        default_fields[i] = i;
    }

    rwAsciiAppendFields(ascii_str, default_fields, count);

    return 0;
}


/*
 *  status = selectFieldsAll();
 *
 *    Set the global ascii-stream to print all known fields---both
 *    built-in and from plug-ins.  Return 0 on success or -1 on memory
 *    error.
 */
static int
selectFieldsAll(
    void)
{
    int rv = -1;
    uint32_t i;
    FILE *old_errs = NULL;
    sk_bitmap_t *field_seen = NULL;
    sk_dll_iter_t node;
    sk_stringmap_entry_t *sm_entry;

    /* create a bitmap to keep track of the fields we've added */
    if (skBitmapCreate(&field_seen, 65536)) {
        goto END;
    }

    /* add all built-in fields to the ascii-stream */
    for (i = 0; i < RWREC_PRINTABLE_FIELD_COUNT; ++i) {
        if (rwAsciiAppendOneField(ascii_str, i)) {
            skAppPrintErr(("Cannot add field %" PRIu32 " to stream"), i);
            goto END;
        }
    }

    /* disable error output to avoid seeing warnings from plug-ins */
    old_errs = skAppSetErrStream(NULL);

    /* add the fields from every plug-in */
    skDLLAssignIter(&node, key_field_map);
    while (skDLLIterForward(&node, (void **)&sm_entry) == 0) {
        if ((NULL != sm_entry->userdata)
            && !skBitmapGetBit(field_seen, sm_entry->id))
        {
            /* ignore errors */
            (void)appAddPluginField(sm_entry);
            skBitmapSetBit(field_seen, sm_entry->id);
        }
    }

    /* re-enable errors */
    skAppSetErrStream(old_errs);

    /* successful */
    rv = 0;

  END:
    if (field_seen) {
        skBitmapDestroy(&field_seen);
    }

    return rv;
}


/*
 *  status = parseFields(fields_string);
 *
 *    Parse the user's option for the --fields switch and set up the
 *    rwAsciiStream.  Return 0 on success; 1 on failure.
 */
static int
parseFields(
    const char         *field_string)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry;
    char *errmsg;
    int rv = -1;

    if (field_string == NULL || field_string[0] == '\0') {
        skAppPrintErr("Missing --fields value");
        return -1;
    }

    /* parse the field-list */
    if (skStringMapParse(key_field_map, field_string, SKSTRINGMAP_DUPES_KEEP,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_FIELDS].name, errmsg);
        goto END;
    }

    while (skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK) {
        if (sm_entry->id == RWREC_PRINTABLE_FIELD_COUNT) {
            /* handle the icmpTypeCode field */
            rwrec_printable_fields_t icmp_fields[] = {
                RWREC_FIELD_ICMP_TYPE, RWREC_FIELD_ICMP_CODE
            };
            char name_buf[128];
            size_t k;

            for (k = 0; k < sizeof(icmp_fields)/sizeof(icmp_fields[0]); ++k) {
                if (rwAsciiAppendOneField(ascii_str, icmp_fields[k])) {
                    rwAsciiGetFieldName(name_buf, sizeof(name_buf),
                                        icmp_fields[k]);
                    skAppPrintErr("Cannot add key field '%s' to stream",
                                  name_buf);
                    goto END;
                }
            }
        } else if (sm_entry->userdata == NULL) {
            /* field is built-in */
            if (rwAsciiAppendOneField(ascii_str, sm_entry->id)) {
                skAppPrintErr("Cannot add field %s to stream",
                              sm_entry->name);
                goto END;
            }
        } else {
            /* field comes from a plug-in */
            assert(sm_entry->id > RWREC_PRINTABLE_FIELD_COUNT);

            if (appAddPluginField(sm_entry)) {
                skAppPrintErr("Cannot add field %s from plugin",
                              sm_entry->name);
                goto END;
            }
        }
    }

    /* successful */
    rv = 0;

  END:
    if (sm_iter) {
        skStringMapIterDestroy(sm_iter);
    }
    return rv;
}


/*
 *  usageFields(fh);
 *
 *    Print the usage (help) message for --fields to the 'fh' file pointer
 */
static void
usageFields(
    FILE               *fh)
{
    uint32_t i;

    /* Create the string map for --fields */
    createStringmaps();

    fprintf(fh, ("Print these fields in the output. Specify fields as a\n"
                 "\tcomma-separated list of names, IDs, and/or ID-ranges.\n"));

    skStringMapPrintUsage(key_field_map, fh, 4);

    /* Print default fields */
    i = 0;
    fprintf(fh, "\tDef. %s", skStringMapGetFirstName(key_field_map, i));
    for (++i; i <= RWCUT_LAST_DEFAULT_FIELD; ++i) {
        fprintf(fh, ",%s", skStringMapGetFirstName(key_field_map, i));
    }
    fprintf(fh, "\n");
}


/*
 *  helpFields(fh);
 *
 *    Print a description of each field to the 'fh' file pointer
 */
static void
helpFields(
    FILE               *fh)
{
    if (createStringmaps()) {
        exit(EXIT_FAILURE);
    }

    fprintf(fh, "The following name(s) may be used in the --%s switch.\n",
            appOptions[OPT_FIELDS].name);

    skStringMapPrintDetailedUsage(key_field_map, fh);
}


/*
 *  ok = createStringmaps();
 *
 *    Create the string-map to assist in parsing the --fields switch.
 */
static int
createStringmaps(
    void)
{
    skplugin_field_iter_t  pi_iter;
    skplugin_err_t         pi_err;
    skplugin_field_t      *pi_field;
    sk_stringmap_status_t  sm_err;
    sk_stringmap_entry_t   sm_entry;
    const char           **field_names;
    const char           **name;
    uint32_t               max_id;

    /* initialize string-map of field identifiers */
    if (rwAsciiFieldMapAddDefaultFields(&key_field_map)) {
        skAppPrintErr("Unable to setup fields stringmap");
        return -1;
    }
    max_id = RWREC_PRINTABLE_FIELD_COUNT - 1;

    /* add "icmpTypeCode" field */
    ++max_id;
    if (rwAsciiFieldMapAddIcmpTypeCode(key_field_map, max_id)) {
        skAppPrintErr("Unable to add icmpTypeCode");
        return -1;
    }

    /* add --fields from plug-ins */
    pi_err = skPluginFieldIteratorBind(&pi_iter, SKPLUGIN_APP_CUT, 1);
    if (pi_err != SKPLUGIN_OK) {
        assert(pi_err == SKPLUGIN_OK);
        skAppPrintErr("Unable to bind plugin field iterator");
        return -1;
    }

    while (skPluginFieldIteratorNext(&pi_iter, &pi_field)) {
        skPluginFieldName(pi_field, &field_names);
        ++max_id;

        /* Add fields to the key_field_map */
        for (name = field_names; *name; name++) {
            memset(&sm_entry, 0, sizeof(sm_entry));
            sm_entry.name = *name;
            sm_entry.id = max_id;
            sm_entry.userdata = pi_field;
            skPluginFieldDescription(pi_field, &sm_entry.description);
            sm_err = skStringMapAddEntries(key_field_map, 1, &sm_entry);
            if (sm_err != SKSTRINGMAP_OK) {
                const char *plugin_name;
                skPluginFieldGetPluginName(pi_field, &plugin_name);
                skAppPrintErr(("Plug-in cannot add field named '%s': %s."
                               " Plug-in file: %s"),
                              *name, skStringMapStrerror(sm_err),plugin_name);
                return -1;
            }
        }
    }

    return 0;
}


static void
appPluginGetTitle(
    char               *text_buf,
    size_t              text_buf_size,
    void               *cb_data)
{
    skplugin_field_t *pi_field = (skplugin_field_t*)cb_data;
    const char *title;

    skPluginFieldTitle(pi_field, &title);
    strncpy(text_buf, title, text_buf_size);
    text_buf[text_buf_size-1] = '\0';
}


static int
appPluginGetValue(
    const rwRec        *rwrec,
    char               *text_buf,
    size_t              text_buf_size,
    void               *cb_data)
{
    skplugin_field_t *pi_field = (skplugin_field_t*)cb_data;
    skplugin_err_t pi_err;

    pi_err = skPluginFieldRunRecToTextFn(pi_field, text_buf, text_buf_size,
                                         rwrec, NULL);
    if (pi_err != SKPLUGIN_OK) {
        const char **name;
        skPluginFieldName(pi_field, &name);
        skAppPrintErr(("Plugin-based field %s failed converting to text "
                       "with error code %d"), name[0], pi_err);
        exit(EXIT_FAILURE);
    }
    return 0;
}


/*
 *  status = appAddPluginField(sm_entry);
 *
 *    Add callbacks to the global 'ascii_str' to print a field that
 *    comes from a plug-in.
 *
 *    Returns 0 on success, or -1 for a memory allocation error or if
 *    the plug-in that provides the field numbered 'field_id' cannot
 *    be found.
 */
static int
appAddPluginField(
    const sk_stringmap_entry_t *sm_entry)
{
    skplugin_field_t *pi_field;
    size_t            text_width;
    skplugin_err_t    pi_err;

    pi_field = (skplugin_field_t*)sm_entry->userdata;

    /* Activate the plugin (so cleanup knows about it) */
    pi_err = skPluginFieldActivate(pi_field);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }

    /* Initialize this field */
    pi_err = skPluginFieldRunInitialize(pi_field);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }

    /* get the text width for this field */
    pi_err = skPluginFieldGetLenText(pi_field, &text_width);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }
    if (0 == text_width) {
        const char *title;
        skPluginFieldTitle(pi_field, &title);
        skAppPrintErr("Plug-in field '%s' has a textual width of 0",
                      title);
        return -1;
    }

    return rwAsciiAppendCallbackField(ascii_str, &appPluginGetTitle,
                                      &appPluginGetValue, pi_field,
                                      text_width);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
