/*
** Copyright (C) 2001-2017 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
** See license information in ../../LICENSE.txt
** @OPENSOURCE_LICENSE_END@
*/

/*
**  rwcombinesetup.c
**
**    Options processing and additional set-up for rwcombine.  See
**    rwcombine.c for implementation details.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcombinesetup.c 57cd46fed37f 2017-03-13 21:54:02Z mthomas $");

#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include "rwcombine.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to send --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* available actions */
static const sk_stringmap_entry_t actions[] = {
    {"all",       0, NULL,
     "perform all the following actions"},
    {"timeout",   1, NULL,
     "combine flows where timeout flags are set"},
    SK_STRINGMAP_SENTINEL
};

/* available fields; rwAsciiFieldMapAddDefaultFields() fills this */
static sk_stringmap_t *field_map = NULL;

/* input checker */
static sk_options_ctx_t *optctx = NULL;

/* non-zero if we are shutting down due to a signal; controls whether
 * errors are printed in appTeardown(). */
static int caught_signal = 0;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* the string containing the list of fields to ignore */
static const char *ignore_fields = NULL;

/* temporary directory */
static const char *temp_directory = NULL;

/* read-only cache of argc and argv used for writing header to output
 * file */
static int pargc;
static char **pargv;


/* OPTIONS */

typedef enum {
    OPT_HELP_FIELDS,
    OPT_ACTIONS,
    OPT_IGNORE_FIELDS,
    OPT_MAX_IDLE_TIME,
    OPT_PRINT_STATISTICS,
    OPT_OUTPUT_PATH,
    OPT_BUFFER_SIZE
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"actions",             REQUIRED_ARG, 0, OPT_ACTIONS},
    {"ignore-fields",       REQUIRED_ARG, 0, OPT_IGNORE_FIELDS},
    {"max-idle-time",       REQUIRED_ARG, 0, OPT_MAX_IDLE_TIME},
    {"print-statistics",    OPTIONAL_ARG, 0, OPT_PRINT_STATISTICS},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"buffer-size",         REQUIRED_ARG, 0, OPT_BUFFER_SIZE},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each possible field and exit. Def. no",
    ("Select how input records should be combined. Def. all.\n"
     "\tAvailable actions:"),
    ("Ignore this comma separated list of field(s) when\n"
     "\tcomparing records---that is, treat these fields as if identical:"),
    ("Do not combine flows that are idle for more than\n"
     "\tthis number of seconds (may be fractional). Def. no limit"),
    ("Print statistics regarding number of flows combined\n"
     "\tand idle times to the named file or stream or to 'stderr' when no\n"
     "\targument provided to switch. Def. no"),
    ("Write the combined SiLK Flow records to this location\n"
     "\t(a file, named pipe, or '-' or 'stdout'). Def. stdout"),
    NULL, /* generated dynamically */
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void appHandleSignal(int sig);
static int  parseActions(const char *actions_string);
static int  parseFields(const char *fields_string);
static void helpFields(FILE *fh);
static int
setSortFields(
    uint32_t            ignore_count,
    uint32_t           *ignore_field_ids);



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
     "\tRead SiLK Flow records from FILES given on command line or from\n"    \
     "\tthe standard input, create a single record from flows that were\n"    \
     "\tclosed due to a timeout or were a continuation of a timed-out\n"      \
     "\tflow, and write the combined flows and the unmodified flows to\n"     \
     "\tthe named output path or to the standard output.\n")

    FILE *fh = USAGE_FH;
    const sk_stringmap_entry_t *e;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_IGNORE_FIELDS:
            /* Dynamically build the help */
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(field_map, fh, 4);
            break;
          case OPT_ACTIONS:
            fprintf(fh, "%s\n", appHelp[i]);
            for (e = actions; e->name; ++e) {
                if (e->userdata) {
                    fprintf(fh, "\t  %-8s - %s\n",
                            e->name, (const char*)e->userdata);
                }
            }
            break;
          case OPT_BUFFER_SIZE:
            fprintf(fh,
                    ("Attempt to allocate this much memory for the in-core\n"
                     "\tbuffer, in bytes."
                     "  Append k, m, g, for kilo-, mega-, giga-bytes,\n"
                     "\trespectively. Range: %" SK_PRIuZ "-%" SK_PRIuZ
                     ". Def. " DEFAULT_BUFFER_SIZE "\n"),
                    MINIMUM_BUFFER_SIZE, MAXIMUM_BUFFER_SIZE);
            break;
          default:
            /* Simple help text from the appHelp array */
            assert(appHelp[i]);
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skOptionsTempDirUsage(fh);
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
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
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close and destroy output */
    if (out_stream) {
        rv = skStreamDestroy(&out_stream);
        if (rv && !caught_signal) {
            /* only print error when not in signal handler */
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        out_stream = NULL;
    }

    if (print_statistics) {
        skStreamDestroy(&print_statistics);
    }

    /* remove any temporary files */
    skTempFileTeardown(&tmpctx);

    /* free variables */
    if (field_map) {
        skStringMapDestroy(field_map);
    }

    skOptionsNotesTeardown();
    skOptionsCtxDestroy(&optctx);
    skAppUnregister();
}


/*
 *  appExit(status)
 *
 *  Exit the application with the given status.
 */
void
appExit(
    int                 status)
{
    appTeardown();
    exit(status);
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
    uint64_t tmp64;
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
    rv = skStringParseHumanUint64(&tmp64, DEFAULT_BUFFER_SIZE,SK_HUMAN_NORMAL);
    assert(0 == rv);
    buffer_size = tmp64;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES);

    /* store a copy of the arguments */
    pargc = argc;
    pargv = argv;

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsTempDirRegister(&temp_directory)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        appExit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appExit(EXIT_FAILURE);
    }

    /* initialize string-map of field identifiers.  Remove any fields
     * that do not correspond to a field on the actual rwRec */
    if (rwAsciiFieldMapAddDefaultFields(&field_map)) {
        skAppPrintErr("Unable to setup fields stringmap");
        appExit(EXIT_FAILURE);
    }
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_STIME);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ETIME);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ELAPSED);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_STIME_MSEC);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ETIME_MSEC);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ELAPSED_MSEC);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ICMP_TYPE);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ICMP_CODE);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_PKTS);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_BYTES);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_FLAGS);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_INIT_FLAGS);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_REST_FLAGS);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_TCP_STATE);

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* parse the ignore fields list and set the sort-fields */
    if (ignore_fields) {
        if (parseFields(ignore_fields)) {
            appExit(EXIT_FAILURE);
        }
    } else if (setSortFields(0, NULL)) {
        appExit(EXIT_FAILURE);
    }

    /* verify that the temp directory is valid */
    if (skTempFileInitialize(&tmpctx, temp_directory, NULL, &skAppPrintErr)) {
        appExit(EXIT_FAILURE);
    }

    /* Check for an output stream; or default to stdout  */
    if (out_stream == NULL) {
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, "-")))
        {
            skStreamPrintLastErr(out_stream, rv, NULL);
            skStreamDestroy(&out_stream);
            appExit(EXIT_FAILURE);
        }
    }

    /* set the compmethod on the header */
    rv = skHeaderSetCompressionMethod(skStreamGetSilkHeader(out_stream),
                                      comp_method);
    if (rv) {
        skAppPrintErr("Error setting header on %s: %s",
                      skStreamGetPathname(out_stream), skHeaderStrerror(rv));
        appExit(EXIT_FAILURE);
    }

    /* open statistics */
    if (print_statistics) {
        rv = skStreamOpen(print_statistics);
        if (rv) {
            skStreamPrintLastErr(print_statistics, rv, NULL);
            skAppPrintErr("Could not open output file.  Exiting.");
            appExit(EXIT_FAILURE);
        }
    }

    /* open output */
    rv = skStreamOpen(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, NULL);
        skAppPrintErr("Could not open output file.  Exiting.");
        appExit(EXIT_FAILURE);
    }

    /* set signal handler to clean up temp files on SIGINT, SIGTERM, etc */
    if (skAppSetSignalHandler(&appHandleSignal)) {
        appExit(EXIT_FAILURE);
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
    uint64_t tmp64;
    double d;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_ACTIONS:
        if (parseActions(opt_arg)) {
            return 1;
        }
        break;

      case OPT_IGNORE_FIELDS:
        if (ignore_fields) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        ignore_fields = opt_arg;
        break;

      case OPT_MAX_IDLE_TIME:
        rv = skStringParseDouble(&d, opt_arg, 0.0, ((double)INT64_MAX / 1e3));
        if (rv) {
            goto PARSE_ERROR;
        }
        /* convert seconds to milliseconds */
        max_idle_time = (int64_t)(d * 1e3);
        break;

      case OPT_PRINT_STATISTICS:
        if (print_statistics) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(
                 &print_statistics, SK_IO_WRITE, SK_CONTENT_TEXT))
            || (rv = skStreamBind(
                    print_statistics, (opt_arg ? opt_arg : "stderr"))))
        {
            skStreamPrintLastErr(print_statistics, rv, &skAppPrintErr);
            skStreamDestroy(&print_statistics);
            skAppPrintErr("Invalid %s '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_OUTPUT_PATH:
        /* check for switch given multiple times */
        if (out_stream) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            skStreamDestroy(&out_stream);
            return 1;
        }
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, opt_arg)))
        {
            skStreamPrintLastErr(out_stream, rv, NULL);
            return 1;
        }
        break;

      case OPT_BUFFER_SIZE:
        rv = skStringParseHumanUint64(&tmp64, opt_arg, SK_HUMAN_NORMAL);
        if (rv) {
            goto PARSE_ERROR;
        }
        if ((tmp64 < MINIMUM_BUFFER_SIZE)
            || (tmp64 > MAXIMUM_BUFFER_SIZE))
        {
            skAppPrintErr(
                ("The --%s value must be between %" SK_PRIuZ " and %" SK_PRIuZ),
                appOptions[opt_index].name,
                MINIMUM_BUFFER_SIZE, MAXIMUM_BUFFER_SIZE);
            return 1;
        }
        buffer_size = tmp64;
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
 *  appHandleSignal(signal_value)
 *
 *    Call appExit() to exit the program.  If signal_value is SIGPIPE,
 *    close cleanly; otherwise print a message that we've caught the
 *    signal and exit with EXIT_FAILURE.
 */
static void
appHandleSignal(
    int                 sig)
{
    caught_signal = 1;

    if (sig == SIGPIPE) {
        /* we get SIGPIPE if something downstream, like rwcut, exits
         * early, so don't bother to print a warning, and exit
         * successfully */
        appExit(EXIT_SUCCESS);
    } else {
        skAppPrintErr("Caught signal..cleaning up and exiting");
        appExit(EXIT_FAILURE);
    }
}


/*
 *  status = parseFields(fields_string);
 *
 *    Parse the user's option for the --actions switch to verify it is valid.
 *
 *    Since rwcombine currently does a single task there is nothing to set.
 *
 *    Return 0 on success; -1 on failure.
 */
static int
parseActions(
    const char *actions_string)
{
    sk_stringmap_t *action_map = NULL;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    char *errmsg;
    int do_all;
    int do_other;
    int rv = -1;

    /* create a stringmap of the available actions */
    if (SKSTRINGMAP_OK != skStringMapCreate(&action_map)) {
        skAppPrintErr("Unable to create action string-map");
        goto END;
    }
    if (skStringMapAddEntries(action_map, -1, actions) != SKSTRINGMAP_OK){
        skAppPrintErr("Unable to fill action string-map");
        goto END;
    }

    if (skStringMapParse(action_map, actions_string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_ACTIONS].name, errmsg);
        goto END;
    }

    do_all = do_other = 0;
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (entry->id == actions[0].id) {
            do_all = 1;
        } else {
            do_other = 1;
        }
        if (do_all && do_other) {
            skAppPrintErr("Invalid %s: May not mix '%s' and other selections",
                          appOptions[OPT_ACTIONS].name, actions[0].name);
            goto END;
        }
    }

    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    if (action_map) {
        skStringMapDestroy(action_map);
    }
    return rv;
}


/*
 *  status = parseFields(fields_string);
 *
 *    Parse the user's option for the --ignore-fields switch and then
 *    fill in the globals sort_fields[] and num_fields.  Return 0 on
 *    success; -1 on failure.
 */
static int
parseFields(
    const char         *field_string)
{
#define COMBINE_MAX_FIELDS  256
    uint32_t ignore_field_ids[COMBINE_MAX_FIELDS];
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    uint32_t ignore_count = 0;
    char *errmsg;
    int rv = -1;

    /* only visit this function once */
    assert(0 == num_fields);

    /* parse the input */
    if (skStringMapParse(field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_IGNORE_FIELDS].name, errmsg);
        goto END;
    }

    /* fill the array of IDs */
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (ignore_count >= COMBINE_MAX_FIELDS) {
            skAppPrintErr("Only %d ignore-fields are supported",
                          COMBINE_MAX_FIELDS);
            goto END;
        }
        ignore_field_ids[ignore_count] = entry->id;
        ++ignore_count;
    }

    /* set the sort fields ignoring some fields */
    if (setSortFields(ignore_count, ignore_field_ids)) {
        goto END;
    }

    /* success */
    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    return rv;
}


/*
 *  status = setSortFields(count, list);
 *
 *    Add the fields defined in 'field_map' that are NOT listed in
 *    'list' to the global 'sort_fields'.  Update 'num_fields' with
 *    the number of fields to sort over.  The parameter 'count' lists
 *    the number of fields in 'list'.  'count' may be zero.  Any
 *    fields related to delta.* fields should be last in the sort
 *    list.
 */
static int
setSortFields(
    uint32_t            ignore_count,
    uint32_t           *ignore_field_ids)
{
    uint32_t i, j;
    int ignore;

    for (i = 0; i < RWREC_PRINTABLE_FIELD_COUNT; ++i) {
        /* are we concerned with this id? */
        if (NULL == skStringMapGetFirstName(field_map, i)) {
            /* no entries with this id.  ignore it */
            continue;
        }

        ignore = 0;

        /* did the user request we ignore it? */
        for (j = 0; j < ignore_count; ++j) {
            if (i == ignore_field_ids[j]) {
                ignore = 1;
                break;
            }
            /* handle the fields that are "linked" */
            if ((i == RWREC_FIELD_FTYPE_CLASS
                 && ignore_field_ids[j] == RWREC_FIELD_FTYPE_TYPE)
                || (i == RWREC_FIELD_FTYPE_TYPE
                    && ignore_field_ids[j] == RWREC_FIELD_FTYPE_CLASS))
            {
                ignore = 1;
                break;
            }
        }

        if (!ignore) {
            /* field was not ignored and no delta for it; add it */
            sort_fields[num_fields] = i;
            ++num_fields;
        }
    }

    sort_fields[num_fields] = RWREC_FIELD_STIME;
    ++num_fields;
    sort_fields[num_fields] = RWREC_FIELD_ELAPSED;
    ++num_fields;

    return 0;
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
    fprintf(fh,
            ("The following names may be used in the --%s switch. Names are\n"
             "case-insensitive and may be abbreviated to the shortest"
             " unique prefix.\n"),
            appOptions[OPT_IGNORE_FIELDS].name);

    skStringMapPrintDetailedUsage(field_map, fh);
}


/*
 *  int = appNextInput(&stream);
 *
 *    Fill 'stream' with the next input file to read.  Return 0 if
 *    'stream' was successfully opened or 1 if there are no more input
 *    files.  Return -1 if a file cannot be opened.
 */
int
appNextInput(
    skstream_t        **stream)
{
    static int first_file = 1;
    int retval;
    int rv;

    retval = skOptionsCtxNextSilkFile(optctx, stream, &skAppPrintErr);
    if (0 == retval && 1 == first_file) {
        /* since rwcombine may begin to write output immediately, the
         * output file may only contain the information from the
         * initial input file */
        first_file = 0;

        /* copy annotations and command line entries from the input to
         * the output */
        if ((rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                      skStreamGetSilkHeader(*stream),
                                      SK_HENTRY_INVOCATION_ID))
            || (rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                         skStreamGetSilkHeader(*stream),
                                         SK_HENTRY_ANNOTATION_ID)))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            retval = -1;
        }
        /* add final information to header */
        if ((rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream),
                                        1, pargc, pargv))
            || (rv = skOptionsNotesAddToStream(out_stream)))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            retval = -1;
        }
    }

    return retval;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
