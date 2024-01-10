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
**  rwfilterutils.c
**
**  utility routines for rwfilter.c
**
**  Suresh L. Konda
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwfiltersetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silkpython.h>
#include <silk/skprefixmap.h>
#include "rwfilter.h"

/* TYPEDEFS AND DEFINES */



/* LOCAL VARIABLES */

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* fields that get defined just like plugins */
static const struct app_static_plugins_st {
    const char         *name;
    skplugin_setup_fn_t setup_fn;
} app_static_plugins[] = {
    {"addrtype",        skAddressTypesAddFields},
    {"pmapfilter",      skPrefixMapAddFields},
#if SK_ENABLE_PYTHON
    {"silkpython",      skSilkPythonAddFields},
#endif
    {NULL, NULL}        /* sentinel */
};

/* names of plug-ins to attempt to load at startup */
static const char *app_plugin_names[] = {
    /* keep python last in this list so all other filtering happens
     * first.  since python is a full (albeit slow) programming
     * environment, it should have the benefit of being last. */
    SK_PLUGIN_ADD_SUFFIX("ipafilter"),
    NULL /* sentinel */
};



/* OPTION SETUP */

/* these values used to index into following arrays.  need to keep
 * everything in sync */
typedef enum {
    OPT_DRY_RUN,
#if SK_RWFILTER_THREADED
    OPT_THREADS,
#endif
    OPT_MAX_PASS_RECORDS, OPT_MAX_FAIL_RECORDS,
    OPT_PRINT_FILE, OPT_PLUGIN,
    OPT_INPUT_PIPE, OPT_XARGS,
    OPT_PASS_DEST, OPT_FAIL_DEST, OPT_ALL_DEST,
    OPT_PRINT_STAT, OPT_PRINT_VOLUME
} appOptionsEnum;

static struct option appOptions[] = {
    {"dry-run",                 NO_ARG,       0, OPT_DRY_RUN},
#if SK_RWFILTER_THREADED
    {"threads",                 REQUIRED_ARG, 0, OPT_THREADS},
#endif
    {"max-pass-records",        REQUIRED_ARG, 0, OPT_MAX_PASS_RECORDS},
    {"max-fail-records",        REQUIRED_ARG, 0, OPT_MAX_FAIL_RECORDS},
    {"print-filenames",         NO_ARG,       0, OPT_PRINT_FILE},
    {"plugin",                  REQUIRED_ARG, 0, OPT_PLUGIN},

    {"input-pipe",              REQUIRED_ARG, 0, OPT_INPUT_PIPE},
    {"xargs",                   OPTIONAL_ARG, 0, OPT_XARGS},
    {"pass-destination",        REQUIRED_ARG, 0, OPT_PASS_DEST},
    {"fail-destination",        REQUIRED_ARG, 0, OPT_FAIL_DEST},
    {"all-destination",         REQUIRED_ARG, 0, OPT_ALL_DEST},
    {"print-statistics",        OPTIONAL_ARG, 0, OPT_PRINT_STAT},
    {"print-volume-statistics", OPTIONAL_ARG, 0, OPT_PRINT_VOLUME},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    "Parse command line switches but do not process records",
#if SK_RWFILTER_THREADED
    "Use this number of threads. Def $SILK_RWFILTER_THREADS or 1",
#endif
    ("Write at most this many records to\n"
     "\tthe pass-destination; 0 for all.  Def. 0"),
    ("Write at most this many records to\n"
     "\tthe fail-destination; 0 for all.  Def. 0"),
    "Print names of input files during processing. Def. No",
    ("Augment processing with the specified plug-in.\n"
     "\tSwitch may be repeated to load multiple plug-ins. No default"),
    ("Read SiLK flow records from a pipe: 'stdin' or\n"
     "\tpath to named pipe. No default. UNNEEDED AND DEPRECATED: Simply\n"
     "\tprovide 'stdin' or the named pipe as an ordinary argument"),
    ("Read list of input file names from a file or pipe\n"
     "\tpathname or 'stdin'. No default"),
    ("Destination for records which pass the filter(s):\n"
     "\tpathname or 'stdout'. If pathname, it must not exist. No default"),
    ("Destination for records which fail the filter(s):\n"
     "\tpathname or 'stdout'. If pathname, it must not exist. No default"),
    ("Destination for all records regardless of pass/fail:\n"
     "\tpathname or 'stdout'. If pathname, it must not exist. No default"),
    ("Print a count of total flows read to named file.\n"
     "\tIf no pathname provided, use stderr. No default"),
    ("Print count of flows/packets/bytes read\n"
     "\tto named file. If no pathname provided, use stderr. No default"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  filterCheckInputs(int argc);
static int  filterCheckOutputs(void);
static int  filterOpenOutputs(void);
static checktype_t filterPluginCheck(rwRec *rec);
static int  filterSetCheckers(void);


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
#define USAGE_MSG                                                           \
    ("<app-opts> <partition-opts> {<selection-opts> | <inputFiles>}\n"      \
     "\tPartitions SiLK Flow records into one or more 'pass' and/or\n"      \
     "\t'fail' output streams.  The source of the SiLK records can\n"       \
     "\tbe stdin, a named pipe, files listed on the command line, or\n"     \
     "\tfiles selected from the data-store via the selection switches.\n"   \
     "\tThere is no default input or output; these must be specified.\n")

    FILE *fh = USAGE_FH;
    int i;


    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);

    fprintf(fh, "\nGENERAL SWITCHES:\n\n");
    skOptionsDefaultUsage(fh);

    /* print everything before --input-pipe */
    for (i = 0; appOptions[i].name && appOptions[i].val < OPT_INPUT_PIPE; ++i){
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);

    /* print remaining options */
    fprintf(fh, ("\nINPUT/OUTPUT SWITCHES."
                 " An input switch or a SELECTION switch (below) is\n"
                 "\trequired.  At least one output switch is required:\n\n"));
    for ( ; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    /* selection switches */
    fglobUsage(fh);

    /* partitioning switches */
    filterUsage(fh);
    tupleUsage(fh);

    /* switches from plug-ins */
    skPluginOptionsUsage(fh);
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
    int j;
    int input_count;
    int output_count;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char*)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    /* skAppRegister(argv[0]);  -- we do this in main() */
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize variables */
    memset(&dest_type, 0, sizeof(dest_type));

    /* load fglob module */
    if (fglobSetup()) {
        skAppPrintErr("Unable to setup fglob module");
        exit(EXIT_FAILURE);
    }

    /* load filter module */
    if (filterSetup()) {
        skAppPrintErr("Unable to setup filter module");
        exit(EXIT_FAILURE);
    }

    /* load tuple module */
    if (tupleSetup()) {
        skAppPrintErr("Unable to setup tuple module");
        exit(EXIT_FAILURE);
    }

    skPluginSetup(1, SKPLUGIN_APP_FILTER);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }


    /* specify the function that plug-ins should use for opening any
     * input files (e.g., a python script) that they require */
    skPluginSetOpenInputFunction(&filterOpenInputData);

    /* try to load hard-coded plugins */
    for (j = 0; app_static_plugins[j].name; ++j) {
        skPluginAddAsPlugin(app_static_plugins[j].name,
                            app_static_plugins[j].setup_fn);
    }
    for (j = 0; app_plugin_names[j]; ++j) {
        skPluginLoadPlugin(app_plugin_names[j], 0);
    }

#if SK_RWFILTER_THREADED
    {
        /* check the thread count envar */
        char *env;
        uint32_t tc;

        env = getenv(RWFILTER_THREADS_ENVAR);
        if (env && env[0]) {
            if (skStringParseUint32(&tc, env, 0, 0) == 0) {
                thread_count = tc;
            } else {
                thread_count = 1;
            }
        }
    }
#endif  /* SK_RWFILTER_THREADED */

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();
    }

    /* initialize the plug-ins */
    if (skPluginRunInititialize(SKPLUGIN_APP_FILTER) != SKPLUGIN_OK) {
        exit(EXIT_FAILURE);
    }

#if SK_RWFILTER_THREADED
    /* do not use threading when the plug-in doesn't support
     * it */
    if ((thread_count > 1) && !skPluginIsThreadSafe()) {
        thread_count = 1;
    }
#endif  /* SK_RWFILTER_THREADED */

    /* Check that there is one and only one source of input to process */
    input_count = filterCheckInputs(argc);
    if (input_count < 0) {
        /* fatal error. msg already printed */
        exit(EXIT_FAILURE);
    } else if (input_count > 1) {
        skAppPrintErr("Multiple input sources were specified\n"
                      "\tInput must come from only one of --input-pipe,"
                      " --xargs, file names on\n"
                      "\tthe command line,"
                      " or a combination of the file selection switches");
        skAppUsage();
    } else if (input_count == 0) {
        skAppPrintErr("No input was specified.\n"
                      "\tNo file selection switches were given,"
                      " neither --input-pipe nor --xargs\n"
                      "\twas specified, and no files are present on the"
                      " command line");
        skAppUsage();
    }

    /* check that the user asked for some output */
    output_count = filterCheckOutputs();
    if (output_count < 0) {
        /* fatal error. msg already printed */
        exit(EXIT_FAILURE);
    }
    if (output_count == 0) {
        skAppPrintErr("No output(s) specified");
        skAppUsage();
    }

    /* Check whether we have a filtering rule--either built in or from
     * a plugin.  If we don't, complain unless the --all-dest switch
     * was given */
    checker_count = filterSetCheckers();
    if (checker_count < 0) {
        /* fatal error */
        exit(EXIT_FAILURE);
    }
    if (checker_count == 0) {
        if (dest_type[DEST_PASS].dest_list) {
            skAppPrintErr("Must specify partitioning rules when using --%s",
                          appOptions[OPT_PASS_DEST].name);
            skAppUsage();
        }
        if (dest_type[DEST_FAIL].dest_list) {
            skAppPrintErr("Must specify partitioning rules when using --%s",
                          appOptions[OPT_FAIL_DEST].name);
            skAppUsage();
        }
        if (NULL == dest_type[DEST_ALL].dest_list) {
            skAppPrintErr(("Must specify partitioning rules when using --%s"
                           " without --%s"),
                          (print_volume_stats
                           ? appOptions[OPT_PRINT_VOLUME].name
                           : appOptions[OPT_PRINT_STAT].name),
                          appOptions[OPT_ALL_DEST].name);
            skAppUsage();
        }
    }


    /* open the output streams, unless this is a "dry-run" */
    if (NULL == dryrun_fp) {
        if (filterOpenOutputs()) {
            /* fatal error. msg already printed */
            exit(EXIT_FAILURE);
        }
    }

    /* Try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names.  If fglob
     * is active, it will require the configuration file. */
    sksiteConfigure(0);

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
    char errbuf[2 * PATH_MAX];
    destination_t *dest;
    destination_t **end;
    dest_type_t *d_type;
    int dest_id;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_PASS_DEST:
      case OPT_FAIL_DEST:
      case OPT_ALL_DEST:
        /* an output stream */
        dest_id = opt_index - OPT_PASS_DEST;
        assert(dest_id >= 0 && dest_id < DESTINATION_TYPES);

        dest = (destination_t*)calloc(1, sizeof(destination_t));
        if (dest == NULL) {
            skAppPrintOutOfMemory(NULL);
            return 1;
        }
        if ((rv = skStreamCreate(&dest->stream, SK_IO_WRITE,
                                 SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(dest->stream, opt_arg)))
        {
            skStreamLastErrMessage(dest->stream, rv, errbuf, sizeof(errbuf));
            skAppPrintErr("Unable to create %s to '%s': %s",
                          appOptions[opt_index].name, opt_arg, errbuf);
            skStreamDestroy(&dest->stream);
            free(dest);
            return 1;
        }

        d_type = &dest_type[dest_id];
        ++d_type->count;
        end = &d_type->dest_list;
        while (*end != NULL) {
            end = &((*end)->next);
        }
        *end = dest;
        break;

#if SK_RWFILTER_THREADED
      case OPT_THREADS:
        rv = skStringParseUint32(&thread_count, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;
#endif  /* SK_RWFILTER_THREADED */

      case OPT_INPUT_PIPE:
        /*
         *  input-pipe. Delay check for multiple inputs sources till all
         *  options have been parsed
         */
        if (input_pipe) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        input_pipe = opt_arg;
        break;

      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1)) {
            skAppPrintErr("Fatal error loading plugin '%s'", opt_arg);
            return 1;
        }
        break;

      case OPT_DRY_RUN:
        dryrun_fp = DRY_RUN_FH;
        break;

      case OPT_PRINT_FILE:
        filenames_fp = PRINT_FILENAMES_FH;
        break;

      case OPT_PRINT_VOLUME:
        print_volume_stats = 1;
        /* FALLTHROUGH */
      case OPT_PRINT_STAT:
        if (print_stat) {
            skAppPrintErr("May only specified one of --%s or --%s",
                          appOptions[OPT_PRINT_STAT].name,
                          appOptions[OPT_PRINT_VOLUME].name);
            return 1;
        }
        if ((rv = skStreamCreate(&print_stat, SK_IO_WRITE, SK_CONTENT_TEXT))
            || (rv = skStreamBind(print_stat, (opt_arg ? opt_arg : "stderr"))))
        {
            skStreamLastErrMessage(print_stat, rv, errbuf, sizeof(errbuf));
            skAppPrintErr("Unable to create %s writing to '%s': %s",
                          appOptions[opt_index].name,
                          (opt_arg ? opt_arg : "stderr"), errbuf);
            skStreamDestroy(&print_stat);
            return 1;
        }
        break;

      case OPT_MAX_PASS_RECORDS:
        rv = skStringParseUint64(&(dest_type[DEST_PASS].max_records),
                                 opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MAX_FAIL_RECORDS:
        rv = skStringParseUint64(&(dest_type[DEST_FAIL].max_records),
                                 opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_XARGS:
        /* a file containing a list of file names */
        if (xargs) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&xargs, SK_IO_READ, SK_CONTENT_TEXT))
            || (rv = skStreamBind(xargs, (opt_arg ? opt_arg : "stdin"))))
        {
            skStreamLastErrMessage(xargs, rv, errbuf, sizeof(errbuf));
            skAppPrintErr("Unable to create %s reading '%s': %s",
                          appOptions[opt_index].name,
                          (opt_arg ? opt_arg : "stdin"), errbuf);
            skStreamDestroy(&xargs);
            return 1;
        }
        break;
    } /* switch */

    return 0;                     /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
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
    char errbuf[2 * PATH_MAX];
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    skPluginRunCleanup(SKPLUGIN_APP_FILTER);
    skPluginTeardown();

    tupleTeardown();
    filterTeardown();
    skOptionsNotesTeardown();
    fglobTeardown();

    closeAllDests();

    /* close stats */
    if (print_stat) {
        rv = skStreamClose(print_stat);
        switch (rv) {
          case SKSTREAM_OK:
          case SKSTREAM_ERR_NOT_OPEN:
          case SKSTREAM_ERR_CLOSED:
            break;
          default:
            skStreamLastErrMessage(print_stat, rv, errbuf, sizeof(errbuf));
            skAppPrintErr("Error closing %s stream '%s': %s",
                          (print_volume_stats
                           ? appOptions[OPT_PRINT_VOLUME].name
                           : appOptions[OPT_PRINT_STAT].name),
                          skStreamGetPathname(print_stat), errbuf);
            break;
        }
        skStreamDestroy(&print_stat);
    }

    /* close xargs stream */
    if (xargs) {
        skStreamDestroy(&xargs);
    }


    skAppUnregister();
}


/*
 *  ignoreSigPipe();
 *
 *    Ignore SIGPIPE.
 */
void
filterIgnoreSigPipe(
    void)
{
    /* install a signal handler to ignore SIGPIPE */
    struct sigaction act;

    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGPIPE, &act, NULL) < 0) {
        skAppPrintErr("Cannot register handler for SIGPIPE");
    }
}


/*
 *  stream_count = filterCheckInputs(argc)
 *
 *    Do basic checks for the input, and return the number of inputs
 *    selected from among: command-line files, fglob options, piped
 *    input, or xargs.  Returns -1 on error, such as trying to read
 *    binary records from a TTY.
 */
static int
filterCheckInputs(
    int                 argc)
{
    unsigned int count = 0;
    int rv;

    /* Check for file names on command line */
    if (arg_index < argc) {
        ++count;
    }

    /* the input-pipe must be 'stdin' or it must be an existing FIFO.
     * If 'stdin', stdin must not be a TTY, since we expect binary. */
    if (input_pipe) {
        ++count;
        if ((0 == strcmp(input_pipe, "stdin"))
            || (0 == strcmp(input_pipe, "-")))
        {
            if (FILEIsATty(stdin)) {
                skAppPrintErr(("Invalid %s '%s':"
                               " Will not read binary data from a terminal"),
                              appOptions[OPT_INPUT_PIPE].name, input_pipe);
                return -1;
            }
        } else if ( !skFileExists(input_pipe)) {
            skAppPrintErr(("Invalid %s '%s':"
                           " File does not exist"),
                          appOptions[OPT_INPUT_PIPE].name, input_pipe);
            return -1;
        } else if ( !isFIFO(input_pipe)) {
            skAppPrintErr(("Invalid %s '%s':"
                           " File is not named pipe"),
                          appOptions[OPT_INPUT_PIPE].name, input_pipe);
            return -1;
        }
    }

    /* check if an --xargs value was given */
    if (xargs) {
        ++count;
    }

    if (count == 1) {
        /* Let any traditional fglob options work as filters. */
        if (filterGetFGlobFilters()) {
            return -1;
        }
    }

    /* Check if fglob args were given */
    rv = fglobValid();
    if (rv == -1) {
        /* error with fglob options */
        return -1;
    }
    if (rv) {
        ++count;
    }

    return (int)count;
}


/*
 *  stream_count = filterCheckOutputs()
 *
 *    Count the number of output streams, and do basic checks for the
 *    outputs, such as making certain only one stream uses stdout.
 *
 *    Returns the number of output streams requested, or -1 on error.
 */
static int
filterCheckOutputs(
    void)
{
    destination_t *dest;
    int count = 0;
    int stdout_used = 0;
    int dest_id;

    /* Basic checks: Only allow one output stream to use 'stdout'.
     * Make certain no one uses 'stderr'. */
    for (dest_id = 0; dest_id < DESTINATION_TYPES; ++dest_id) {
        for (dest = dest_type[dest_id].dest_list;
             dest != NULL;
             dest = dest->next)
        {
            ++count;
            if (strcmp("stderr", skStreamGetPathname(dest->stream)) == 0) {
                skAppPrintErr(("Invalid %s '%s': Will not write"
                               " binary data to the standard error"),
                              appOptions[dest_id+OPT_PASS_DEST].name,
                              skStreamGetPathname(dest->stream));
                return -1;
            }
            if ((strcmp("stdout", skStreamGetPathname(dest->stream)) == 0)
                || (strcmp("-", skStreamGetPathname(dest->stream)) == 0))
            {
                if (stdout_used) {
                    skAppPrintErr("Invalid %s '%s':"
                                  " The standard output is already allocated",
                                  appOptions[dest_id+OPT_PASS_DEST].name,
                                  skStreamGetPathname(dest->stream));
                    return -1;
                }
                stdout_used = 1;
            }
        }
    }

    /* Check the STATISTICS stream: increment the output count and
     * check whether stdout is already used if the stats are going to
     * stdout. */
    if (print_stat) {
        ++count;
        if (stdout_used
            && ((strcmp(skStreamGetPathname(print_stat), "stdout") == 0)
                || (strcmp(skStreamGetPathname(print_stat), "-") == 0)))
        {
            skAppPrintErr(("Invalid %s '%s':"
                           " The standard output is already allocated"),
                          (print_volume_stats
                           ? appOptions[OPT_PRINT_VOLUME].name
                           : appOptions[OPT_PRINT_STAT].name),
                          skStreamGetPathname(print_stat));
            return -1;
        }
    }

    return count;
}


/*
 *  status = filterOpenOutputs()
 *
 *    Open all output streams.  Return 0 on success, or -1 on failure.
 */
static int
filterOpenOutputs(
    void)
{
    destination_t *dest = NULL;
    int dest_id;
    int rv = SKSTREAM_OK;

    /* open the STATISTICS stream */
    if (print_stat) {
        rv = skStreamOpen(print_stat);
        if (rv) {
            skStreamPrintLastErr(print_stat, rv, &skAppPrintErr);
            return -1;
        }
    }



    /* Open all the SiLK Flow output streams */
    for (dest_id = 0; dest_id < DESTINATION_TYPES; ++dest_id) {

        for (dest = dest_type[dest_id].dest_list;
             dest != NULL;
             dest = dest->next)
        {
            /* set compression level */
            rv = (skHeaderSetCompressionMethod(
                      skStreamGetSilkHeader(dest->stream), comp_method));
            if (rv) {
                goto DEST_ERROR;
            }
            rv = skStreamOpen(dest->stream);
            if (rv) {
                goto DEST_ERROR;
            }
        }
    }

    return 0;

  DEST_ERROR:
    skStreamPrintLastErr(dest->stream, rv, &skAppPrintErr);
    closeAllDests();
    return -1;
}


/*
 *  count = filterSetCheckers();
 *
 *    Set the array of function pointers to the pass/fail checking
 *    routines, and return the number of pointers that were set.  If a
 *    check-routine is a plug-in, call the plug-in's initialize()
 *    routine.  If the initialize() routine fails, return -1.  A
 *    return code of 0 means no filtering rules were specified.
 */
static int
filterSetCheckers(
    void)
{
    int count = 0;
    int rv;

    if (filterGetCheckCount() > 0) {
        checker[count] = (checktype_t (*)(rwRec*))filterCheck;
        ++count;
    }

    rv = tupleGetCheckCount();
    if (rv == -1) {
        return -1;
    }
    if (rv) {
        checker[count] = (checktype_t (*)(rwRec*))tupleCheck;
        ++count;
    }

    if (skPluginFiltersRegistered()) {
        checker[count] = &filterPluginCheck;
        ++count;
    }

    return count;
}


/*
 *  result = filterPluginCheck(rec);
 *
 *    Runs plugin rwfilter functions, and converts the result to an
 *    RWF enum.
 */
static checktype_t
filterPluginCheck(
    rwRec              *rec)
{
    skplugin_err_t err = skPluginRunFilterFn(rec, NULL);
    switch (err) {
      case SKPLUGIN_FILTER_PASS:
        return RWF_PASS;
      case SKPLUGIN_FILTER_PASS_NOW:
        return RWF_PASS_NOW;
      case SKPLUGIN_FILTER_IGNORE:
        return RWF_IGNORE;
      case SKPLUGIN_FILTER_FAIL:
        return RWF_FAIL;
      default:
        skAppPrintErr("Plugin-based filter failed with error code %d", err);
        exit(EXIT_FAILURE);
    }
}


/*
 *  status = filterOpenInputData(&stream, content_type, filename);
 *
 *    This is the function that plug-ins should use for opening any
 *    input files they use.  The function opens 'filename', a file
 *    having the specified 'content_type', and fills 'stream' with a
 *    handle to the file.  Returns 0 if the file was successfully
 *    opened, and -1 if the file could not be opened.
 */
int
filterOpenInputData(
    skstream_t        **stream,
    skcontent_t         content_type,
    const char         *filename)
{
    skstream_t *s;
    int rv;


    if ((rv = skStreamCreate(&s, SK_IO_READ, content_type))
        || (rv = skStreamBind(s, filename))
        || (rv = skStreamOpen(s)))
    {
        skStreamPrintLastErr(s, rv, &skAppPrintErr);
        skStreamDestroy(&s);
        return -1;
    }
    *stream = s;
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
