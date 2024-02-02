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
**  rwsort reads SiLK Flow Records from the standard input or from
**  named files and sorts them on one or more user-specified fields.
**
**  See rwsort.c for implementation details.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsortsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silkpython.h>
#include <silk/skcountry.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include "rwsort.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to send --help output */
#define USAGE_FH stdout

/* Where to write filenames if --print-file specified */
#define PRINT_FILENAMES_FH  stderr


/* LOCAL VARIABLES */

/* the text the user entered for the --fields switch */
static char *fields_arg = NULL;

/* available key fields; rwAsciiFieldMapAddDefaultFields() fills this */
static sk_stringmap_t *key_field_map = NULL;

/* handle input streams */
static sk_options_ctx_t *optctx = NULL;

/* whether to print names of files as they are opened; 0 == no */
static int print_filenames = 0;

/* non-zero if we are shutting down due to a signal; controls whether
 * errors are printed in appTeardown(). */
static int caught_signal = 0;

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
    {"ccfilter",        skCountryAddFields},
    {"pmapfilter",      skPrefixMapAddFields},
#if SK_ENABLE_PYTHON
    {"silkpython",      skSilkPythonAddFields},
#endif
    {NULL, NULL}        /* sentinel */
};

/* names of plug-ins to attempt to load at startup */
static const char *app_plugin_names[] = {
    NULL /* sentinel */
};

/* temporary directory */
static const char *temp_directory = NULL;

/* read-only cache of argc and argv used for writing header to output
 * file */
static int pargc;
static char **pargv;


/* OPTIONS */

typedef enum {
    OPT_HELP_FIELDS,
    OPT_FIELDS,
    OPT_REVERSE,
    OPT_PRINT_FILENAMES,
    OPT_OUTPUT_PATH,
    OPT_PLUGIN,
    OPT_PRESORTED_INPUT,
    OPT_SORT_BUFFER_SIZE
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {"reverse",             NO_ARG,       0, OPT_REVERSE},
    {"print-filenames",     NO_ARG,       0, OPT_PRINT_FILENAMES},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"plugin",              REQUIRED_ARG, 0, OPT_PLUGIN},
    {"presorted-input",     NO_ARG,       0, OPT_PRESORTED_INPUT},
    {"sort-buffer-size",    REQUIRED_ARG, 0, OPT_SORT_BUFFER_SIZE},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each possible field and exit. Def. no",
    ("Use these fields as the sorting key. Specify fields as a\n"
     "\tcomma-separated list of names, IDs, and/or ID-ranges"),
    "Reverse the sort order. Def. No",
    "Print names of input files as they are opened. Def. No",
    ("Write sorted output to this stream or file. Def. stdout"),
    ("Load given plug-in to add fields. Switch may be repeated to\n"
     "\tload multiple plug-ins. Def. None"),
    ("Assume input has been presorted using\n"
     "\trwsort invoked with the exact same --fields value. Def. No"),
    NULL, /* generated dynamically */
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void appHandleSignal(int sig);
static int  parseFields(const char *fields_string);
static void helpFields(FILE *fh);
static int  createStringmaps(void);



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
    ("--fields=<FIELDS> [SWITCHES] [FILES]\n"                                 \
     "\tRead SiLK Flow records, sort them by the specified FIELD(S), and\n"   \
     "\twrite the records to the named output path or to the standard\n"      \
     "\toutput.  When no FILES are given on command line, flows are read\n"   \
     "\tfrom the standard input.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    /* Create the string map for --fields */
    createStringmaps();

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_FIELDS:
            /* Dynamically build the help */
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(key_field_map, fh, 4);
            break;
          case OPT_SORT_BUFFER_SIZE:
            fprintf(fh,
                    ("Attempt to allocate this much memory for the sort\n"
                     "\tbuffer, in bytes."
                     "  Append k, m, g, for kilo-, mega-, giga-bytes,\n"
                     "\trespectively. Range: %" SK_PRIuZ "-%" SK_PRIuZ
                     ". Def. " DEFAULT_SORT_BUFFER_SIZE "\n"),
                    MINIMUM_SORT_BUFFER_SIZE, MAXIMUM_SORT_BUFFER_SIZE);
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

    /* close and destroy output */
    if (out_stream) {
        rv = skStreamDestroy(&out_stream);
        if (rv && !caught_signal) {
            /* only print error when not in signal handler */
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        out_stream = NULL;
    }

    /* remove any temporary files */
    skTempFileTeardown(&tmpctx);

    /* plug-in teardown */
    skPluginRunCleanup(SKPLUGIN_APP_SORT);
    skPluginTeardown();

    /* free variables */
    if (sort_fields != NULL) {
        free(sort_fields);
    }
    if (key_field_map) {
        skStringMapDestroy(key_field_map);
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
    int j;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* Initialize variables */
    memset(key_fields, 0, sizeof(key_fields));
    rv = skStringParseHumanUint64(&tmp64, DEFAULT_SORT_BUFFER_SIZE,
                                  SK_HUMAN_NORMAL);
    assert(0 == rv);
    sort_buffer_size = tmp64;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_INPUT_PIPE);

    /* store a copy of the arguments */
    pargc = argc;
    pargv = argv;

    /* Initialize plugin library */
    skPluginSetup(1, SKPLUGIN_APP_SORT);

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
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* create the --fields */
    if (createStringmaps()) {
        appExit(EXIT_FAILURE);
    }

    /* Parse the fields argument */
    if (fields_arg != NULL) {
        if (parseFields(fields_arg)) {
            exit(EXIT_FAILURE);
        }
    }

    /* Make sure the user specified at least one field */
    if (num_fields == 0) {
        skAppPrintErr("The sorting key (--%s switch) was not given",
                      appOptions[OPT_FIELDS].name);
        skAppUsage();           /* never returns */
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
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_FIELDS:
        assert(opt_arg);
        if (fields_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        fields_arg = opt_arg;
        break;

      case OPT_REVERSE:
        reverse = 1;
        break;

      case OPT_PRINT_FILENAMES:
        print_filenames = 1;
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

      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1) != 0) {
            skAppPrintErr("Unable to load %s as a plugin", opt_arg);
            return 1;
        }
        break;

      case OPT_PRESORTED_INPUT:
        presorted_input = 1;
        break;

      case OPT_SORT_BUFFER_SIZE:
        rv = skStringParseHumanUint64(&tmp64, opt_arg, SK_HUMAN_NORMAL);
        if (rv) {
            goto PARSE_ERROR;
        }
        if ((tmp64 < MINIMUM_SORT_BUFFER_SIZE)
            || (tmp64 >= MAXIMUM_SORT_BUFFER_SIZE))
        {
            skAppPrintErr(
                ("The --%s value must be between %" SK_PRIuZ " and %" SK_PRIuZ),
                appOptions[opt_index].name,
                MINIMUM_SORT_BUFFER_SIZE, MAXIMUM_SORT_BUFFER_SIZE);
            return 1;
        }
        sort_buffer_size = tmp64;
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
 *    Parse the user's option for the --fields switch and fill in the
 *    global sort_fields[].  Return 0 on success; -1 on failure.
 */
static int
parseFields(
    const char         *field_string)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry;
    char *errmsg;
    uint32_t i;
    int have_icmp_type_code;
    int rv = -1;

    /* have we been here before? */
    if (num_fields > 0) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      appOptions[OPT_FIELDS].name);
        goto END;
    }

    /* parse the input */
    if (skStringMapParse(key_field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s", appOptions[OPT_FIELDS].name, errmsg);
        goto END;
    }

    num_fields = 0;

    /* check and handle legacy icmpTypeCode field */
    have_icmp_type_code = 0;
    while (skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK) {
        switch (sm_entry->id) {
          case RWREC_FIELD_ICMP_TYPE:
          case RWREC_FIELD_ICMP_CODE:
            have_icmp_type_code |= 1;
            break;
          case RWREC_PRINTABLE_FIELD_COUNT:
            have_icmp_type_code |= 2;
            break;
        }
    }
    if (3 == have_icmp_type_code) {
        skAppPrintErr("Invalid %s: May not mix field %s with %s or %s",
                      appOptions[OPT_FIELDS].name,
                      skStringMapGetFirstName(
                          key_field_map, RWREC_PRINTABLE_FIELD_COUNT),
                      skStringMapGetFirstName(
                          key_field_map, RWREC_FIELD_ICMP_TYPE),
                      skStringMapGetFirstName(
                          key_field_map, RWREC_FIELD_ICMP_CODE));
        goto END;
    }
    if (2 == have_icmp_type_code) {
        /* add 1 since icmpTypeCode will become 2 fields */
        num_fields = 1;
    }

    skStringMapIterReset(sm_iter);

    num_fields += skStringMapIterCountMatches(sm_iter);
    sort_fields = (uint32_t*)malloc(num_fields * sizeof(uint32_t));
    if (NULL == sort_fields) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* convert the vector to an array, and initialize any plug-ins */
    for (i = 0;
         skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK;
         ++i)
    {
        assert(i < num_fields);
        if (sm_entry->id == RWREC_PRINTABLE_FIELD_COUNT) {
            /* handle the icmpTypeCode field */
            sort_fields[i] = RWREC_FIELD_ICMP_TYPE;
            ++i;
            assert(i < num_fields);
            sort_fields[i] = RWREC_FIELD_ICMP_CODE;
            continue;
        }

        sort_fields[i] = sm_entry->id;
        if (NULL != sm_entry->userdata) {
            /* field comes from a plug-in */
            key_field_t      *key;
            skplugin_field_t *pi_field;
            size_t            bin_width;
            skplugin_err_t    pi_err;

            if (key_num_fields == MAX_PLUGIN_KEY_FIELDS) {
                skAppPrintErr("Too many fields specified %lu > %u max",
                              (unsigned long)key_num_fields,
                              MAX_PLUGIN_KEY_FIELDS);
                goto END;
            }

            pi_field = (skplugin_field_t*)(sm_entry->userdata);

            /* Activate the plugin (so cleanup knows about it) */
            pi_err = skPluginFieldActivate(pi_field);
            if (pi_err != SKPLUGIN_OK) {
                goto END;
            }

            /* Initialize this field */
            pi_err = skPluginFieldRunInitialize(pi_field);
            if (pi_err != SKPLUGIN_OK) {
                goto END;
            }

            /* get the bin width for this field */
            pi_err = skPluginFieldGetLenBin(pi_field, &bin_width);
            if (pi_err != SKPLUGIN_OK) {
                goto END;
            }
            if (0 == bin_width) {
                const char *title;
                skPluginFieldTitle(pi_field, &title);
                skAppPrintErr("Plug-in field '%s' has a binary width of 0",
                              title);
                goto END;
            }

            key = &(key_fields[key_num_fields]);
            key->kf_field_handle = pi_field;
            key->kf_offset       = node_size;
            key->kf_width        = bin_width;

            ++key_num_fields;

            node_size += bin_width;
            if (node_size > MAX_NODE_SIZE) {
                skAppPrintErr(("Sort key is too large %" SK_PRIuZ
                               " bytes > %" SK_PRIuZ " max"),
                              node_size, MAX_NODE_SIZE);
                goto END;
            }
        }
    }

#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
    /* records must be aligned */
    node_size = (1 + ((node_size - 1) / sizeof(uint64_t))) * sizeof(uint64_t);
    if (node_size > MAX_NODE_SIZE) {
        skAppPrintErr(("Sort key is too large %" SK_PRIuZ
                       " bytes > %" SK_PRIuZ " max"),
                      node_size, MAX_NODE_SIZE);
        goto END;
    }
#endif

    /* success */
    rv = 0;

  END:
    if (sm_iter) {
        skStringMapIterDestroy(sm_iter);
    }
    return rv;
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

    fprintf(fh,
            ("The following names may be used in the --%s switch. Names are\n"
             "case-insensitive and may be abbreviated to the shortest"
             " unique prefix.\n"),
            appOptions[OPT_FIELDS].name);

    skStringMapPrintDetailedUsage(key_field_map, fh);
}


/*
 *  int = appNextInput(&stream);
 *
 *    Fill 'stream' with the next input file to read.  Return 0 if
 *    'stream' was successfully opened or 1 if there are no more input
 *    files.
 *
 *    When an input file cannot be opened, the return value is
 *    dependent on the error.  If the error is due to being out of
 *    file handles or memory (EMFILE or ENOMEM), return -2; otherwise
 *    return -1.
 */
int
appNextInput(
    skstream_t        **stream)
{
    static char *path = NULL;
    int rv;

    /* 'path' will be non-NULL if we failed to open the file last time
     * due to being out of memory or file handles. */

    if (NULL == path) {
        rv = skOptionsCtxNextArgument(optctx, &path);
        if (rv < 0) {
            appExit(EXIT_FAILURE);
        }
        if (1 == rv) {
            /* no more input.  add final information to header */
            if ((rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream),
                                            1, pargc, pargv))
                || (rv = skOptionsNotesAddToStream(out_stream)))
            {
                skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            }
            return 1;
        }
    }

    /* create stream and open file */
    errno = 0;
    rv = skStreamOpenSilkFlow(stream, path, SK_IO_READ);
    if (rv) {
        if (errno == EMFILE || errno == ENOMEM) {
            TRACEMSG(("Unable to open '%s': %s", path, strerror(errno)));
            rv = -2;
        } else {
            if (print_filenames) {
                fprintf(PRINT_FILENAMES_FH, "%s\n",
                        skStreamGetPathname(*stream));
            }
            skStreamPrintLastErr(*stream, rv, &skAppPrintErr);
            rv = -1;
        }
        skStreamDestroy(stream);
        return rv;
    }

    /* successfully opened file */
    path = NULL;

    /* copy annotations and command line entries from the input to the
     * output */
    if ((rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                  skStreamGetSilkHeader(*stream),
                                  SK_HENTRY_INVOCATION_ID))
        || (rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                     skStreamGetSilkHeader(*stream),
                                     SK_HENTRY_ANNOTATION_ID)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }

    if (print_filenames) {
        fprintf(PRINT_FILENAMES_FH, "%s\n", skStreamGetPathname(*stream));
    }

    return 0;
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

    /* initialize string-map of field identifiers: add default fields;
     * keep the millisecond fields so that SiLK applications take the
     * same switches; the seconds and milliseconds value map to the
     * same code. */
    if (rwAsciiFieldMapAddDefaultFields(&key_field_map)) {
        skAppPrintErr("Unable to setup fields stringmap");
        appExit(EXIT_FAILURE);
    }
    max_id = RWREC_PRINTABLE_FIELD_COUNT - 1;

    /* add "icmpTypeCode" field */
    ++max_id;
    if (rwAsciiFieldMapAddIcmpTypeCode(key_field_map, max_id)) {
        skAppPrintErr("Unable to add icmpTypeCode");
        return -1;
    }

    /* add --fields from plug-ins */
    pi_err = skPluginFieldIteratorBind(&pi_iter, SKPLUGIN_APP_SORT, 1);
    if (pi_err != SKPLUGIN_OK) {
        assert(pi_err == SKPLUGIN_OK);
        skAppPrintErr("Unable to bind plugin field iterator");
        return -1;
    }

    while (skPluginFieldIteratorNext(&pi_iter, &pi_field)) {
        skPluginFieldName(pi_field, &field_names);
        ++max_id;

        /* Add the field to the key_field_map */
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


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
