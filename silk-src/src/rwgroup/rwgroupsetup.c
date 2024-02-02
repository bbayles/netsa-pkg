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
**  rwgroupsetup.c
**
**   Application setup, teardown, and option parsing for rwgroup.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwgroupsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silkpython.h>
#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include <silk/skprefixmap.h>
#include <silk/skcountry.h>
#include "rwgroup.h"


/* TYPEDEFS AND DEFINES */

/* File handle for --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* the text the user entered for the --id-fields switch */
static const char *id_fields_arg = NULL;

/* the text the user entered for the --delta-field switch */
static const char *delta_field_arg = NULL;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* where to write a copy of the input */
static skstream_t *copy_input = NULL;

/* whether stdout has been used as an output stream */
static int stdout_used = 0;

/* available key fields; rwAsciiFieldMapAddDefaultFields() fills this */
static sk_stringmap_t *key_field_map = NULL;

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


/* OPTIONS SETUP */

typedef enum {
    OPT_HELP_FIELDS,
    OPT_ID_FIELDS, OPT_PLUGIN,
    OPT_DELTA_FIELD, OPT_DELTA_VALUE,
    OPT_OBJECTIVE, OPT_SUMMARIZE,
    OPT_REC_THRESHOLD, OPT_GROUP_OFFSET,
    OPT_OUTPUT_PATH, OPT_COPY_INPUT
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"id-fields",           REQUIRED_ARG, 0, OPT_ID_FIELDS},
    {"plugin",              REQUIRED_ARG, 0, OPT_PLUGIN},
    {"delta-field",         REQUIRED_ARG, 0, OPT_DELTA_FIELD},
    {"delta-value",         REQUIRED_ARG, 0, OPT_DELTA_VALUE},
    {"objective",           NO_ARG,       0, OPT_OBJECTIVE},
    {"summarize",           NO_ARG,       0, OPT_SUMMARIZE},
    {"rec-threshold",       REQUIRED_ARG, 0, OPT_REC_THRESHOLD},
    {"group-offset",        REQUIRED_ARG, 0, OPT_GROUP_OFFSET},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"copy-input",          REQUIRED_ARG, 0, OPT_COPY_INPUT},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each possible field and exit. Def. no",
    ("Add these fields to the grouping key, where the values\n"
     "\tof the fields are identical for each group. Specify fields as a\n"
     "\tcomma-separated list of names, IDs, and/or ID-ranges"),
    ("Load given plug-in to add fields. Switch may be repeated to\n"
     "\tload multiple plug-ins. Def. None"),
    ("Add this single field to the grouping key, where the\n"
     "\tvalue of the field may differ by the specified delta-value"),
    ("Put records in the same group as long as the difference\n"
     "\tin the values of the delta-field is no more than this amount. The\n"
     "\tdifference is measured between consecutive records (current record\n"
     "\tand the previous record) unless the --objective switch is specified"),
    ("Measure the differece in the values of the delta-field by\n"
     "\tcomparing the current record with the first record in the group.\n"
     "\tNormally, the current record is compared with the previous record."),
    ("Output a summary (a single record) for each group rather\n"
     "\tthan a all the records in the group. Def. No"),
    ("Only write flow records to the output stream when the\n"
     "\trecord's group contains at least this number of records. Def. 1"),
    ("Use thie value as the ID for first group. Def. 0"),
    ("Write the output to this stream or file. Def. stdout"),
    ("Copy the input records to the named location. Def. No"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseIdFields(const char *field_string);
static int  parseDeltaField(const char *field_string);
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
#define USAGE_MSG                                                          \
    ("{--id-fields=KEY | --delta-field=F --delta-value=N} [SWITCHES]\n"    \
     "\tAssign flows to a group when the values of the --id-fields are\n"  \
     "\tidentical and the value of the --delta-field differs by no more\n" \
     "\tthan the --delta-value.  Store the group ID in the Next Hop IP\n"  \
     "\tfield and write binary flow records.  The input must be sorted\n"  \
     "\tby the same keys as specified in --id-fields and --delta-field.\n")

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
          case OPT_ID_FIELDS:
            /* Dynamically build the help */
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(key_field_map, fh, 4);
            break;
          default:
            /* Simple help text from the appHelp array */
            assert(appHelp[i]);
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

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
void
appTeardown(
    void)
{
    static int teardownFlag = 0;
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close the copy stream */
    if (copy_input) {
        rv = skStreamClose(copy_input);
        if (rv) {
            skStreamPrintLastErr(copy_input, rv, &skAppPrintErr);
        }
        skStreamDestroy(&copy_input);
    }

    /* close and destroy output */
    if (out_stream) {
        rv = skStreamDestroy(&out_stream);
        if (rv) {
            /* only print error when not in signal handler */
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        out_stream = NULL;
    }

    /* close input */
    skStreamDestroy(&in_stream);

    /* plug-in teardown */
    skPluginRunCleanup(SKPLUGIN_APP_SORT);
    skPluginTeardown();

    /* free variables */
    if (thresh_buf) {
        free(thresh_buf);
        thresh_buf = NULL;
    }
    if (id_fields != NULL) {
        free(id_fields);
    }
    if (key_field_map) {
        skStringMapDestroy(key_field_map);
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
void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    const char *in_path = "stdin";
    int arg_index;
    int j;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *))
           == (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize variables */
    skipaddrClear(&group_id);

    /* initialize plugin library */
    skPluginSetup(1, SKPLUGIN_APP_GROUP);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
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
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();             /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* create the --fields */
    if (createStringmaps()) {
        exit(EXIT_FAILURE);
    }

    /* verify that some field was specified */
    if (NULL == id_fields_arg && NULL == delta_field_arg) {
        skAppPrintErr("No fields specified; must specify --%s or --%s",
                      appOptions[OPT_ID_FIELDS].name,
                      appOptions[OPT_DELTA_FIELD].name);
        skAppUsage();             /* never returns */
    }

    /* parse the id-fields argument */
    if (id_fields_arg != NULL) {
        if (parseIdFields(id_fields_arg)) {
            exit(EXIT_FAILURE);
        }
    }

    /* parse the delta-field argument and ensure value is specified */
    if (NULL != delta_field_arg) {
        if (parseDeltaField(delta_field_arg)) {
            exit(EXIT_FAILURE);
        }
    } else if (delta_value) {
        skAppPrintErr("The --%s switch only allowed when a --%s is specified",
                      appOptions[OPT_DELTA_VALUE].name,
                      appOptions[OPT_DELTA_FIELD].name);
        skAppUsage();             /* never returns */
    }

    /* check for an input file name on the command line */
    if (arg_index < argc) {
        in_path = argv[arg_index];
        ++arg_index;
    }

    /* check for extra options */
    if (arg_index != argc) {
        skAppPrintErr(("Too many arguments;"
                       " only a single input file is permitted"));
        skAppUsage();             /* never returns */
    }

    /* create threshold buffer */
    if (threshold) {
        thresh_buf = (rwRec*)calloc(threshold, sizeof(rwRec));
        if (NULL == thresh_buf) {
            skAppPrintOutOfMemory(NULL);
            exit(EXIT_FAILURE);
        }
    }

    /* check for an output stream; or default to stdout  */
    if (out_stream == NULL) {
        if (stdout_used) {
            skAppPrintErr("Only one output stream may use stdout");
            exit(EXIT_FAILURE);
        }
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, "stdout")))
        {
            skStreamPrintLastErr(out_stream, rv, NULL);
            skStreamDestroy(&out_stream);
            exit(EXIT_FAILURE);
        }
    }

    /* open the input stream */
    rv = skStreamOpenSilkFlow(&in_stream, in_path, SK_IO_READ);
    if (rv) {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        skStreamDestroy(&in_stream);
        skAppPrintErr("Could not open %s for reading.  Exiting.", in_path);
        exit(EXIT_FAILURE);
    }

    /* set the copy-input stream to get everything we read */
    if (copy_input) {
        rv = skStreamSetCopyInput(in_stream, copy_input);
        if (rv) {
            skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* set the compmethod on the output */
    rv = skHeaderSetCompressionMethod(skStreamGetSilkHeader(out_stream),
                                      comp_method);
    if (rv) {
        skAppPrintErr("Error setting header on %s: %s",
                      skStreamGetPathname(out_stream), skHeaderStrerror(rv));
        exit(EXIT_FAILURE);
    }

    /* copy annotations and command line entries from the input to the
     * output */
    if ((rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                  skStreamGetSilkHeader(in_stream),
                                  SK_HENTRY_INVOCATION_ID))
        || (rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream),
                                     skStreamGetSilkHeader(in_stream),
                                     SK_HENTRY_ANNOTATION_ID)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* add invocation and notes to the output */
    if ((rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream),
                                    1, argc, argv))
        || (rv = skOptionsNotesAddToStream(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* open output */
    rv = skStreamOpen(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skAppPrintErr("Could not open output file.");
        exit(EXIT_FAILURE);
    }

    /* write the header */
    rv = skStreamWriteSilkHeader(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skAppPrintErr("Could not write header to output file.");
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
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_ID_FIELDS:
        if (id_fields_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        id_fields_arg = opt_arg;
        break;

      case OPT_OUTPUT_PATH:
        if (!opt_arg || 0 == strlen(opt_arg)) {
            skAppPrintErr("Missing file name for --%s option",
                          appOptions[opt_index].name);
            return 1;
        }
        if (out_stream) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((0 == strcmp(opt_arg, "stdout")) || (0 == strcmp(opt_arg, "-"))) {
            if (stdout_used) {
                skAppPrintErr("Only one output stream may use stdout");
                return 1;
            }
            stdout_used = 1;
        }
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, opt_arg)))
        {
            skStreamPrintLastErr(out_stream, rv, NULL);
            return 1;
        }
        break;

      case OPT_COPY_INPUT:
        if (!opt_arg || 0 == strlen(opt_arg)) {
            skAppPrintErr("Missing file name for --%s option",
                          appOptions[opt_index].name);
            return 1;
        }
        if (copy_input) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((0 == strcmp(opt_arg, "stdout")) || (0 == strcmp(opt_arg, "-"))) {
            if (stdout_used) {
                skAppPrintErr("Only one output stream may use stdout");
                return 1;
            }
            stdout_used = 1;
        }
        rv = skStreamOpenSilkFlow(&copy_input, opt_arg, SK_IO_WRITE);
        if (rv) {
            skStreamPrintLastErr(copy_input, rv, &skAppPrintErr);
            skStreamDestroy(&copy_input);
            return 1;
        }
        break;

      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1) != 0) {
            skAppPrintErr("Unable to load %s as a plugin", opt_arg);
            return 1;
        }
        break;

      case OPT_DELTA_FIELD:
        if (delta_field_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        delta_field_arg = opt_arg;
        break;

      case OPT_DELTA_VALUE:
        rv = skStringParseUint64(&delta_value, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_REC_THRESHOLD:
        rv = skStringParseUint32(&threshold, opt_arg, 0, MAX_THRESHOLD);
        if (rv) {
            goto PARSE_ERROR;
        }
        /* threshold of 1 is effectively 0 */
        if (threshold <= 1) {
            threshold = 0;
        }
        break;

      case OPT_GROUP_OFFSET:
        rv = skStringParseIP(&group_id, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SUMMARIZE:
        summarize = 1;
        break;

      case OPT_OBJECTIVE:
        objective = 1;
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
 *  status = parseIdFields(fields_string);
 *
 *    Parse the user's option for the --fields switch.  Fill the
 *    global 'id_list' with the list of fields, and set 'num_fields'
 *    to the number of fields in 'id_list'.  Also initialize the
 *    plug-ins.  Return 0 on success; -1 on failure.
 */
static int
parseIdFields(
    const char         *field_string)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry;
    char *errmsg;
    uint32_t i;
    int have_icmp_type_code;
    int rv = -1;

    /* parse the input */
    if (skStringMapParse(key_field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_ID_FIELDS].name, errmsg);
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
                      appOptions[OPT_ID_FIELDS].name,
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
    id_fields = (uint32_t*)malloc(num_fields * sizeof(uint32_t));
    if (NULL == id_fields) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* fill the array, and initialize any plug-ins */
    for (i = 0;
         skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK;
         ++i)
    {
        assert(i < num_fields);
        if (sm_entry->id == RWREC_PRINTABLE_FIELD_COUNT) {
            /* handle the icmpTypeCode field */
            id_fields[i] = RWREC_FIELD_ICMP_TYPE;
            ++i;
            assert(i < num_fields);
            id_fields[i] = RWREC_FIELD_ICMP_CODE;
            continue;
        }

        id_fields[i] = sm_entry->id;
        if (NULL != sm_entry->userdata) {
            /* field comes from a plug-in */
            key_field_t            *key;
            skplugin_field_t       *pi_field;
            size_t                  bin_width;
            skplugin_err_t          pi_err;

            assert(id_fields[i] >  RWREC_PRINTABLE_FIELD_COUNT);

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
                skAppPrintErr("Sort key is too large %lu bytes > %d max",
                              (unsigned long)node_size, MAX_NODE_SIZE);
                goto END;
            }
        }
    }

    /* success */
    rv = 0;

  END:
    if (sm_iter) {
        skStringMapIterDestroy(sm_iter);
    }
    return rv;
}


static int
parseDeltaField(
    const char         *field_string)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry;
    char *errmsg;
    uint64_t limit = 1;
    int rv = -1;

    /* verify user gave us input */
    if (field_string == NULL || field_string[0] == '\0') {
        skAppPrintErr("Missing a value for the --%s switch",
                      appOptions[OPT_DELTA_FIELD].name);
        goto END;
    }

    /* parse the input */
    if (skStringMapParse(key_field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_DELTA_FIELD].name, errmsg);
        goto END;
    }

    /* we only expect one field */
    if (skStringMapIterCountMatches(sm_iter) > 1) {
        skAppPrintErr("Invalid %s: Only one field may be specified",
                      appOptions[OPT_DELTA_FIELD].name);
        goto END;
    }

    skStringMapIterNext(sm_iter, &sm_entry, NULL);
    delta_field = sm_entry->id;

    /* make certain the field and delta-value make sense */
    switch (delta_field) {
      case RWREC_FIELD_SIP:
      case RWREC_FIELD_DIP:
      case RWREC_FIELD_NHIP:
        /* for IPs, the delta_value is the number of LEAST significant
         * bits to REMOVE */
#if SK_ENABLE_IPV6
        limit = 127;
        if (delta_value <= limit) {
            uint8_t mask[16];
            uint32_t i = (128 - delta_value) >> 3;
            memset(&mask[0], 0xFF, i);
            mask[i] = ~(0xFF >> ((128 - delta_value) & 0x7));
            memset(&mask[i+1], 0, (15 - i));
            skipaddrSetV6(&delta_value_ip, mask);
        }
#else
        limit = 31;
        if (delta_value <= limit) {
            limit = 0;
            delta_value = UINT32_MAX << delta_value;
        }
#endif /* SK_ENABLE_IPV6 */
        break;

      case RWREC_FIELD_STIME:
      case RWREC_FIELD_STIME_MSEC:
      case RWREC_FIELD_ETIME:
      case RWREC_FIELD_ETIME_MSEC:
        /* this is a sktime_t. multiply user's value by 1000 to
         * convert from seconds to milliseconds */
        limit = INT64_MAX / 1000;
        if (delta_value <= limit) {
            limit = 0;
            delta_value *= 1000;
        }
        break;

      case RWREC_FIELD_ELAPSED:
      case RWREC_FIELD_ELAPSED_MSEC:
        /* max elapsed is UINT32_MAX milliseconds.  multiply user's
         * value by 1000 to convert from seconds to milliseconds. */
        limit = UINT32_MAX / 1000;
        if (delta_value <= limit) {
            limit = 0;
            delta_value *= 1000;
        }
        break;

      case RWREC_FIELD_PKTS:
      case RWREC_FIELD_BYTES:
        /* these values hold uint32_t */
        limit = UINT32_MAX - 1;
        break;

      case RWREC_FIELD_SPORT:
      case RWREC_FIELD_DPORT:
      case RWREC_FIELD_APPLICATION:
      case RWREC_FIELD_SID:
      case RWREC_FIELD_INPUT:
      case RWREC_FIELD_OUTPUT:
        /* these values hold uint16_t */
        limit = UINT16_MAX - 1;
        break;

      case RWREC_FIELD_PROTO:
      case RWREC_FIELD_ICMP_TYPE:
      case RWREC_FIELD_ICMP_CODE:
        /* these value hold uint8_t */
        limit = UINT8_MAX - 1;
        break;

      case RWREC_FIELD_FLAGS:
      case RWREC_FIELD_INIT_FLAGS:
      case RWREC_FIELD_REST_FLAGS:
      case RWREC_FIELD_TCP_STATE:
      case RWREC_FIELD_FTYPE_CLASS:
      case RWREC_FIELD_FTYPE_TYPE:
      default:
        /* these are nonsense */
        skAppPrintErr(("Invalid %s '%s':"
                       " Cannot compute a delta value for the field"),
                      appOptions[OPT_DELTA_FIELD].name, sm_entry->name);
        goto END;
    }

    /* verify delta_value is not too large */
    if (limit != 0 && delta_value > limit) {
        skAppPrintErr(("Invalid %s '%" PRIu64
                       ": The maximum the '%s' field supports is %" PRIu64),
                      appOptions[OPT_DELTA_VALUE].name, delta_value,
                      sm_entry->name, limit);
        goto END;
    }

    /* a delta value is required */
    if (0 == delta_value) {
        skAppPrintErr("Using the --%s switch requires a --%s",
                      appOptions[OPT_DELTA_FIELD].name,
                      appOptions[OPT_DELTA_VALUE].name);
        goto END;
    }

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
            ("The following names may be used in the --%s switch,"
             " and most names\n"
             "may be used in the --%s switch."
             "  Names are case-insensitive and may\n"
             "be abbreviated to the shortest unique prefix.\n"),
            appOptions[OPT_ID_FIELDS].name,
            appOptions[OPT_DELTA_FIELD].name);

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

    /* initialize string-map of field identifiers: add default fields;
     * keep the millisecond fields so that SiLK applications take the
     * same switches; the seconds and milliseconds value map to the
     * same code. */
    if (rwAsciiFieldMapAddDefaultFields(&key_field_map)) {
        skAppPrintErr("Unable to setup fields stringmap");
        exit(EXIT_FAILURE);
    }
    max_id = RWREC_PRINTABLE_FIELD_COUNT - 1;

    /* add icmpTypeCode */
    ++max_id;
    if (rwAsciiFieldMapAddIcmpTypeCode(key_field_map, max_id)) {
        skAppPrintErr("Unable to add icmpTypeCode");
        return -1;
    }

    /* add --fields from plug-ins */
    pi_err = skPluginFieldIteratorBind(&pi_iter, SKPLUGIN_APP_GROUP, 1);
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


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
