/*
** Copyright (C) 2016-2023 by Carnegie Mellon University.
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
 *  rwaggbag.c
 *
 *    Read SiLK Flow records and create a file where an aggregate key
 *    (i.e., a key composed of multiple characteristics of a SiLK Flow
 *    record) maps to an aggregate counter (i.e., a counter composed
 *    by summing the volumes of each record that matches the aggregate
 *    key.)
 *
 *  Mark Thomas
 *  December 2016
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwaggbag.c e95eb8cd5b0c 2023-09-05 21:09:53Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/silk_files.h>
#include <silk/skaggbag.h>
#include <silk/skcountry.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */

/* file handle for --help usage message */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

#if 0
/* create aliases for exisitng counter fields.  the struct contains
 * the name of the alias and an ID to match in the builtin_values[]
 * array */
static const struct builtin_value_aliases_st {
    const char         *ba_name;
    sk_aggbag_type_t    ba_id;
} builtin_value_aliases[] = {
    {"Flows",   SKAGGBAG_FIELD_RECORDS},
    {NULL,      (sk_aggbag_type_t)0}
};
#endif  /* 0 */

/* available key field names */
static sk_stringmap_t *key_name_map = NULL;

/* available counter field names */
static sk_stringmap_t *counter_name_map = NULL;

/* the text the user entered for the --keys switch */
static const char *keys_arg = NULL;

/* the text the user entered for the --counters switch */
static const char *counters_arg = NULL;

/* the output stream */
static skstream_t *output = NULL;

/* how to handle IPv6 flows */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;

/* input checker */
static sk_options_ctx_t *optctx = NULL;

/* options for writing the AggBag file */
static sk_aggbag_options_t ab_options;

/* the aggbag to create */
static sk_aggbag_t *ab = NULL;


/* OPTIONS */

typedef enum {
    OPT_HELP_FIELDS,
    OPT_KEYS,
    OPT_COUNTERS,
    OPT_OUTPUT_PATH
} appOptionsEnum;


static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"keys",                REQUIRED_ARG, 0, OPT_KEYS},
    {"counters",            REQUIRED_ARG, 0, OPT_COUNTERS},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each supported key and counter and exit. Def. no",
    ("Use these fields as the grouping key. Specify fields as a\n"
     "\tcomma-separated list of names"),
    ("Compute these values for each group.\n"
     "\tSpecify values as a comma-separated list of names"),
    "Send output to given file path. Def. stdout",
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void helpFields(FILE *fh);
static int  createStringmaps(void);
static int
parseFields(
    const sk_stringmap_t   *str_map,
    const char             *field_arg,
    appOptionsEnum          key_or_counter);


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
    FILE *fh = USAGE_FH;
    unsigned int i;

#define USAGE_MSG                                                             \
    ("--keys=KEYS --counters=COUNTERS [SWITCHES] [FILES]\n"                   \
     "\tRead SiLK Flow records, bin the records by the fields in KEYS,\n"     \
     "\tcompute the COUNTERS field(s) for each KEYS, and write the binary\n"  \
     "\tAggregate Bag output to the standard output or the --output-path.\n"  \
     "\tRead SiLK Flows from the named files or from the standard input.\n")

    /* Create the string maps for --keys and --counters */
    createStringmaps();

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);

    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_KEYS:
            /* Dynamically build the help */
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(key_name_map, fh, 4);
            break;
          case OPT_COUNTERS:
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(counter_name_map, fh, 4);
            break;
          case OPT_OUTPUT_PATH:
            /* include the help for --notes and --invocation-strip
             * after --output-path */
            fprintf(fh, "%s\n", appHelp[i]);
            skAggBagOptionsUsage(fh);
            break;
          default:
            /* Simple help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    sksiteOptionsUsage(fh);
    /* skPluginOptionsUsage(fh); */
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
    static int teardown_flag = 0;

    if (teardown_flag) {
        return;
    }
    teardown_flag = 1;

    skAggBagDestroy(&ab);

    /* close output */
    skStreamClose(output);
    skStreamDestroy(&output);

    /* destroy string maps for keys and counters */
    skStringMapDestroy(key_name_map);
    key_name_map = NULL;

    skStringMapDestroy(counter_name_map);
    counter_name_map = NULL;

    skAggBagOptionsTeardown();
    skCountryTeardown();
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
    memset(&ab_options, 0, sizeof(sk_aggbag_options_t));
    ab_options.existing_silk_files = 1;
    ab_options.argc = argc;
    ab_options.argv = argv;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_COPY_INPUT
                    | SK_OPTIONS_CTX_PRINT_FILENAMES);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skAggBagOptionsRegister(&ab_options)
        || skIPv6PolicyOptionsRegister(&ipv6_policy)
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

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names, but we
     * should not consider it a complete failure */
    sksiteConfigure(0);

    /* make sure the user specified at least one key field and one
     * counter field */
    if (keys_arg == NULL || keys_arg[0] == '\0') {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_KEYS].name);
        skAppUsage();         /* never returns */
    }
    if (counters_arg == NULL || counters_arg[0] == '\0') {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_COUNTERS].name);
        skAppUsage();         /* never returns */
    }

    /* set up the key_name_map and counter_name_map */
    if (createStringmaps()) {
        exit(EXIT_FAILURE);
    }

    /* create the aggregate bag */
    if (skAggBagCreate(&ab)) {
        exit(EXIT_FAILURE);
    }
    skAggBagOptionsBind(ab, &ab_options);

    /* parse the --keys and --counters switches */
    if (parseFields(key_name_map, keys_arg, OPT_KEYS)) {
        exit(EXIT_FAILURE);
    }
    if (parseFields(counter_name_map, counters_arg, OPT_COUNTERS)) {
        exit(EXIT_FAILURE);
    }

    /* create output stream to stdout if no --output-path was given */
    if (NULL == output) {
        if ((rv = skStreamCreate(&output, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(output, "-")))
        {
            skStreamPrintLastErr(output, rv, &skAppPrintErr);
            skStreamDestroy(&output);
            exit(EXIT_FAILURE);
        }
    }

    /* make certain stdout is not being used for multiple outputs */
    if (skStreamIsStdout(output) && skOptionsCtxCopyStreamIsStdout(optctx)) {
        skAppPrintErr("May not use stdout for multiple output streams");
        exit(EXIT_FAILURE);
    }

    /* open the output stream but do not write anything yet */
    rv = skStreamOpen(output);
    if (rv) {
        skStreamPrintLastErr(output, rv, &skAppPrintErr);
        skStreamDestroy(&output);
        exit(EXIT_FAILURE);
    }

    /* open the --copy-input stream */
    if (skOptionsCtxOpenStreams(optctx, &skAppPrintErr)) {
        exit(EXIT_FAILURE);
    }

    return;                       /* OK */
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
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_KEYS:
        if (keys_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        keys_arg = opt_arg;
        break;

      case OPT_COUNTERS:
        if (counters_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        counters_arg = opt_arg;
        break;

      case OPT_OUTPUT_PATH:
        if (output) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&output, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(output, opt_arg)))
        {
            skStreamPrintLastErr(output, rv, &skAppPrintErr);
            skStreamDestroy(&output);
            return 1;
        }
        break;
    }

    return 0;                     /* OK */
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
#define HELP_FIELDS_MSG                                                 \
    ("The following names may be used in the --%s switch."              \
     " Names are case-\n"                                               \
     "insensitive and may be abbreviated to the shortest unique prefix.\n")

    if (createStringmaps()) {
        exit(EXIT_FAILURE);
    }

    fprintf(fh, HELP_FIELDS_MSG, appOptions[OPT_KEYS].name);
    skStringMapPrintDetailedUsage(key_name_map, fh);

    fprintf(fh, "\n");

    fprintf(fh, HELP_FIELDS_MSG, appOptions[OPT_COUNTERS].name);
    skStringMapPrintDetailedUsage(counter_name_map, fh);
}


/*
 *  ok = createStringmaps();
 *
 *    Create the string-maps to assist in parsing the --keys and
 *    --counters switches.
 */
static int
createStringmaps(
    void)
{
    sk_stringmap_t *map;
    sk_stringmap_status_t sm_err;
    sk_stringmap_entry_t sm_entry;
    sk_aggbag_type_iter_t iter;
    sk_aggbag_type_t type;
    const char *names[] = {"key", "counter"};
    unsigned int looping;
    unsigned int i;

    memset(&sm_entry, 0, sizeof(sm_entry));

    for (i = 0; i < 2; ++i) {
        /* create the string-map of field identifiers */
        if (0 == i) {
            sm_err = skStringMapCreate(&key_name_map);
            map = key_name_map;
        } else {
            sm_err = skStringMapCreate(&counter_name_map);
            map = counter_name_map;
        }
        if (sm_err) {
            skAppPrintErr("Unable to create string map for %ss", names[i]);
            return -1;
        }

        looping = 1;
        skAggBagFieldTypeIteratorBind(
            &iter, ((0 == i) ? SK_AGGBAG_KEY : SK_AGGBAG_COUNTER));
        while (looping && NULL !=
               (sm_entry.name = skAggBagFieldTypeIteratorNext(&iter, &type)))
        {
            /* skip unsupported/non-applicable fields */
            switch (type) {
              case SKAGGBAG_FIELD_ANY_COUNTRY:
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                /* stop looping.  there are no more supported fields */
                looping = 0;
                continue;
              case SKAGGBAG_FIELD_ANY_IPv4:
              case SKAGGBAG_FIELD_ANY_IPv6:
              case SKAGGBAG_FIELD_ANY_PORT:
              case SKAGGBAG_FIELD_ANY_SNMP:
              case SKAGGBAG_FIELD_ANY_TIME:
              case SKAGGBAG_FIELD_CUSTOM_KEY:
                continue;
              default:
                break;
            }
            sm_entry.id = type;
            sm_entry.description = skAggBagFieldTypeGetDescription(type);
            sm_err = skStringMapAddEntries(map, 1, &sm_entry);
            if (sm_err) {
                skAppPrintErr("Unable to add %s field named '%s': %s",
                              names[i], sm_entry.name,
                              skStringMapStrerror(sm_err));
                return -1;
            }
        }
    }

    return 0;
}


/*
 *    Parse the user's string argument that represents the list of key
 *    fields or the counter fields to use in the AggBag.  Parse the
 *    string against the specified string map.  The final parameter is
 *    the argument type.  On success, set the keys or counters on the
 *    AggBag and return 0.  Return non-zero on error.
 */
static int
parseFields(
    const sk_stringmap_t   *string_map,
    const char             *name_list_arg,
    appOptionsEnum          key_or_counter)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry = NULL;
    sk_aggbag_type_t *fields = NULL;
    unsigned int i;
    /* error message generated when parsing fields */
    char *errmsg;
    ssize_t err;
    /* return value; assume failure */
    int rv = -1;

    assert(string_map);
    assert(name_list_arg);
    assert(OPT_KEYS == key_or_counter
           || OPT_COUNTERS == key_or_counter);

    /* parse the argument */
    if (skStringMapParse(string_map, name_list_arg, SKSTRINGMAP_DUPES_ERROR,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[key_or_counter].name, errmsg);
        goto END;
    }

    /* create array to hold field IDs */
    fields = (sk_aggbag_type_t *)calloc(skStringMapIterCountMatches(sm_iter),
                                        sizeof(sk_aggbag_type_t));
    if (NULL == fields) {
        goto END;
    }

    /* add the field IDs to the array */
    i = 0;
    while (skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK) {
        assert(i < skStringMapIterCountMatches(sm_iter));
        fields[i] = (sk_aggbag_type_t)sm_entry->id;
        if ((fields[i] == SKAGGBAG_FIELD_SIP_COUNTRY
             || fields[i] == SKAGGBAG_FIELD_DIP_COUNTRY)
            && skCountrySetup(NULL, &skAppPrintErr))
        {
            goto END;
        }
        ++i;
    }
    assert(skStringMapIterCountMatches(sm_iter) == i);

    if (OPT_KEYS == key_or_counter) {
        err = skAggBagSetKeyFields(ab, i, fields);
    } else {
        err = skAggBagSetCounterFields(ab, i, fields);
    }
    if (err) {
        skAppPrintErr("Unable to set %s %" SK_PRIdZ,
                      appOptions[key_or_counter].name, err);
        goto END;
    }

    /* successful */
    rv = 0;

  END:
    skStringMapIterDestroy(sm_iter);
    free(fields);
    return rv;
}


/*
 *    Process a single input stream (file) of SiLK Flow records: Copy
 *    the header entries from the input stream to the output stream,
 *    read the file, fill a Key and Counter for each flow record, and
 *    add the Key and Counter to the AggBag.
 */
static int
processFile(
    skstream_t         *stream)
{
    sk_aggbag_field_t k_it;
    sk_aggbag_field_t c_it;
    sk_aggbag_aggregate_t key;
    sk_aggbag_aggregate_t counter;
    skipaddr_t ip;
    rwRec rwrec;
    ssize_t rv;
    ssize_t err;

    /* copy invocation and notes (annotations) from the SiLK Flow
     * files to the output stream; these headers will not be written
     * to the output if --invocation-strip or --notes-strip was
     * specified. */
    rv = skHeaderCopyEntries(skStreamGetSilkHeader(output),
                             skStreamGetSilkHeader(stream),
                             SK_HENTRY_INVOCATION_ID);
    if (rv) {
        skStreamPrintLastErr(output, rv, &skAppPrintErr);
    }
    rv = skHeaderCopyEntries(skStreamGetSilkHeader(output),
                             skStreamGetSilkHeader(stream),
                             SK_HENTRY_ANNOTATION_ID);
    if (rv) {
        skStreamPrintLastErr(output, rv, &skAppPrintErr);
    }

    err = SKAGGBAG_OK;
    while (SKSTREAM_OK == (rv = skStreamReadRecord(stream, &rwrec))) {
        skAggBagInitializeKey(ab, &key, &k_it);
        do {
            switch (skAggBagFieldIterGetType(&k_it)) {
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_SIPv4:
                rwRecMemGetSIP(&rwrec, &ip);
                skAggBagAggregateSetIPAddress(&key, &k_it, &ip);
                break;
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_DIPv4:
                rwRecMemGetDIP(&rwrec, &ip);
                skAggBagAggregateSetIPAddress(&key, &k_it, &ip);
                break;
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_NHIPv4:
                rwRecMemGetNhIP(&rwrec, &ip);
                skAggBagAggregateSetIPAddress(&key, &k_it, &ip);
                break;
              case SKAGGBAG_FIELD_SPORT:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetSPort(&rwrec));
                break;
              case SKAGGBAG_FIELD_DPORT:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetDPort(&rwrec));
                break;
              case SKAGGBAG_FIELD_ICMP_TYPE:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it,
                    (rwRecIsICMP(&rwrec) ? rwRecGetIcmpType(&rwrec) : 0));
                break;
              case SKAGGBAG_FIELD_ICMP_CODE:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it,
                    (rwRecIsICMP(&rwrec) ? rwRecGetIcmpCode(&rwrec) : 0));
                break;
              case SKAGGBAG_FIELD_PROTO:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetProto(&rwrec));
                break;
              case SKAGGBAG_FIELD_PACKETS:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetPkts(&rwrec));
                break;
              case SKAGGBAG_FIELD_BYTES:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetBytes(&rwrec));
                break;
              case SKAGGBAG_FIELD_FLAGS:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetFlags(&rwrec));
                break;
              case SKAGGBAG_FIELD_SID:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetSensor(&rwrec));
                break;
              case SKAGGBAG_FIELD_INPUT:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetInput(&rwrec));
                break;
              case SKAGGBAG_FIELD_OUTPUT:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetOutput(&rwrec));
                break;
              case SKAGGBAG_FIELD_INIT_FLAGS:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetInitFlags(&rwrec));
                break;
              case SKAGGBAG_FIELD_REST_FLAGS:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetRestFlags(&rwrec));
                break;
              case SKAGGBAG_FIELD_TCP_STATE:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it,
                    (rwRecGetTcpState(&rwrec) & SK_TCPSTATE_ATTRIBUTE_MASK));
                break;
              case SKAGGBAG_FIELD_APPLICATION:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetApplication(&rwrec));
                break;
              case SKAGGBAG_FIELD_FTYPE_CLASS:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it,
                    sksiteFlowtypeGetClassID(rwRecGetFlowType(&rwrec)));
                break;
              case SKAGGBAG_FIELD_FTYPE_TYPE:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetFlowType(&rwrec));
                break;
              case SKAGGBAG_FIELD_STARTTIME:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetStartSeconds(&rwrec));
                break;
              case SKAGGBAG_FIELD_ELAPSED:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetElapsedSeconds(&rwrec));
                break;
              case SKAGGBAG_FIELD_ENDTIME:
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, rwRecGetEndSeconds(&rwrec));
                break;
              case SKAGGBAG_FIELD_SIP_COUNTRY:
                rwRecMemGetSIP(&rwrec, &ip);
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, skCountryLookupCode(&ip));
                break;
              case SKAGGBAG_FIELD_DIP_COUNTRY:
                rwRecMemGetDIP(&rwrec, &ip);
                skAggBagAggregateSetUnsigned(
                    &key, &k_it, skCountryLookupCode(&ip));
                break;
              default:
                break;
            }
        } while (skAggBagFieldIterNext(&k_it) == SK_ITERATOR_OK);

        skAggBagInitializeCounter(ab, &counter, &c_it);
        do {
            switch (skAggBagFieldIterGetType(&c_it)) {
              case SKAGGBAG_FIELD_RECORDS:
                skAggBagAggregateSetUnsigned(&counter, &c_it, 1);
                break;
              case SKAGGBAG_FIELD_SUM_BYTES:
                skAggBagAggregateSetUnsigned(
                    &counter, &c_it, rwRecGetBytes(&rwrec));
                break;
              case SKAGGBAG_FIELD_SUM_PACKETS:
                skAggBagAggregateSetUnsigned(
                    &counter, &c_it, rwRecGetPkts(&rwrec));
                break;
              case SKAGGBAG_FIELD_SUM_ELAPSED:
                skAggBagAggregateSetUnsigned(
                    &counter, &c_it, rwRecGetElapsedSeconds(&rwrec));
                break;
              default:
                break;
            }
        } while (skAggBagFieldIterNext(&c_it) == SK_ITERATOR_OK);

        err = skAggBagKeyCounterAdd(ab, &key, &counter, NULL);
        if (err) {
            skAppPrintErr("Unable to add to key: %s", skAggBagStrerror(err));
            break;
        }
    }

    if (rv != SKSTREAM_ERR_EOF) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        return -1;
    }

    return 0;
}


int main(int argc, char **argv)
{
    skstream_t *stream = NULL;
    ssize_t rv;

    /* Global setup */
    appSetup(argc, argv);

    /* process input */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        skStreamSetIPv6Policy(stream, ipv6_policy);
        if (0 != processFile(stream)) {
            skAppPrintErr("Error processing input from %s",
                          skStreamGetPathname(stream));
            skStreamDestroy(&stream);
            return EXIT_FAILURE;
        }
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    rv = skAggBagWrite(ab, output);
    if (rv) {
        if (SKAGGBAG_E_WRITE == rv) {
            skStreamPrintLastErr(output, skStreamGetLastReturnValue(output),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing Aggregate Bag to '%s': %s",
                          skStreamGetPathname(output), skAggBagStrerror(rv));
        }
        exit(EXIT_FAILURE);
    }

    skAggBagDestroy(&ab);

    /* Done, do cleanup */
    appTeardown();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
