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
 *  rwaggbagcat.c
 *
 *    Print an Aggregate Bag file as text.
 *
 *  Mark Thomas
 *  December 2016
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwaggbagcat.c 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/silk_files.h>
#include <silk/skaggbag.h>
#include <silk/skcountry.h>
#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>
#include <silk/skvector.h>


/* TYPEDEFS AND DEFINES */

/* file handle for --help usage message */
#define USAGE_FH stdout

/* sizes of arrays that hold column info */
#define AGGBAGCAT_ARRAY_SIZE    64

/* the type used for user_fields */
typedef struct user_field_data_st {
    /* the type of the user_field */
    sk_aggbag_type_t    field_type;
    /* whether the field is present in current input AggBag */
    uint8_t             is_missing;
    /* string to print if the user field does not appear in the input; default
     * is empty_string, may be set by --missing-field */
    const char         *missing_string;
    /* the value from the current entry in the AggBag, used while reading */
    struct field_value_st {
        uint64_t    number;
        skipaddr_t  ip;
    }                   value;
} user_field_data_t;


/* LOCAL VARIABLES */

/* how to print IP addresses */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* how to print timestamps */
static uint32_t timestamp_format = 0;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags =
    (SK_OPTION_TIMESTAMP_NEVER_MSEC);

/* the output stream.  stdout, PAGER, or value set by --output-path */
static sk_fileptr_t output;

/* name of program to run to page output, set by --pager or PAGER */
static char *pager;

/* the width of each column in the output */
static int width[AGGBAGCAT_ARRAY_SIZE];

/* separator between output columns */
static char column_separator = '|';

/* available fields */
static sk_stringmap_t *field_map = NULL;

/* the argument to the --fields switch */
static char *fields = NULL;

/* when --fields is given, the fields (columns) to print in the order to print
 * them */
static user_field_data_t *user_fields = NULL;

/* each argument to the --missing-field switch; switch may be
 * repeated; vector of char* */
static sk_vector_t *missing_field = NULL;

/* default to print when the input does not contain a field specified in
 * user_fields (a missing field) */
static const char * const empty_string = "";

/* output features set by the specified switch */
static struct app_flags_st {
    /* --no-columns */
    unsigned no_columns         :1;
    /* --no-titles */
    unsigned no_titles          :1;
    /* --no-final-delimiter */
    unsigned no_final_delimiter :1;
    /* --integer-sensors */
    unsigned integer_sensors    :1;
    /* --integer-tcp-flags */
    unsigned integer_tcp_flags  :1;
} app_flags;

/* input checker */
static sk_options_ctx_t *optctx = NULL;


/* OPTIONS */

typedef enum {
    OPT_HELP_FIELDS,
    OPT_FIELDS,
    OPT_MISSING_FIELD,
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
    {"missing-field",       REQUIRED_ARG, 0, OPT_MISSING_FIELD},
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
    "Describe each supported field and exit. Def. no",
    ("Print only the key and/or counter fields in this comma-\n"
     "\tseparated set of fields, and print them in the order specified by\n"
     "\tthe argument. If a field is not in input, prints blank or value\n"
     "\tspecified for that field by --missing-field. Supported fields:"),
    ("Given an argument of FIELD=STRING when --fields is\n"
     "\tactive, print STRING as the value for FIELD when FIELD is not in the\n"
     "\tinput AggBag. FIELD must be present in --fields.  Repeat the switch\n"
     "\tto set the missing value for multiple FIELDs"),
    "Print sensor as an integer. Def. Sensor name",
    "Print TCP Flags as an integer. Def. No",
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
static int  createStringmap(void);
static void helpFields(FILE *fh);
static int  parseFieldsString(const char *fields_string, char **errmsg);
static int  parseMissingFieldValues(void);


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

#define USAGE_MSG                                                           \
    ("[SWITCHES] [AGGBAG_FILES]\n"                                          \
     "\tPrint binary Aggregate Bag files as text to the standard output,\n" \
     "\tthe pager, or the --output-path. When multiple files are given,\n"  \
     "\tthe files are processed sequentially: they are not merged.\n")

    /* Create the string maps for --fields and --values */
    /*createStringmaps();*/

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);

    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
        switch (appOptions[i].val) {
          case OPT_FIELDS:
            skStringMapPrintUsage(field_map, fh, 4);
            break;
          case OPT_MISSING_FIELD:
            skOptionsTimestampFormatUsage(fh);
            skOptionsIPFormatUsage(fh);
            break;
          default:
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
    static int teardown_flag = 0;

    if (teardown_flag) {
        return;
    }
    teardown_flag = 1;

    /* close output */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }

    skVectorDestroy(missing_field);
    missing_field = NULL;
    (void)skStringMapDestroy(field_map);
    field_map = NULL;
    free(user_fields);
    user_fields = NULL;

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
    memset(&app_flags, 0, sizeof(app_flags));
    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_BINARY | SK_OPTIONS_CTX_ALLOW_STDIN);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsTimestampFormatRegister(
            &timestamp_format, time_register_flags)
        || skOptionsIPFormatRegister(&ip_format, 0)
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

    /* initialize the string-map of field identifiers, and add the
     * locally defined fields. */
    if (createStringmap()) {
        skAppPrintErr("Unable to setup fields string map");
        exit(EXIT_FAILURE);
    }

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file */
    sksiteConfigure(0);

    /* parse the --fields switch if given */
    if (fields) {
        char *errmsg;
        if (parseFieldsString(fields, &errmsg)) {
            skAppPrintErr("Invalid %s: %s",
                          appOptions[OPT_FIELDS].name, errmsg);
            exit(EXIT_FAILURE);
        }

        if (parseMissingFieldValues()) {
            exit(EXIT_FAILURE);
        }
    } else if (missing_field) {
        skAppPrintErr("May only use --%s when --%s is also specified",
                      appOptions[OPT_MISSING_FIELD].name,
                      appOptions[OPT_FIELDS].name);
        exit(EXIT_FAILURE);
    }

    /* open the --output-path.  the 'of_name' member is NULL if user
     * did not specify an output-path. */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Unable to open %s '%s': %s",
                          appOptions[OPT_OUTPUT_PATH].name,
                          output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }
    }

    return;
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
    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_FIELDS:
        if (fields) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        fields = opt_arg;
        break;

      case OPT_MISSING_FIELD:
        if (NULL == missing_field) {
            missing_field = skVectorNew(sizeof(char *));
            if (NULL == missing_field) {
                skAppPrintOutOfMemory("vector");
                return 1;
            }
        }
        if (skVectorAppendValue(missing_field, &opt_arg)) {
            skAppPrintOutOfMemory("vector entry");
            return 1;
        }
        break;

      case OPT_INTEGER_SENSORS:
        app_flags.integer_sensors = 1;
        break;

      case OPT_INTEGER_TCP_FLAGS:
        app_flags.integer_tcp_flags = 1;
        break;

      case OPT_NO_TITLES:
        app_flags.no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        app_flags.no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        app_flags.no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        column_separator = opt_arg[0];
        break;

      case OPT_DELIMITED:
        app_flags.no_columns = 1;
        app_flags.no_final_delimiter = 1;
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
#define HELP_FIELDS_MSG                                                 \
    ("The following names may be used in the --%s and --%s switches\n"  \
     "for FIELD names. Names are case-insensitive"                      \
     " and may be abbreviated to the\n"                                 \
     "shortest unique prefix.\n")

    fprintf(fh, HELP_FIELDS_MSG,
            appOptions[OPT_FIELDS].name,
            appOptions[OPT_MISSING_FIELD].name);

    skStringMapPrintDetailedUsage(field_map, fh);
}


/*
 *  ok = createStringmap();
 *
 *    Create the global 'field_map'.  Return 0 on success, or -1 on
 *    failure.
 */
static int
createStringmap(
    void)
{
    sk_stringmap_status_t sm_err;
    sk_stringmap_entry_t sm_entry;
    sk_aggbag_type_iter_t iter;
    sk_aggbag_type_t type;
    unsigned int key_counter[] = {SK_AGGBAG_KEY, SK_AGGBAG_COUNTER};
    unsigned int i;

    memset(&sm_entry, 0, sizeof(sm_entry));

    sm_err = skStringMapCreate(&field_map);
    if (sm_err) {
        skAppPrintErr("Unable to create string map");
        return -1;
    }

    for (i = 0; i < sizeof(key_counter)/sizeof(key_counter[0]); ++i) {
        skAggBagFieldTypeIteratorBind(&iter, key_counter[i]);
        while ((sm_entry.name = skAggBagFieldTypeIteratorNext(&iter, &type))
               != NULL)
        {
            sm_entry.id = type;
            sm_entry.description = skAggBagFieldTypeGetDescription(type);
            sm_err = skStringMapAddEntries(field_map, 1, &sm_entry);
            if (sm_err) {
                skAppPrintErr("Unable to add %s field named '%s': %s",
                              ((SK_AGGBAG_KEY == key_counter[i])
                               ? "key" : "counter"),
                              sm_entry.name, skStringMapStrerror(sm_err));
                return -1;
            }
        }
    }

    return 0;
}


/*
 *  status = parseFieldsString(fields_string, &errmsg);
 *
 *    Parse the user's argument to the --fields switch and use it to allocate
 *    and fill the user_fields array.
 */
static int
parseFieldsString(
    const char         *fields_string,
    char              **errmsg)
{
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    user_field_data_t *uf;
    int rv = -1;

    /* parse the fields */
    if (skStringMapParse(field_map, fields_string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, errmsg))
    {
        goto END;
    }

    user_fields = ((user_field_data_t *)
                   calloc(1 + skStringMapIterCountMatches(iter),
                          sizeof(*user_fields)));
    if (NULL == user_fields) {
        skAppPrintOutOfMemory("user_fields");
        exit(EXIT_FAILURE);
    }

    uf = user_fields;
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        uf->field_type = (sk_aggbag_type_t)entry->id;
        uf->missing_string = empty_string;
        ++uf;
    }
    assert((uf - user_fields) == (ptrdiff_t)skStringMapIterCountMatches(iter));
    uf->field_type = SKAGGBAG_FIELD_INVALID;
    uf->missing_string = empty_string;

    rv = 0;

  END:
    skStringMapIterDestroy(iter);
    return rv;
}


/*
 *    For each NAME=VALUE specified to --missing-field, find NAME in the
 *    field_map, ensure NAME was specified in --fields, and set the missing
 *    value for that field to the string VALUE.  Do not parse VALUE.
 *
 *    Return an error if NAME is not a valid field, if NAME not in --fields,
 *    or if a previous value has already been set for NAME.
 */
static int
parseMissingFieldValues(
    void)
{
    sk_stringmap_entry_t *sm_entry;
    sk_stringmap_status_t sm_err;
    user_field_data_t *uf;
    char *argument;
    char *eq;
    size_t i;

    if (NULL == missing_field) {
        return 0;
    }

    /* parse each of the NAME=VALUE arguments */
    for (i = 0; 0 == skVectorGetValue(&argument, missing_field, i); ++i) {
        /* find the '=' */
        eq = strchr(argument, '=');
        if (NULL == eq) {
            skAppPrintErr("Invalid %s '%s': Unable to find '=' character",
                          appOptions[OPT_MISSING_FIELD].name, argument);
            return -1;
        }

        /* split into name and value */
        *eq = '\0';

        /* find the field with that name */
        sm_err = skStringMapGetByName(field_map, argument, &sm_entry);
        if (sm_err) {
            skAppPrintErr("Invalid %s: Unable to find a field named '%s': %s",
                          appOptions[OPT_MISSING_FIELD].name, argument,
                          skStringMapStrerror(sm_err));
            return -1;
        }

        /* find the field in the user_fields */
        for (uf = user_fields; uf->field_type != SKAGGBAG_FIELD_INVALID; ++uf) {
            if (uf->field_type == sm_entry->id) {
                break;
            }
        }
        if (SKAGGBAG_FIELD_INVALID == uf->field_type) {
            skAppPrintErr("Invalid %s: Field '%s' does not appear in --%s",
                          appOptions[OPT_MISSING_FIELD].name, sm_entry->name,
                          appOptions[OPT_FIELDS].name);
            return -1;
        }
        if (empty_string != uf->missing_string) {
            skAppPrintErr(("Invalid %s: Missing value previously set"
                           " for field '%s' ('%s')"),
                          appOptions[OPT_MISSING_FIELD].name, sm_entry->name,
                          uf->missing_string);
            return -1;
        }
        uf->missing_string = eq + 1;
    }

    return 0;
}


/*
 *    Return the file handle to use for output.  This invokes the
 *    pager if necessary.
 */
static FILE *
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
 *    Determine the widths of the output columns and print the titles when
 *    user_fields have not been specified.  Does nothing when --no-columns and
 *    --no-titles are true.
 */
static void
printTitles(
    const sk_aggbag_t  *ab,
    FILE               *fh)
{
    sk_aggbag_field_t field;
    sk_aggbag_aggregate_t agg;
    sk_aggbag_type_t t;
    unsigned int col;
    char delim[] = {'\0', '\0'};
    unsigned int kc;
    int w;

    if (app_flags.no_columns && app_flags.no_titles) {
        return;
    }

    col = 0;

    /* loop over keys then over counters */
    for (kc = 0; kc < 2; ++kc) {
        if (0 == kc) {
            skAggBagInitializeKey(ab, &agg, &field);
        } else {
            skAggBagInitializeCounter(ab, &agg, &field);
        }

        do {
            w = 0;
            t = skAggBagFieldIterGetType(&field);
            switch (t) {
              case SKAGGBAG_FIELD_SIPv4:
              case SKAGGBAG_FIELD_DIPv4:
              case SKAGGBAG_FIELD_NHIPv4:
              case SKAGGBAG_FIELD_ANY_IPv4:
                w = skipaddrStringMaxlen(0, ip_format);
                break;
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_ANY_IPv6:
                w = skipaddrStringMaxlen(1, ip_format);
                break;
              case SKAGGBAG_FIELD_SPORT:
              case SKAGGBAG_FIELD_DPORT:
              case SKAGGBAG_FIELD_ANY_PORT:
              case SKAGGBAG_FIELD_ELAPSED:
              case SKAGGBAG_FIELD_APPLICATION:
              case SKAGGBAG_FIELD_INPUT:
              case SKAGGBAG_FIELD_OUTPUT:
              case SKAGGBAG_FIELD_ANY_SNMP:
                w = 5;
                break;
              case SKAGGBAG_FIELD_PROTO:
              case SKAGGBAG_FIELD_ICMP_TYPE:
              case SKAGGBAG_FIELD_ICMP_CODE:
                w = 3;
                break;
              case SKAGGBAG_FIELD_PACKETS:
              case SKAGGBAG_FIELD_BYTES:
              case SKAGGBAG_FIELD_CUSTOM_KEY:
                w = 10;
                break;
              case SKAGGBAG_FIELD_STARTTIME:
              case SKAGGBAG_FIELD_ENDTIME:
              case SKAGGBAG_FIELD_ANY_TIME:
                if (timestamp_format & SKTIMESTAMP_EPOCH) {
                    w = 10;
                } else {
                    w = 19;
                }
                break;
              case SKAGGBAG_FIELD_FLAGS:
              case SKAGGBAG_FIELD_INIT_FLAGS:
              case SKAGGBAG_FIELD_REST_FLAGS:
                if (app_flags.integer_tcp_flags) {
                    w = 3;
                } else {
                    w = 8;
                }
                break;
              case SKAGGBAG_FIELD_TCP_STATE:
                w = 8;
                break;
              case SKAGGBAG_FIELD_SID:
                if (app_flags.integer_sensors) {
                    w = 5;
                } else {
                    w = sksiteSensorGetMaxNameStrLen();
                }
                break;
              case SKAGGBAG_FIELD_FTYPE_CLASS:
                w = sksiteClassGetMaxNameStrLen();
                break;
              case SKAGGBAG_FIELD_FTYPE_TYPE:
                w = (int)sksiteFlowtypeGetMaxTypeStrLen();
                break;
              case SKAGGBAG_FIELD_SIP_COUNTRY:
              case SKAGGBAG_FIELD_DIP_COUNTRY:
              case SKAGGBAG_FIELD_ANY_COUNTRY:
                w = 2;
                break;
              case SKAGGBAG_FIELD_RECORDS:
                w = 10;
                break;
              case SKAGGBAG_FIELD_SUM_BYTES:
                w = 20;
                break;
              case SKAGGBAG_FIELD_SUM_PACKETS:
                w = 15;
                break;
              case SKAGGBAG_FIELD_SUM_ELAPSED:
                w = 10;
                break;
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                w = 20;
                break;
              default:
                break;
            }

            if (w) {
                if (app_flags.no_titles) {
                    /* no_columns must be false; otherwise we would have
                     * returned at the top of this function */
                    width[col] = w;
                } else {
                    const char *name = skAggBagFieldTypeGetName(t);
                    if (app_flags.no_columns) {
                        fprintf(fh, "%s%s", delim, name);
                    } else {
                        width[col] = w;
                        fprintf(fh, "%s%*.*s", delim, w, w, name);
                    }
                    if (0 == col) {
                        delim[0] = column_separator;
                    }
                }
                ++col;
            }
        } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);
    }

    if (app_flags.no_titles) {
        /* do nothing */
    } else if (app_flags.no_final_delimiter) {
        fprintf(fh, "\n");
    } else {
        fprintf(fh, "%c\n", column_separator);
    }
}


/*
 *    Prints the contents of the AggBag when user_fields has not been
 *    specified.
 */
static void
printAggBag(
    const sk_aggbag_t  *ab,
    FILE               *fh)
{
    sk_aggbag_iter_t iter = SK_AGGBAG_ITER_INITIALIZER;
    sk_aggbag_iter_t *it = &iter;
    char buf[1024];
    uint64_t number;
    skipaddr_t ip;
    char delim[] = {'\0', '\0'};
    unsigned int col;

    printTitles(ab, fh);

    skAggBagIteratorBind(it, ab);

    while (skAggBagIteratorNext(it) == SK_ITERATOR_OK) {
        col = 0;
        do {
            switch (skAggBagFieldIterGetType(&it->key_field_iter)) {
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_SIPv4:
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_DIPv4:
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_NHIPv4:
              case SKAGGBAG_FIELD_ANY_IPv6:
              case SKAGGBAG_FIELD_ANY_IPv4:
                skAggBagAggregateGetIPAddress(
                    &it->key, &it->key_field_iter, &ip);
                fprintf(fh, "%s%*s", delim, width[col],
                        skipaddrString(buf, &ip, ip_format));
                ++col;
                break;
              case SKAGGBAG_FIELD_SPORT:
              case SKAGGBAG_FIELD_DPORT:
              case SKAGGBAG_FIELD_PROTO:
              case SKAGGBAG_FIELD_PACKETS:
              case SKAGGBAG_FIELD_BYTES:
              case SKAGGBAG_FIELD_ELAPSED:
              case SKAGGBAG_FIELD_INPUT:
              case SKAGGBAG_FIELD_OUTPUT:
              case SKAGGBAG_FIELD_APPLICATION:
              case SKAGGBAG_FIELD_ICMP_TYPE:
              case SKAGGBAG_FIELD_ICMP_CODE:
              case SKAGGBAG_FIELD_ANY_PORT:
              case SKAGGBAG_FIELD_ANY_SNMP:
              case SKAGGBAG_FIELD_CUSTOM_KEY:
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                fprintf(fh, "%s%*" PRIu64, delim, width[col], number);
                ++col;
                break;
              case SKAGGBAG_FIELD_STARTTIME:
              case SKAGGBAG_FIELD_ENDTIME:
              case SKAGGBAG_FIELD_ANY_TIME:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                fprintf(fh, "%s%*s", delim, width[col],
                        sktimestamp_r(buf, sktimeCreate(number, 0),
                                      timestamp_format));
                ++col;
                break;
              case SKAGGBAG_FIELD_FLAGS:
              case SKAGGBAG_FIELD_INIT_FLAGS:
              case SKAGGBAG_FIELD_REST_FLAGS:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                fprintf(fh, "%s%*s", delim, width[col],
                        skTCPFlagsString(number, buf, 0));
                ++col;
                break;
              case SKAGGBAG_FIELD_TCP_STATE:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                fprintf(fh, "%s%*s", delim, width[col],
                        skTCPStateString(number, buf, 0));
                ++col;
                break;
              case SKAGGBAG_FIELD_SID:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                sksiteSensorGetName(buf, sizeof(buf), number);
                fprintf(fh, "%s%*s", delim, width[col], buf);
                ++col;
                break;
              case SKAGGBAG_FIELD_FTYPE_CLASS:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                sksiteClassGetName(buf, sizeof(buf), number);
                fprintf(fh, "%s%*s", delim, width[col], buf);
                ++col;
                break;
              case SKAGGBAG_FIELD_FTYPE_TYPE:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                sksiteFlowtypeGetType(buf, sizeof(buf), number);
                fprintf(fh, "%s%*s", delim, width[col], buf);
                ++col;
                break;
              case SKAGGBAG_FIELD_SIP_COUNTRY:
              case SKAGGBAG_FIELD_DIP_COUNTRY:
              case SKAGGBAG_FIELD_ANY_COUNTRY:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &number);
                skCountryCodeToName(number, buf, sizeof(buf));
                fprintf(fh, "%s%*s", delim, width[col], buf);
                ++col;
                break;
              default:
                break;
            }
            if (1 == col) {
                delim[0] = column_separator;
            }
        } while (skAggBagFieldIterNext(&it->key_field_iter) == SK_ITERATOR_OK);

        /* handle counter fields */
        do {
            switch (skAggBagFieldIterGetType(&it->counter_field_iter)) {
              case SKAGGBAG_FIELD_RECORDS:
              case SKAGGBAG_FIELD_SUM_BYTES:
              case SKAGGBAG_FIELD_SUM_PACKETS:
              case SKAGGBAG_FIELD_SUM_ELAPSED:
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                skAggBagAggregateGetUnsigned(
                    &it->counter, &it->counter_field_iter, &number);
                fprintf(fh, "%s%*" PRIu64, delim, width[col], number);
                ++col;
                break;
              default:
                break;
            }
        } while (skAggBagFieldIterNext(&it->counter_field_iter)
                 == SK_ITERATOR_OK);

        if (app_flags.no_final_delimiter) {
            fprintf(fh, "\n");
        } else {
            fprintf(fh, "%c\n", column_separator);
        }
        delim[0] = '\0';
    }

    skAggBagIteratorFree(it);
}


/*
 *    Determine the widths of the output columns and print the titles using
 *    user_fields.  Does nothing when --no-columns and --no-titles are true.
 */
static void
printTitlesUserFields(
    FILE           *fh)
{
    char delim[] = {'\0', '\0'};
    const user_field_data_t *uf;
    size_t missing_width;
    unsigned int col;
    int w;

    if (app_flags.no_columns && app_flags.no_titles) {
        return;
    }

    col = 0;
    for (uf = user_fields; uf->field_type != SKAGGBAG_FIELD_INVALID; ++uf) {
        w = 0;
        switch (uf->field_type) {
          case SKAGGBAG_FIELD_SIPv4:
          case SKAGGBAG_FIELD_DIPv4:
          case SKAGGBAG_FIELD_NHIPv4:
          case SKAGGBAG_FIELD_ANY_IPv4:
            w = skipaddrStringMaxlen(0, ip_format);
            break;
          case SKAGGBAG_FIELD_SIPv6:
          case SKAGGBAG_FIELD_DIPv6:
          case SKAGGBAG_FIELD_NHIPv6:
          case SKAGGBAG_FIELD_ANY_IPv6:
            w = skipaddrStringMaxlen(1, ip_format);
            break;
          case SKAGGBAG_FIELD_SPORT:
          case SKAGGBAG_FIELD_DPORT:
          case SKAGGBAG_FIELD_ANY_PORT:
          case SKAGGBAG_FIELD_ELAPSED:
          case SKAGGBAG_FIELD_APPLICATION:
          case SKAGGBAG_FIELD_INPUT:
          case SKAGGBAG_FIELD_OUTPUT:
          case SKAGGBAG_FIELD_ANY_SNMP:
            w = 5;
            break;
          case SKAGGBAG_FIELD_PROTO:
          case SKAGGBAG_FIELD_ICMP_TYPE:
          case SKAGGBAG_FIELD_ICMP_CODE:
            w = 3;
            break;
          case SKAGGBAG_FIELD_PACKETS:
          case SKAGGBAG_FIELD_BYTES:
          case SKAGGBAG_FIELD_CUSTOM_KEY:
            w = 10;
            break;
          case SKAGGBAG_FIELD_STARTTIME:
          case SKAGGBAG_FIELD_ENDTIME:
          case SKAGGBAG_FIELD_ANY_TIME:
            if (timestamp_format & SKTIMESTAMP_EPOCH) {
                w = 10;
            } else {
                w = 19;
            }
            break;
          case SKAGGBAG_FIELD_FLAGS:
          case SKAGGBAG_FIELD_INIT_FLAGS:
          case SKAGGBAG_FIELD_REST_FLAGS:
            if (app_flags.integer_tcp_flags) {
                w = 3;
            } else {
                w = 8;
            }
            break;
          case SKAGGBAG_FIELD_TCP_STATE:
            w = 8;
            break;
          case SKAGGBAG_FIELD_SID:
            if (app_flags.integer_sensors) {
                w = 5;
            } else {
                w = sksiteSensorGetMaxNameStrLen();
            }
            break;
          case SKAGGBAG_FIELD_FTYPE_CLASS:
            w = sksiteClassGetMaxNameStrLen();
            break;
          case SKAGGBAG_FIELD_FTYPE_TYPE:
            w = (int)sksiteFlowtypeGetMaxTypeStrLen();
            break;
          case SKAGGBAG_FIELD_SIP_COUNTRY:
          case SKAGGBAG_FIELD_DIP_COUNTRY:
          case SKAGGBAG_FIELD_ANY_COUNTRY:
            w = 2;
            break;
          case SKAGGBAG_FIELD_RECORDS:
            w = 10;
            break;
          case SKAGGBAG_FIELD_SUM_BYTES:
            w = 20;
            break;
          case SKAGGBAG_FIELD_SUM_PACKETS:
            w = 15;
            break;
          case SKAGGBAG_FIELD_SUM_ELAPSED:
            w = 10;
            break;
          case SKAGGBAG_FIELD_CUSTOM_COUNTER:
            w = 20;
            break;
          default:
            break;
        }

        if (w) {
            missing_width = strlen(uf->missing_string);
            if (w < (int)missing_width) {
                w = (int)missing_width;
            }

            if (app_flags.no_titles) {
                width[col] = w;
            } else {
                const char *name = skAggBagFieldTypeGetName(uf->field_type);
                if (app_flags.no_columns) {
                    fprintf(fh, "%s%s", delim, name);
                } else {
                    width[col] = w;
                    fprintf(fh, "%s%*.*s", delim, w, w, name);
                }
                if (0 == col) {
                    delim[0] = column_separator;
                }
            }
            ++col;
        }
    }

    if (app_flags.no_titles) {
        /* do nothing */
    } else if (app_flags.no_final_delimiter) {
        fprintf(fh, "\n");
    } else {
        fprintf(fh, "%c\n", column_separator);
    }
}


/*
 *    Given the AggBag `ab`, for its key or counter at position `pos`
 *    determines which `user_fields[col].value` to write the value into, for
 *    all `pos`.  Sets `order[pos]` to `col` or leaves it unchanged if the
 *    key/counter at position `pos` is not in `user_fields`.  Assumes order[]
 *    has been initialized with all bits high.
 */
static void
determineFieldMappingUserFields(
    const sk_aggbag_t  *ab,
    uint8_t             order[])
{
    sk_aggbag_field_t field;
    sk_aggbag_aggregate_t agg;
    sk_aggbag_type_t ab_field_type;
    user_field_data_t *uf;
    unsigned int col;
    unsigned int pos;
    unsigned int kc;

    /* set all fields in user_fields to be missing */
    for (uf = user_fields; uf->field_type != SKAGGBAG_FIELD_INVALID; ++uf) {
        uf->is_missing = 1;
    }

    pos = 0;

    /* loop over keys then over counters */
    for (kc = 0; kc < 2; ++kc) {
        if (0 == kc) {
            skAggBagInitializeKey(ab, &agg, &field);
        } else {
            skAggBagInitializeCounter(ab, &agg, &field);
        }

        do {
            ab_field_type = skAggBagFieldIterGetType(&field);

            /* find the AggBag's field in user_fields */
            for (uf = user_fields, col = 0;
                 uf->field_type != SKAGGBAG_FIELD_INVALID;
                 ++uf, ++col)
            {
                if (ab_field_type == uf->field_type) {
                    assert(pos < AGGBAGCAT_ARRAY_SIZE);
                    order[pos] = col;
                    uf->is_missing = 0;
                    break;
                }
            }
            ++pos;
        } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);
    }
}


/*
 *    Prints the contents of the AggBag when user_fields is active.
 */
static void
printAggBagUserFields(
    const sk_aggbag_t  *ab,
    FILE               *fh)
{
    static int first_file = 1;
    sk_aggbag_iter_t iter = SK_AGGBAG_ITER_INITIALIZER;
    sk_aggbag_iter_t *it = &iter;
    user_field_data_t *uf;
    char buf[1024];
    char delim[] = {'\0', '\0'};
    unsigned int col;
    unsigned int pos;

    /* contains the mapping from user_fields to AggBag fields, where order[i]
     * contains the index into user_fields[].  If order[i] is 0xff,
     * user_fields does not contain that field. */
    uint8_t order[AGGBAGCAT_ARRAY_SIZE];

    /* print titles and determine widths when processing the first file */
    if (first_file) {
        first_file = 0;
        printTitlesUserFields(fh);
    }

    /* determine the index into user_fields[] to use for each key/counter */
    memset(order, 0xff, sizeof(order));
    determineFieldMappingUserFields(ab, order);

    /* visit the "rows" in the AggBag */
    skAggBagIteratorBind(it, ab);
    while (skAggBagIteratorNext(it) == SK_ITERATOR_OK) {
        /* first loop over the key and counter fields and fill the
         * user_fields[x].value with the value from the AggBag */

        pos = 0;
        /* handle key fields */
        do {
            if (UINT8_MAX == order[pos]) {
                continue;
            }
            uf = &user_fields[order[pos]];
            assert(skAggBagFieldIterGetType(&it->key_field_iter)
                   == uf->field_type);
            switch (uf->field_type) {
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_SIPv4:
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_DIPv4:
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_NHIPv4:
              case SKAGGBAG_FIELD_ANY_IPv6:
              case SKAGGBAG_FIELD_ANY_IPv4:
                skAggBagAggregateGetIPAddress(
                    &it->key, &it->key_field_iter, &uf->value.ip);
                break;
              case SKAGGBAG_FIELD_SPORT:
              case SKAGGBAG_FIELD_DPORT:
              case SKAGGBAG_FIELD_PROTO:
              case SKAGGBAG_FIELD_PACKETS:
              case SKAGGBAG_FIELD_BYTES:
              case SKAGGBAG_FIELD_ELAPSED:
              case SKAGGBAG_FIELD_INPUT:
              case SKAGGBAG_FIELD_OUTPUT:
              case SKAGGBAG_FIELD_APPLICATION:
              case SKAGGBAG_FIELD_ICMP_TYPE:
              case SKAGGBAG_FIELD_ICMP_CODE:
              case SKAGGBAG_FIELD_ANY_PORT:
              case SKAGGBAG_FIELD_ANY_SNMP:
              case SKAGGBAG_FIELD_CUSTOM_KEY:
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_STARTTIME:
              case SKAGGBAG_FIELD_ENDTIME:
              case SKAGGBAG_FIELD_ANY_TIME:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_FLAGS:
              case SKAGGBAG_FIELD_INIT_FLAGS:
              case SKAGGBAG_FIELD_REST_FLAGS:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_TCP_STATE:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_SID:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_FTYPE_CLASS:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_FTYPE_TYPE:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              case SKAGGBAG_FIELD_SIP_COUNTRY:
              case SKAGGBAG_FIELD_DIP_COUNTRY:
              case SKAGGBAG_FIELD_ANY_COUNTRY:
                skAggBagAggregateGetUnsigned(
                    &it->key, &it->key_field_iter, &uf->value.number);
                break;
              default:
                break;
            }
        } while (++pos && (skAggBagFieldIterNext(&it->key_field_iter)
                           == SK_ITERATOR_OK));

        /* handle counter fields */
        do {
            if (UINT8_MAX == order[pos]) {
                continue;
            }
            uf = &user_fields[order[pos]];
            assert(skAggBagFieldIterGetType(&it->counter_field_iter)
                   == uf->field_type);
            switch (uf->field_type) {
              case SKAGGBAG_FIELD_RECORDS:
              case SKAGGBAG_FIELD_SUM_BYTES:
              case SKAGGBAG_FIELD_SUM_PACKETS:
              case SKAGGBAG_FIELD_SUM_ELAPSED:
              case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                skAggBagAggregateGetUnsigned(
                    &it->counter, &it->counter_field_iter, &uf->value.number);
                break;
              default:
                break;
            }
        } while (++pos && (skAggBagFieldIterNext(&it->counter_field_iter)
                           == SK_ITERATOR_OK));

        /* loop over user_fields[] and print each */
        for (uf = user_fields, col = 0;
             uf->field_type != SKAGGBAG_FIELD_INVALID;
             ++uf, ++col)
        {
            if (uf->is_missing) {
                /* not present, display the missing_string */
                fprintf(fh, "%s%*s", delim, width[col], uf->missing_string);
            } else {
                switch (uf->field_type) {
                  case SKAGGBAG_FIELD_SIPv6:
                  case SKAGGBAG_FIELD_SIPv4:
                  case SKAGGBAG_FIELD_DIPv6:
                  case SKAGGBAG_FIELD_DIPv4:
                  case SKAGGBAG_FIELD_NHIPv6:
                  case SKAGGBAG_FIELD_NHIPv4:
                  case SKAGGBAG_FIELD_ANY_IPv6:
                  case SKAGGBAG_FIELD_ANY_IPv4:
                    fprintf(fh, "%s%*s", delim, width[col],
                            skipaddrString(buf, &uf->value.ip, ip_format));
                    break;
                  case SKAGGBAG_FIELD_SPORT:
                  case SKAGGBAG_FIELD_DPORT:
                  case SKAGGBAG_FIELD_PROTO:
                  case SKAGGBAG_FIELD_PACKETS:
                  case SKAGGBAG_FIELD_BYTES:
                  case SKAGGBAG_FIELD_ELAPSED:
                  case SKAGGBAG_FIELD_INPUT:
                  case SKAGGBAG_FIELD_OUTPUT:
                  case SKAGGBAG_FIELD_APPLICATION:
                  case SKAGGBAG_FIELD_ICMP_TYPE:
                  case SKAGGBAG_FIELD_ICMP_CODE:
                  case SKAGGBAG_FIELD_ANY_PORT:
                  case SKAGGBAG_FIELD_ANY_SNMP:
                  case SKAGGBAG_FIELD_CUSTOM_KEY:
                  case SKAGGBAG_FIELD_CUSTOM_COUNTER:
                  case SKAGGBAG_FIELD_RECORDS:
                  case SKAGGBAG_FIELD_SUM_BYTES:
                  case SKAGGBAG_FIELD_SUM_PACKETS:
                  case SKAGGBAG_FIELD_SUM_ELAPSED:
                    fprintf(fh, "%s%*" PRIu64, delim, width[col],
                            uf->value.number);
                    break;
                  case SKAGGBAG_FIELD_STARTTIME:
                  case SKAGGBAG_FIELD_ENDTIME:
                  case SKAGGBAG_FIELD_ANY_TIME:
                    fprintf(fh, "%s%*s", delim, width[col],
                            sktimestamp_r(buf,
                                          sktimeCreate(uf->value.number, 0),
                                          timestamp_format));
                    break;
                  case SKAGGBAG_FIELD_FLAGS:
                  case SKAGGBAG_FIELD_INIT_FLAGS:
                  case SKAGGBAG_FIELD_REST_FLAGS:
                    fprintf(fh, "%s%*s", delim, width[col],
                            skTCPFlagsString(uf->value.number, buf, 0));
                    break;
                  case SKAGGBAG_FIELD_TCP_STATE:
                    fprintf(fh, "%s%*s", delim, width[col],
                            skTCPStateString(uf->value.number, buf, 0));
                    break;
                  case SKAGGBAG_FIELD_SID:
                    sksiteSensorGetName(buf, sizeof(buf), uf->value.number);
                    fprintf(fh, "%s%*s", delim, width[col], buf);
                    break;
                  case SKAGGBAG_FIELD_FTYPE_CLASS:
                    sksiteClassGetName(buf, sizeof(buf), uf->value.number);
                    fprintf(fh, "%s%*s", delim, width[col], buf);
                    break;
                  case SKAGGBAG_FIELD_FTYPE_TYPE:
                    sksiteFlowtypeGetType(buf, sizeof(buf), uf->value.number);
                    fprintf(fh, "%s%*s", delim, width[col], buf);
                    break;
                  case SKAGGBAG_FIELD_SIP_COUNTRY:
                  case SKAGGBAG_FIELD_DIP_COUNTRY:
                  case SKAGGBAG_FIELD_ANY_COUNTRY:
                    skCountryCodeToName(uf->value.number, buf, sizeof(buf));
                    fprintf(fh, "%s%*s", delim, width[col], buf);
                    break;
                  default:
                    break;
                }
            }
            if (0 == col) {
                delim[0] = column_separator;
            }
        }

        if (app_flags.no_final_delimiter) {
            fprintf(fh, "\n");
        } else {
            fprintf(fh, "%c\n", column_separator);
        }
        delim[0] = '\0';
    }

    skAggBagIteratorFree(it);
}


int main(int argc, char **argv)
{
    char *filename;
    FILE *fh;
    sk_aggbag_t *ab;
    ssize_t rv;
    int err;

    /* Global setup */
    appSetup(argc, argv);

    fh = NULL;
    while ((rv = skOptionsCtxNextArgument(optctx, &filename)) == 0) {
        err = skAggBagLoad(&ab, filename);
        if (err != SKAGGBAG_OK) {
            skAppPrintErr("Error reading aggbag from input stream '%s': %s",
                          filename, skAggBagStrerror(err));
            exit(EXIT_FAILURE);
        }

        if (NULL == fh) {
            fh = getOutputHandle();
        }

        if (user_fields) {
            printAggBagUserFields(ab, fh);
        } else {
            printAggBag(ab, fh);
        }

        skAggBagDestroy(&ab);
    }

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
