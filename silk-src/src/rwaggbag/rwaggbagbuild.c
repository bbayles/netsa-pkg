/*
** Copyright (C) 2017-2023 by Carnegie Mellon University.
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
 *  rwaggbagbuild.c
 *
 *    Read textual input and create an Aggregate Bag.
 *
 *  Mark Thomas
 *  January 2017
 *
 */
#define AB_SETBAG  0

#include <silk/silk.h>

RCSIDENT("$SiLK: rwaggbagbuild.c 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/rwascii.h>
#include <silk/skaggbag.h>
#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#if AB_SETBAG
#include <silk/skbag.h>
#include <silk/skipset.h>
#endif  /* AB_SETBAG */

/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* size to use for arrays that hold field IDs */
#define AGGBAGBUILD_ARRAY_SIZE      65536

/* the longest input line to accept; lines longer than this size are
 * ignored */
#define AGGBAGBUILD_LINE_BUFSIZE    2048

/* the ident for the "ignored" field */
#define AGGBAGBUILD_FIELD_IGNORED   ((sk_stringmap_id_t)INT32_MAX)

/* whitespace chars used in strspn(); list taken from isspace() */
#define AGGBAGBUILD_WHITESPACE      "\t\v\f\r "

/* the default input type */
#define AGGBAGBUILD_DEFAULT_INPUT_TYPE  AGGBAGBUILD_INPUT_TEXT

/* parsed_value_t is a structure to hold the unparsed value, an
 * indication as to whether the value is active, and the parsed
 * value. there is an array of these for all possible field
 * identifiers */
typedef struct parsed_value_st {
    const char     *pv_raw;
    /* True if the field is part of the key or counter */
    unsigned        pv_is_used  : 1;
    /* True if the field was specified by --constant-field and its
     * value only needs to be computed once */
    unsigned        pv_is_const : 1;
    /* True if the value of the field is fixed for this input file
     * because either it was not mentioned in file's title line or
     * because it was mentioned in --constant-field */
    unsigned        pv_is_fixed : 1;
    union parsed_value_v_un {
        uint64_t        pv_int;
        sktime_t        pv_time;
        skipaddr_t      pv_ip;
    }               pv;
} parsed_value_t;

/* current input line */
typedef struct current_line_st {
    /* input line (as read from input) */
    char        text[AGGBAGBUILD_LINE_BUFSIZE];
    /* input stream currently being processed */
    skstream_t *stream;
    /* line number in the 'stream' */
    int         lineno;
} current_line_t;

typedef enum input_type_en {
    AGGBAGBUILD_INPUT_TEXT = 1
#if AB_SETBAG
    ,AGGBAGBUILD_INPUT_IPSET,
    AGGBAGBUILD_INPUT_BAG
#endif  /* #if AB_SETBAG */
} input_type_t;


/* LOCAL VARIABLES */

/* fields in addition to those provided by rwascii */
static sk_stringmap_entry_t aggbagbuild_fields[] = {
    {"ignore", AGGBAGBUILD_FIELD_IGNORED,
     "field to be skipped when parsing (repeatable)", NULL},
    SK_STRINGMAP_SENTINEL
};

/* available types of input */
static sk_stringmap_entry_t input_types[] = {
    {"text",    AGGBAGBUILD_INPUT_TEXT,     NULL, NULL},
#if AB_SETBAG
    {"ipset",   AGGBAGBUILD_INPUT_IPSET,    NULL, NULL},
    {"bag",     AGGBAGBUILD_INPUT_BAG,      NULL, NULL},
#endif  /* #if AB_SETBAG */
    SK_STRINGMAP_SENTINEL
};

/* where to send output, set by --output-path */
static skstream_t *out_stream = NULL;

/* where to copy bad input lines, set by --bad-output-lines */
static skstream_t *bad_stream = NULL;

/* number of lines that are bad */
static unsigned int bad_line_count = 0;

/* whether to report parsing errors, set by --verbose */
static int verbose = 0;

/* whether to halt on first error, set by --stop-on-error */
static int stop_on_error = 0;

/* whether to always parse the first line as data, set by --no-titles */
static int no_titles = 0;

/* available fields */
static sk_stringmap_t *field_map = NULL;

/* the argument to the --fields switch */
static char *fields = NULL;

/* the fields (columns) to parse in the order to parse them; each
 * value is an ID from field_map, set by --fields */
static sk_vector_t *field_vec = NULL;

/* each argument to the --constant-field switch; switch may be
 * repeated; vector of char* */
static sk_vector_t *constant_field = NULL;

/* fields that have a constant value for all inputs; vector of IDs */
static sk_vector_t *const_fields = NULL;

/* fields that have been parsed; the index into this array an
 * sk_aggbag_type_t type ID */
static parsed_value_t parsed_value[AGGBAGBUILD_ARRAY_SIZE];

/* type of input */
static input_type_t input_type = AGGBAGBUILD_DEFAULT_INPUT_TYPE;

/* string-map for parsing the input_type */
static sk_stringmap_t *input_type_map = NULL;

/* character that separates input fields (the delimiter) */
static char column_separator = '|';

/* for processing the input files */
static sk_options_ctx_t *optctx;

/* current input line and stream from which it was read */
static current_line_t current_line;

/* a pointer to the current input line */
static current_line_t *curline = &current_line;

/* the aggbag to create */
static sk_aggbag_t *ab = NULL;

/* options for writing the AggBag file */
static sk_aggbag_options_t ab_options;


/* OPTIONS SETUP */

typedef enum {
    OPT_HELP_FIELDS,
#if AB_SETBAG
    OPT_INPUT_TYPE,
#endif  /* #if AB_SETBAG */
    OPT_FIELDS,
    OPT_CONSTANT_FIELD,
    OPT_COLUMN_SEPARATOR,
    OPT_OUTPUT_PATH,
    OPT_BAD_INPUT_LINES,
    OPT_VERBOSE,
    OPT_STOP_ON_ERROR,
    OPT_NO_TITLES
} appOptionsEnum;


static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
#if AB_SETBAG
    {"input-type",          REQUIRED_ARG, 0, OPT_INPUT_TYPE},
#endif  /* #if AB_SETBAG */
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {"constant-field",      REQUIRED_ARG, 0, OPT_CONSTANT_FIELD},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"bad-input-lines",     REQUIRED_ARG, 0, OPT_BAD_INPUT_LINES},
    {"verbose",             NO_ARG,       0, OPT_VERBOSE},
    {"stop-on-error",       NO_ARG,       0, OPT_STOP_ON_ERROR},
    {"no-titles",           NO_ARG,       0, OPT_NO_TITLES},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each supported field and exit. Def. no",
#if AB_SETBAG
    ("Specify the type of input to read"),
#endif  /* #if AB_SETBAG */
    NULL, /* generated dynamically */
    ("Given an argument of FIELD=VALUE, add the extra\n"
     "\tfield FIELD to each entry in the Aggregate Bag and give that field\n"
     "\tthe specified value.  May be repeated to set multiple FIELDs"),
    "Split input fields on this character. Def. '|'",
    "Write the aggregate bag to this stream. Def. stdout",
    ("Write each bad input line to this file or stream.\n"
     "\tLines will have the file name and line number prepended. Def. none"),
    ("Print an error message for each bad input line to the\n"
     "\tstandard error. Def. Quietly ignore errors"),
    ("Print an error message for a bad input line to stderr\n"
     "\tand exit. Def. Quietly ignore errors and continue processing"),
    ("Parse the first line as record values. Requires --fields.\n"
     "\tDef. Skip first line if it appears to contain titles"),
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  createStringmap(void);
static void helpFields(FILE *fh);
#if AB_SETBAG
static int  parseInputType(const char *type_string);
#endif  /* #if AB_SETBAG */
static int  parseFieldList(const char *field_string, char **errmsg);
static int  parseConstantFieldValues(void);
static int  setAggBagFields(void);
static void badLine(const char *fmt, ...)  SK_CHECK_PRINTF(1, 2);


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
     "\tCreate a binary Aggregate Bag file from textual input and write it\n" \
     "\tto the standard output or the specified --output-path.  The input\n"  \
     "\tshould contain delimited field values. The names of the fields may\n" \
     "\tbe specified in the --fields switch or the first line of the\n"       \
     "\tinput.  At least one key and one counter field are required.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;
#if AB_SETBAG
    unsigned int j;
#endif  /* #if AB_SETBAG */

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
#if AB_SETBAG
          case OPT_INPUT_TYPE:
            fprintf(fh, "%s. Def. %s\n\tChoices: %s",
                    appHelp[i],
                    skStringMapGetFirstName(input_type_map,
                                            AGGBAGBUILD_DEFAULT_INPUT_TYPE),
                    input_types[0].name);
            for (j = 1; input_types[j].name; ++j) {
                fprintf(fh, ", %s", input_types[j].name);
            }
            fprintf(fh, "\n");
            break;
#endif  /* #if AB_SETBAG */
          case OPT_FIELDS:
            fprintf(fh, ("Parse the input into this comma-separated set of"
                         " fields and\n\tadd to the Aggregate Bag.\n"));
            skStringMapPrintUsage(field_map, fh, 4);
            break;
          case OPT_OUTPUT_PATH:
            /* include the help for --notes and --invocation-strip
             * after --output-path */
            fprintf(fh, "%s\n", appHelp[i]);
            skAggBagOptionsUsage(fh);
            break;
          default:
            /* Simple static help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
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
    static int teardownFlag = 0;
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (out_stream) {
        rv = skStreamClose(out_stream);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&out_stream);
    }

    if (bad_stream) {
        rv = skStreamClose(bad_stream);
        if (SKSTREAM_OK == rv) {
            if (0 == bad_line_count && skStreamIsSeekable(bad_stream)) {
                unlink(skStreamGetPathname(bad_stream));
            }
        } else if (rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(bad_stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&bad_stream);
        bad_stream = NULL;
    }

    skVectorDestroy(constant_field);
    constant_field = NULL;
    skVectorDestroy(const_fields);
    const_fields = NULL;
    skVectorDestroy(field_vec);
    field_vec = NULL;

    (void)skStringMapDestroy(input_type_map);
    input_type_map = NULL;
    (void)skStringMapDestroy(field_map);
    field_map = NULL;

    skAggBagOptionsTeardown();
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
    sk_stringmap_status_t sm_err;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(parsed_value, 0, sizeof(parsed_value));
    memset(&ab_options, 0, sizeof(sk_aggbag_options_t));
    ab_options.argc = argc;
    ab_options.argv = argv;

    optctx_flags = (SK_OPTIONS_CTX_ALLOW_STDIN | SK_OPTIONS_CTX_XARGS
                    | SK_OPTIONS_CTX_INPUT_BINARY);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skAggBagOptionsRegister(&ab_options)
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

    /* initialize the string-map of field identifiers, and add the
     * locally defined fields. */
    if (createStringmap()) {
        skAppPrintErr("Unable to setup fields string map");
        exit(EXIT_FAILURE);
    }

    /* initialize the string-map of input-types */
    if ((sm_err = skStringMapCreate(&input_type_map))
        || (sm_err = skStringMapAddEntries(input_type_map, -1, input_types)))
    {
        skAppPrintErr("Unable to input-type string map");
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();
    }

    /* cannot specify --no-titles unless --fields is given */
    if (no_titles && !fields) {
        skAppPrintErr("May only use --%s when --%s is specified",
                      appOptions[OPT_NO_TITLES].name,
                      appOptions[OPT_FIELDS].name);
        skAppUsage();
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* create the aggregate bag */
    if (skAggBagCreate(&ab)) {
        exit(EXIT_FAILURE);
    }
    skAggBagOptionsBind(ab, &ab_options);

    /* parse each of the constant field values */
    parseConstantFieldValues();

    /* parse the --fields switch if given */
    if (fields) {
        char *errmsg;
        if (parseFieldList(fields, &errmsg)) {
            skAppPrintErr("Invalid %s: %s",
                          appOptions[OPT_FIELDS].name, errmsg);
            exit(EXIT_FAILURE);
        }
        if (setAggBagFields()) {
            exit(EXIT_FAILURE);
        }
    }

    /* use "stdout" as default output path */
    if (NULL == out_stream) {
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(out_stream, "stdout")))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skAppPrintErr("Could not create output stream");
            exit(EXIT_FAILURE);
        }
    }

    /* open bad output, but first ensure it is not the same as the
     * record output */
    if (bad_stream) {
        if (0 == strcmp(skStreamGetPathname(out_stream),
                        skStreamGetPathname(bad_stream)))
        {
            skAppPrintErr("Cannot use same stream for bad input and records");
            exit(EXIT_FAILURE);
        }
        rv = skStreamOpen(bad_stream);
        if (rv) {
            skStreamPrintLastErr(bad_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* open output */
    rv = skStreamOpen(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    const char *char_name;
    int rv;

    SK_UNUSED_PARAM(cData);

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

#if AB_SETBAG
      case OPT_INPUT_TYPE:
        if (parseInputType(opt_arg)) {
            return 1;
        }
        break;
#endif  /* #if AB_SETBAG */

      case OPT_FIELDS:
        if (fields) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        fields = opt_arg;
        break;

      case OPT_CONSTANT_FIELD:
        if (NULL == constant_field) {
            constant_field = skVectorNew(sizeof(char *));
            if (NULL == constant_field) {
                skAppPrintOutOfMemory("vector");
                return 1;
            }
        }
        if (skVectorAppendValue(constant_field, &opt_arg)) {
            skAppPrintOutOfMemory("vector entry");
            return 1;
        }
        break;

      case OPT_COLUMN_SEPARATOR:
        switch (opt_arg[0]) {
          case '#':
            char_name = "comment start('#')";
            break;
          case '\n':
            char_name = "newline";
            break;
          case '\r':
            char_name = "carriage return";
            break;
          case '\0':
            char_name = "end-of-string";
            break;
          default:
            char_name = NULL;
            break;
        }
        if (char_name) {
            skAppPrintErr("Invalid %s: May not be the %s character",
                          appOptions[opt_index].name, char_name);
            return 1;
        }
        column_separator = opt_arg[0];
        break;

      case OPT_OUTPUT_PATH:
        if (out_stream) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(out_stream, opt_arg)))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            return 1;
        }
        break;

      case OPT_BAD_INPUT_LINES:
        if (bad_stream) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&bad_stream, SK_IO_WRITE, SK_CONTENT_TEXT))
            || (rv = skStreamBind(bad_stream, opt_arg)))
        {
            skStreamPrintLastErr(bad_stream, rv, &skAppPrintErr);
            return 1;
        }
        break;

      case OPT_VERBOSE:
        verbose = 1;
        break;

      case OPT_STOP_ON_ERROR:
        stop_on_error = 1;
        break;

      case OPT_NO_TITLES:
        no_titles = 1;
        break;
    }

    return 0;  /* OK */
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
            appOptions[OPT_CONSTANT_FIELD].name);

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

#ifndef NDEBUG
    {
        sk_stringmap_iter_t *sm_iter = NULL;

        skStringMapGetByID(field_map, AGGBAGBUILD_FIELD_IGNORED, &sm_iter);
        if (0 != skStringMapIterCountMatches(sm_iter)) {
            skStringMapIterDestroy(sm_iter);
            skAbort();
        }
        skStringMapIterDestroy(sm_iter);
    }
#endif  /* NDEBUG */

    sm_err = skStringMapAddEntries(field_map, -1, aggbagbuild_fields);
    if (sm_err) {
        skAppPrintErr("Unable to add fields: %s", skStringMapStrerror(sm_err));
        return -1;
    }

    return 0;
}


/*
 *  status = parseFieldList(fields_string, &errmsg);
 *
 *    Parse the user's argument to the --fields switch or from the
 *    first line of the input and fill the global 'field_vec' vector
 *    with the field IDs.  Return 0 on success; -1 on failure.
 */
static int
parseFieldList(
    const char         *field_string,
    char              **errmsg)
{
    static char buf[256];
    BITMAP_DECLARE(field_dup, AGGBAGBUILD_ARRAY_SIZE);
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    int rv = -1;

    /* parse the fields; duplicate 'ignore' fields are okay, but any
     * other duplcate is an error */
    if (skStringMapParse(field_map, field_string, SKSTRINGMAP_DUPES_KEEP,
                         &iter, errmsg))
    {
        goto END;
    }

    /* check for duplicate fields */
    BITMAP_INIT(field_dup);
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (AGGBAGBUILD_FIELD_IGNORED != entry->id) {
            if (BITMAP_GETBIT(field_dup, entry->id)) {
                snprintf(buf, sizeof(buf), "Duplicate name '%s'", entry->name);
                *errmsg = buf;
                goto END;
            }
            BITMAP_SETBIT(field_dup, entry->id);
        }
    }

    /* clear or create the vector as necessary */
    if (field_vec) {
        skVectorClear(field_vec);
    } else {
        field_vec = skVectorNew(sizeof(uint32_t));
        if (NULL == field_vec) {
            skAppPrintOutOfMemory("vector");
            goto END;
        }
    }

    /* fill the vector */
    skStringMapIterReset(iter);
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (skVectorAppendValue(field_vec, &entry->id)) {
            skAppPrintOutOfMemory("vector element");
            goto END;
        }
    }

    rv = 0;

  END:
    skStringMapIterDestroy(iter);
    return rv;
}


#if AB_SETBAG
/*
 *    Parse the input-type string specified in 'type_string' and
 *    update the globlal 'input_type' with the type.
 */
static int
parseInputType(
    const char         *type_string)
{
    sk_stringmap_status_t sm_err = SKSTRINGMAP_OK;
    sk_stringmap_entry_t *sm_entry;

    sm_err = skStringMapGetByName(input_type_map, type_string, &sm_entry);
    if (sm_err) {
        skAppPrintErr("Invalid %s '%s': %s",
                      appOptions[OPT_INPUT_TYPE].name, type_string,
                      skStringMapStrerror(sm_err));
        goto END;
    }
    input_type = sm_entry->id;

  END:
    return (sm_err != SKSTRINGMAP_OK);
}
#endif  /* #if AB_SETBAG */


/*
 *    If invalid input lines are being written to a stream, write the
 *    text in 'curline', preceeded by the input file's name and line
 *    number.
 *
 *    If verbose output or stop-on-error is set, format the error
 *    message given by the arguments and print an error message.  The
 *    error message includes the current input file and line number.
 */
static void
badLine(
    const char         *fmt,
    ...)
{
    char errbuf[2 * PATH_MAX];
    va_list ap;

    ++bad_line_count;

    va_start(ap, fmt);
    if (bad_stream) {
        skStreamPrint(bad_stream, "%s:%d:%s\n",
                      skStreamGetPathname(curline->stream),
                      curline->lineno, curline->text);
    }
    if (verbose || stop_on_error) {
        vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
        skAppPrintErr("%s:%d: %s",
                      skStreamGetPathname(curline->stream), curline->lineno,
                      errbuf);
        if (stop_on_error) {
            va_end(ap);
            exit(EXIT_FAILURE);
        }
    }
    va_end(ap);
}


/*
 *    Parse the string in 'str_value' which is a value for the field
 *    'id' and set the appropriate entry in the global 'parsed_value'
 *    array.  The 'is_const_field' parameter is used in error
 *    reporting.  Report an error message and return -1 if parsing
 *    fails.
 */
static int
parseSingleField(
    const char         *str_value,
    uint32_t            id,
    int                 is_const_field)
{
    parsed_value_t *pv;
    sktime_t tmp_time;
    uint8_t tcp_flags;
    int rv;

    assert(id < AGGBAGBUILD_ARRAY_SIZE);
    pv = &parsed_value[id];

    assert(1 == pv->pv_is_used);
    switch (id) {
      case SKAGGBAG_FIELD_RECORDS:
      case SKAGGBAG_FIELD_SUM_BYTES:
      case SKAGGBAG_FIELD_SUM_PACKETS:
      case SKAGGBAG_FIELD_SUM_ELAPSED:
      case SKAGGBAG_FIELD_PACKETS:
      case SKAGGBAG_FIELD_BYTES:
      case SKAGGBAG_FIELD_ELAPSED:
      case SKAGGBAG_FIELD_CUSTOM_KEY:
      case SKAGGBAG_FIELD_CUSTOM_COUNTER:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseUint64(&pv->pv.pv_int, str_value, 0, UINT64_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case SKAGGBAG_FIELD_SPORT:
      case SKAGGBAG_FIELD_DPORT:
      case SKAGGBAG_FIELD_ANY_PORT:
      case SKAGGBAG_FIELD_INPUT:
      case SKAGGBAG_FIELD_OUTPUT:
      case SKAGGBAG_FIELD_ANY_SNMP:
      case SKAGGBAG_FIELD_APPLICATION:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseUint64(&pv->pv.pv_int, str_value, 0, UINT16_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case SKAGGBAG_FIELD_PROTO:
      case SKAGGBAG_FIELD_ICMP_TYPE:
      case SKAGGBAG_FIELD_ICMP_CODE:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseUint64(&pv->pv.pv_int, str_value, 0, UINT8_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case SKAGGBAG_FIELD_SIPv4:
      case SKAGGBAG_FIELD_DIPv4:
      case SKAGGBAG_FIELD_NHIPv4:
      case SKAGGBAG_FIELD_ANY_IPv4:
        if (NULL == str_value) {
            skipaddrClear(&pv->pv.pv_ip);
            break;
        }
        rv = skStringParseIP(&pv->pv.pv_ip, str_value);
        if (rv) {
            goto PARSE_ERROR;
        }
#if SK_ENABLE_IPV6
        if (skipaddrIsV6(&pv->pv.pv_ip)
            && skipaddrV6toV4(&pv->pv.pv_ip, &pv->pv.pv_ip))
        {
            /* FIXME: Need to produce some error code */
        }
#endif  /* SK_ENABLE_IPV6 */
        break;

      case SKAGGBAG_FIELD_SIPv6:
      case SKAGGBAG_FIELD_DIPv6:
      case SKAGGBAG_FIELD_NHIPv6:
      case SKAGGBAG_FIELD_ANY_IPv6:
        if (NULL == str_value) {
            skipaddrClear(&pv->pv.pv_ip);
            skipaddrSetVersion(&pv->pv.pv_ip, 6);
            break;
        }
        rv = skStringParseIP(&pv->pv.pv_ip, str_value);
        if (rv) {
            goto PARSE_ERROR;
        }
#if SK_ENABLE_IPV6
        if (!skipaddrIsV6(&pv->pv.pv_ip)) {
            skipaddrV4toV6(&pv->pv.pv_ip, &pv->pv.pv_ip);
        }
#endif  /* SK_ENABLE_IPV6 */
        break;

      case SKAGGBAG_FIELD_STARTTIME:
      case SKAGGBAG_FIELD_ENDTIME:
      case SKAGGBAG_FIELD_ANY_TIME:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseDatetime(&tmp_time, str_value, NULL);
        if (rv) {
            goto PARSE_ERROR;
        }
        pv->pv.pv_int = sktimeGetSeconds(tmp_time);
        break;

      case SKAGGBAG_FIELD_FLAGS:
      case SKAGGBAG_FIELD_INIT_FLAGS:
      case SKAGGBAG_FIELD_REST_FLAGS:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseTCPFlags(&tcp_flags, str_value);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case SKAGGBAG_FIELD_TCP_STATE:
        if (NULL == str_value) {
            pv->pv.pv_int = 0;
            break;
        }
        rv = skStringParseTCPState(&tcp_flags, str_value);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case SKAGGBAG_FIELD_SID:
        if (NULL == str_value) {
            pv->pv.pv_int = SK_INVALID_SENSOR;
            break;
        }
        if (isdigit((int)*str_value)) {
            rv = skStringParseUint64(&pv->pv.pv_int, str_value, 0,
                                     SK_INVALID_SENSOR-1);
            if (rv) {
                goto PARSE_ERROR;
            }
        } else {
            pv->pv.pv_int = sksiteSensorLookup(str_value);
        }
        break;

      case SKAGGBAG_FIELD_FTYPE_CLASS:
        if (NULL == str_value) {
            pv->pv.pv_int = SK_INVALID_FLOWTYPE;
            break;
        }
        pv->pv.pv_int = sksiteClassLookup(str_value);
        break;

      case SKAGGBAG_FIELD_FTYPE_TYPE:
        if (NULL == str_value) {
            pv->pv.pv_int = SK_INVALID_FLOWTYPE;
            break;
        }
        pv->pv.pv_int = (sksiteFlowtypeLookupByClassIDType(
                             parsed_value[SKAGGBAG_FIELD_FTYPE_CLASS].pv.pv_int,
                             str_value));
        break;

      case SKAGGBAG_FIELD_SIP_COUNTRY:
      case SKAGGBAG_FIELD_DIP_COUNTRY:
      case SKAGGBAG_FIELD_ANY_COUNTRY:
        if (NULL == str_value) {
            pv->pv.pv_int = SK_COUNTRYCODE_INVALID;
            break;
        }
        pv->pv.pv_int = skCountryNameToCode(str_value);
        break;

      default:
        break;
    }

    return 0;

  PARSE_ERROR:
    if (is_const_field) {
        skAppPrintErr("Invalid %s '%s=%s': %s",
                      appOptions[OPT_CONSTANT_FIELD].name,
                      skAggBagFieldTypeGetName((sk_aggbag_type_t)id),
                      str_value, skStringParseStrerror(rv));
    } else {
        badLine("Invalid %s '%s': %s",
                skAggBagFieldTypeGetName((sk_aggbag_type_t)id), str_value,
                skStringParseStrerror(rv));
    }
    return -1;
}


/*
 *    Parse all the NAME=VALUE arguments to the --constant-field
 *    switch (the switch may be repeated) which are specified in the
 *    'constant_field' vector.  Set the appropriate field(s) in the
 *    global 'parsed_value' array to the value(s) and update the
 *    'const_fields' vector with the numeric IDs of those fields.
 *
 *    Return 0 on success or if no constant fields were specified.
 *    Return -1 on failure.
 */
static int
parseConstantFieldValues(
    void)
{
    sk_stringmap_entry_t *sm_entry;
    sk_stringmap_status_t sm_err;
    parsed_value_t *pv;
    char *argument;
    char *cp;
    char *eq;
    size_t i;

    if (NULL == constant_field) {
        return 0;
    }

    const_fields = skVectorNew(sizeof(uint32_t));
    if (NULL == const_fields) {
        skAppPrintOutOfMemory("vector");
        return -1;
    }

    /* parse each of the NAME=VALUE arguments */
    for (i = 0; 0 == skVectorGetValue(&argument, constant_field, i); ++i) {
        /* find the '=' */
        eq = strchr(argument, '=');
        if (NULL == eq) {
            skAppPrintErr("Invalid %s '%s': Unable to find '=' character",
                          appOptions[OPT_CONSTANT_FIELD].name, argument);
            return -1;
        }

        /* ensure a value is given */
        cp = eq + 1;
        while (*cp && isspace((int)*cp)) {
            ++cp;
        }
        if ('\0' == *cp) {
            skAppPrintErr("Invalid %s '%s': No value specified for field",
                          appOptions[OPT_CONSTANT_FIELD].name, argument);
            return -1;
        }

        /* split into name and value */
        *eq = '\0';
        cp = eq + 1;

        /* find the field with that name */
        sm_err = skStringMapGetByName(field_map, argument, &sm_entry);
        if (sm_err) {
            skAppPrintErr("Invalid %s: Unable to find a field named '%s': %s",
                          appOptions[OPT_CONSTANT_FIELD].name, argument,
                          skStringMapStrerror(sm_err));
            return -1;
        }

        /* ensure the field is ok to use: not ignore, not a duplicate */
        if (AGGBAGBUILD_FIELD_IGNORED == sm_entry->id) {
            skAppPrintErr("Invalid %s: May not set a default value for '%s'",
                          appOptions[OPT_CONSTANT_FIELD].name, sm_entry->name);
            return -1;
        }
        assert(sm_entry->id < AGGBAGBUILD_ARRAY_SIZE);
        pv = &parsed_value[sm_entry->id];
        if (pv->pv_is_used) {
            skAppPrintErr(
                "Invalid %s: A constant value for '%s' is already set",
                appOptions[OPT_CONSTANT_FIELD].name, sm_entry->name);
            return -1;
        }

        pv->pv_is_used = 1;
        if (parseSingleField(cp, sm_entry->id, 1)) {
            return -1;
        }
        pv->pv_is_const = 1;
        pv->pv_is_fixed = 1;

        if (skVectorAppendValue(const_fields, &sm_entry->id)) {
            skAppPrintOutOfMemory("vector element");
            return -1;
        }
    }

    return 0;
}


/*
 *    Use the values in 'field_vec' and 'const_fields' to determine
 *    fields to parse and the key and counter settings for the AggBag
 *    file.
 *
 *    The function requires that 'field_vec' contains a list of field
 *    IDs that were determined from the --fields switch, the first
 *    line of a text file, or the key and counter of a Bag file.
 *
 *    Constant fields---specified in the 'const_fields' vector---are
 *    also added to key and/or counter fields.  If a constant field
 *    matches a value in 'field_vec', the value in 'field_vec' is
 *    changed to AGGBAGBUILD_FIELD_IGNORED to ignore the field.
 *
 *    The function ensures at least one key and one counter field are
 *    specified.  For IPset and Bag inputs, additional checks are
 *    performed.
 *
 *    When this function returns, the number of entries in the
 *    'field_vec' vector represents the number of textual columns in
 *    the input.
 *
 *    Return 0 on success and -1 on error.
 */
static int
setAggBagFields(
    void)
{
    sk_vector_t *key_vec;
    sk_vector_t *counter_vec;
    sk_aggbag_type_t *id_array;
    unsigned int id_count;
    size_t missing_fields;
    sk_aggbag_type_t t;
    parsed_value_t *pv;
    int have_type;
    uint32_t id;
    size_t i;
    unsigned int j;

    assert(field_vec);

    if (AGGBAGBUILD_INPUT_TEXT == input_type) {
        /* nothing to check for yet */
#if AB_SETBAG
    } else if (AGGBAGBUILD_INPUT_IPSET == input_type) {
        /* for IPset input files, the field list must have a single
         * field that is either an IP type or ignore */
        if (skVectorGetCount(field_vec) != 1) {
            skAppPrintErr(
                "When using --%s=%s, the --%s switch accepts exactly 1 field",
                appOptions[OPT_INPUT_TYPE].name,
                skStringMapGetFirstName(input_type_map, input_type),
                appOptions[OPT_FIELDS].name);
            return -1;
        }
        skVectorGetValue(&id, field_vec, 0);
        switch (id) {
          case AGGBAGBUILD_FIELD_IGNORED:
            break;
          case SKAGGBAG_FIELD_SIPv4:
          case SKAGGBAG_FIELD_DIPv4:
          case SKAGGBAG_FIELD_NHIPv4:
          case SKAGGBAG_FIELD_ANY_IPv4:
          case SKAGGBAG_FIELD_SIPv6:
          case SKAGGBAG_FIELD_DIPv6:
          case SKAGGBAG_FIELD_NHIPv6:
          case SKAGGBAG_FIELD_ANY_IPv6:
            break;
          default:
            skAppPrintErr(
                "When using --%s=%s, the --%s switch must be an IP type or %s",
                appOptions[OPT_INPUT_TYPE].name,
                skStringMapGetFirstName(input_type_map, input_type),
                appOptions[OPT_FIELDS].name,
                skStringMapGetFirstName(field_map, AGGBAGBUILD_FIELD_IGNORED));
            return -1;
        }
    } else if (AGGBAGBUILD_INPUT_BAG == input_type) {
        /* for Bag input files, the field list must have exactly two
         * fields */
        if (skVectorGetCount(field_vec) != 2) {
            skAppPrintErr(
                "When using --%s=%s, the --%s switch accepts exactly 2 fields",
                appOptions[OPT_INPUT_TYPE].name,
                skStringMapGetFirstName(input_type_map, input_type),
                appOptions[OPT_FIELDS].name);
            return -1;
        }
#endif  /* AB_SETBAG */
    } else {
        skAbortBadCase(input_type);
    }

    /* ensure the flowtype type field is the final field */
    have_type = 0;

    /* ignore fields that are duplicates of constant fields */
    for (i = 0; 0 == skVectorGetValue(&id, field_vec, i); ++i) {
        if (AGGBAGBUILD_FIELD_IGNORED != id) {
            assert(id < AGGBAGBUILD_ARRAY_SIZE);
            pv = &parsed_value[id];
            if (pv->pv_is_const) {
                id = AGGBAGBUILD_FIELD_IGNORED;
                skVectorSetValue(field_vec, i, &id);
            } else {
                assert(0 == pv->pv_is_used);
                pv->pv_is_used = 1;
            }
        }
    }

    /* we have a list of fields; divide them into keys and counters */

    /* create vectors to hold the IDs that are being used */
    key_vec = skVectorNew(sizeof(sk_aggbag_type_t));
    counter_vec = skVectorNew(sizeof(sk_aggbag_type_t));
    if (!key_vec || !counter_vec) {
        skAppPrintOutOfMemory("vector");
        skVectorDestroy(key_vec);
        skVectorDestroy(counter_vec);
        exit(EXIT_FAILURE);
    }

    /* add any constant fields, then the other fields, to the key or
     * counter vectors */
    for (j = 0; j < 2; ++j) {
        const sk_vector_t *v = (0 == j) ? const_fields : field_vec;
        if (NULL == v) {
            continue;
        }
        for (i = 0; 0 == skVectorGetValue(&id, v, i); ++i) {
            switch (skAggBagFieldTypeGetDisposition((sk_aggbag_type_t)id)) {
              case SK_AGGBAG_KEY:
                t = (sk_aggbag_type_t)id;
                if (SKAGGBAG_FIELD_FTYPE_TYPE == t) {
                    have_type = 1;
                } else {
                    skVectorAppendValue(key_vec, &t);
                }
                break;
              case SK_AGGBAG_COUNTER:
                t = (sk_aggbag_type_t)id;
                skVectorAppendValue(counter_vec, &t);
                break;
              case 0:
                if (id == AGGBAGBUILD_FIELD_IGNORED && v == field_vec) {
                    break;
                }
                skAppPrintErr("Unknown field id %u", id);
                skAbort();
              default:
                skAppPrintErr(
                    "Unsupported type %u for field id %u",
                    skAggBagFieldTypeGetDisposition((sk_aggbag_type_t)id), id);
                skAbort();
            }
        }
    }

    if (have_type) {
        t = SKAGGBAG_FIELD_FTYPE_TYPE;
        skVectorAppendValue(key_vec, &t);
    }

    /* ensure key and counter are defined */
    missing_fields = ((0 == skVectorGetCount(key_vec))
                      + 2 * (0 == skVectorGetCount(counter_vec)));
    if (missing_fields) {
        skAppPrintErr(
            "Do not have any %s fields; at least one %s field %s required",
            ((missing_fields == 3)
             ? "key fields or counter"
             : ((missing_fields == 1) ? "key" : "counter")),
            ((missing_fields == 3)
             ? "key field and one counter"
             : ((missing_fields == 1) ? "key" : "counter")),
            ((missing_fields == 3) ? "are" : "is"));
        skVectorDestroy(key_vec);
        skVectorDestroy(counter_vec);
        return -1;
    }

    /* set key and counter */
    id_count = skVectorGetCount(key_vec);
    id_array = (sk_aggbag_type_t *)skVectorToArrayAlloc(key_vec);
    skAggBagSetKeyFields(ab, id_count, id_array);
    skVectorDestroy(key_vec);
    free(id_array);

    id_count = skVectorGetCount(counter_vec);
    id_array = (sk_aggbag_type_t *)skVectorToArrayAlloc(counter_vec);
    skAggBagSetCounterFields(ab, id_count, id_array);
    skVectorDestroy(counter_vec);
    free(id_array);

#if AB_SETBAG
    /* special handling for IPset and Bag input types: number of
     * non-constant key and counter fields is restricted */
    if (AGGBAGBUILD_INPUT_TEXT != input_type) {
        sk_aggbag_field_t field;
        const char *limit_msg;
        uint32_t count;

        for (i = 0; i < 2; ++i) {
            count = 0;
            if (0 == i) {
                skAggBagInitializeKey(ab, NULL, &field);
                limit_msg = "Only one key field";
            } else {
                skAggBagInitializeCounter(ab, NULL, &field);
                if (AGGBAGBUILD_INPUT_IPSET == input_type) {
                    limit_msg = "No counter fields";
                    count = 1;
                } else {
                    limit_msg = "Only one counter field";
                }
            }
            do {
                id = skAggBagFieldIterGetType(&field);
                assert(id < AGGBAGBUILD_ARRAY_SIZE);
                pv = &parsed_value[id];
                count += (1 != pv->pv_is_const);
            } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);

            if (count > 1) {
                skAppPrintErr("Invalid %s: %s may be specified when %s is %s",
                              appOptions[OPT_FIELDS].name, limit_msg,
                              appOptions[OPT_INPUT_TYPE].name,
                              skStringMapGetFirstName(input_type_map,
                                                      input_type));
                return -1;
            }
        }
    }
#endif  /* #if AB_SETBAG */

    return 0;
}


/*
 *    Determine if the input line in 'first_line' is a title line.
 *
 *    If 'no_titles' is set, simply return 0.  Otherwise, check
 *    whether a name in 'first_line' matches a field name.  Return 1
 *    if a field name is found to match, 0 otherwise.
 */
static int
checkFirstLineIsTitle(
    char               *first_line)
{
    sk_stringmap_entry_t *entry;
    char *cp;
    char *ep;
    size_t i;
    int is_title = 0;
    uint32_t id;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);
    assert(first_line);
    assert(fields);
    assert(field_vec);

    if (no_titles) {
        return 0;
    }

    /* we have the fields, need to determine if first_line is a
     * title line. */
    cp = first_line;
    for (i = 0; 0 == skVectorGetValue(&id, field_vec, i); ++i) {
        ep = strchr(cp, column_separator);
        if (!is_title && (id != AGGBAGBUILD_FIELD_IGNORED)) {
            if (ep) {
                *ep = '\0';
            }
            while ((isspace((int)*cp))) {
                ++cp;
            }
            if ('\0' == *cp) {
                /* ignore */
            } else if (!isdigit((int)*cp)) {
                if (skStringMapGetByName(field_map, cp, &entry)
                    == SKSTRINGMAP_OK)
                {
                    is_title = 1;
                }
            }
        }
        if (ep) {
            *ep = column_separator;
            cp = ep + 1;
        } else {
            cp += strlen(cp);
            if (is_title && (1 + i != skVectorGetCount(field_vec))) {
                badLine(("Too few fields on title line:"
                         " found %" SK_PRIuZ " of %" SK_PRIuZ " expected"),
                        i, skVectorGetCount(field_vec));
            }
            break;
        }
    }

    if (is_title && (*cp != '\0')
        && (strlen(cp) != strspn(cp, AGGBAGBUILD_WHITESPACE)))
    {
        badLine(("Too many fields on title line:"
                 " text follows delimiter number %" SK_PRIuZ),
                skVectorGetCount(field_vec));
    }

    return is_title;
}


/*
 *    Remove all whitespace from 'first_line' and convert the
 *    column_separator to a comma.
 *
 *    FIXME: How should this code handle double column_separators?
 */
static void
convertTitleLineToCSV(
    char               *first_line)
{
    char *cp, *ep;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);
    assert(first_line);

    cp = ep = first_line;
    while (*cp) {
        if (*cp == column_separator) {
            /* convert column_separator to comma for parseFieldList() */
            *ep++ = ',';
            ++cp;
        } else if (isspace((int)*cp)) {
            /* ignore spaces */
            ++cp;
        } else {
            /* copy character */
            *ep++ = *cp++;
        }
    }
    *ep = *cp;
}


/*
 *    Determine which fields (columns) to parse across all input files
 *    based on the title line in given in 'first_line'.
 *
 *    This function determines a set of fields based on the column
 *    titles specified in 'first_line', then invokes setAggBagFields()
 *    to initialize the key and counter fields on the AggBag.  See
 *    setAggBagFields() for details.
 *
 *    Return 0 on success and -1 on error.
 */
static int
parseFirstLineAsFieldList(
    char               *first_line)
{
    char *errmsg;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);
    assert(first_line);
    assert(NULL == field_vec);
    assert(NULL == fields);
    assert(0 == no_titles);

    /* make the title line look like the argument to --fields and then
     * parse it as a field list */
    convertTitleLineToCSV(first_line);
    if (parseFieldList(first_line, &errmsg)) {
        skAppPrintErr(
            "Unable to guess fields from first line of file '%s': %s",
            skStreamGetPathname(curline->stream), errmsg);
        return -1;
    }

    /* use 'field_vec' to set the key and value fields */
    if (setAggBagFields()) {
        return -1;
    }

    return 0;
}


/*
 *    Update the global 'field_vec' based on the titles present in
 *    'first_line'.
 *
 *    This function is used when parsing multiple text files and
 *    'first_line' contains the first line of the second, third, etc
 *    text file.  It updates the 'field_vec' based on the new title
 *    line.
 *
 *    The parseFirstLineAsFieldList() function is used when parsing
 *    the first line of the first text file.
 */
static int
updateFieldVectorMultipleFiles(
    char               *first_line)
{
    parsed_value_t *pv;
    uint32_t id;
    size_t i;
    char *errmsg;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);
    assert(first_line);
    assert(field_vec);
    assert(NULL == fields);
    assert(0 == no_titles);

    /* clear all non-const values in current field_vec */
    for (i = 0; 0 == skVectorGetValue(&id, field_vec, i); ++i) {
        if (AGGBAGBUILD_FIELD_IGNORED != id) {
            assert(id < AGGBAGBUILD_ARRAY_SIZE);
            pv = &parsed_value[id];
            assert(1 == pv->pv_is_used);
            assert(0 == pv->pv_is_const);
            pv->pv_is_fixed = 1;
            pv->pv_raw = NULL;
            parseSingleField(NULL, id, 0);
        }
    }

    /* make the title line look like the argument to --fields and then
     * parse it as a field list */
    convertTitleLineToCSV(first_line);
    if (parseFieldList(first_line, &errmsg)) {
        skAppPrintErr(
            "Unable to guess fields from first line of file '%s': %s",
            skStreamGetPathname(curline->stream), errmsg);
        return -1;
    }

    /* update the field_vec */
    for (i = 0; 0 == skVectorGetValue(&id, field_vec, i); ++i) {
        if (AGGBAGBUILD_FIELD_IGNORED != id) {
            assert(id < AGGBAGBUILD_ARRAY_SIZE);
            pv = &parsed_value[id];
            if (pv->pv_is_const || !pv->pv_is_used) {
                id = AGGBAGBUILD_FIELD_IGNORED;
                skVectorSetValue(field_vec, i, &id);
            } else {
                pv->pv_is_fixed = 0;
            }
        }
    }

    return 0;
}


/*
 *    Parse one row of textual values used by the AggBag's key and
 *    counter and insert the key/counter into the AggBag.
 *
 *    This function is used when reading textual data, and it
 *    processes a single row of values.  This function expects the
 *    string value for each key or counter field to be set in the
 *    global 'parsed_value' array.
 *
 *    Return 0 on success or -1 if a string value cannot be parsed.
 */
static int
processFields(
    void)
{
    sk_aggbag_aggregate_t *agg;
    sk_aggbag_aggregate_t key;
    sk_aggbag_aggregate_t counter;
    sk_aggbag_field_t field;
    parsed_value_t *pv;
    uint32_t id;
    int i;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);

    /* loop twice: once for key and again for counter */
    for (i = 0; i < 2; ++i) {
        if (0 == i) {
            agg = &key;
            skAggBagInitializeKey(ab, agg, &field);
        } else {
            agg = &counter;
            skAggBagInitializeCounter(ab, agg, &field);
        }
        do {
            id = skAggBagFieldIterGetType(&field);
            assert(id < AGGBAGBUILD_ARRAY_SIZE);
            pv = &parsed_value[id];
            assert(pv->pv_is_used);
            if (!pv->pv_is_fixed) {
                if (parseSingleField(pv->pv_raw, id, 0)) {
                    return -1;
                }
            }
            switch (id) {
              case SKAGGBAG_FIELD_SIPv4:
              case SKAGGBAG_FIELD_DIPv4:
              case SKAGGBAG_FIELD_NHIPv4:
              case SKAGGBAG_FIELD_ANY_IPv4:
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_ANY_IPv6:
                skAggBagAggregateSetIPAddress(agg, &field, &pv->pv.pv_ip);
                break;

              default:
                skAggBagAggregateSetUnsigned(agg, &field, pv->pv.pv_int);
                break;
            }
        } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);
    }

    skAggBagKeyCounterAdd(ab, &key, &counter, NULL);
    return 0;
}


/*
 *  ok = processInputText();
 *
 *    Read each line of text from the stream in the global 'curline'
 *    structure, create a key and a counter from the fields on the
 *    line, and add the key and counter to the global aggbag
 *    structure.
 *
 *    Return 0 on success, -1 on failure.
 */
static int
processInputText(
    void)
{
    static char line[AGGBAGBUILD_LINE_BUFSIZE];
    char *cp;
    char *ep;
    int is_first_line = 1;
    size_t i;
    uint32_t id;
    int rv;

    assert(AGGBAGBUILD_INPUT_TEXT == input_type);

    if (skStreamSetCommentStart(curline->stream, "#")) {
        return 1;
    }

    /* read until end of file */
    while ((rv = skStreamGetLine(curline->stream, line, sizeof(line),
                                 &curline->lineno))
           != SKSTREAM_ERR_EOF)
    {
        if (bad_stream) {
            /* stash copy; used by badLine() */
            strncpy(curline->text, line, sizeof(curline->text));
        }
        switch (rv) {
          case SKSTREAM_OK:
            /* good, we got our line */
            break;
          case SKSTREAM_ERR_LONG_LINE:
            /* bad: line was longer than sizeof(line) */
            badLine("Input line too long");
            continue;
          default:
            /* unexpected error */
            skStreamPrintLastErr(curline->stream, rv, &skAppPrintErr);
            return -1;
        }

        if (is_first_line) {
            /* this is the first line in the file. either initialize
             * or update the parsed_value array based on the values in
             * the --fields switch or on this line */
            is_first_line = 0;

            if (fields) {
                /* user provided the list of fields; only need to
                 * determine whether to skip this line */
                if (checkFirstLineIsTitle(line)) {
                    continue;
                }
            } else {
                assert(0 == no_titles);
                if (field_vec) {
                    /* this is a second text file; recompute which
                     * fields to ignore */
                    if (updateFieldVectorMultipleFiles(line)) {
                        return -1;
                    }
                } else {
                    /* create field_vec based on title line */
                    if (parseFirstLineAsFieldList(line)) {
                        return -1;
                    }
                }
                /* this line must be a title */
                continue;
            }
        }

        /* We have a line; process it */
        cp = line;
        i = 0;

        /* break the line into separate fields */
        while (0 == skVectorGetValue(&id, field_vec, i)) {
            if (id != AGGBAGBUILD_FIELD_IGNORED) {
                assert(1 == parsed_value[id].pv_is_used);
                assert(0 == parsed_value[id].pv_is_const);
                while (isspace((int)*cp)) {
                    ++cp;
                }
                if (*cp == column_separator) {
                    parsed_value[id].pv_raw = NULL;
                } else {
                    parsed_value[id].pv_raw = cp;
                }
            }
            ++i;

            /* find end of current field */
            ep = strchr(cp, column_separator);
            if (NULL == ep) {
                /* at end of line; break out of while() */
                cp += strlen(cp);
                break;
            } else {
                *ep = '\0';
                cp = ep + 1;
            }
        }

        if (*cp != '\0') {
            if (strlen(cp) != strspn(cp, AGGBAGBUILD_WHITESPACE)) {
                /* there are extra fields at the end */
                badLine(("Too many fields on line:"
                         " text follows delimiter number %" SK_PRIuZ),
                        skVectorGetCount(field_vec));
            }
        } else if (i != skVectorGetCount(field_vec)) {
            /* there are too few fields */
            badLine(("Too few fields on line:"
                     " found %" SK_PRIuZ " of %" SK_PRIuZ " expected"),
                    i, skVectorGetCount(field_vec));
        } else {
            processFields();
        }
    } /* outer loop over lines  */

    return 0;
}


#if AB_SETBAG
/*
 *  ok = processInputIPSet(stream);
 *
 *    Read an IPset from 'stream'.  Use each IP and one or more
 *    constant fields to create a key and a counter, and add the key
 *    and the counter to the global aggbag structure.
 *
 *    Return 0 on success, -1 on failure.
 */
static int
processInputIPSet(
    skstream_t         *stream)
{
    skipset_t *set = NULL;
    skipset_iterator_t iter;
    sk_ipv6policy_t policy;
    sk_aggbag_aggregate_t key;
    sk_aggbag_aggregate_t counter;
    sk_aggbag_field_t field;
    parsed_value_t *pv;
    unsigned int key_field_count;
    unsigned int nonfixed_count;
    skipaddr_t ipaddr;
    uint32_t prefix;
    uint32_t id;
    ssize_t rv;

    assert(AGGBAGBUILD_INPUT_IPSET == input_type);

    /* read the IPset from the stream.  FIXME: change this to use
     * skIPSetProcessStream(). */
    rv = skIPSetRead(&set, stream);
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            char errbuf[2 * PATH_MAX];
            skStreamLastErrMessage(stream, skStreamGetLastReturnValue(stream),
                                   errbuf, sizeof(errbuf));
            skAppPrintErr("Unable to read IPset from '%s': %s",
                          skStreamGetPathname(stream), errbuf);
        } else {
            skAppPrintErr("Unable to read IPset from '%s': %s",
                          skStreamGetPathname(stream), skIPSetStrerror(rv));
        }
        return -1;
    }

    if (NULL == field_vec) {
        const char *faux_list;
        char *errmsg;

        faux_list = skIPSetContainsV6(set) ? "any-IPv6" : "any-IPv4";
        if (parseFieldList(faux_list, &errmsg)) {
            skAppPrintErr("Error parsing programmer field list '%s': %s",
                          faux_list, errmsg);
            exit(EXIT_FAILURE);
        }
        if (setAggBagFields()) {
            return -1;
        }
    }

    /* initialize the counter, which must contain only fixed/constant
     * values */
    skAggBagInitializeCounter(ab, &counter, &field);
    do {
        id = skAggBagFieldIterGetType(&field);
        assert(id < AGGBAGBUILD_ARRAY_SIZE);
        pv = &parsed_value[id];
        assert(pv->pv_is_used);
        assert(pv->pv_is_fixed);
        skAggBagAggregateSetUnsigned(&counter, &field, pv->pv.pv_int);
    } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);

    /* count the number of fields in the key, and determine whether an
     * IPv4 or IPv6 IP is wanted. */
    key_field_count = 0;
    nonfixed_count = 0;
    policy = SK_IPV6POLICY_MIX;
    skAggBagInitializeKey(ab, NULL, &field);
    do {
        id = skAggBagFieldIterGetType(&field);
        assert(id < AGGBAGBUILD_ARRAY_SIZE);
        pv = &parsed_value[id];
        assert(pv->pv_is_used);
        if (!pv->pv_is_fixed) {
            ++nonfixed_count;
            switch (id) {
              case SKAGGBAG_FIELD_SIPv4:
              case SKAGGBAG_FIELD_DIPv4:
              case SKAGGBAG_FIELD_NHIPv4:
              case SKAGGBAG_FIELD_ANY_IPv4:
                policy = SK_IPV6POLICY_ASV4;
                break;
              case SKAGGBAG_FIELD_SIPv6:
              case SKAGGBAG_FIELD_DIPv6:
              case SKAGGBAG_FIELD_NHIPv6:
              case SKAGGBAG_FIELD_ANY_IPv6:
                policy = SK_IPV6POLICY_FORCE;
                break;
              default:
                skAbortBadCase(id);
            }
        }
        ++key_field_count;
    } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);

    if (SK_IPV6POLICY_MIX == policy) {
        if (nonfixed_count) {
            skAbort();
        }
        /* the key is also fixed; fill it in */
        skAggBagInitializeKey(ab, &key, &field);
        do {
            id = skAggBagFieldIterGetType(&field);
            assert(id < AGGBAGBUILD_ARRAY_SIZE);
            pv = &parsed_value[id];
            assert(pv->pv_is_used);
            assert(pv->pv_is_fixed);
            skAggBagAggregateSetUnsigned(&key, &field, pv->pv.pv_int);
        } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);
    }

    skIPSetIteratorBind(&iter, set, 0, policy);

    if (0 == nonfixed_count) {
        while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK){
            skAggBagAggregateSetIPAddress(&key, &field, &ipaddr);
            skAggBagKeyCounterAdd(ab, &key, &counter, NULL);
        }
    } else if (1 == key_field_count) {
        /* no need to move the field, just update the IP address in
         * the key each time */
        skAggBagInitializeKey(ab, &key, &field);
        pv = &parsed_value[skAggBagFieldIterGetType(&field)];
        while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK){
            skAggBagAggregateSetIPAddress(&key, &field, &ipaddr);
            skAggBagKeyCounterAdd(ab, &key, &counter, NULL);
        }
    } else {
        while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK){
            skAggBagInitializeKey(ab, &key, &field);
            do {
                id = skAggBagFieldIterGetType(&field);
                assert(id < AGGBAGBUILD_ARRAY_SIZE);
                pv = &parsed_value[id];
                assert(pv->pv_is_used);
                if (!pv->pv_is_fixed) {
                    skAggBagAggregateSetIPAddress(&key, &field, &ipaddr);
                } else {
                    switch (id) {
                      case SKAGGBAG_FIELD_SIPv4:
                      case SKAGGBAG_FIELD_DIPv4:
                      case SKAGGBAG_FIELD_NHIPv4:
                      case SKAGGBAG_FIELD_ANY_IPv4:
                      case SKAGGBAG_FIELD_SIPv6:
                      case SKAGGBAG_FIELD_DIPv6:
                      case SKAGGBAG_FIELD_NHIPv6:
                      case SKAGGBAG_FIELD_ANY_IPv6:
                        skAggBagAggregateSetIPAddress(
                            &key, &field, &pv->pv.pv_ip);
                        break;
                      default:
                        skAggBagAggregateSetUnsigned(
                            &key, &field, pv->pv.pv_int);
                        break;
                    }
                }
            } while (skAggBagFieldIterNext(&field) == SK_ITERATOR_OK);
            skAggBagKeyCounterAdd(ab, &key, &counter, NULL);
        }
    }

    skIPSetDestroy(&set);
    return 0;
}


/*
 *  ok = processInputBag(stream);
 *
 *    Read a Bag from 'stream'.  add the key and the counter to the
 *    global aggbag structure.
 *
 *    Return 0 on success, -1 on failure.
 */
static int
processInputBag(
    skstream_t         *stream)
{
    skBag_t *bag = NULL;
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t b_key;
    skBagTypedCounter_t b_counter;
    skBagErr_t b_err;
    sk_aggbag_aggregate_t ab_key;
    sk_aggbag_aggregate_t ab_counter;
    sk_aggbag_field_t k_field;
    sk_aggbag_field_t c_field;
    parsed_value_t *pv;
    uint32_t id;

    assert(AGGBAGBUILD_INPUT_BAG == input_type);

    /* read the bag from the stream; FIXME: change this to use
     * skBagProcessStreamTyped(). */
    b_err = skBagRead(&bag, stream);
    if (b_err) {
        if (SKBAG_ERR_READ == b_err) {
            char errbuf[2 * PATH_MAX];
            skStreamLastErrMessage(stream, skStreamGetLastReturnValue(stream),
                                   errbuf, sizeof(errbuf));
            skAppPrintErr("Unable to read Bag from '%s': %s",
                          skStreamGetPathname(stream), errbuf);
        } else {
            skAppPrintErr("Unable to read Bag from '%s': %s",
                          skStreamGetPathname(stream), skBagStrerror(b_err));
        }
        skBagDestroy(&bag);
        return -1;
    }

    if (NULL == field_vec) {
        char k_name[SKBAG_MAX_FIELD_BUFLEN];
        char c_name[SKBAG_MAX_FIELD_BUFLEN];
        char faux_list[3 * SKBAG_MAX_FIELD_BUFLEN];
        skBagFieldType_t t;
        char *errmsg;

        t = skBagKeyFieldName(bag, k_name, sizeof(k_name));
        if (SKBAG_FIELD_CUSTOM == t) {
            snprintf(k_name, sizeof(k_name), "%s",
                     skAggBagFieldTypeGetName(SKAGGBAG_FIELD_CUSTOM_KEY));
        }
        t = skBagCounterFieldName(bag, c_name, sizeof(c_name));
        if (SKBAG_FIELD_CUSTOM == t) {
            snprintf(c_name, sizeof(c_name), "%s",
                     skAggBagFieldTypeGetName(SKAGGBAG_FIELD_CUSTOM_COUNTER));
        }

        snprintf(faux_list, sizeof(faux_list), "%s,%s", k_name, c_name);
        if (parseFieldList(faux_list, &errmsg)) {
            skAppPrintErr("Error parsing field list '%s': %s",
                          faux_list, errmsg);
            exit(EXIT_FAILURE);
        }
        if (setAggBagFields()) {
            return -1;
        }
    }

    /* initialize 'key' with any contant key fields and determine the
     * type of the key that the Bag's key is to fill */
    skAggBagInitializeKey(ab, &ab_key, &k_field);
    do {
        id = skAggBagFieldIterGetType(&k_field);
        assert(id < AGGBAGBUILD_ARRAY_SIZE);
        pv = &parsed_value[id];
        assert(pv->pv_is_used);
        switch (id) {
          case SKAGGBAG_FIELD_SIPv4:
          case SKAGGBAG_FIELD_DIPv4:
          case SKAGGBAG_FIELD_NHIPv4:
          case SKAGGBAG_FIELD_ANY_IPv4:
          case SKAGGBAG_FIELD_SIPv6:
          case SKAGGBAG_FIELD_DIPv6:
          case SKAGGBAG_FIELD_NHIPv6:
          case SKAGGBAG_FIELD_ANY_IPv6:
            if (!pv->pv_is_fixed) {
                b_key.type = SKBAG_KEY_IPADDR;
            } else {
                skAggBagAggregateSetIPAddress(&ab_key, &k_field, &pv->pv.pv_ip);
            }
            break;
          default:
            if (!pv->pv_is_fixed) {
                b_key.type = SKBAG_KEY_U32;
            } else {
                skAggBagAggregateSetUnsigned(&ab_key, &k_field, pv->pv.pv_int);
            }
            break;
        }
    } while (skAggBagFieldIterNext(&k_field) == SK_ITERATOR_OK);

    /* initialize 'counter' with any contant counter fields */
    skAggBagInitializeCounter(ab, &ab_counter, &c_field);
    do {
        id = skAggBagFieldIterGetType(&c_field);
        assert(id < AGGBAGBUILD_ARRAY_SIZE);
        pv = &parsed_value[id];
        assert(pv->pv_is_used);
        if (!pv->pv_is_fixed) {
            b_counter.type = SKBAG_COUNTER_U64;
        } else {
            skAggBagAggregateSetUnsigned(&ab_counter, &c_field, pv->pv.pv_int);
        }
    } while (skAggBagFieldIterNext(&c_field) == SK_ITERATOR_OK);

    /* Position 'k_field' and 'c_field' on the field to map the bag's
     * key and counter into.  Note use of NULL as second parameter */
    skAggBagInitializeKey(ab, NULL, &k_field);
    do {
        pv = &parsed_value[skAggBagFieldIterGetType(&k_field)];
    } while (pv->pv_is_fixed
             && skAggBagFieldIterNext(&k_field) == SK_ITERATOR_OK);

    skAggBagInitializeCounter(ab, NULL, &c_field);
    do {
        pv = &parsed_value[skAggBagFieldIterGetType(&c_field)];
    } while (pv->pv_is_fixed
             && skAggBagFieldIterNext(&c_field) == SK_ITERATOR_OK);

    /* iterate over the entries in the bag  */
    skBagIteratorCreate(bag, &iter);
    if (SKBAG_KEY_IPADDR == b_key.type) {
        while (skBagIteratorNextTyped(iter, &b_key, &b_counter) == SKBAG_OK) {
            skAggBagAggregateSetIPAddress(
                &ab_key, &k_field, &b_key.val.addr);
            skAggBagAggregateSetUnsigned(
                &ab_counter, &c_field, b_counter.val.u64);
            skAggBagKeyCounterAdd(ab, &ab_key, &ab_counter, NULL);
        }
    } else {
        while (skBagIteratorNextTyped(iter, &b_key, &b_counter) == SKBAG_OK) {
            skAggBagAggregateSetUnsigned(
                &ab_key, &k_field, b_key.val.u32);
            skAggBagAggregateSetUnsigned(
                &ab_counter, &c_field, b_counter.val.u64);
            skAggBagKeyCounterAdd(ab, &ab_key, &ab_counter, NULL);
        }
    }

    skBagIteratorDestroy(iter);
    skBagDestroy(&bag);
    return 0;
}
#endif  /* #if AB_SETBAG */


int main(int argc, char **argv)
{
    skcontent_t stream_type;
    skstream_t *stream;
    char *fname;
    ssize_t rv = 0;

    appSetup(argc, argv);

    if (AGGBAGBUILD_INPUT_TEXT == input_type) {
        stream_type = SK_CONTENT_TEXT;
    } else {
        stream_type = SK_CONTENT_SILK;
    }

    while ((rv = skOptionsCtxNextArgument(optctx, &fname)) == 0) {
        /* create an input stream and open the file */
        stream = NULL;
        if ((rv = skStreamCreate(&stream, SK_IO_READ, stream_type))
            || (rv = skStreamBind(stream, fname))
            || (rv = skStreamOpen(stream)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            rv = -1;
            break;
        }
        switch (input_type) {
          case AGGBAGBUILD_INPUT_TEXT:
            curline->lineno = 0;
            curline->stream = stream;
            rv = processInputText();
            break;
#if AB_SETBAG
          case AGGBAGBUILD_INPUT_IPSET:
            rv = processInputIPSet(stream);
            break;
          case AGGBAGBUILD_INPUT_BAG:
            rv = processInputBag(stream);
            break;
#endif  /* #if AB_SETBAG */
        }

        skStreamDestroy(&stream);
        if (rv != 0) {
            break;
        }
    }

    if (1 == rv) {
        rv = skAggBagWrite(ab, out_stream);
        if (rv) {
            if (SKAGGBAG_E_WRITE == rv) {
                skStreamPrintLastErr(out_stream,
                                     skStreamGetLastReturnValue(out_stream),
                                     &skAppPrintErr);
            } else {
                skAppPrintErr("Error writing Aggregate Bag to '%s': %s",
                              skStreamGetPathname(out_stream),
                              skAggBagStrerror(rv));
            }
            exit(EXIT_FAILURE);
        }

        if (bad_line_count && !verbose) {
            if (bad_stream) {
                skAppPrintErr(("Could not parse %u line%s;"
                               " invalid input written to '%s'"),
                              bad_line_count,
                              ((1 == bad_line_count) ? "" : "s"),
                              skStreamGetPathname(bad_stream));
            } else {
                skAppPrintErr(("Could not parse %u line%s;"
                               " try again with --%s or --%s for details"),
                              bad_line_count,
                              ((1 == bad_line_count) ? "" : "s"),
                              appOptions[OPT_STOP_ON_ERROR].name,
                              appOptions[OPT_VERBOSE].name);
            }
        }
    }

    skAggBagDestroy(&ab);

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
