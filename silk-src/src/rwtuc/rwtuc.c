/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  rwtuc - Text Utility Converter
**
**  Takes the output from rwcut and generates SiLK flow records from it.
**
**  Mark Thomas, March 2006
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwtuc.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* size to use for arrays that hold field IDs; number of valid
 * elements in array is given by 'max_avail_field' */
#define TUC_ARRAY_SIZE  32

/* regular expression to match the old ("ancient" at this point)
 * format for the time field: "MM/DD/YYYY hh:mm:ss".  We just need to
 * match enough to know whether we have MM/DD/YYYY or YYYY/MM/DD. */
#define RWTUC_TIME_REGEX "^[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:"

/* how big of an input line to accept; lines longer than this size are
 * ignored */
#define RWTUC_LINE_BUFSIZE 2048

/* whitespace chars used in strspn(); list taken from isspace() */
#define RWTUC_WHITESPACE    "\t\v\f\r "

/* additional field types to define, it addition to the RWREC_FIELD_*
 * values defined by rwascii.h; values must be contiguous with the
 * RWREC_FIELD_* values. */
typedef enum {
    TUC_FIELD_IGNORED = RWREC_PRINTABLE_FIELD_COUNT
} field_ident_t;

/* depending on what we are parsing, there may be various parts of the
 * time we need to calculate */
typedef enum {
    /* sTime and elapsed are being set; nothing to calculate */
    CALC_NONE,
    /* must calculate sTime from eTime - elapsed */
    CALC_STIME,
    /* must calculate elapsed from eTime - sTime */
    CALC_ELAPSED
} time_calc_t;

/* various values that get parsed; either from the fixed values the
 * user enters on the command line or one per line that is read. */
typedef struct parsed_values_st {
    rwRec       rec;
    char       *class_name;
    char       *type_name;
    sktime_t    eTime;
    uint8_t     itype;
    uint8_t     icode;
    time_calc_t handle_time;
    unsigned    bytes_equals_pkts :1;
    unsigned    have_icmp         :1;
} parsed_values_t;

/* current input line */
typedef struct current_line_st {
    /* input line (as read from input) */
    char        text[RWTUC_LINE_BUFSIZE];
    /* input stream currently being processed */
    skstream_t *stream;
    /* line number in the 'stream' */
    int         lineno;
} current_line_t;


/* LOCAL VARIABLES */

/* one more than maximum valid field ID.  This is used when
 * determining which fields were seen and which fields have
 * defaults. */
static const uint32_t max_avail_field = TUC_FIELD_IGNORED;

/* fields in addition to those provided by rwascii */
static sk_stringmap_entry_t tuc_fields[] = {
    {"ignore", TUC_FIELD_IGNORED,   NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* where to send output, set by --output-path */
static skstream_t *out_stream = NULL;

/* where to copy bad input lines, set by --bad-output-lines */
static skstream_t *bad_stream = NULL;

/* the number of bad input lines */
static unsigned int bad_line_count = 0;

/* whether to report parsing errors, set by --verbose */
static int verbose = 0;

/* whether to halt on first error, set by --stop-on-error */
static int stop_on_error = 0;

/* whether to always parse the first line as data, set by --no-titles */
static int no_titles = 0;

/* available fields */
static sk_stringmap_t *field_map = NULL;

/* character that separates input fields (the delimiter) */
static char column_separator = '|';

/* for processing the input files */
static sk_options_ctx_t *optctx;

/* the fields (columns) to parse in the order to parse them; each
 * value is an ID from field_map, set by --fields */
static uint32_t *field_list = NULL;

/* number of fields to get from input; length of field_list */
static uint32_t num_fields = 0;

/* default values from user */
static char *default_val[TUC_ARRAY_SIZE];

/* regular expression used to determine the time format */
static regex_t time_regex;

/* automatically set the class for sites that have a single class */
static char global_class_name[SK_MAX_STRLEN_FLOWTYPE];

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* current input line, and stream from which it was read */
static current_line_t current_line;

/* a pointer to the current input line */
static current_line_t *curline = &current_line;


/* OPTIONS SETUP */

typedef enum {
    OPT_FIELDS, OPT_COLUMN_SEPARATOR,
    OPT_OUTPUT_PATH, OPT_BAD_INPUT_LINES,
    OPT_VERBOSE, OPT_STOP_ON_ERROR, OPT_NO_TITLES
} appOptionsEnum;


static struct option appOptions[] = {
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"bad-input-lines",     REQUIRED_ARG, 0, OPT_BAD_INPUT_LINES},
    {"verbose",             NO_ARG,       0, OPT_VERBOSE},
    {"stop-on-error",       NO_ARG,       0, OPT_STOP_ON_ERROR},
    {"no-titles",           NO_ARG,       0, OPT_NO_TITLES},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    NULL, /* generated dynamically */
    "Split input fields on this character. Def. '|'",
    "Write the SiLK Flow records to this stream. Def. stdout",
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

static struct option defaultValueOptions[] = {
    {"saddress",          REQUIRED_ARG, 0, RWREC_FIELD_SIP},
    {"daddress",          REQUIRED_ARG, 0, RWREC_FIELD_DIP},
    {"sport",             REQUIRED_ARG, 0, RWREC_FIELD_SPORT},
    {"dport",             REQUIRED_ARG, 0, RWREC_FIELD_DPORT},
    {"protocol",          REQUIRED_ARG, 0, RWREC_FIELD_PROTO},

    {"packets",           REQUIRED_ARG, 0, RWREC_FIELD_PKTS},
    {"bytes",             REQUIRED_ARG, 0, RWREC_FIELD_BYTES},
    {"flags-all",         REQUIRED_ARG, 0, RWREC_FIELD_FLAGS},

    {"stime",             REQUIRED_ARG, 0, RWREC_FIELD_STIME},
    {"duration",          REQUIRED_ARG, 0, RWREC_FIELD_ELAPSED},
    {"etime",             REQUIRED_ARG, 0, RWREC_FIELD_ETIME},

    {"sensor",            REQUIRED_ARG, 0, RWREC_FIELD_SID},

    {"input-index",       REQUIRED_ARG, 0, RWREC_FIELD_INPUT},
    {"output-index",      REQUIRED_ARG, 0, RWREC_FIELD_OUTPUT},
    {"next-hop-ip",       REQUIRED_ARG, 0, RWREC_FIELD_NHIP},

    {"flags-initial",     REQUIRED_ARG, 0, RWREC_FIELD_INIT_FLAGS},
    {"flags-session",     REQUIRED_ARG, 0, RWREC_FIELD_REST_FLAGS},
    {"attributes",        REQUIRED_ARG, 0, RWREC_FIELD_TCP_STATE},
    {"application",       REQUIRED_ARG, 0, RWREC_FIELD_APPLICATION},

    {"class",             REQUIRED_ARG, 0, RWREC_FIELD_FTYPE_CLASS},
    {"type",              REQUIRED_ARG, 0, RWREC_FIELD_FTYPE_TYPE},

    {"stime+msec",        REQUIRED_ARG, 0, RWREC_FIELD_STIME_MSEC},
    {"etime+msec",        REQUIRED_ARG, 0, RWREC_FIELD_ETIME_MSEC},
    {"duration+msec",     REQUIRED_ARG, 0, RWREC_FIELD_ELAPSED_MSEC},

    {"icmp-type",         REQUIRED_ARG, 0, RWREC_FIELD_ICMP_TYPE},
    {"icmp-code",         REQUIRED_ARG, 0, RWREC_FIELD_ICMP_CODE},

    {0,0,0,0}             /* sentinel entry */
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  defaultValueHandler(clientData cData, int opt_ind, char *opt_arg);
static int  createStringmaps(void);
static int  parseFields(const char *field_string, char **errmsg);
static int
processFields(
    parsed_values_t        *val,
    uint32_t                field_count,
    uint32_t               *field_type,
    char                  **field_val,
    int                     checking_defaults);
static void badLine(const char *fmt, ...)
    SK_CHECK_PRINTF(1, 2);


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
     "\tGenerate SiLK flow records from textual input; the input should be\n" \
     "\tin a form similar to what rwcut generates.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_FIELDS:
            fprintf(fh, "Field(s) to parse from the input. List fields by"
                    " name or\n\tnumber, separated by commas:\n");
            skStringMapPrintUsage(field_map, fh, 4);
            break;
          default:
            /* Simple static help text from the appHelp array */
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
    sksiteOptionsUsage(fh);
    skOptionsCtxOptionsUsage(optctx, fh);

    for (i = 0; defaultValueOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. Use given value for the %s field.\n",
                defaultValueOptions[i].name,
                SK_OPTION_HAS_ARG(defaultValueOptions[i]),
                defaultValueOptions[i].name);
    }

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

    if (field_map) {
        (void)skStringMapDestroy(field_map);
    }
    if (field_list) {
        free(field_list);
        field_list = NULL;
    }

    regfree(&time_regex);

    skOptionsNotesTeardown();
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

    assert(TUC_FIELD_IGNORED < TUC_ARRAY_SIZE);

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(default_val, 0, sizeof(default_val));

    /* although the input to rwtuc is text and not binary, set the
     * INPUT_BINARY flag so rwtuc does not accept input from a TTY
     * without the user explicitly providing an arg of "stdin" */
    optctx_flags = (SK_OPTIONS_CTX_ALLOW_STDIN | SK_OPTIONS_CTX_XARGS
                    | SK_OPTIONS_CTX_INPUT_BINARY);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(defaultValueOptions, &defaultValueHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* set time regex */
    rv = regcomp(&time_regex, RWTUC_TIME_REGEX, REG_EXTENDED|REG_NOSUB);
    if (rv) {
        char errbuf[1024];
        regerror(rv, &time_regex, errbuf, sizeof(errbuf));
        skAppPrintErr("Unable to compile time regex: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* initialize string-map of field identifiers, and add the locally
     * defined fields. */
    if (createStringmaps()) {
        skAppPrintErr("Unable to setup fields stringmap");
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* cannot specify --no-titles unless --fields is given */
    if (no_titles && !field_list) {
        skAppPrintErr("May only use --%s when --%s is specified",
                      appOptions[OPT_NO_TITLES].name,
                      appOptions[OPT_FIELDS].name);
        skAppUsage();
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* use "stdout" as default output path */
    if (NULL == out_stream) {
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
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
    if ((rv = skStreamSetCompressionMethod(out_stream, comp_method))
        || (rv = skOptionsNotesAddToStream(out_stream))
        || (rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream),
                                       1, argc, argv))
        || (rv = skStreamOpen(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skAppPrintErr("Could not open output file");
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
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    const char *char_name;
    char *errmsg;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_FIELDS:
        if (field_list != NULL) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (parseFields(opt_arg, &errmsg)) {
            skAppPrintErr("Invalid %s: %s",
                          appOptions[opt_index].name, errmsg);
            return 1;
        }
        break;

      case OPT_COLUMN_SEPARATOR:
        switch (opt_arg[0]) {
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
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
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
 *  ok = defaultValueHandler(cData, opt_index, opt_arg);
 *
 *    Like appOptionsHandler(), except it handles the options
 *    specified in the defaultValueOptions[] array.
 */
static int
defaultValueHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    if (opt_index < 0 || opt_index >= TUC_ARRAY_SIZE) {
        skAbort();
    }
    default_val[opt_index] = opt_arg;
    return 0;
}


/*
 *  ok = createStringmaps();
 *
 *    Create the global 'field_map'.  Return 0 on success, or -1 on
 *    failure.
 */
static int
createStringmaps(
    void)
{
    if (rwAsciiFieldMapAddDefaultFields(&field_map)
        || skStringMapAddEntries(field_map, -1, tuc_fields))
    {
        return -1;
    }

    if (max_avail_field > TUC_ARRAY_SIZE) {
        skAbort();
    }

    return 0;
}


/*
 *  status = parseFields(fields_string);
 *
 *    Parse the user's option for the --fields switch and fill in the
 *    global 'outputs[]' array of out_stream_t's.  Return 0 on
 *    success; -1 on failure.
 */
static int
parseFields(
    const char         *field_string,
    char              **errmsg)
{
    static char buf[256];
    BITMAP_DECLARE(field_dup, TUC_ARRAY_SIZE);
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    int rv = -1;
    uint32_t i;

    assert(NULL == field_list);

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
        assert(entry->id < TUC_ARRAY_SIZE);
        if (BITMAP_GETBIT(field_dup, entry->id)
            && TUC_FIELD_IGNORED != entry->id)
        {
            snprintf(buf, sizeof(buf), "Duplicate name '%s'", entry->name);
            *errmsg = buf;
            goto END;
        }
        BITMAP_SETBIT(field_dup, entry->id);
    }

    skStringMapIterReset(iter);

    /* create an array to hold the IDs */
    num_fields = skStringMapIterCountMatches(iter);
    field_list = (uint32_t*)malloc(num_fields * sizeof(uint32_t));
    if (NULL == field_list) {
        skAppPrintOutOfMemory("field id list");
        goto END;
    }

    /* fill the array */
    for (i = 0; skStringMapIterNext(iter, &entry, NULL)==SK_ITERATOR_OK; ++i) {
        assert(i < num_fields);
        field_list[i] = entry->id;
    }

    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    return rv;
}


/*
 *    If invalid input lines are being written to a stream, write the
 *    text in 'curline', preceeded by the input file's name and line
 *    number.
 *
 *    If verbose output or stop-on-error is set, format the error
 *    message given by the arguments and print an error message.  The
 *    error message includes the current input file and line number.
 */
static void badLine(
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
        skAppPrintErr("%s:%d:%s",
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
 *  is_title = firstLineIsTitle(first_line);
 *
 *    Determine if the input line in 'first_line' is a title line by
 *    looking for a word that matches a field name.  Return 1 if it
 *    is, 0 if it is not.
 */
static int
firstLineIsTitle(
    char               *first_line)
{
    sk_stringmap_entry_t *entry;
    char *cp;
    char *ep;
    uint32_t i;
    int is_title = 0;

    assert(first_line);
    assert(field_list);

    /* we have the fields, need to determine if first_line is a
     * title line. */
    cp = first_line;
    for (i = 0; i < num_fields; ++i) {
        ep = strchr(cp, column_separator);
        if (!is_title && field_list[i] != TUC_FIELD_IGNORED) {
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
            if ((1 + i != num_fields) && is_title) {
                badLine(("Too few fields on title line:"
                         " found %" PRIu32 " of %" PRIu32 " expected"),
                        i, num_fields);
            }
            break;
        }
    }

    if (is_title && (*cp != '\0')
        && (strlen(cp) != strspn(cp, RWTUC_WHITESPACE)))
    {
        badLine(("Too many fields on title line:"
                 " text follows delimiter number %" PRIu32), num_fields);
    }

    return is_title;
}


/*
 *  is_title = determineFields(&field_type, &field_val, &defaults, firstline);
 *
 *    Set the types of fields to be parsed in this file (field_type),
 *    an array to hold the strings to be parsed on each row
 *    (field_val), and the default values for this file (defaults).
 *    When finished with the file, the caller should free the
 *    'field_type' and 'field_val' arrays.
 *
 *    The set of field_type's will be determined from the --fields
 *    value if present, otherwise from the firstline of the file,
 *    which must be a title-line.  If the user provided a fixed value
 *    for the field, any field having that type will be set to
 *    'ignore'.
 *
 *    Return 0 if the first line contains data to be parsed; 1 if it
 *    contains a title; or -1 on error.
 *
 *    We should be smarter; if the user provided a --fields switch,
 *    there is no need to recompute the defaults each time, and the
 *    field_type and field_val arrays will have fixed sizes, so they
 *    would not need to be reallocated each time.
 */
static int
determineFields(
    uint32_t              **field_type,
    char                 ***field_val,
    parsed_values_t        *defaults,
    char                   *first_line)
{
    uint32_t have_field[TUC_ARRAY_SIZE];
    uint32_t default_list[TUC_ARRAY_SIZE];
    char *active_defaults[TUC_ARRAY_SIZE];
    uint32_t num_defaults;
    uint32_t i;
    int is_title = 0;
    int per_file_field_list = 0;
    int have_stime, have_etime, have_elapsed;
    char *errmsg;

    memset(defaults, 0, sizeof(parsed_values_t));
    memset(have_field, 0, sizeof(have_field));

    if (field_list != NULL) {
        /* already have a field list */
        if (0 == no_titles) {
            /* check whether the first line a title */
            is_title = firstLineIsTitle(first_line);
            if (is_title < 0) {
                return is_title;
            }
        }
    } else {
        /* need to get fields from the first line */
        char *cp, *ep;
        assert(0 == no_titles);
        cp = ep = first_line;
        while (*cp) {
            if (*cp == column_separator) {
                /* convert column_separator to comma for parseFields() */
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
        if (parseFields(first_line, &errmsg)) {
            skAppPrintErr(("Unable to determine fields from first line"
                           " of stream '%s': %s"),
                          skStreamGetPathname(curline->stream), errmsg);
            return -1;
        }
        is_title = 1;
        per_file_field_list = 1;
    }

    /* create an array to hold a copy of the field_list */
    *field_type = (uint32_t*)calloc(num_fields, sizeof(uint32_t));
    if (*field_type == NULL) {
        skAppPrintOutOfMemory("field list copy");
        exit(EXIT_FAILURE);
    }

    /* create an array to hold the field values */
    *field_val = (char**)calloc(num_fields, sizeof(char*));
    if (*field_val == NULL) {
        skAppPrintOutOfMemory("field values");
        exit(EXIT_FAILURE);
    }

    /* set have_field[] for all the fields we saw.  In addition, copy
     * the field_list into the copy (field_type) that gets returned,
     * but set any fields that have default values to 'ignore' so they
     * do not get parsed. */
    for (i = 0; i < num_fields; ++i) {
        have_field[field_list[i]] = 1;
        if (default_val[field_list[i]] == NULL) {
            (*field_type)[i] = field_list[i];
        } else {
            (*field_type)[i] = TUC_FIELD_IGNORED;
        }
    }

    /* destroy the field_list if we created it above */
    if (per_file_field_list) {
        free(field_list);
        field_list = NULL;
    }

    /* set have_field[] for all values that have defaults */
    for (i = 0; i < max_avail_field; ++i) {
        if (default_val[i] != NULL) {
            have_field[i] = 1;
        }
    }

    /* if there is no packets value, set to 1 */
    if ( !have_field[RWREC_FIELD_PKTS]) {
        rwRecSetPkts(&defaults->rec, 1);
    }

    /* if no bytes value, we will set it to the packets value */
    if ( !have_field[RWREC_FIELD_BYTES]) {
        if ( !have_field[RWREC_FIELD_PKTS]) {
            /* packets field is fixed, so bytes field can be fixed too */
            rwRecSetBytes(&defaults->rec, 1);
        } else {
            /* must do calculation each time */
            defaults->bytes_equals_pkts = 1;
        }
    }

    /* must have both or neither ICMP type and ICMP code */
    if (have_field[RWREC_FIELD_ICMP_TYPE]
        != have_field[RWREC_FIELD_ICMP_CODE])
    {
        skAppPrintErr("Either both ICMP type and ICMP code"
                      " must be present or neither may be present");
        return -1;
    }
    if (have_field[RWREC_FIELD_ICMP_TYPE]) {
        defaults->have_icmp = 1;
    }

    /* must have both or neither initial and session flags */
    if (have_field[RWREC_FIELD_INIT_FLAGS]
        != have_field[RWREC_FIELD_REST_FLAGS])
    {
        skAppPrintErr("Either both initial- and session-flags"
                      " must be present or neither may be present");
        return -1;
    }
    if (have_field[RWREC_FIELD_INIT_FLAGS]) {
        rwRecSetTcpState(&defaults->rec, SK_TCPSTATE_EXPANDED);
    }

    /* need a time */
    have_stime = (have_field[RWREC_FIELD_STIME]
                  || have_field[RWREC_FIELD_STIME_MSEC]);
    have_etime = (have_field[RWREC_FIELD_ETIME]
                  || have_field[RWREC_FIELD_ETIME_MSEC]);
    have_elapsed = (have_field[RWREC_FIELD_ELAPSED]
                    || have_field[RWREC_FIELD_ELAPSED_MSEC]);
    if (have_stime) {
        if (have_elapsed) {
            defaults->handle_time = CALC_NONE;
            if (have_etime) {
                /* we will set etime from stime+elapsed */
                default_val[RWREC_FIELD_ETIME] = NULL;
                default_val[RWREC_FIELD_ETIME_MSEC] = NULL;
                for (i = 0; i < num_fields; ++i) {
                    if (((*field_type)[i] == RWREC_FIELD_ETIME)
                        || ((*field_type)[i] == RWREC_FIELD_ETIME_MSEC))
                    {
                        (*field_type)[i] = TUC_FIELD_IGNORED;
                    }
                }
            }
        } else if (have_etime) {
            /* must compute elapsed from eTime - sTime */
            defaults->handle_time = CALC_ELAPSED;
        }
        /* else elapsed is fixed at 0 */
    } else if (have_etime) {
        /* must calculate stime from etime and duration */
        defaults->handle_time = CALC_STIME;

        /* we could be smarter here: if we have etime but no elapsed
         * time, then stime and etime will be equal, and we could just
         * set the stime instead of the etime */
    } else {
        /* have no stime or etime.  set stime to now */
        rwRecSetStartTime(&defaults->rec, sktimeNow());
        defaults->handle_time = CALC_NONE;
    }

    /* set the class to the default when 'type' is specified but class
     * isn't and silk.conf defines only one class. */
    if (have_field[RWREC_FIELD_FTYPE_TYPE]
        && !have_field[RWREC_FIELD_FTYPE_CLASS]
        && (0 == sksiteClassGetMaxID()))
    {
        sksiteClassGetName(global_class_name, sizeof(global_class_name), 0);
        defaults->class_name = global_class_name;
    }

    /* create a list of fields for which we have default values */
    num_defaults = 0;
    for (i = 0; i < max_avail_field; ++i) {
        if (default_val[i] != NULL) {
            default_list[num_defaults] = i;
            active_defaults[num_defaults] = default_val[i];
            ++num_defaults;
        }
    }

    /* process the default fields */
    if (processFields(defaults,num_defaults,default_list,active_defaults,1))
    {
        return -1;
    }

    /* verify class and type */
    if (defaults->class_name && defaults->type_name) {
        if (rwRecGetFlowType(&defaults->rec) == SK_INVALID_FLOWTYPE) {
            skAppPrintErr("Bad default class/type combination: %s/%s",
                          defaults->class_name, defaults->type_name);
            return -1;
        }
        /* we have set the flow_type on the default record, there is
         * no need to look it up for each line. */
        defaults->class_name = defaults->type_name = NULL;
    }

    return is_title;
}


/*
 *  convertOldTime(old_time_str);
 *
 *    Convert the 'old_time_str' that should have a form of
 *
 *        MM/DD/YYYY hh:mm:ss[.sss]
 *
 *    to the new form of YYYY/MM/DD:hh:mm:ss[.sss]
 */
static void
convertOldTime(
    char               *old_time_str)
{
    char tmp;
    int i;

    for (i = 0; i < 5; ++i) {
        tmp = old_time_str[i];
        old_time_str[i] = old_time_str[i+6];
        old_time_str[i+5] = tmp;
    }
    old_time_str[4] = '/';
    old_time_str[10] = ':';
}


/*
 *  ok = processFields(val, field_count, field_types, field_values, checking_defaults);
 *
 *    Parse the 'field_count' fields whose types and string-values are
 *    given in the 'field_types' and 'field_values' arrays,
 *    respectively.  Set the fields specified in the 'val' structure.
 *
 *    'checking_defaults' should be non-zero when processing the
 *    default values and 0 otherwise.  It is used to determine the
 *    text of the error message should a value be invalid.
 *
 *    Return 0 on success, non-zero on failure.
 */
static int
processFields(
    parsed_values_t        *val,
    uint32_t                field_count,
    uint32_t               *field_type,
    char                  **field_val,
    int                     checking_defaults)
{
    char field_name[128];
    sktime_t t;
    skipaddr_t ipaddr;
    uint32_t tmp32;
    uint8_t proto;
    uint8_t flags;
    uint8_t tcp_state;
    uint32_t i;
    char *cp;
    int rv = 0;

    tcp_state = rwRecGetTcpState(&val->rec);

    for (i = 0; i < field_count; ++i) {
        cp = field_val[i];
        while (isspace((int)*cp)) {
            ++cp;
        }

        switch (field_type[i]) {
          case TUC_FIELD_IGNORED:
            break;

          case RWREC_FIELD_ICMP_TYPE:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT8_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            val->itype = (uint8_t)tmp32;
            break;

          case RWREC_FIELD_ICMP_CODE:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT8_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            val->icode = (uint8_t)tmp32;
            break;

          case RWREC_FIELD_SIP:
            rv = skStringParseIP(&ipaddr, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecMemSetSIP(&val->rec, &ipaddr);
            break;

          case RWREC_FIELD_DIP:
            rv = skStringParseIP(&ipaddr, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecMemSetDIP(&val->rec, &ipaddr);
            break;

          case RWREC_FIELD_SPORT:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT16_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetSPort(&val->rec, (uint16_t)tmp32);
            break;

          case RWREC_FIELD_DPORT:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT16_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetDPort(&val->rec, (uint16_t)tmp32);
            break;

          case RWREC_FIELD_PROTO:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT8_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetProto(&val->rec, (uint8_t)tmp32);
            break;

          case RWREC_FIELD_PKTS:
            rv = skStringParseUint32(&tmp32, cp, 1, 0);
            if (rv) {
                /* FIXME: Clamp value to max instead of rejecting */
                goto PARSE_ERROR;
            }
            rwRecSetPkts(&val->rec, tmp32);
            break;

          case RWREC_FIELD_BYTES:
            rv = skStringParseUint32(&tmp32, cp, 1, 0);
            if (rv) {
                /* FIXME: Clamp value to max instead of rejecting */
                goto PARSE_ERROR;
            }
            rwRecSetBytes(&val->rec, tmp32);
            break;

          case RWREC_FIELD_FLAGS:
            rv = skStringParseTCPFlags(&flags, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetFlags(&val->rec, flags);
            break;

          case RWREC_FIELD_STIME:
          case RWREC_FIELD_STIME_MSEC:
            if (0 == regexec(&time_regex, cp, 0, NULL, 0)) {
                convertOldTime(cp);
            }
            rv = skStringParseDatetime(&t, cp, NULL);
            if (rv) {
                /* FIXME: Allow small integers as epoch times? */
                goto PARSE_ERROR;
            }
            rwRecSetStartTime(&val->rec, t);
            break;

          case RWREC_FIELD_ELAPSED:
          case RWREC_FIELD_ELAPSED_MSEC:
            {
                double dur;
                rv = skStringParseDouble(&dur, cp, 0.0,
                                         ((double)UINT32_MAX / 1e3));
                if (rv) {
                    /* FIXME: Clamp value to max instead of rejecting */
                    goto PARSE_ERROR;
                }
                /* add a bit of slop since doubles aren't exact */
                rwRecSetElapsed(&val->rec, (uint32_t)(1000 * (dur + 5e-7)));
            }
            break;

          case RWREC_FIELD_ETIME:
          case RWREC_FIELD_ETIME_MSEC:
            if (0 == regexec(&time_regex, cp, 0, NULL, 0)) {
                convertOldTime(cp);
            }
            rv = skStringParseDatetime(&(val->eTime), cp, NULL);
            if (rv) {
                /* FIXME: Allow small integers as epoch times? */
                goto PARSE_ERROR;
            }
            break;

          case RWREC_FIELD_SID:
            if (isdigit((int)*cp)) {
                rv = skStringParseUint32(&tmp32, cp, 0, SK_INVALID_SENSOR-1);
                if (rv) {
                    goto PARSE_ERROR;
                }
                rwRecSetSensor(&val->rec, (sk_sensor_id_t)tmp32);
            } else {
                rwRecSetSensor(&val->rec, sksiteSensorLookup(cp));
            }
            break;

          case RWREC_FIELD_INPUT:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT16_MAX);
            if (rv) {
                /* FIXME: Clamp value to max instead of rejecting */
                goto PARSE_ERROR;
            }
            rwRecSetInput(&val->rec, (uint16_t)tmp32);
            break;

          case RWREC_FIELD_OUTPUT:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT16_MAX);
            if (rv) {
                /* FIXME: Clamp value to max instead of rejecting */
                goto PARSE_ERROR;
            }
            rwRecSetOutput(&val->rec, (uint16_t)tmp32);
            break;

          case RWREC_FIELD_NHIP:
            rv = skStringParseIP(&ipaddr, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecMemSetNhIP(&val->rec, &ipaddr);
            break;

          case RWREC_FIELD_INIT_FLAGS:
            rv = skStringParseTCPFlags(&flags, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetInitFlags(&val->rec, flags);
            break;

          case RWREC_FIELD_REST_FLAGS:
            rv = skStringParseTCPFlags(&flags, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetRestFlags(&val->rec, flags);
            break;

          case RWREC_FIELD_TCP_STATE:
            rv = skStringParseTCPState(&flags, cp);
            if (rv) {
                goto PARSE_ERROR;
            }
            tcp_state |= flags;
            break;

          case RWREC_FIELD_APPLICATION:
            rv = skStringParseUint32(&tmp32, cp, 0, UINT16_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            rwRecSetApplication(&val->rec, (uint16_t)tmp32);
            break;

          case RWREC_FIELD_FTYPE_CLASS:
            val->class_name = cp;
            break;

          case RWREC_FIELD_FTYPE_TYPE:
            val->type_name = cp;
            break;

          default:
            skAbortBadCase(field_type[i]);
        }
    }


    proto = rwRecGetProto(&val->rec);

    /* use the ICMP type/code when appropriate */
    if (val->have_icmp && (IPPROTO_ICMP == proto || IPPROTO_ICMPV6 == proto)) {
        rwRecSetDPort(&val->rec, (uint16_t)((val->itype << 8) | val->icode));
    }

    /* handle class and type */
    if (val->class_name && val->type_name) {
        rwRecSetFlowType(&val->rec,
                         sksiteFlowtypeLookupByClassType(val->class_name,
                                                         val->type_name));
    }

    /* Handle initialFlags, sessionFlags, and ALL-Flags */
    if (checking_defaults) {
        /* processing the defaults; do not modify anything */
    } else if (rwRecGetInitFlags(&val->rec) || rwRecGetRestFlags(&val->rec)) {
        if (IPPROTO_TCP == proto) {
            /* if either initial-flags or rest-flags is set, set
             * overall-flags to their combination */
            rwRecSetFlags(&val->rec, (rwRecGetInitFlags(&val->rec)
                                      | rwRecGetRestFlags(&val->rec)));
        } else {
            /* if flow is not TCP, do not record the initial-flags and
             * session-flags, and unset the EXPANDED flag. */
            rwRecSetInitFlags(&val->rec, 0);
            rwRecSetRestFlags(&val->rec, 0);
            tcp_state &= ~SK_TCPSTATE_EXPANDED;
        }
    } else {
        /* unset the EXPANDED bit */
        tcp_state &= ~SK_TCPSTATE_EXPANDED;
    }

    rwRecSetTcpState(&val->rec, tcp_state);

    return 0;

  PARSE_ERROR:
    rwAsciiGetFieldName(field_name, sizeof(field_name),
                        (rwrec_printable_fields_t)field_type[i]);
    if (checking_defaults) {
        skAppPrintErr("Error parsing default %s value '%s': %s",
                      field_name, cp, skStringParseStrerror(rv));
        return -1;
    }
    badLine("Invalid %s '%s': %s", field_name, cp, skStringParseStrerror(rv));
    return -1;
}


/*
 *  ok = processFile();
 *
 *    Read each line of text from the stream in the global 'curline'
 *    structure, create an rwRec from the fields on the line, and
 *    write the records to the global out_stream stream.
 *
 *    Return 0 on success or -1 on failure.
 */
static int
processFile(
    void)
{
    static char line[RWTUC_LINE_BUFSIZE];
    parsed_values_t defaults;
    parsed_values_t currents;
    uint32_t *field_type = NULL;
    char **field_val = NULL;
    char *cp;
    char *ep;
    uint32_t field;
    int is_title = -1;
    int rv;

    /* read until end of file */
    while ((rv = skStreamGetLine(curline->stream, line, sizeof(line),
                                 &curline->lineno))
           != SKSTREAM_ERR_EOF)
    {
        if (bad_stream) {
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
            goto END;
        }

        /* initialize the field_type array either from the --fields
         * switch or based on the first line in the file. */
        if (is_title < 0) {
            /* fill in the defaults */
            is_title = determineFields(&field_type, &field_val,
                                       &defaults, line);
            if (is_title < 0) {
                /* error */
                return -1;
            }
            if (is_title > 0) {
                /* goto next line */
                continue;
            }
        }

        /* We have a line; process it */
        cp = line;
        field = 0;
        memcpy(&currents, &defaults, sizeof(parsed_values_t));

        /* break the line into separate fields */
        while (field < num_fields) {
            field_val[field] = cp;
            ++field;

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

        /* check for extra fields at the end */
        if ((*cp != '\0') && (strlen(cp) != strspn(cp, RWTUC_WHITESPACE))) {
            badLine(("Too many fields on line:"
                     " text follows delimiter number %" PRIu32),
                    num_fields);
            goto NEXT_LINE;
        }

        /* check for too few fields */
        if (field != num_fields) {
            badLine(("Too few fields on line:"
                     " found %" PRIu32 " of %" PRIu32 " expected"),
                    field, num_fields);
            goto NEXT_LINE;
        }

        /* process fields */
        if (processFields(&currents, num_fields, field_type, field_val, 0)) {
            goto NEXT_LINE;
        }

        /* verify bytes */
        if (currents.bytes_equals_pkts) {
            rwRecSetBytes(&currents.rec, rwRecGetPkts(&currents.rec));
        }

        /* handle time */
        switch (currents.handle_time) {
          case CALC_STIME:
            rwRecSetStartTime(&currents.rec,
                              (currents.eTime
                               - rwRecGetElapsed(&currents.rec)));
            break;

          case CALC_ELAPSED:
            if (rwRecGetStartTime(&currents.rec) > currents.eTime) {
                badLine("End time less than start time");
                goto NEXT_LINE;
            }
            if (currents.eTime - rwRecGetStartTime(&currents.rec) > UINT32_MAX)
            {
                /* FIXME: Clamp value to max instead of rejecting */
                badLine("Computed duration too large");
                goto NEXT_LINE;
            }
            rwRecSetElapsed(&currents.rec,
                            (currents.eTime-rwRecGetStartTime(&currents.rec)));
            break;

          case CALC_NONE:
            break;
        }

        /* output binary rwrec */
        rv = skStreamWriteRecord(out_stream, &currents.rec);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                return -1;
            }
        }

      NEXT_LINE:
        ; /* empty */
    } /* outer loop over lines  */

  END:
    if (field_type) {
        free(field_type);
    }
    if (field_val) {
        free(field_val);
    }

    return 0;
}


int main(int argc, char **argv)
{
    char *fname;
    ssize_t rv = 0;

    appSetup(argc, argv);

    /* process the input file(s) */
    while ((rv = skOptionsCtxNextArgument(optctx, &fname)) == 0) {
        /* create an input stream and open text file */
        if ((rv = skStreamCreate(&curline->stream, SK_IO_READ,SK_CONTENT_TEXT))
            || (rv = skStreamBind(curline->stream, fname))
            || (rv = skStreamOpen(curline->stream)))
        {
            skStreamPrintLastErr(curline->stream, rv, &skAppPrintErr);
            skStreamDestroy(&curline->stream);
            rv = -1;
            break;
        }
        rv = processFile();
        skStreamDestroy(&curline->stream);
        if (rv != 0) {
            break;
        }
    }

    /* if everything went well, make certain there are headers in our
     * output */
    if (rv == 1) {
        rv = skStreamWriteSilkHeader(out_stream);
        if (rv) {
            if (rv == SKSTREAM_ERR_PREV_DATA) {
                /* headers already printed */
                rv = 0;
            } else {
                skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            }
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

    return ((rv == -1) ? EXIT_FAILURE : EXIT_SUCCESS);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
