/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
 *    rwbagtool performs various operations on bags.  It can add bags
 *    together, subtract a subset of data from a bag, perform key
 *    intersection with an IPset, extract the key list of a bag as an
 *    IPset, or filter bag records based on their counter value.
 *
 */


#include <silk/silk.h>

RCSIDENT("$SiLK: rwbagtool.c 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/skbag.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skstream.h>
#include <silk/sksite.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* minimum counter that can be specified to --mincounter */
#define BAGTOOL_MIN_COUNTER  UINT64_C(1)

/* What to do when malloc() fails */
#define EXIT_NO_MEMORY                                               \
    do {                                                             \
        skAppPrintOutOfMemory(NULL);                                 \
        exit(EXIT_FAILURE);                                          \
    } while(0)

#define ERR_READ_BAG(erb_stream, erb_err)                               \
    if (SKBAG_ERR_READ == (erb_err)) {                                  \
        skStreamPrintLastErr((erb_stream),                              \
                             skStreamGetLastReturnValue(erb_stream),    \
                             &skAppPrintErr);                           \
    } else {                                                            \
        skAppPrintErr("Could not read Bag from '%s': %s",               \
                      skStreamGetPathname(erb_stream),                  \
                      skBagStrerror(erb_err));                          \
    }

#define ERR_GET_COUNT(egc_key, egc_err)                                 \
    skAppPrintErr("Error getting count for key (%s): %s",               \
                  skipaddrString(ipbuf1, &(egc_key).val.addr, 0),       \
                  skBagStrerror(egc_err))

#define ERR_SET_COUNT(esc_key, esc_val, esc_err)                        \
    skAppPrintErr(("Error setting key=>counter (%s=>%" PRIu64 ": %s"),  \
                  skipaddrString(ipbuf1, &(esc_key).val.addr, 0),       \
                  (esc_val).val.u64, skBagStrerror(esc_err))

#define ERR_REMOVE_KEY(erk_key, erk_err)                                \
    skAppPrintErr("Error removing key (%s): %s",                        \
                  skipaddrString(ipbuf1, &(erk_key).val.addr, 0),       \
                  skBagStrerror(erk_err))

#define ERR_ITERATOR(ei_description, ei_err)                    \
    skAppPrintErr("Error in %s bag iterator: %s",               \
                  ei_description, skBagStrerror(ei_err))

/* the IDs for options.  we need this early */
typedef enum {
    OPT_ADD,
    OPT_SUBTRACT,
    OPT_MINIMIZE,
    OPT_MAXIMIZE,
    OPT_DIVIDE,
    OPT_COMPARE,
    OPT_SCALAR_MULTIPLY,
    OPT_INTERSECT,
    OPT_COMPLEMENT,
    OPT_MINKEY,
    OPT_MAXKEY,
    OPT_MINCOUNTER,
    OPT_MAXCOUNTER,
    OPT_INVERT,
    OPT_COVERSET,
    OPT_OUTPUT_PATH,
    OPT_MODIFY_INPLACE,
    OPT_BACKUP_PATH
} appOptionsEnum;

#define NUM_BAG_COMARISONS 5

/* types of comparisons we support */
typedef enum {
    BAG_CMP_LT,
    BAG_CMP_LE,
    BAG_CMP_EQ,
    BAG_CMP_GE,
    BAG_CMP_GT
} bag_compare_t;


/* LOCAL VARIABLES */

/* the output bag that we create */
static skBag_t *out_bag = NULL;

/* where to write the resulting bag */
static skstream_t *out_stream = NULL;

/* the filename of the output file */
static const char *output_path = NULL;

/* whether --modify-inplace was given */
static int modify_inplace = 0;

/* when --modify-inplace is given, the name of the --backup-path if
 * requested */
static const char *backup_path = NULL;

/* when --modify-inplace is given, the stat() of the original file; used to
 * copy permission, owner, group to new file */
static struct stat stat_orig;

/* whether to remove the temporary file in the atexit() handler */
static volatile sig_atomic_t remove_temp_file = 0;

/* whether signals are being paused during file move */
static volatile sig_atomic_t signal_deferred = 0;

/* the ID of a signal that arrives while signals are defered */
static volatile sig_atomic_t signal_pending = 0;

/* whether a signal arrives while processing a signal */
static volatile sig_atomic_t signal_signaled = 0;

/* set of signals that are handled or blocked */
static int sig_list[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM,
#ifdef SIGPWR
    SIGPWR,
#endif
    0  /* sentinel */
};

/* What action the user wants to take (add, intersect, etc).  The
 * variable 'user_action' should be a value between OPT_ADD and
 * OPT_SCALAR_MULTIPLY.  Set 'user_action_none' to a value outside
 * that range; this denotes that the user did not choose a value.
 */
static const appOptionsEnum user_action_none = OPT_OUTPUT_PATH;
static appOptionsEnum user_action;

/* Type of comparison to do */
static bag_compare_t bag_cmp;

/* When writing the new bag, only output entries whose keys and/or
 * whose values lie between these limits. */
static uint64_t mincounter = SKBAG_COUNTER_MIN;
static uint64_t maxcounter = SKBAG_COUNTER_MAX;

static skipaddr_t minkey;
static skipaddr_t maxkey;

static const char *have_minkey = NULL;
static const char *have_maxkey = NULL;

/* Bag comparison map */
static const struct bag_compare_map_st {
    const char     *name;
    bag_compare_t   value;
} bag_compare_map[NUM_BAG_COMARISONS] = {
    {"lt",      BAG_CMP_LT},
    {"le",      BAG_CMP_LE},
    {"eq",      BAG_CMP_EQ},
    {"ge",      BAG_CMP_GE},
    {"gt",      BAG_CMP_GT}
};

/* Index of current file argument in argv */
static int arg_index = 0;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* buffers for printing IPs */
static char ipbuf1[SKIPADDR_STRLEN];
static char ipbuf2[SKIPADDR_STRLEN];

/* For scalar multiplication, the scalar */
static uint64_t scalar_multiply = 1;

/* Set to use for intersect and complement intersect */
static skipset_t *mask_set = NULL;

/* options for writing the cover IPset */
static skipset_options_t ipset_options;

static struct app_flags_st {
    /* whether the mask_set is intersect(0) or complement(1) */
    unsigned  complement_set:1;

    /* whether to produce a coverset(1) instead of a bag(0) */
    unsigned  coverset      :1;

    /* whether to invert the bag(1 = yes) */
    unsigned  invert        :1;
} app_flags = {
    0, 0, 0
};

/* whether the --note-strip flag was specified */
static int note_strip = 0;


/* OPTIONS SETUP */

static struct option appOptions[] = {
    {"add",                  NO_ARG,       0, OPT_ADD},
    {"subtract",             NO_ARG,       0, OPT_SUBTRACT},
    {"minimize",             NO_ARG,       0, OPT_MINIMIZE},
    {"maximize",             NO_ARG,       0, OPT_MAXIMIZE},
    {"divide",               NO_ARG,       0, OPT_DIVIDE},
    {"compare",              REQUIRED_ARG, 0, OPT_COMPARE},
    {"scalar-multiply",      REQUIRED_ARG, 0, OPT_SCALAR_MULTIPLY},
    {"intersect",            REQUIRED_ARG, 0, OPT_INTERSECT},
    {"complement-intersect", REQUIRED_ARG, 0, OPT_COMPLEMENT},
    {"minkey",               REQUIRED_ARG, 0, OPT_MINKEY},
    {"maxkey",               REQUIRED_ARG, 0, OPT_MAXKEY},
    {"mincounter",           REQUIRED_ARG, 0, OPT_MINCOUNTER},
    {"maxcounter",           REQUIRED_ARG, 0, OPT_MAXCOUNTER},
    {"invert",               NO_ARG,       0, OPT_INVERT},
    {"coverset",             NO_ARG,       0, OPT_COVERSET},
    {"output-path",          REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"modify-inplace",       NO_ARG,       0, OPT_MODIFY_INPLACE},
    {"backup-path",          REQUIRED_ARG, 0, OPT_BACKUP_PATH},
    {0,0,0,0}                /* sentinel entry */
};

static const char *appHelp[] = {
    "Add the counters for each key across all Bag files",
    "Subtract from first Bag file all subsequent Bag files",
    ("Write to the output the minimum counter for each key across\n"
     "\tall input Bag files. Counter for a missing key is 0"),
    ("Write to the output the maximum counter for each key across\n"
     "\tall input Bag files"),
    "Divide the first Bag by the second Bag",
    ("Compare key/value pairs in exactly two Bag files.  Keep\n"
     "\tonly those keys in the first Bag that also appear in the second Bag\n"
     "\tand whose counter is OP those in the second Bag, where OP is one of:\n"
     "\t  'lt': less than; 'le': less than or equal to; 'eq': equal to;\n"
     "\t  'ge': greater than or equal to; 'gt': greater than.\n"
     "\tThe counter for each key that remains is set to 1."),
    ("Multiply each counter in the Bag by the specified\n"
     "\tvalue. Accepts a single Bag file as input."),
    "Masks keys in bag file using IPs in given IPset file",
    ("Masks keys in bag file using IPs NOT\n"
     "\tin given IPset file"),
    NULL,
    NULL,
    NULL,
    NULL,
    "Count keys for each unique counter value",
    "Extract the IPs from the bag file into an IPset file",
    "Write the output to this stream or file. Def. stdout",
    ("Allow overwriting an existing file and properly handle\n"
     "\tthe case when --output-path names an input file"),
    ("Move the existing OUTPUT-PATH to this location prior to\n"
     "\toverwriting when --modify-inplace is given"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void setUpModifyInplace(void);
static int  bagtoolDivide(skstream_t *stream);
static int  bagtoolSubtract(skstream_t *stream);
static int  writeOutput(void);


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
    ("[SWITCHES] BAG_FILE [BAG_FILES...]\n"                                \
     "\tPerform operations on bag files, creating a new bag file.\n"       \
     "\tRequires at least one bag file to be given on the command line\n"  \
     "\tor to be read from the standard input.  The resulting bag will\n"  \
     "\twill be written to the specified output file or to the standard\n" \
     "\toutput.\n")

    FILE *fh = USAGE_FH;
    int i;
#if SK_ENABLE_IPV6
    const char *v4_or_v6 = "v6";
#else
    const char *v4_or_v6 = "v4";
#endif

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_MINKEY:
            fprintf(fh,
                    ("Output records whose key is at least VALUE,"
                     " an IP%s address\n\tor an integer between"
                     " %" PRIu64 " and %" PRIu64 ", inclusive."
                     " Def. Records with\n\tnon-zero counters\n"),
                    v4_or_v6,
                    (uint64_t)SKBAG_KEY_MIN, (uint64_t)SKBAG_KEY_MAX);
            break;
          case OPT_MAXKEY:
            fprintf(fh,
                    ("Output records whose key is not more than VALUE,"
                     " an IP%s\n\taddress or an integer."
                     " Def. Records with non-zero counters\n"),
                    v4_or_v6);
            break;
          case OPT_MINCOUNTER:
            fprintf(fh,
                    ("Output records whose counter is at least VALUE,"
                     " an integer\n\tbetween %" PRIu64 " and %" PRIu64
                     ", inclusive. Def. %" PRIu64 "\n"),
                    BAGTOOL_MIN_COUNTER, SKBAG_COUNTER_MAX,
                    BAGTOOL_MIN_COUNTER);
            break;
          case OPT_MAXCOUNTER:
            fprintf(fh,
                    ("Output records whose counter is not more than VALUE,"
                     " an\n\tinteger.  Def. %" PRIu64 "\n"),
                    SKBAG_COUNTER_MAX);
            break;
          case OPT_COVERSET:
            fprintf(fh, "%s\n", appHelp[i]);
            skIPSetOptionsUsageRecordVersion(fh);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* free the output bag, stream, and set */
    skBagDestroy(&out_bag);
    skStreamDestroy(&out_stream);
    skIPSetDestroy(&mask_set);
    skIPSetOptionsTeardown();
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
static void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    user_action = user_action_none;
    memset(&ipset_options, 0, sizeof(skipset_options_t));

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skIPSetOptionsRegisterRecordVersion(&ipset_options,
                                               "ipset-record-version")
        || skOptionsNotesRegister(&note_strip)
        || skCompMethodOptionsRegister(&comp_method))
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

    /* parse the options; returns the index into argv[] of the first
     * non-option or < 0 on error  May re-arrange argv[]. */
    arg_index = skOptionsParse(argc, argv);
    assert(arg_index <= argc);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();             /* never returns */
    }

    /* The default action is to add the bags together */
    if (user_action_none == user_action) {
        user_action = OPT_ADD;
    }

    /* error if a minimum is greater than a maximum */
    if (mincounter > maxcounter) {
        skAppPrintErr(("Minimum counter greater than maximum: "
                       "%" PRIu64 " > %" PRIu64),
                      mincounter, maxcounter);
        exit(EXIT_FAILURE);
    }
    if (have_minkey && have_maxkey &&
        skipaddrCompare(&minkey, &maxkey) > 0)
    {
        skAppPrintErr("Minimum key greater than maximum: %s (%s) > %s (%s)",
                      have_minkey, skipaddrString(ipbuf1, &minkey, 0),
                      have_maxkey, skipaddrString(ipbuf2, &maxkey, 0));
        exit(EXIT_FAILURE);
    }

    /* arg_index is looking at first file name to process.  We
     * require at least one bag file, either from stdin or from the
     * command line. */
    switch (user_action) {
      case OPT_COMPARE:
      case OPT_DIVIDE:
        if ((argc - arg_index) != 2) {
            skAppPrintErr("The --%s switch requires exactly two Bag files",
                          appOptions[user_action].name);
            skAppUsage();
        }
        break;

      case OPT_SCALAR_MULTIPLY:
        if ((argc - arg_index) > 1) {
            skAppPrintErr("The --%s switch operates on a single Bag file",
                          appOptions[user_action].name);
            skAppUsage();
        }
        if ((arg_index == argc) && (FILEIsATty(stdin))) {
            skAppPrintErr("No input files on command line and"
                          " stdin is connected to a terminal");
            skAppUsage();
        }
        break;

      default:
        if ((arg_index == argc) && (FILEIsATty(stdin))) {
            skAppPrintErr("No input files on command line and"
                          " stdin is connected to a terminal");
            skAppUsage();
        }
        break;
    }

    /* default to stdout if no --output-path */
    if (NULL == output_path) {
        output_path = "-";
    }

    /* handle --modify-inplace if given: Disable if output-path is stdout or
     * does not exist, and otherwise error if output-path is not a file. Error
     * when --backup-path given but --modify-inplace is not.  */
    if (modify_inplace) {
        /* this function exits on error */
        setUpModifyInplace();
    } else if (backup_path) {
        skAppPrintErr("May only use --%s when --%s is given",
                      appOptions[OPT_BACKUP_PATH].name,
                      appOptions[OPT_MODIFY_INPLACE].name);
        skAppUsage();
    }

    /* handle the typical (not modify-inplace) case */
    if (!out_stream) {
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(out_stream, output_path))
            || (rv = skStreamOpen(out_stream)))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skStreamDestroy(&out_stream);
            exit(EXIT_FAILURE);
        }
    }

    /* set the compression method on the output */
    if ((rv = skStreamSetCompressionMethod(out_stream, comp_method))) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
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
    skstream_t *stream = NULL;
    uint64_t val64;
    int i;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_ADD:
      case OPT_SUBTRACT:
      case OPT_DIVIDE:
      case OPT_MINIMIZE:
      case OPT_MAXIMIZE:
        if (user_action != user_action_none) {
            if (user_action == (appOptionsEnum)opt_index) {
                skAppPrintErr("Invalid %s: Switch used multiple times",
                              appOptions[opt_index].name);
            } else {
                skAppPrintErr("Switches --%s and --%s are incompatible",
                              appOptions[opt_index].name,
                              appOptions[user_action].name);
            }
            return 1;
        }
        user_action = (appOptionsEnum)opt_index;
        break;

      case OPT_COMPARE:
        if (user_action != user_action_none) {
            if (user_action == (appOptionsEnum)opt_index) {
                skAppPrintErr("Invalid %s: Switch used multiple times",
                              appOptions[opt_index].name);
            } else {
                skAppPrintErr("Switches --%s and --%s are incompatible",
                              appOptions[opt_index].name,
                              appOptions[user_action].name);
            }
            return 1;
        }
        user_action = (appOptionsEnum)opt_index;
        for (i = 0; i < NUM_BAG_COMARISONS; ++i) {
            if (0 == strcasecmp(opt_arg, bag_compare_map[i].name)) {
                bag_cmp = bag_compare_map[i].value;
                break;
            }
        }
        if (i == NUM_BAG_COMARISONS) {
            skAppPrintErr("Invalid %s: Unknown comparator '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_SCALAR_MULTIPLY:
        if (user_action != user_action_none) {
            if (user_action == (appOptionsEnum)opt_index) {
                skAppPrintErr("Invalid %s: Switch used multiple times",
                              appOptions[opt_index].name);
            } else {
                skAppPrintErr("Switches --%s and --%s are incompatible",
                              appOptions[opt_index].name,
                              appOptions[user_action].name);
            }
            return 1;
        }
        user_action = (appOptionsEnum)opt_index;
        rv = skStringParseUint64(&val64, opt_arg, 1, SKBAG_COUNTER_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        scalar_multiply = val64;
        break;

      case OPT_INVERT:
        app_flags.invert = 1;
        break;

      case OPT_COVERSET:
        app_flags.coverset = 1;
        break;

      case OPT_COMPLEMENT:
        app_flags.complement_set = 1;
        /* FALLTHROUGH */

      case OPT_INTERSECT:
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, opt_arg))
            || (rv = skStreamOpen(stream)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            exit(EXIT_FAILURE);
        }
        rv = skIPSetRead(&mask_set, stream);
        if (rv) {
            if (SKIPSET_ERR_FILEIO == rv) {
                skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                     &skAppPrintErr);
            } else {
                skAppPrintErr("Unable to read %s IPset from '%s': %s",
                              appOptions[user_action].name, opt_arg,
                              skIPSetStrerror(rv));
            }
            skStreamDestroy(&stream);
            exit(EXIT_FAILURE);
        }
        skStreamDestroy(&stream);
        break;

      case OPT_MINCOUNTER:
        rv = skStringParseUint64(&mincounter, opt_arg,
                                 BAGTOOL_MIN_COUNTER, SKBAG_COUNTER_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MAXCOUNTER:
        rv = skStringParseUint64(&maxcounter, opt_arg,
                                 BAGTOOL_MIN_COUNTER, SKBAG_COUNTER_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_MINKEY:
        rv = skStringParseIP(&minkey, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
        have_minkey = opt_arg;
        break;

      case OPT_MAXKEY:
        rv = skStringParseIP(&maxkey, opt_arg);
        if (rv) {
            goto PARSE_ERROR;
        }
        have_maxkey = opt_arg;
        break;

      case OPT_OUTPUT_PATH:
        if (output_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        output_path = opt_arg;
        break;

      case OPT_MODIFY_INPLACE:
        modify_inplace = 1;
        break;

      case OPT_BACKUP_PATH:
        if (backup_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        backup_path = opt_arg;
        break;
    }

    return 0;                   /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  ok = bagtoolDivide(stream);
 *
 *    Divide the values in the global 'out_bag' by the values found in
 *    the bag read from 'stream'.  Ignore a key when it is in the
 *    input bag but not in 'out_bag'.  Return an error code when a key
 *    is in 'out_bag' but not in the input bag---treat it as division
 *    by zero.  is in Return 0 on success; non-zero otherwise.
 */
static int
bagtoolDivide(
    skstream_t         *stream)
{
    skBag_t *in_bag;
    skBagIterator_t *iter_dividend = NULL;
    skBagIterator_t *iter_divisor = NULL;
    skBagErr_t rv_dividend;
    skBagErr_t rv_divisor;
    skBagTypedKey_t key_dividend;
    skBagTypedKey_t key_divisor;
    skBagTypedCounter_t counter_dividend;
    skBagTypedCounter_t counter_divisor;
    int cmp;
    int rv = -1;

    /* set the types for the keys and counters */
    key_divisor.type = SKBAG_KEY_IPADDR;
    counter_divisor.type = SKBAG_COUNTER_U64;
    key_dividend.type = SKBAG_KEY_IPADDR;
    counter_dividend.type = SKBAG_COUNTER_U64;

    /* read the bag containing the divisors */
    rv_divisor = skBagRead(&in_bag, stream);
    if (SKBAG_OK != rv_divisor) {
        ERR_READ_BAG(stream, rv_divisor);
        return rv;
    }

    /* Create an iterator to loop over the divisor bag */
    rv_divisor = skBagIteratorCreate(in_bag, &iter_divisor);
    if (SKBAG_OK != rv_divisor) {
        iter_divisor = NULL;
        goto END;
    }
    rv_divisor = skBagIteratorNextTyped(iter_divisor, &key_divisor,
                                        &counter_divisor);

    /* Create an iterator to loop over the dividend bag */
    rv_dividend = skBagIteratorCreate(out_bag, &iter_dividend);
    if (SKBAG_OK != rv_dividend) {
        iter_dividend = NULL;
        goto END;
    }
    rv_dividend = skBagIteratorNextTyped(iter_dividend, &key_dividend,
                                         &counter_dividend);

    while (SKBAG_OK == rv_dividend && SKBAG_OK == rv_divisor) {
        cmp = skipaddrCompare(&key_divisor.val.addr, &key_dividend.val.addr);
        if (0 == cmp) {
            /* key is in both bags.  do the division and round up for
             * any remainder that is more than half the divisor. */
            counter_dividend.val.u64 =
                ((counter_dividend.val.u64 / counter_divisor.val.u64)
                 + ((counter_dividend.val.u64 % counter_divisor.val.u64)
                    >= ((counter_divisor.val.u64 >> 1)
                        + (counter_divisor.val.u64 & 1))));
            rv_dividend = skBagCounterSet(out_bag, &key_dividend,
                                          &counter_dividend);
            if (SKBAG_OK != rv_dividend) {
                ERR_SET_COUNT(key_dividend, counter_dividend, rv_dividend);
                goto END;
            }

            /* get next keys */
            rv_dividend = skBagIteratorNextTyped(iter_dividend, &key_dividend,
                                                 &counter_dividend);
            rv_divisor = skBagIteratorNextTyped(iter_divisor, &key_divisor,
                                                &counter_divisor);

        } else if (cmp < 0) {
            /* key is in divisor bag only; ignore--that is, treat as
             * if dividend value is 0 */
            rv_divisor = skBagIteratorNextTyped(iter_divisor, &key_divisor,
                                                &counter_divisor);
        } else {
            /* key is only in dividend bag.  complain---that is, treat
             * as division by 0. */
            skAppPrintErr("Error dividing bags; key %s not in divisor bag",
                          skipaddrString(ipbuf1, &key_dividend.val.addr, 0));
            goto END;
        }
    }

    /* Verify no errors from the divisor bag */
    if (SKBAG_OK != rv_divisor) {
        if (SKBAG_ERR_KEY_NOT_FOUND == rv_divisor) {
            rv_divisor = SKBAG_OK;
        } else {
            ERR_ITERATOR("divisor", rv_divisor);
            goto END;
        }
    }

    /* If keys remain in the dividend bag, we have a division by zero
     * problem. */
    if (SKBAG_OK == rv_dividend) {
        skAppPrintErr(("Error dividing bags; key %" PRIu32
                       " not in divisor bag"),
                      key_dividend.val.u32);
        goto END;
    } else if (SKBAG_ERR_KEY_NOT_FOUND != rv_dividend) {
        ERR_ITERATOR("dividend", rv_divisor);
        goto END;
    }

    /* Success */
    rv = 0;

    /* Modify key-type and counter-type */
    skBagModify(out_bag, skBagFieldTypeMerge(skBagKeyFieldType(out_bag),
                                             skBagKeyFieldType(in_bag)),
                skBagFieldTypeMerge(skBagCounterFieldType(out_bag),
                                    skBagCounterFieldType(in_bag)),
                SKBAG_OCTETS_NO_CHANGE, SKBAG_OCTETS_NO_CHANGE);

  END:
    skBagIteratorDestroy(iter_dividend);
    skBagIteratorDestroy(iter_divisor);
    /* Blow the bag away. We're done with it */
    skBagDestroy(&in_bag);

    return rv;
}


/*
 *  status = bagtoolSubtractInit(stream_bag, bag);
 *
 *    Callback to support bagtoolSubtract().  Set the key and counter
 *    types on the output bag.
 */
static skBagErr_t
bagtoolSubtractInit(
    const skBag_t      *bag2,
    void               *v_bag1)
{
    skBag_t *bag1 = (skBag_t*)v_bag1;

    /* Modify key-type and counter-type */
    return skBagModify(bag1, skBagFieldTypeMerge(skBagKeyFieldType(bag1),
                                                 skBagKeyFieldType(bag2)),
                       skBagFieldTypeMerge(skBagCounterFieldType(bag1),
                                           skBagCounterFieldType(bag2)),
                       SKBAG_OCTETS_NO_CHANGE, SKBAG_OCTETS_NO_CHANGE);
}


/*
 *  status = bagtoolSubtractEntry(stream_bag, key, counter, bag);
 *
 *    Callback to support bagtoolSubtract().  Subtract from the value
 *    of 'key' in 'bag' the value 'counter'.  If the resulting value
 *    would be negative, remove 'key' from 'bag'.  Return SKBAG_OK on
 *    success.
 */
static skBagErr_t
bagtoolSubtractEntry(
    const skBag_t               UNUSED(*bag2),
    const skBagTypedKey_t              *key_bag2,
    const skBagTypedCounter_t          *counter_bag2,
    void                               *v_bag1)
{
    skBag_t *bag1 = (skBag_t*)v_bag1;
    skBagErr_t rv_bag;

    rv_bag = skBagCounterSubtract(bag1, key_bag2, counter_bag2, NULL);
    switch (rv_bag) {
      case SKBAG_OK:
        break;

      case SKBAG_ERR_OP_BOUNDS:
        /* value is negative or not in bag. remove it */
        rv_bag = skBagKeyRemove(bag1, key_bag2);
        if (SKBAG_OK != rv_bag) {
            ERR_REMOVE_KEY(*key_bag2, rv_bag);
        }
        break;

      default:
        skAppPrintErr(("Error when subtracting from bag for key %" PRIu32
                       ": %s"),
                      key_bag2->val.u32, skBagStrerror(rv_bag));
        break;
    }

    return rv_bag;
}



/*
 *  ok = bagtoolSubtract(stream);
 *
 *    Subtract the values found in the bag read from 'stream' from the
 *    values in the global 'out_bag'.  Ignore a key read from 'stream'
 *    when the key is not present in 'out_bag'.  Remove a key from
 *    'out_bag' when its counter is less than the counter read from
 *    'stream'.
 */
static int
bagtoolSubtract(
    skstream_t         *stream)
{
    skBagErr_t rv_bag;

    rv_bag = skBagProcessStreamTyped(stream, out_bag, &bagtoolSubtractInit,
                                     &bagtoolSubtractEntry);

    return ((SKBAG_OK == rv_bag) ? 0 : -1);
}


/*
 *  ok = bagtoolMinimize(stream);
 *
 *    Perform multi-set intersection.
 *
 *    Update the counters in the global 'out_bag' to the minimum of
 *    the 'out_bag' counter or the counter from the bag read from
 *    'stream'.  Remove form 'out_bag' keys that are not present in
 *    the input bag---that is, treat them as having the value zero.
 */
static int
bagtoolMinimize(
    skstream_t         *stream)
{
    skBag_t *in_bag;
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t key;
    skBagTypedCounter_t out_counter;
    skBagTypedCounter_t in_counter;
    skBagErr_t rv_bag;

    /* Read Bag from the 'stream' */
    rv_bag = skBagRead(&in_bag, stream);
    if (SKBAG_OK != rv_bag) {
        ERR_READ_BAG(stream, rv_bag);
        return 1;
    }

    /* Create an iterator to loop over the global output bag. */
    rv_bag = skBagIteratorCreate(out_bag, &iter);
    if (SKBAG_OK != rv_bag) {
        goto END;
    }

    /* set the types for the key and counters */
    key.type = SKBAG_KEY_IPADDR;
    in_counter.type = SKBAG_COUNTER_U64;
    out_counter.type = SKBAG_COUNTER_U64;

    /* If out_bag's counter is larger than that from in_bag, set
     * out_bag's counter to the input value.  Since missing keys have
     * a value of 0, this will remove keys from out_bag that do not
     * appear in in_bag. */
    while (skBagIteratorNextTyped(iter, &key, &out_counter) == SKBAG_OK) {
        skBagCounterGet(in_bag, &key, &in_counter);
        if (in_counter.val.u64 < out_counter.val.u64) {
            /* must set value to the minimum */
            rv_bag = skBagCounterSet(out_bag, &key, &in_counter);
            if (SKBAG_OK != rv_bag) {
                ERR_SET_COUNT(key, in_counter, rv_bag);
                goto END;
            }
        }
    }

  END:
    skBagIteratorDestroy(iter);
    /* Blow the input bag away. We're done with it */
    skBagDestroy(&in_bag);

    return ((SKBAG_OK == rv_bag) ? 0 : -1);
}


/*
 *  status = bagtoolMaximizeCallback(key, counter, bag);
 *
 *    Callback to support bagtoolMaximize().  Look up the value of
 *    'key' in 'bag'.  If 'counter' is greater than the value, set the
 *    value of 'key' to 'counter'.  Since missing keys have the value
 *    0, keys not already in 'bag' are added.  Return SKBAG_OK on
 *    success.
 */
static skBagErr_t
bagtoolMaximizeCallback(
    const skBag_t               UNUSED(*bag2),
    const skBagTypedKey_t              *key_bag2,
    const skBagTypedCounter_t          *counter_bag2,
    void                               *v_bag1)
{
    skBag_t *bag1 = (skBag_t*)v_bag1;
    skBagTypedCounter_t counter_bag1;
    skBagErr_t rv_bag;

    counter_bag1.type = SKBAG_COUNTER_U64;

    /* Use the counter value from bag2 if that value is larger than
     * the value from bag1. */
    rv_bag = skBagCounterGet(bag1, key_bag2, &counter_bag1);
    if (counter_bag2->val.u64 > counter_bag1.val.u64) {
        /* set counter to the maximum */
        rv_bag = skBagCounterSet(bag1, key_bag2, counter_bag2);
        if (SKBAG_OK != rv_bag) {
            ERR_SET_COUNT(*key_bag2, *counter_bag2, rv_bag);
        }
    }

    return rv_bag;
}


/*
 *  ok = bagtoolMaximize(stream);
 *
 *    Perform multi-set union.
 *
 *    Update the counters in the global 'out_bag' to the maximum of
 *    the 'out_bag' counter or the counter from the bag read from
 *    'stream'.  Missing keys are treated as 0.
 */
static int
bagtoolMaximize(
    skstream_t         *stream)
{
    skBagErr_t rv_bag;

    rv_bag = skBagProcessStreamTyped(stream, out_bag, NULL,
                                     &bagtoolMaximizeCallback);
    return ((SKBAG_OK == rv_bag) ? 0 : -1);
}


/*
 *  ok = bagtoolCompare(stream);
 *
 *    Compare the counters in 'out_bag' with the counters in the bag
 *    read from 'stream' using the comparison specified in the global
 *    'bag_cmp'.  For a key in 'out_bag' but not in the input bag,
 *    treat its comparison as false and remove it from 'out_bag'.
 *
 *    Compare the counter pair for each key: If the comparison is
 *    true, set the key's counter in 'out_bag' to one; otherwise
 *    remove the key from 'out_bag'.
 */
static int
bagtoolCompare(
    skstream_t         *stream)
{
    skBag_t *bag2;

    skBagIterator_t *iter_bag1 = NULL;
    skBagIterator_t *iter_bag2 = NULL;
    skBagErr_t rv_bag1 = SKBAG_OK;
    skBagErr_t rv_bag2;
    int cmp;

    skBagTypedKey_t key_bag1;
    skBagTypedKey_t key_bag2;

    skBagTypedCounter_t counter_bag1;
    skBagTypedCounter_t counter_bag2;
    skBagTypedCounter_t new_counter;

    rv_bag2 = skBagRead(&bag2, stream);
    if (SKBAG_OK != rv_bag2) {
        ERR_READ_BAG(stream, rv_bag2);
        return 1;
    }

    /* set the types for the keys and counters */
    key_bag1.type = SKBAG_KEY_IPADDR;
    key_bag2.type = SKBAG_KEY_IPADDR;
    counter_bag1.type = SKBAG_COUNTER_U64;
    counter_bag2.type = SKBAG_COUNTER_U64;
    new_counter.type = SKBAG_COUNTER_U64;

    /* Create an iterator to loop over the input bag */
    rv_bag2 = skBagIteratorCreate(bag2, &iter_bag2);
    if (SKBAG_OK != rv_bag2) {
        goto END;
    }
    rv_bag2 = skBagIteratorNextTyped(iter_bag2, &key_bag2, &counter_bag2);

    /* Create an iterator to loop over the output bag */
    rv_bag1 = skBagIteratorCreate(out_bag, &iter_bag1);
    if (SKBAG_OK != rv_bag1) {
        goto END;
    }
    rv_bag1 = skBagIteratorNextTyped(iter_bag1, &key_bag1, &counter_bag1);

    while (SKBAG_OK == rv_bag1 && SKBAG_OK == rv_bag2) {
        cmp = skipaddrCompare(&key_bag1.val.addr, &key_bag2.val.addr);
        if (0 == cmp) {
            /* key is in both bags */
            new_counter.val.u64 = 0;
            switch (bag_cmp) {
              case BAG_CMP_LT:
                if (counter_bag1.val.u64 < counter_bag2.val.u64) {
                    new_counter.val.u64 = 1;
                }
                break;
              case BAG_CMP_LE:
                if (counter_bag1.val.u64 <= counter_bag2.val.u64) {
                    new_counter.val.u64 = 1;
                }
                break;
              case BAG_CMP_EQ:
                if (counter_bag1.val.u64 == counter_bag2.val.u64) {
                    new_counter.val.u64 = 1;
                }
                break;
              case BAG_CMP_GE:
                if (counter_bag1.val.u64 >= counter_bag2.val.u64) {
                    new_counter.val.u64 = 1;
                }
                break;
              case BAG_CMP_GT:
                if (counter_bag1.val.u64 > counter_bag2.val.u64) {
                    new_counter.val.u64 = 1;
                }
                break;
            }
            rv_bag1 = skBagCounterSet(out_bag, &key_bag1, &new_counter);
            if (rv_bag1) {
                ERR_SET_COUNT(key_bag1, new_counter, rv_bag1);
                goto END;
            }
            rv_bag1 = skBagIteratorNextTyped(iter_bag1, &key_bag1,
                                             &counter_bag1);
            rv_bag2 = skBagIteratorNextTyped(iter_bag2, &key_bag2,
                                             &counter_bag2);

        } else if (cmp < 0) {
            /* key is in bag1 only.  remove it */
            rv_bag1 = skBagKeyRemove(out_bag, &key_bag1);
            if (rv_bag1) {
                ERR_REMOVE_KEY(key_bag1, rv_bag1);
                goto END;
            }
            rv_bag1 = skBagIteratorNextTyped(iter_bag1, &key_bag1,
                                             &counter_bag1);

        } else {
            assert(cmp > 0);

            /* key is in bag2 only.  it will not appear in the output. */
            rv_bag2 = skBagIteratorNextTyped(iter_bag2, &key_bag2,
                                             &counter_bag2);
        }
    }

    /* Verify no errors from bag2 */
    if (SKBAG_OK != rv_bag2) {
        if (SKBAG_ERR_KEY_NOT_FOUND == rv_bag2) {
            rv_bag2 = SKBAG_OK;
        } else {
            ERR_ITERATOR(skStreamGetPathname(stream), rv_bag2);
            goto END;
        }
    }

    /* Check to see if keys remain in bag1; if so, we must remove
     * them. */
    while (SKBAG_OK == rv_bag1) {
        rv_bag1 = skBagKeyRemove(out_bag, &key_bag1);
        if (rv_bag1) {
            ERR_REMOVE_KEY(key_bag1, rv_bag1);
            goto END;
        }
        rv_bag1 = skBagIteratorNextTyped(iter_bag1, &key_bag1, &counter_bag1);
    }

    /* Verify that we reached the end of bag1 */
    if (SKBAG_ERR_KEY_NOT_FOUND == rv_bag1) {
        rv_bag1 = SKBAG_OK;
    } else {
        ERR_ITERATOR(skStreamGetPathname(out_stream), rv_bag1);
        goto END;
    }

  END:
    skBagIteratorDestroy(iter_bag1);
    skBagIteratorDestroy(iter_bag2);
    /* Blow the bag away. We're done with it */
    skBagDestroy(&bag2);

    return (((SKBAG_OK == rv_bag1) && (SKBAG_OK == rv_bag2)) ? 0 : -1);
}


/*
 *  status = bagtoolInvert(bag);
 *
 *    Invert the Bag 'bag' in place.  Return 0 on success, or -1 on
 *    error.
 */
static int
bagtoolInvert(
    skBag_t            *bag)
{
    skBag_t *inv_bag = NULL;
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t bin;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skBagErr_t rv_bag;
    int rv = -1;

    /* We cannot invert the bag in place.  We create a new bag and
     * make a pass through the existing bag, removing its entries and
     * inserting the inverted values into the new bag.  Once that is
     * complete, we make a pass over the inverted bag and set the
     * values in the original bag. */
    if (skBagCreate(&inv_bag) != SKBAG_OK) {
        goto END;
    }

    /* set the types for the keys and counter */
    bin.type = SKBAG_KEY_U32;
    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    /* Run through the original bag */
    rv_bag = skBagIteratorCreate(bag, &iter);
    if (SKBAG_OK != rv_bag) {
        goto END;
    }
    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        /* remove this key from the bag--set its count to 0 */
        rv_bag = skBagKeyRemove(bag, &key);
        if (SKBAG_OK != rv_bag) {
            ERR_REMOVE_KEY(key, rv_bag);
            goto END;
        }
        /* determine key to use in inverted bag, handing overflow */
        bin.val.u32 = ((counter.val.u64 < (uint64_t)SKBAG_KEY_MAX)
                       ? (uint32_t)counter.val.u64
                       : SKBAG_KEY_MAX);

        /* increment value in the inverted bag */
        rv_bag = skBagCounterIncrement(inv_bag, &bin);
        if (SKBAG_OK != rv_bag) {
            if (SKBAG_ERR_OP_BOUNDS == rv_bag) {
                skAppPrintErr(("Overflow when inverting bag (key %" PRIu32 ")"),
                              bin.val.u32);
                goto END;
            }
            skAppPrintErr("Error when inverting bag: %s",
                          skBagStrerror(rv_bag));
            goto END;
        }
    }
    skBagIteratorDestroy(iter);
    iter = NULL;

    /* The output bag is empty; modify it to hold integer keys and
     * counters */
    rv_bag = skBagModify(bag, skBagCounterFieldType(bag), SKBAG_FIELD_CUSTOM,
                         sizeof(uint32_t), SKBAG_OCTETS_NO_CHANGE);
    if (SKBAG_OK != rv_bag) {
        skAppPrintErr("Error when modifying bag: %s",
                      skBagStrerror(rv_bag));
        goto END;
    }

    /* Run through the inverted bag and set the values in the output bag. */
    rv_bag = skBagIteratorCreate(inv_bag, &iter);
    if (SKBAG_OK != rv_bag) {
        goto END;
    }
    while (skBagIteratorNextTyped(iter, &bin, &counter) == SKBAG_OK) {
        rv_bag = skBagCounterSet(bag, &bin, &counter);
        if (SKBAG_OK != rv_bag) {
            ERR_SET_COUNT(bin, counter, rv_bag);
            goto END;
        }
    }

    /* done */
    rv = 0;

  END:
    skBagDestroy(&inv_bag);
    skBagIteratorDestroy(iter);

    return rv;
}


/*
 *  status = bagtoolCoverSet(bag, stream);
 *
 *    Create an IPset and fill it with the keys in the Bag 'bag'.
 *    Write the IPset to 'stream'.  Return 0 on success, or -1 on
 *    failure.
 */
static int
bagtoolCoverSet(
    skBag_t            *bag,
    skstream_t         *stream)
{
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    int rv;
    skipset_t *set = NULL;

    /* Create the cover set */
    rv = skIPSetCreate(&set, 0);
    if (rv) {
        skAppPrintErr("Error creating cover IPset: %s", skIPSetStrerror(rv));
        goto END;
    }
    ipset_options.comp_method = comp_method;
    skIPSetOptionsBind(set, &ipset_options);

    /* set the types for the keys and counter */
    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    /* Run through the bag, adding items to the set */
    if (skBagIteratorCreate(bag, &iter)) {
        goto END;
    }

    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        rv = skIPSetInsertAddress(set, &key.val.addr, 0);
        if (rv) {
            skAppPrintErr("Error inserting into IPset: %s",
                          skIPSetStrerror(rv));
            goto END;
        }
    }

    skIPSetClean(set);

    /* Write the set */
    rv = skIPSetWrite(set, stream);
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            char errbuf[2 * PATH_MAX];
            skStreamLastErrMessage(stream, skStreamGetLastReturnValue(stream),
                                   errbuf, sizeof(errbuf));
            skAppPrintErr("Error writing cover IPset: %s", errbuf);
        } else {
            skAppPrintErr("Error writing cover IPset to '%s': %s",
                          skStreamGetPathname(stream), skIPSetStrerror(rv));
        }
        goto END;
    }

    /* done */
    rv = 0;

  END:
    skBagIteratorDestroy(iter);
    skIPSetDestroy(&set);

    return ((rv == 0) ? 0 : -1);
}


/*
 *  ok = applyCutoffs(bag);
 *
 *    Run through the bag and zero out any entries not within range or
 *    which aren't in the masking set.  Return 0 on success, non-zero
 *    otherwise.
 *
 *    FIXME: We could do some of this during the insertion stage
 *    instead output to save ourselves some storage. This is not the
 *    most efficient implementation.
 */
static int
applyCutoffs(
    skBag_t            *bag)
{
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skBagErr_t rv_bag;

    /* determine whether there are any cut-offs to apply. If no sets
     * are given and the limits are all at their defaults, return. */
    if ((NULL == mask_set)
        && (NULL == have_minkey)
        && (NULL == have_maxkey)
        && (SKBAG_COUNTER_MIN == mincounter)
        && (SKBAG_COUNTER_MAX == maxcounter))
    {
        return 0;
    }

    /* set the types for the keys and counter */
    key.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    /* Create an iterator to loop over the bag */
    rv_bag = skBagIteratorCreate(bag, &iter);
    if (SKBAG_OK != rv_bag) {
        iter = NULL;
        goto END;
    }

    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        if ((mask_set && (skIPSetCheckAddress(mask_set, &key.val.addr)
                          == app_flags.complement_set))
            || (have_minkey && skipaddrCompare(&key.val.addr, &minkey) < 0)
            || (have_maxkey && skipaddrCompare(&key.val.addr, &maxkey) > 0)
            || (counter.val.u64 < mincounter)
            || (counter.val.u64 > maxcounter))
        {
            /* if we're here, we DO NOT want the record */
            rv_bag = skBagKeyRemove(bag, &key);
            if (SKBAG_OK != rv_bag) {
                ERR_REMOVE_KEY(key, rv_bag);
                goto END;
            }
        }
    }

  END:
    skBagIteratorDestroy(iter);
    return ((SKBAG_OK == rv_bag) ? 0 : -1);
}


/*
 *  ok = bagtoolScalarMultiply();
 *
 *    Apply the scalar_multiply multiplier to every counter
 */
static int
bagtoolScalarMultiply(
    void)
{
    skBagIterator_t *iter = NULL;
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skBagTypedCounter_t overflow;
    skBagErr_t rv_bag;

    /* Determine the counter value that will cause an overflow */
    overflow.type = SKBAG_COUNTER_U64;
    overflow.val.u64 = SKBAG_COUNTER_MAX / scalar_multiply;

    /* Create an iterator to loop over the bag */
    rv_bag = skBagIteratorCreate(out_bag, &iter);
    if (SKBAG_OK != rv_bag) {
        iter = NULL;
        goto END;
    }

    /* set types for key and counter */
    key.type = SKBAG_KEY_ANY;
    counter.type = SKBAG_COUNTER_U64;

    /* modify the bag while we iterate over it.  should be safe since
     * we are not adding any new keys. */
    while (skBagIteratorNextTyped(iter, &key, &counter) == SKBAG_OK) {
        if (counter.val.u64 > overflow.val.u64) {
            skAppPrintErr("Overflow when applying scalar multiplier");
        }
        /*
         * mthomas.2023.07.31: I think the idea here was to wrap-around when
         * we overflowed (though the Add operation doesn't wrap-around, so why
         * does multiply?).  Wrap-around worked in SiLK-2, but in SiLK-3
         * UINT64_MAX become an illegal Bag counter value, making it possible
         * that the next line gives a that value which then causes "Illegal
         * argument to function" error.  If we get a value greater than the
         * max, use the max, otherwise use wrap-around.
         */
        counter.val.u64 *= scalar_multiply;
        if (counter.val.u64 > SKBAG_COUNTER_MAX) {
            counter.val.u64 = SKBAG_COUNTER_MAX;
        }
        rv_bag = skBagCounterSet(out_bag, &key, &counter);
        if (rv_bag) {
            ERR_SET_COUNT(key, counter, rv_bag);
            goto END;
        }
    }

  END:
    skBagIteratorDestroy(iter);
    return ((SKBAG_OK == rv_bag) ? 0 : -1);
}


/*
 *  ok = writeOutput();
 *
 *    Generate the output.
 */
static int
writeOutput(
    void)
{
    skBagErr_t rv;

    /* Remove anything that's not in range or not in the intersecting
     * set (or complement) as appropriate */
    applyCutoffs(out_bag);

    if (app_flags.invert) {
        bagtoolInvert(out_bag);
    }

    if (app_flags.coverset) {
        return bagtoolCoverSet(out_bag, out_stream);
    }

    rv = skBagWrite(out_bag, out_stream);
    if (SKBAG_OK != rv) {
        if (SKBAG_ERR_OUTPUT == rv) {
            skStreamPrintLastErr(out_stream,
                                 skStreamGetLastReturnValue(out_stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing bag to output file '%s': %s",
                          skStreamGetPathname(out_stream), skBagStrerror(rv));
        }
        return -1;
    }

    return 0;
}


/*
 *  ok = appNextInput(argc, argv, &stream);
 *
 *    Fill 'stream' with the opened skStream object to next input
 *    file from the command line or the standard input if no files
 *    were given on the command line.
 *
 *    Return 1 if input is available, 0 if all input files have been
 *    processed, and -1 to indicate an error opening a file.
 */
static int
appNextInput(
    int                 argc,
    char              **argv,
    skstream_t        **stream)
{
    static int initialized = 0;
    const char *fname = NULL;
    sk_file_header_t *hdr = NULL;
    int rv;

    if (arg_index < argc) {
        /* get current file and prepare to get next */
        fname = argv[arg_index];
        ++arg_index;
    } else {
        if (initialized) {
            /* no more input */
            return 0;
        }
        /* input is from stdin */
        fname = "stdin";
    }

    initialized = 1;

    /* open the input stream */
    if ((rv = skStreamCreate(stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind((*stream), fname))
        || (rv = skStreamOpen((*stream)))
        || (rv = skStreamReadSilkHeader((*stream), &hdr)))
    {
        skStreamPrintLastErr((*stream), rv, &skAppPrintErr);
        skStreamDestroy(stream);
        return -1;
    }

    /* copy notes (annotations) from the input files to the output file */
    if (!note_strip) {
        rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream), hdr,
                                 SK_HENTRY_ANNOTATION_ID);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skStreamDestroy(&(*stream));
            return -1;
        }
    }

    return 1;
}


/*
 *    Removes the temp file if remove_temp_file is non-zero.  Installed as an
 *    at-exit handler and called by the signal handler.
 */
static void
removeTempFileCallback(
    void)
{
    if (remove_temp_file && out_stream && skStreamGetPathname(out_stream)) {
        unlink(skStreamGetPathname(out_stream));
    }
}


/*
 *    Signal handler that calls removeTempFileCallback().
 */
static void
signalHandler(
    int recv_signal)
{
    struct sigaction action;

    if (signal_deferred) {
        /* we are moving temp-file over output-path */
        signal_pending = recv_signal;

    } else if (signal_signaled) {
        /* we received another signal while in the handler */
        raise(recv_signal);

    } else {
        /* handle the signal */
        signal_signaled = 1;

        /* remove the temp file */
        removeTempFileCallback();

        /* restore the default behavior for the signal and raise it */
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_DFL;
        sigaction(recv_signal, &action, NULL);

        raise(recv_signal);
    }
}


/*
 *    Sets up the application to handle --modify-inplace and --backup-path.
 *    Exits the application on error.
 */
static void
setUpModifyInplace(
    void)
{
    char temp_file[PATH_MAX+1];
    struct sigaction action;
    unsigned int i;
    ssize_t rv;

    assert(modify_inplace);

    /* check for non-file output */
    if (0 == strcmp(output_path, "-")
        || 0 == strcmp(output_path, "stdout")
        || 0 == strcmp(output_path, "stderr"))
    {
        skAppPrintErr(
            "Ignoring --%s since the output-path is the standard %s",
            appOptions[OPT_MODIFY_INPLACE].name,
            ((0 == strcmp(output_path, "stderr")) ? "error" : "output"));
        modify_inplace = 0;
        backup_path = NULL;
        return;
    }

    /* ask file system about the output-path */
    rv = lstat(output_path, &stat_orig);
    if (-1 == rv) {
        if (ENOENT != errno) {
            skAppPrintSyserror("Error getting status of %s '%s'",
                               appOptions[OPT_OUTPUT_PATH].name, output_path);
            exit(EXIT_FAILURE);
        }
        /* Named file does not exist and there is no output-path to worry
         * about overwriting */
        skAppPrintErr("Ignoring --%s since '%s' does not exist",
                      appOptions[OPT_MODIFY_INPLACE].name,
                      appOptions[OPT_OUTPUT_PATH].name);
        modify_inplace = 0;
        backup_path = NULL;
        return;
    }

    if (0 == S_ISREG(stat_orig.st_mode)) {
        skAppPrintErr("May use --%s only when --%s is a regular file",
                      appOptions[OPT_MODIFY_INPLACE].name,
                      appOptions[OPT_OUTPUT_PATH].name);
        exit(EXIT_FAILURE);
    }

    /* create a temporary file and open its stream */
    memset(temp_file, 0, sizeof(temp_file));
    rv = snprintf(temp_file, sizeof(temp_file) - 1, "%s.XXXXXXXX",
                  output_path);
    if ((size_t)rv > sizeof(temp_file) - 1) {
        skAppPrintErr("Length of temporary file name is too long");
        exit(EXIT_FAILURE);
    }

    if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(out_stream, temp_file))
        || (rv = skStreamMakeTemp(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&out_stream);
        exit(EXIT_FAILURE);
    }

    /* install an atexit handler to remove the temp file */
    remove_temp_file = 1;
    if (atexit(removeTempFileCallback) < 0) {
        skAppPrintSyserror("Unable to set atexit handlder");
        unlink(skStreamGetPathname(out_stream));
        skStreamDestroy(&out_stream);
        exit(EXIT_FAILURE);
    }

    /* set up the signal handler to remove the temp file */
    memset(&action, 0, sizeof(action));
    action.sa_handler = signalHandler;
    action.sa_flags = SA_RESTART;

    /* add all interesting signals to the mask */
    sigemptyset(&action.sa_mask);
    for (i = 0; sig_list[i] != 0; ++i) {
        sigaddset(&action.sa_mask, sig_list[i]);
    }

    /* install the signal handler for each interesting signal */
    for (i = 0; sig_list[i] != 0; ++i) {
        if (sigaction(sig_list[i], &action, NULL) == -1) {
            skAppPrintSyserror("Warning: Unable to set handler for %s",
                               skSignalToName(sig_list[i]));
        }
    }
}


/*
 *    Moves the output files into place.
 *
 *    If backup_path is set, first moves the existing output_path to
 *    backup_path.  Moves the temp file to output_path.  Returns 0 on success
 *    and -1 on failure.
 */
static int
moveTempFileToOutputPath(
    void)
{
    const char *src;
    const char *dst;
    const char *tmp;
    int err;

    /* Tell atexit() not to remove temp file if file moves fail */
    remove_temp_file = 0;

    /* Get name of temp file and set its permissions, owner, and group to
     * match the original file.  Warn on permissions failure; ignore
     * owner/group failure. */
    tmp = skStreamGetPathname(out_stream);
    if (-1 == chmod(tmp, stat_orig.st_mode)) {
        skAppPrintSyserror("Warning: Unable to set permission flags on '%s'",
                           tmp);
    }
    if (-1 == chown(tmp, stat_orig.st_uid, stat_orig.st_gid)) {
        /* changing owner failed; try setting group only */
        (void)chown(tmp, -1, stat_orig.st_gid);
    }

    /* Move existing output-path to the backup-path */
    if (backup_path) {
        src = output_path;
        dst = backup_path;
        err = skMoveFile(src, dst);
        if (err) {
            goto ERROR;
        }
    }

    /* Prepare to move temp-file to output-path */
    src = tmp;
    dst = output_path;

    /* Defer signals */
    ++signal_deferred;

    /* move the file */
    err = skMoveFile(src, dst);

    /* return to default signal handling */
    --signal_deferred;
    if (signal_pending) {
        raise(signal_pending);
    }

    if (err) {
        goto ERROR;
    }

    return 0;

  ERROR:
    skAppPrintErr("Error moving '%s' to '%s': %s",
                  src, dst, strerror(err));
    skAppPrintErr("Leaving resulting IPset in '%s'", tmp);
    return -1;
}


int main(int argc, char **argv)
{
    skstream_t *in_stream;
    skBagErr_t err;
    ssize_t rv;

    appSetup(argc, argv);                       /* never returns on error */

    /* Read the first bag; this will be the basis of the output bag. */
    if (appNextInput(argc, argv, &in_stream) != 1) {
        return 1;
    }
    err = skBagRead(&out_bag, in_stream);
    if (SKBAG_OK != err) {
        ERR_READ_BAG(in_stream, err);
        skStreamDestroy(&in_stream);
        return 1;
    }
    skStreamDestroy(&in_stream);

    /* Open up each remaining bag and process it appropriately */
    while (1 == appNextInput(argc, argv, &in_stream)) {
        switch (user_action) {
          case OPT_ADD:
            err = skBagAddFromStream(out_bag, in_stream);
            if (SKBAG_OK != err) {
                skAppPrintErr("Error when adding bags: %s",
                              skBagStrerror(err));
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_SUBTRACT:
            if (bagtoolSubtract(in_stream)) {
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_MINIMIZE:
            if (bagtoolMinimize(in_stream)) {
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_MAXIMIZE:
            if (bagtoolMaximize(in_stream)) {
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_DIVIDE:
            if (bagtoolDivide(in_stream)) {
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_COMPARE:
            if (bagtoolCompare(in_stream)) {
                skStreamDestroy(&in_stream);
                return 1;
            }
            break;

          case OPT_SCALAR_MULTIPLY:
            /* should never get here, since we only take one file and
             * we tested for this above */
            skAppPrintErr("Only one file allowed for scalar multiply");
            skAbortBadCase(user_action);

          default:
            /* Processing options not handled in this switch require a
             * single bag file */
            skAbortBadCase(user_action);
        }

        skStreamDestroy(&in_stream);
    }

    /* Now that the notes from all input streams have been seen, add the
     * notes to the output stream */
    rv = skOptionsNotesAddToStream(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }
    skOptionsNotesTeardown();

    if (OPT_SCALAR_MULTIPLY == user_action) {
        if (bagtoolScalarMultiply()) {
            return 1;
        }
    }

    /* Write the output */
    if (writeOutput()) {
        return 1;
    }

    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&out_stream);
        skBagDestroy(&out_bag);
        return EXIT_FAILURE;
    }

    if (modify_inplace) {
        rv = moveTempFileToOutputPath();
        if (rv) {
            skStreamDestroy(&out_stream);
            skBagDestroy(&out_bag);
            return EXIT_FAILURE;
        }
    }

    skBagDestroy(&out_bag);
    rv = skStreamDestroy(&out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        return EXIT_FAILURE;
    }

    /* done */
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
