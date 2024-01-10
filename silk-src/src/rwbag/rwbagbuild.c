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
 *    rwbagbuild can read an IP set and generate a bag with a default
 *    count for each IP address, or it can read a pipe-separated text
 *    file representing a bag.
 *
 *
 *    TODO:
 *
 *        Add a --multiple-files={ipset | text} switch that allows
 *        rwbagbuild to process data from multiple input files.  This
 *        switch is parallel to --set-input and --bag-input.
 *
 *        Make --text-input an alias for --bag-input.
 *
 *        Add a --missing-count=VALUE switch that only uses VALUE as
 *        the counter when none is specified on a line.
 *
 *        Replace the --default-count switch with a --force-count (or
 *        --use-count (hard ess), --displace-count) to make it clear
 *        that the counter on a line is being ignored and displaced
 *        (replaced, dislodged, ousted) with a different counter.
 */


#include <silk/silk.h>

RCSIDENT("$SiLK: rwbagbuild.c 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/skbag.h>
#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* What to do when malloc() fails */
#define EXIT_NO_MEMORY                                               \
    do {                                                             \
        skAppPrintOutOfMemory(NULL);                                 \
        exit(EXIT_FAILURE);                                          \
    } while(0)

/* return 1 if 'm_arg' refers to the standard input */
#define IS_STDIN(m_arg)                                                 \
    (0 == strcmp((m_arg), "-") || 0 == strcmp((m_arg), "stdin"))

/*
 *    bag_key_counter_t is a structure passed into the callback
 *    function when creating a bag from an IPset.
 */
struct bag_key_counter_st {
    skBag_t            *bag;
    skBagTypedKey_t     key;
    skBagTypedCounter_t counter;
};
typedef struct bag_key_counter_st bag_key_counter_t;


/* LOCAL VARIABLES */

/* output stream */
static skstream_t *out_stream = NULL;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* input streams (for reading a textual bag or an ip set */
static skstream_t *bag_input = NULL;
static skstream_t *set_input = NULL;

/* counter */
static int f_use_default_count = 0;
static uint64_t default_count = 1;

/* delimiter between key and counter for text input */
static char delimiter = '|';

/* delimiter between protocol and port for text input; same as
 * delimiter unless it is explicitly set. */
static char proto_port_delimiter = '\0';

/* key and counter type */
static skBagFieldType_t key_type = SKBAG_FIELD_CUSTOM;
static skBagFieldType_t counter_type = SKBAG_FIELD_CUSTOM;

/* string map of key types */
static sk_stringmap_t *field_map;

/* whether the key field should be mapped to a country code */
static int country_code = 0;

/* map the key to an entry in this prefix map */
static skPrefixMap_t *prefix_map = NULL;

/* do not record the command line invocation in the generated bag
 * file. set by --invocation-strip */
static int invocation_strip = 0;

/* whether stdin has been used */
static int stdin_used = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_SET_INPUT,
    OPT_BAG_INPUT,
    OPT_DELIMITER,
    OPT_PROTO_PORT_DELIMITER,
    OPT_DEFAULT_COUNT,
    OPT_KEY_TYPE,
    OPT_COUNTER_TYPE,
    OPT_PMAP_FILE,
    OPT_OUTPUT_PATH,
    OPT_INVOCATION_STRIP
} appOptionsEnum;

static struct option appOptions[] = {
    {"set-input",           REQUIRED_ARG, 0, OPT_SET_INPUT},
    {"bag-input",           REQUIRED_ARG, 0, OPT_BAG_INPUT},
    {"delimiter",           REQUIRED_ARG, 0, OPT_DELIMITER},
    {"proto-port-delimiter",REQUIRED_ARG, 0, OPT_PROTO_PORT_DELIMITER},
    {"default-count",       REQUIRED_ARG, 0, OPT_DEFAULT_COUNT},
    {"key-type",            REQUIRED_ARG, 0, OPT_KEY_TYPE},
    {"counter-type",        REQUIRED_ARG, 0, OPT_COUNTER_TYPE},
    {"pmap-file",           REQUIRED_ARG, 0, OPT_PMAP_FILE},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"invocation-strip",    NO_ARG,       0, OPT_INVOCATION_STRIP},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Create a bag from the specified IP set.",
    "Create a bag from a delimiter-separated text file.",
    ("Specify the delimiter separating the key and counter\n"
     "\tfor the --bag-input switch. Def. '|'"),
    ("Specify the delimiter separating the protocol\n"
     "\tand port when key-type is sport-pmap, dport-pmap, or any-port-pmap.\n"
     "\tDef. Same as --delimiter unless explicitly set"),
    ("Set the counter for each key in the new bag to this\n"
     "\tvalue, ignoring any value present in the input. Def. 1"),
    ("Set the key type to this value"),
    ("Set the counter type to this value"),
    ("For the key-types that end with '-pmap', map the key field\n"
     "\tin the input to a string using the values in this prefix map file.\n"
     "\tMay be specified as MAPNAME:PATH, but the map-name is ignored"),
    ("Write the new bag to this stream or file. Def. stdout"),
    ("Strip invocation history from the output bag files.\n"
     "\tDef. Record command used to create the file"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void createFieldTypeStringMap(void);
static int  parsePmapFileOption(const char *opt_arg);
static int
parseFieldType(
    const char         *string,
    int                 opt_index,
    skBagFieldType_t   *field_type);
static int
createBagFromTextBag(
    skBag_t            *bag,
    skstream_t         *stream);
static int
createBagFromSet(
    skBag_t            *bag,
    skstream_t         *stream);


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
    ("{--set-input=FILE | --bag-input=FILE} [SWITCHES]\n"                   \
     "\tCreate a binary Bag file from either a binary IPset file or from\n" \
     "\ta textual input file.  Use 'stdin' or '-' for FILE to read from\n"  \
     "\tthe standard input.  The Bag is written to the standard\n"     \
     "\toutput or the location specified with the --output-path switch.\n")

    FILE *fh = USAGE_FH;
    const char *default_type = NULL;
    int i;

    createFieldTypeStringMap();
    if (field_map) {
        default_type = skStringMapGetFirstName(field_map, SKBAG_FIELD_CUSTOM);
    }
    if (!default_type) {
        default_type = "<ERROR>";
    }

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        if (OPT_INVOCATION_STRIP == appOptions[i].val) {
            /* include the help for --notes before
             * --invocation-strip */
            skOptionsNotesUsage(fh);
        }

        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_KEY_TYPE:
            fprintf(fh, "%s Def. '%s'. Choices:\n",
                    appHelp[i], default_type);
            skStringMapPrintUsage(field_map, fh, 8);
            break;
          case OPT_COUNTER_TYPE:
            fprintf(fh, ("%s Def. '%s'.\n"
                         "\tChoices are the same as for the key-type\n"),
                    appHelp[i], default_type);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

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
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (field_map) {
        skStringMapDestroy(field_map);
        field_map = NULL;
    }

    /*
     * close pipes/files
     */
    if (out_stream) {
        rv = skStreamClose(out_stream);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&out_stream);
    }

    skStreamDestroy(&bag_input);
    skStreamDestroy(&set_input);
    skPrefixMapDelete(prefix_map);
    skCountryTeardown();

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
    char key_name[SKBAG_MAX_FIELD_BUFLEN];
    int key_is_ip_pmap = 0;
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* create output stream */
    if (skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK)) {
        skAppPrintErr("Cannot create output stream");
        exit(EXIT_FAILURE);
    }

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
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

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage(); /* never returns */
    }

    /* check for input */
    if ( !set_input && !bag_input) {
        skAppPrintErr("Either --%s or --%s switch is required",
                      appOptions[OPT_SET_INPUT].name,
                      appOptions[OPT_BAG_INPUT].name);
        skAppUsage(); /* never returns */
    }

    /* Complain about extra args on command line */
    if (arg_index != argc) {
        skAppPrintErr("Too many or unrecognized argument specified: '%s'",
                      argv[arg_index]);
        exit(EXIT_FAILURE);
    }

    /* If output was never set, bind it to stdout */
    if (NULL == skStreamGetPathname(out_stream)) {
        rv = skStreamBind(out_stream, "stdout");
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* Load country code map if needed; ensure prefix map file is
     * available if needed and that it is correct type. */
    switch (key_type) {
      case SKBAG_FIELD_SIP_COUNTRY:
      case SKBAG_FIELD_DIP_COUNTRY:
      case SKBAG_FIELD_ANY_COUNTRY:
        if (skCountrySetup(NULL, &skAppPrintErr)) {
            exit(EXIT_FAILURE);
        }
        country_code = 1;
        skPrefixMapDelete(prefix_map);
        prefix_map = NULL;
        break;

      case SKBAG_FIELD_SIP_PMAP:
      case SKBAG_FIELD_DIP_PMAP:
      case SKBAG_FIELD_ANY_IP_PMAP:
        key_is_ip_pmap = 1;
        /* FALLTHROUGH */
      case SKBAG_FIELD_SPORT_PMAP:
      case SKBAG_FIELD_DPORT_PMAP:
      case SKBAG_FIELD_ANY_PORT_PMAP:
        if (NULL == prefix_map) {
            skAppPrintErr(
                "The --%s switch is required for Bags containing %s keys",
                appOptions[OPT_PMAP_FILE].name,
                skBagFieldTypeAsString(key_type, key_name, sizeof(key_name)));
            exit(EXIT_FAILURE);
        }
        if ((skPrefixMapGetContentType(prefix_map)==SKPREFIXMAP_CONT_PROTO_PORT)
            ? key_is_ip_pmap
            : !key_is_ip_pmap)
        {
            skAppPrintErr(("Invalid %s: Cannot use %s prefix map"
                           " to create a Bag containing %s keys"),
                          appOptions[OPT_KEY_TYPE].name,
                          skPrefixMapGetContentName(
                              skPrefixMapGetContentType(prefix_map)),
                          skBagFieldTypeAsString(
                              key_type, key_name, sizeof(key_name)));
            exit(EXIT_FAILURE);
        }
        break;

      default:
        skPrefixMapDelete(prefix_map);
        prefix_map = NULL;
        break;
    }

    /* Open output */
    if ((rv = skStreamSetCompressionMethod(out_stream, comp_method))
        || (rv = skStreamOpen(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* Add invocation */
    if (!invocation_strip) {
        rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream),
                                   1, argc, argv);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* Add notes if given */
    rv = skOptionsNotesAddToStream(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    skOptionsNotesTeardown();

    return;                     /* OK */
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
    const char *char_name;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_SET_INPUT:
        if (set_input) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (bag_input) {
            skAppPrintErr("May only specify one of --%s or --%s",
                          appOptions[OPT_SET_INPUT].name,
                          appOptions[OPT_BAG_INPUT].name);
            return 1;
        }
        if (IS_STDIN(opt_arg)) {
            if (stdin_used) {
                skAppPrintErr(("Invalid %s: Multiple streams attempt"
                               " to read from the standard input"),
                              appOptions[opt_index].name);
            }
            stdin_used = 1;
        }
        if ((rv = skStreamCreate(&set_input, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(set_input, opt_arg))
            || (rv = skStreamOpen(set_input)))
        {
            skStreamPrintLastErr(set_input, rv, &skAppPrintErr);
            skStreamDestroy(&set_input);
            return 1;
        }
        break;

      case OPT_BAG_INPUT:
        if (bag_input) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (set_input) {
            skAppPrintErr("May only specify one of --%s or --%s",
                          appOptions[OPT_SET_INPUT].name,
                          appOptions[OPT_BAG_INPUT].name);
            return 1;
        }
        if (IS_STDIN(opt_arg)) {
            if (stdin_used) {
                skAppPrintErr(("Invalid %s: Multiple streams attempt"
                               " to read from the standard input"),
                              appOptions[opt_index].name);
            }
            stdin_used = 1;
        }
        if ((rv = skStreamCreate(&bag_input, SK_IO_READ, SK_CONTENT_TEXT))
            || (rv = skStreamBind(bag_input, opt_arg))
            || (rv = skStreamOpen(bag_input)))
        {
            skStreamPrintLastErr(bag_input, rv, &skAppPrintErr);
            skStreamDestroy(&bag_input);
            return 1;
        }
        break;

      case OPT_PMAP_FILE:
        if (prefix_map) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (IS_STDIN(opt_arg)) {
            if (stdin_used) {
                skAppPrintErr(("Invalid %s: Multiple streams attempt"
                               " to read from the standard input"),
                              appOptions[opt_index].name);
            }
            stdin_used = 1;
        }
        if (parsePmapFileOption(opt_arg)) {
            return 1;
        }
        break;

      case OPT_OUTPUT_PATH:
        rv = skStreamBind(out_stream, opt_arg);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            return 1;
        }
        break;

      case OPT_DEFAULT_COUNT:
        rv = skStringParseUint64((uint64_t*)&default_count, opt_arg,
                                 SKBAG_COUNTER_MIN, SKBAG_COUNTER_MAX);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[opt_index].name, opt_arg,
                          skStringParseStrerror(rv));
            return 1;
        }
        f_use_default_count = 1;
        break;

      case OPT_DELIMITER:
      case OPT_PROTO_PORT_DELIMITER:
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
        if (OPT_PROTO_PORT_DELIMITER == opt_index) {
            proto_port_delimiter = opt_arg[0];
        } else {
            delimiter = opt_arg[0];
        }
        break;

      case OPT_KEY_TYPE:
        if (parseFieldType(opt_arg, opt_index, &key_type)) {
            return 1;
        }
        break;

      case OPT_COUNTER_TYPE:
        if (parseFieldType(opt_arg, opt_index, &counter_type)) {
            return 1;
        }
        break;

      case OPT_INVOCATION_STRIP:
        invocation_strip = 1;
        break;
    }

    return 0; /* OK */
}


static void
createFieldTypeStringMap(
    void)
{
    skBagFieldType_t field_type;
    skBagFieldTypeIterator_t iter;
    sk_stringmap_entry_t sm_entry;
    sk_stringmap_status_t sm_err;
    char field_name[SKBAG_MAX_FIELD_BUFLEN];

    if (field_map) {
        return;
    }

    memset(&sm_entry, 0, sizeof(sm_entry));

    /* create a stringmap of the available fields */
    sm_err = skStringMapCreate(&field_map);
    if (SKSTRINGMAP_OK != sm_err) {
        skAppPrintErr("Unable to create string map: %s",
                      skStringMapStrerror(sm_err));
        return;
    }

    skBagFieldTypeIteratorBind(&iter);
    while (skBagFieldTypeIteratorNext(&iter, &field_type, NULL,
                                      field_name, sizeof(field_name))
           == SKBAG_OK)
    {
        sm_entry.id = field_type;
        sm_entry.name = field_name;
        sm_err = skStringMapAddEntries(field_map, 1, &sm_entry);
        if (SKSTRINGMAP_OK != sm_err) {
            skAppPrintErr("Unable to add string map entry: %s",
                          skStringMapStrerror(sm_err));
            skStringMapDestroy(field_map);
            field_map = NULL;
            return;
        }
    }
}


static int
parseFieldType(
    const char         *string,
    int                 opt_index,
    skBagFieldType_t   *field_type)
{
    sk_stringmap_status_t sm_err;
    sk_stringmap_entry_t *sm_entry;

    createFieldTypeStringMap();

    /* attempt to match */
    sm_err = skStringMapGetByName(field_map, string, &sm_entry);
    switch (sm_err) {
      case SKSTRINGMAP_OK:
        *field_type = (skBagFieldType_t)sm_entry->id;
        break;
      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s: Field '%s' is ambiguous",
                      appOptions[opt_index].name, string);
        break;
      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s: Field '%s' is not recognized",
                      appOptions[opt_index].name, string);
        break;
      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      sm_err);
        break;
    }

    return ((SKSTRINGMAP_OK == sm_err) ? 0 : -1);
}


/*
 *    Parse the [MAPNAME:]PMAP_PATH option and set the result in the
 *    global 'prefix_map'.  Return 0 on success or -1 on error.
 */
static int
parsePmapFileOption(
    const char         *opt_arg)
{
    skPrefixMapErr_t rv_map;
    skstream_t *stream;
    const char *sep;
    const char *filename;
    int rv;

    /* check for a leading mapname */
    sep = strchr(opt_arg, ':');
    if (NULL == sep) {
        /* no mapname; check for one in the pmap once we read it */
        filename = opt_arg;
    } else if (sep == opt_arg) {
        /* treat a 0-length mapname on the command as having none
         * Allows use of default mapname for files that contain the
         * separator. */
        filename = sep + 1;
    } else {
        /* a mapname was supplied on the command line */
        filename = sep + 1;
#if 0
        /* no need to keep the mapname */
        size_t namelen;
        char *mapname;

        if (memchr(opt_arg, ',', sep - opt_arg) != NULL) {
            skAppPrintErr("Invalid %s: The map-name may not include a comma",
                          appOptions[OPT_PMAP_FILE].name);
            goto END;
        }
        namelen = sep - opt_arg;
        mapname = (char *)malloc(namelen + 1);
        if (NULL == mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
        strncpy(mapname, opt_arg, namelen);
        mapname[namelen] = '\0';
#endif  /* 0 */
    }

    /* open the file and read the prefix map */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }
    rv_map = skPrefixMapRead(&prefix_map, stream);
    if (SKPREFIXMAP_OK != rv_map) {
        if (SKPREFIXMAP_ERR_IO == rv_map) {
            skStreamPrintLastErr(
                stream, skStreamGetLastReturnValue(stream), &skAppPrintErr);
        } else {
            skAppPrintErr("Failed to read the prefix map file '%s': %s",
                          filename, skPrefixMapStrerror(rv_map));
        }
        skStreamDestroy(&stream);
        return -1;
    }
    skStreamDestroy(&stream);

#if 0
    /* get the mapname from the file when none on command line */
    if (NULL == mapname) {
        if (NULL == skPrefixMapGetMapName(prefix_map)) {
            skAppPrintErr(("Invalid %s '%s': Prefix map file does not contain"
                           " a map-name and none provided on the command line"),
                appOptions[OPT_PMAP_FILE].name, filename);
            goto END;
        }
        mapname = strdup(skPrefixMapGetMapName(prefix_map));
        if (NULL == mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }
#endif  /* 0 */

    return 0;
}


/*
 *    Add 'counter' to 'key' in 'bag'.  On success return SKBAG_OK.  On
 *    overflow error, set 'counter' to the maximum, print a message if this is
 *    the first overflow, and return SKBAG_OK.  On any other error, print a
 *    message and return the error code.
 */
static int
bagbuildAddCounter(
    skBag_t                *bag,
    skBagTypedKey_t        *key,
    skBagTypedCounter_t    *counter)
{
    /* warn on overflow one time only */
    static int overflow = 0;
    skBagErr_t err;

    err = skBagCounterAdd(bag, key, counter, NULL);
    switch (err) {
      case SKBAG_OK:
        break;

      case SKBAG_ERR_OP_BOUNDS:
        counter->val.u64 = SKBAG_COUNTER_MAX;
        skBagCounterSet(bag, key, counter);
        if (!overflow) {
            overflow = 1;
            skAppPrintErr(
                "**WARNING** Counter overflow for Bag being written to '%s'",
                skStreamGetPathname(out_stream));
        }
        err = SKBAG_OK;
        break;

      case SKBAG_ERR_MEMORY:
        skAppPrintErr("Out of memory for Bag being written to '%s'.\n"
                      "\tCleaning up and exiting",
                      skStreamGetPathname(out_stream));
        break;

      default:
        skAppPrintErr(
            "Error adding to counter for Bag being written to '%s': %s",
            skStreamGetPathname(out_stream), skBagStrerror(err));
        break;
    }

    return err;
}

/*
 *    Read textual input from 'stream' containing proto-port pairs
 *    with an optional counter.  Map the proto-port pair to a value in
 *    a prefix map file, and add the value and the counter to the bag.
 */
static int
createBagProtoPortPmap(
    skBag_t            *bag,
    skstream_t         *stream)
{
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skPrefixMapProtoPort_t pp;
    char *sz_proto;
    char *sz_port;
    char *sz_counter;
    char line[1024];
    int lc = 0;
    uint32_t tmp32;
    int rv;

    if (!proto_port_delimiter) {
        proto_port_delimiter = delimiter;
    }

    /* set the types for the key and counter once */
    key.type = SKBAG_KEY_U32;
    counter.type = SKBAG_COUNTER_U64;

    /* set counter to the default */
    counter.val.u64 = default_count;

    if (skStreamSetCommentStart(stream, "#")) {
        return 1;
    }

    /* read until end of file */
    while ((rv = skStreamGetLine(stream, line, sizeof(line), &lc))
           != SKSTREAM_ERR_EOF)
    {
        switch (rv) {
          case SKSTREAM_OK:
            /* good, we got our line */
            break;
          case SKSTREAM_ERR_LONG_LINE:
            /* bad: line was longer than sizeof(line_buf) */
            skAppPrintErr("Input line %d too long. ignored",
                          lc);
            continue;
          default:
            /* unexpected error */
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            return 1;
        }

        /* ignore leading whitespace */
        sz_proto = line;
        while (isspace((int)*sz_proto)) {
            ++sz_proto;
        }
        /* search for the proto/port delimiter */
        sz_port = strchr(sz_proto, proto_port_delimiter);
        if (sz_port) {
            /* terminate the string containing the proto */
            *sz_port = '\0';
            /* skip any whitespace */
            do {
                ++sz_port;
            } while (isspace((int)*sz_port));
            if (*sz_port == '\0') {
                /* no port follows the key */
                sz_port = NULL;
            }
        }
        if (!sz_port) {
            /* bad: missing port */
            /* bad: line was longer than sizeof(line_buf) */
            skAppPrintErr("Error on line %d: No port value found", lc);
            return 1;
        }

        /* search for the port/counter delimiter */
        sz_counter = strchr(sz_port, delimiter);
        if (sz_counter) {
            /* terminate the string containing the port */
            *sz_counter = '\0';
            /* skip any whitespace */
            do {
                ++sz_counter;
            } while (isspace((int)*sz_counter));
            if (*sz_counter == '\0') {
                /* no counter follows the key */
                sz_counter = NULL;
            }
        }

        /* parse the protocol */
        rv = skStringParseUint32(&tmp32, sz_proto, 0, UINT8_MAX);
        if (rv) {
            skAppPrintErr("Error parsing protocol on line %d '%s': %s",
                          lc, sz_proto, skStringParseStrerror(rv));
            return 1;
        }
        pp.proto = tmp32;

        /* parse the port */
        rv = skStringParseUint32(&tmp32, sz_port, 0, UINT16_MAX);
        if (rv) {
            skAppPrintErr("Error parsing port on line %d '%s': %s",
                          lc, sz_port, skStringParseStrerror(rv));
            return 1;
        }
        pp.port = tmp32;

        /* handle the counter */
        if (f_use_default_count == 1) {
            /* already set to the default */
        } else if (sz_counter == NULL) {
            /* not a pipe delimited line; use default count */
            counter.val.u64 = default_count;
        } else {
            rv = skStringParseUint64(&counter.val.u64, sz_counter,
                                     SKBAG_COUNTER_MIN, SKBAG_COUNTER_MAX);
            if (rv < 0) {
                /* parse error */
                skAppPrintErr("Error parsing count on line %d '%s': %s",
                              lc, sz_counter, skStringParseStrerror(rv));
                return 1;
            }
            if (rv > 0) {
                while (isspace((int)sz_counter[rv])) {
                    ++rv;
                }
                if (sz_counter[rv] != delimiter) {
                    /* unrecognized stuff after count */
                    skAppPrintErr(
                        "Error parsing line %d: Extra text after count", lc);
                    return 1;
                }
            }
            /* ignore trailing delimiter and everything after it */
        }

        key.val.u32 = skPrefixMapFindValue(prefix_map, &pp);
        if (bagbuildAddCounter(bag, &key, &counter) != 0) {
            return 1;
        }
    }

    return 0;
}


static int
createBagFromTextBag(
    skBag_t            *bag,
    skstream_t         *stream)
{
#if SK_ENABLE_IPV6
    /* types of keys seen in the input */
    struct key_types {
        unsigned    num    :1;
        unsigned    ipv4   :1;
        unsigned    ipv6   :1;
    } key_types;
#endif  /* SK_ENABLE_IPV6 */
    skBagTypedKey_t key;
    skBagTypedKey_t ipkey;
    skBagTypedCounter_t counter;
    char *sz_key;
    char *sz_counter;
    skIPWildcardIterator_t iter;
    skIPWildcard_t ipwild;
    skipaddr_t ipaddr;
    char line[1024];
    int lc = 0;
    int rv;

#if SK_ENABLE_IPV6
    /* initialize types of keys */
    memset(&key_types, 0, sizeof(key_types));
#endif

    /* set the types for the key and counter once */
    key.type = SKBAG_KEY_U32;
    ipkey.type = SKBAG_KEY_IPADDR;
    counter.type = SKBAG_COUNTER_U64;

    /* set counter to the default */
    counter.val.u64 = default_count;

    if (skStreamSetCommentStart(stream, "#")) {
        return 1;
    }

    /* read until end of file */
    while ((rv = skStreamGetLine(stream, line, sizeof(line), &lc))
           != SKSTREAM_ERR_EOF)
    {
        switch (rv) {
          case SKSTREAM_OK:
            /* good, we got our line */
            break;
          case SKSTREAM_ERR_LONG_LINE:
            /* bad: line was longer than sizeof(line_buf) */
            skAppPrintErr("Input line %d too long. ignored",
                          lc);
            continue;
          default:
            /* unexpected error */
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            return 1;
        }

        /* ignore leading whitespace */
        sz_key = line;
        while (isspace((int)*sz_key)) {
            ++sz_key;
        }
        /* search for the delimiter */
        sz_counter = strchr(sz_key, delimiter);
        if (sz_counter) {
            /* terminate the string containing the key */
            *sz_counter = '\0';
            /* skip any whitespace */
            do {
                ++sz_counter;
            } while (isspace((int)*sz_counter));
            if (*sz_counter == '\0') {
                /* no counter follows the key */
                sz_counter = NULL;
            }
        }
        if (f_use_default_count == 1) {
            /* already set to the default */
        } else if (sz_counter == NULL) {
            /* not a pipe delimited line; use default count */
            counter.val.u64 = default_count;
        } else {
            rv = skStringParseUint64(&counter.val.u64, sz_counter,
                                     SKBAG_COUNTER_MIN, SKBAG_COUNTER_MAX);
            if (rv < 0) {
                /* parse error */
                skAppPrintErr("Error parsing count on line %d '%s': %s",
                              lc, sz_counter, skStringParseStrerror(rv));
                return 1;
            }
            if (rv > 0) {
                while (isspace((int)sz_counter[rv])) {
                    ++rv;
                }
                if (sz_counter[rv] != delimiter) {
                    /* unrecognized stuff after count */
                    skAppPrintErr(
                        "Error parsing line %d: Extra text after count", lc);
                    return 1;
                }
            }
            /* ignore trailing delimiter and everything after it */
        }

        /* parse key section of bag line */

#if !SK_ENABLE_IPV6
        /* parse as an integer, an IP, a CIDR block, or an IP wildcard */
        rv = skStringParseIPWildcard(&ipwild, sz_key);
        if (rv != 0) {
            /* not parsable */
            skAppPrintErr("Error parsing IP on line %d '%s': %s",
                          lc, sz_key, skStringParseStrerror(rv));
            return 1;
        }
        /* Add IPs from wildcard to the bag */
        if (country_code) {
            skIPWildcardIteratorBind(&iter, &ipwild);
            while (skIPWildcardIteratorNext(&iter, &ipaddr)
                   == SK_ITERATOR_OK)
            {
                key.val.u32 = skCountryLookupCode(&ipaddr);
                if (bagbuildAddCounter(bag, &key, &counter) != 0) {
                    return 1;
                }
            }

        } else if (prefix_map) {
            skIPWildcardIteratorBind(&iter, &ipwild);
            while (skIPWildcardIteratorNext(&iter, &ipaddr)
                   == SK_ITERATOR_OK)
            {
                key.val.u32 = skPrefixMapFindValue(prefix_map, &ipaddr);
                if (bagbuildAddCounter(bag, &key, &counter) != 0) {
                    return 1;
                }
            }

        } else {
            skIPWildcardIteratorBind(&iter, &ipwild);
            while (skIPWildcardIteratorNext(&iter, &ipkey.val.addr)
                   == SK_ITERATOR_OK)
            {
                if (bagbuildAddCounter(bag, &ipkey, &counter) != 0) {
                    return 1;
                }
            }
        }

#else  /* SK_ENABLE_IPV6 */

        /* do not allow a mix of integer keys with IPv6 addresses */

        /* first, attempt to parse as a number */
        rv = skStringParseUint32(&key.val.u32, sz_key,
                                 SKBAG_KEY_MIN, SKBAG_KEY_MAX);
        if (0 == rv) {
            if (key_types.ipv6) {
                skAppPrintErr(("Error on line %d:"
                               " May not mix integer keys with IPv6 keys"),
                              lc);
                return 1;
            }
            key_types.num = 1;

            if (country_code) {
                skipaddrSetV4(&ipaddr, &key.val.u32);
                key.val.u32 = skCountryLookupCode(&ipaddr);
            } else if (prefix_map) {
                skipaddrSetV4(&ipaddr, &key.val.u32);
                key.val.u32 = skPrefixMapFindValue(prefix_map, &ipaddr);
            }
            if (bagbuildAddCounter(bag, &key, &counter) != 0) {
                return 1;
            }
        } else {
            /* parse as an IP, a CIDR block, or an IP wildcard */
            rv = skStringParseIPWildcard(&ipwild, sz_key);
            if (rv != 0) {
                /* not parsable */
                skAppPrintErr("Error parsing IP on line %d '%s': %s",
                              lc, sz_key, skStringParseStrerror(rv));
                return 1;
            }
            if (skIPWildcardIsV6(&ipwild)) {
                if (key_types.num) {
                    skAppPrintErr(("Error on line %d:"
                                   " May not mix integer keys with IPv6 keys"),
                                  lc);
                    return 1;
                }
                key_types.ipv6 = 1;
            } else {
                key_types.ipv4 = 1;
            }

            /* Add IPs from wildcard to the bag */
            if (country_code) {
                skIPWildcardIteratorBind(&iter, &ipwild);
                while (skIPWildcardIteratorNext(&iter, &ipaddr)
                       == SK_ITERATOR_OK)
                {
                    key.val.u32 = skCountryLookupCode(&ipaddr);
                    if (bagbuildAddCounter(bag, &key, &counter) != 0) {
                        return 1;
                    }
                }

            } else if (prefix_map) {
                skIPWildcardIteratorBind(&iter, &ipwild);
                while (skIPWildcardIteratorNext(&iter, &ipaddr)
                       == SK_ITERATOR_OK)
                {
                    key.val.u32 = skPrefixMapFindValue(prefix_map, &ipaddr);
                    if (bagbuildAddCounter(bag, &key, &counter) != 0) {
                        return 1;
                    }
                }

            } else {
                skIPWildcardIteratorBind(&iter, &ipwild);
                while (skIPWildcardIteratorNext(&iter, &ipkey.val.addr)
                       == SK_ITERATOR_OK)
                {
                    if (bagbuildAddCounter(bag, &ipkey, &counter) != 0) {
                        return 1;
                    }
                }
            }
        }
#endif  /* #else of #if !SK_ENABLE_IPV6 */

    }

    return 0;
}


/*
 *    Callback used when creating a bag containing IPs from an IPset.
 *    This is called for each IP in the IPset.
 */
static int
bagFromSet(
    skipaddr_t         *ipaddr,
    uint32_t     UNUSED(prefix),
    void               *v_bag_key_counter)
{
    bag_key_counter_t *kc = (bag_key_counter_t *)v_bag_key_counter;

    skipaddrCopy(&kc->key.val.addr, ipaddr);
    return skBagCounterSet(kc->bag, &kc->key, &kc->counter);
}


/*
 *    Callback used when creating a bag from an IPset and the bag is
 *    to contain the country code of the IP.  This is called for each
 *    IP in the IPset.
 */
static int
bagFromSetCountry(
    skipaddr_t         *ipaddr,
    uint32_t     UNUSED(prefix),
    void               *v_bag_key_counter)
{
    bag_key_counter_t *kc = (bag_key_counter_t *)v_bag_key_counter;

    kc->key.val.u16 = skCountryLookupCode(ipaddr);
    return bagbuildAddCounter(kc->bag, &kc->key, &kc->counter);
}


/*
 *    Callback used when creating a bag from an IPset and the bag is
 *    to contain prefix map data.  This is called for each IP in the
 *    IPset.
 */
static int
bagFromSetPmap(
    skipaddr_t         *ipaddr,
    uint32_t     UNUSED(prefix),
    void               *v_bag_key_counter)
{
    bag_key_counter_t *kc = (bag_key_counter_t *)v_bag_key_counter;

    kc->key.val.u32 = skPrefixMapFindValue(prefix_map, ipaddr);
    return bagbuildAddCounter(kc->bag, &kc->key, &kc->counter);
}


static int
createBagFromSet(
    skBag_t            *bag,
    skstream_t         *stream)
{
    sk_ipv6policy_t ipv6policy = SK_IPV6POLICY_IGNORE;
    skipset_t *set = NULL;
    bag_key_counter_t kc;
    ssize_t rv;

    /* Read IPset from file */
    rv = skIPSetRead(&set, stream);
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Unable to read IPset from '%s': %s",
                          skStreamGetPathname(stream), skIPSetStrerror(rv));
        }
        return 1;
    }

    if (skIPSetContainsV6(set)) {
        /* have the IPset convert everything to IPv6 */
        ipv6policy = SK_IPV6POLICY_FORCE;
        if (SKBAG_FIELD_CUSTOM == key_type) {
            skBagModify(bag, SKBAG_FIELD_ANY_IPv6, skBagCounterFieldType(bag),
                        SKBAG_OCTETS_FIELD_DEFAULT, SKBAG_OCTETS_NO_CHANGE);
        }
    } else if (SKBAG_FIELD_CUSTOM == key_type) {
        skBagModify(bag, SKBAG_FIELD_ANY_IPv4, skBagCounterFieldType(bag),
                    SKBAG_OCTETS_FIELD_DEFAULT, SKBAG_OCTETS_NO_CHANGE);
    }

    /* initialize the counter once */
    kc.bag = bag;
    kc.counter.type = SKBAG_COUNTER_U64;
    kc.counter.val.u64 = default_count;

    /* invoke one of the callback functions defined above */
    if (country_code) {
        kc.key.type = SKBAG_KEY_U16;
        rv = skIPSetWalk(set, 0, ipv6policy, &bagFromSetCountry, (void *)&kc);
        skIPSetDestroy(&set);
    } else if (prefix_map) {
        kc.key.type = SKBAG_KEY_U32;
        rv = skIPSetWalk(set, 0, ipv6policy, &bagFromSetPmap, (void *)&kc);
        skIPSetDestroy(&set);
    } else {
        kc.key.type = SKBAG_KEY_IPADDR;
        rv = skIPSetWalk(set, 0, ipv6policy, &bagFromSet, (void *)&kc);
        skIPSetDestroy(&set);
    }

    return ((rv == 0) ? 0 : 1);
}


int main(int argc, char **argv)
{
    skBag_t *bag = NULL;
    skBagErr_t err;
    int rv = EXIT_FAILURE;

    appSetup(argc, argv); /* never returns on error */

    /* Create new bag */
    err = skBagCreateTyped(&bag, key_type, counter_type,
                           ((SKBAG_FIELD_CUSTOM == key_type)
                            ? sizeof(uint32_t) : SKBAG_OCTETS_FIELD_DEFAULT),
                           ((SKBAG_FIELD_CUSTOM == counter_type)
                            ? sizeof(uint64_t) : SKBAG_OCTETS_FIELD_DEFAULT));
    if (SKBAG_OK != err) {
        skAppPrintErr("Unable to create bag: %s", skBagStrerror(err));
        exit(EXIT_FAILURE);
    }

    /* Process input */
    if (set_input) {
        /* Handle set-file input */
        if (createBagFromSet(bag, set_input)) {
            skAppPrintErr("Error creating bag from set");
            goto END;
        }
    } else if (bag_input) {
        switch (key_type) {
          case SKBAG_FIELD_SPORT_PMAP:
          case SKBAG_FIELD_DPORT_PMAP:
          case SKBAG_FIELD_ANY_PORT_PMAP:
            if (createBagProtoPortPmap(bag, bag_input)) {
                skAppPrintErr("Error creating bag from text bag");
                goto END;
            }
            break;

          default:
            /* Handle bag-file input */
            if (createBagFromTextBag(bag, bag_input)) {
                skAppPrintErr("Error creating bag from text bag");
                goto END;
            }
            break;
        }
    } else {
        skAbort();
    }

    /* write output */
    err = skBagWrite(bag, out_stream);
    if (SKBAG_OK != err) {
        if (SKBAG_ERR_OUTPUT == err) {
            skStreamPrintLastErr(out_stream,
                                 skStreamGetLastReturnValue(out_stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing bag to '%s': %s",
                          skStreamGetPathname(out_stream), skBagStrerror(err));
        }
        goto END;
    }

    rv = EXIT_SUCCESS;

  END:
    skBagDestroy(&bag);
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
