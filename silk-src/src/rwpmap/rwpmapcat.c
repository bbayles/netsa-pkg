/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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
**  rwpmapcat.c
**
**    Print information about a prefix map file.  Very loosely based
**    on skprefixmap-test.c
**
**    Mark Thomas
**    January 2007
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpmapcat.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skprefixmap.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* types of output to produce */
#define OUTPUT_TYPE    (1<<0)
#define OUTPUT_MAPNAME (1<<1)
#define OUTPUT_LABELS  (1<<2)
#define OUTPUT_RANGES  (1<<3)

/* the default output type */
#define DEFAULT_OUTPUT_TYPES  OUTPUT_RANGES

/* max expected length of a pmap dictionary entry */
#define DICTIONARY_ENTRY_BUFLEN 2048


/* LOCAL VARIABLES */

/* the prefix map being queried */
static const skPrefixMap_t *map = NULL;

/* the prefix map that was opened; this is NULL when using the
 * country-codes or address-types map */
static skPrefixMap_t *opened_map = NULL;

/* true if the map is a country code map */
static int opt_country_codes = 0;

/* true if the map is an address types map */
static int opt_address_types = 0;

/* value indicating to use to environment to find the country-codes or
 * address-types prefix map */
static const char *from_environ = "envar";

/* output stream for the results */
static skstream_t *stream_out = NULL;

/* the value in the prefix map to ignore */
static uint32_t ignore_val = SKPREFIXMAP_NOT_FOUND;

/* the type(s) of output to produce */
static int output_types = DEFAULT_OUTPUT_TYPES;

/* available output types */
static const sk_stringmap_entry_t output_type_names[] = {
    {"type",    OUTPUT_TYPE,    NULL, NULL},
    {"mapname", OUTPUT_MAPNAME, NULL, NULL},
    {"labels",  OUTPUT_LABELS,  NULL, NULL},
    {"ranges",  OUTPUT_RANGES,  NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* output flags */
static struct opt_flags_st {
    unsigned  left_justify_label    :1;
    unsigned  no_cidr_blocks        :1;
    unsigned  no_titles             :1;
    unsigned  no_columns            :1;
    unsigned  no_final_delimiter    :1;
} opt_flags;

/* output delimiter between columns */
static char delimiter = '|';

/* format for printing IP addresses */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);


/* OPTIONS SETUP */

typedef enum {
    OPT_MAP_FILE, OPT_ADDRESS_TYPES, OPT_COUNTRY_CODES,
    OPT_OUTPUT_TYPES,
    OPT_IGNORE_LABEL, OPT_IP_LABEL_TO_IGNORE,
    OPT_LEFT_JUSTIFY_LABEL,  OPT_NO_CIDR_BLOCKS,
    OPT_NO_TITLES, OPT_NO_COLUMNS, OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER, OPT_DELIMITED,
    OPT_OUTPUT_PATH, OPT_PAGER
} appOptionsEnum;

static struct option appOptions[] = {
    {"map-file",            REQUIRED_ARG, 0, OPT_MAP_FILE},
    {"address-types",       OPTIONAL_ARG, 0, OPT_ADDRESS_TYPES},
    {"country-codes",       OPTIONAL_ARG, 0, OPT_COUNTRY_CODES},
    {"output-types",        REQUIRED_ARG, 0, OPT_OUTPUT_TYPES},
    {"ignore-label",        REQUIRED_ARG, 0, OPT_IGNORE_LABEL},
    {"ip-label-to-ignore",  REQUIRED_ARG, 0, OPT_IP_LABEL_TO_IGNORE},
    {"left-justify-labels", NO_ARG,       0, OPT_LEFT_JUSTIFY_LABEL},
    {"no-cidr-blocks",      NO_ARG,       0, OPT_NO_CIDR_BLOCKS},
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
    "Print the contents of this the prefix map",
    ("Print the contents of the named address types mapping\n"
     "\tfile or of the default file when no argument is provided"),
    ("Print the contents of the named country code mapping\n"
     "\tfile or of the default file when no argument is provided"),
    NULL, /* generated dynamically */
    "Do not print ranges having this label. Def. Print all",
    ("Do not print ranges having the label that\n"
     "\tthis IP has. Def. Print all"),
    "Left justify the labels. Def. Right justify",
    "Do not use CIDR notation. Def. Use CIDR notation",
    "Do not print column titles. Def. Print titles",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
    "Write the output to this stream or file. Def. stdout",
    "Invoke this program to page output. Def. $SILK_PAGER or $PAGER",
    NULL
};

typedef struct option_values_st {
    const char *map_file;
    const char *ignore_label;
    const char *ip_label_to_ignore;
    const char *output_types;
    const char *output_path;
    const char *pager;
} option_values_t;



/* LOCAL FUNCTION PROTOTYPES */

static int appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static const skPrefixMap_t *openMapFile(const char *map_file);
static int parseOutputTypes(const char *type_list, int *output_type_flags);


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
#define USAGE_MSG                                                        \
    ("[SWITCHES] [MAP_FILE]\n"                                           \
     "\tPrint information about a prefix map file.  By default, print\n" \
     "\teach IP range in the map and its label\n")

    FILE *fh = USAGE_FH;
    int i, j;
    int print_comma = 0;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ",
                appOptions[i].name, SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_OUTPUT_TYPES:
            fprintf(fh, ("What information to print about the map; enter as\n"
                         "\ta comma separated list. Def. '"));
            for (j = 0; output_type_names[j].name; ++j) {
                if (DEFAULT_OUTPUT_TYPES & output_type_names[j].id) {
                    fprintf(fh, "%s%s",
                            (print_comma ? ", " : ""),
                            output_type_names[j].name);
                    print_comma = 1;
                }
            }
            fprintf(fh, "'.\n\tChoose from among: %s",
                    output_type_names[0].name);
            for (j = 1; output_type_names[j].name; ++j) {
                fprintf(fh, ",%s", output_type_names[j].name);
            }
            fprintf(fh, "\n");
            break;

          case OPT_NO_CIDR_BLOCKS:
            fprintf(fh, "%s\n", appHelp[i]);
            skOptionsIPFormatUsage(fh);
            break;

          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (opt_country_codes) {
        skCountryTeardown();
    } else if (opt_address_types) {
        skAddressTypesTeardown();
    } else if (opened_map) {
        skPrefixMapDelete(opened_map);
        opened_map = NULL;
    }

    skStreamDestroy(&stream_out);
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
    int arg_index;
    option_values_t opt_val;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&opt_val, 0, sizeof(option_values_t));
    memset(&opt_flags, 0, sizeof(opt_flags));

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler,(clientData)&opt_val)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags))
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

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* if no map file was specified with a switch, either check for a
     * name on the command line or read the map from stdin */
    if (NULL == opt_val.map_file) {
        if (arg_index == argc) {
            if (FILEIsATty(stdin)) {
                skAppPrintErr("No file on the command line and"
                              " stdin is connected to a terminal");
                skAppUsage();
            }
            opt_val.map_file = "-";
        } else {
            opt_val.map_file = argv[arg_index];
            ++arg_index;
        }
    }

    /* check for extra arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    /* check for conflicting arguments */
    if (opt_val.ignore_label && opt_val.ip_label_to_ignore) {
        skAppPrintErr("Only one of --%s or --%s may be specified",
                      appOptions[OPT_IGNORE_LABEL].name,
                      appOptions[OPT_IP_LABEL_TO_IGNORE].name);
        exit(EXIT_FAILURE);
    }

    /* parse the output types */
    if (opt_val.output_types) {
        if (parseOutputTypes(opt_val.output_types, &output_types)) {
            exit(EXIT_FAILURE);
        }
    }

    /* open the prefix map file */
    map = openMapFile(opt_val.map_file);
    if (NULL == map) {
        exit(EXIT_FAILURE);
    }

    /* if an ignore-label or an ignore-IP was given, find the
     * corresponding value. */
    if (opt_val.ignore_label) {
        if (opt_country_codes) {
            ignore_val = skCountryNameToCode(opt_val.ignore_label);
            if (ignore_val == SK_COUNTRYCODE_INVALID) {
                skAppPrintErr("Invalid %s '%s': Invalid country code",
                              appOptions[OPT_IGNORE_LABEL].name,
                              opt_val.ignore_label);
                exit(EXIT_FAILURE);
            }
        } else if (skPrefixMapDictionaryGetWordCount(map) == 0) {
            rv = skStringParseUint32(&ignore_val, opt_val.ignore_label,
                                     0, SKPREFIXMAP_MAX_VALUE);
            if (rv) {
                skAppPrintErr("Invalid %s '%s': Value not in dictionary",
                              appOptions[OPT_IGNORE_LABEL].name,
                              opt_val.ignore_label);
                exit(EXIT_FAILURE);
            }
        } else {
            ignore_val = skPrefixMapDictionaryLookup(map, opt_val.ignore_label);
            if (ignore_val == SKPREFIXMAP_NOT_FOUND) {
                skAppPrintErr("Invalid %s '%s': Value not in dictionary",
                              appOptions[OPT_IGNORE_LABEL].name,
                              opt_val.ignore_label);
                exit(EXIT_FAILURE);
            }
        }
    } else if (opt_val.ip_label_to_ignore) {
        skipaddr_t ip;
        rv = skStringParseIP(&ip, opt_val.ip_label_to_ignore);
        if (rv) {
            skAppPrintErr("Invalid IP '%s': %s",
                          opt_val.ip_label_to_ignore,
                          skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
        ignore_val = skPrefixMapFindValue(map, &ip);
    }

    /* if an output_path is set, bypass the pager by setting it to the
     * empty string.  if no output_path was set, use stdout */
    if (opt_val.output_path) {
        opt_val.pager = "";
    } else {
        opt_val.output_path = "-";
    }

    /* create the output stream */
    if ((rv = skStreamCreate(&stream_out, SK_IO_WRITE, SK_CONTENT_TEXT))
        || (rv = skStreamBind(stream_out, opt_val.output_path))
        || (rv = skStreamPageOutput(stream_out, opt_val.pager))
        || (rv = skStreamOpen(stream_out)))
    {
        skStreamPrintLastErr(stream_out, rv, &skAppPrintErr);
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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    option_values_t *opt_val = (option_values_t*)cData;

    switch ((appOptionsEnum)opt_index) {
      case OPT_MAP_FILE:
        if (opt_val->map_file) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->map_file = opt_arg;
        break;

      case OPT_COUNTRY_CODES:
        if (opt_val->map_file) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->map_file = opt_arg ? opt_arg : from_environ;
        opt_country_codes = 1;
        break;

      case OPT_ADDRESS_TYPES:
        if (opt_val->map_file) {
            skAppPrintErr("Invalid %s: May only specify one prefix map file",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->map_file = opt_arg ? opt_arg : from_environ;
        opt_address_types = 1;
        break;

      case OPT_IGNORE_LABEL:
        if (opt_val->ignore_label) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->ignore_label = opt_arg;
        break;

      case OPT_IP_LABEL_TO_IGNORE:
        if (opt_val->ip_label_to_ignore) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->ip_label_to_ignore = opt_arg;
        break;

      case OPT_OUTPUT_TYPES:
        if (opt_val->output_types) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->output_types = opt_arg;
        break;

      case OPT_NO_CIDR_BLOCKS:
        opt_flags.no_cidr_blocks = 1;
        break;

      case OPT_LEFT_JUSTIFY_LABEL:
        opt_flags.left_justify_label = 1;
        break;

      case OPT_NO_TITLES:
        opt_flags.no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        opt_flags.no_columns = 1;
        break;

      case OPT_NO_FINAL_DELIMITER:
        opt_flags.no_final_delimiter = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        opt_flags.no_columns = 1;
        opt_flags.no_final_delimiter = 1;
        if (opt_arg) {
            delimiter = opt_arg[0];
        }
        break;

      case OPT_OUTPUT_PATH:
        if (opt_val->output_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        opt_val->output_path = opt_arg;
        break;

      case OPT_PAGER:
        opt_val->pager = opt_arg;
        break;
    }

    return 0;                   /* OK */
}


/*
 *  pmap = openMapFile(path);
 *
 *    Open the Country Code prefix map, the Address Types prefix map,
 *    or the prefix map file at 'path' and return a pointer to it.
 *    Return NULL on error.
 */
static const skPrefixMap_t *
openMapFile(
    const char         *map_file)
{
    skPrefixMapErr_t map_error;

    if (opt_country_codes) {
        if (skCountrySetup((map_file == from_environ) ? NULL : map_file,
                           &skAppPrintErr))
        {
            return NULL;
        }
        return skCountryGetPrefixMap();
    }

    if (opt_address_types) {
        if (skAddressTypesSetup((map_file == from_environ) ? NULL : map_file,
                                &skAppPrintErr))
        {
            return NULL;
        }
        return skAddressTypesGetPmap();
    }

    /* open the prefixmap file and read it in */
    map_error = skPrefixMapLoad(&opened_map, map_file);
    if (SKPREFIXMAP_OK != map_error) {
        skAppPrintErr("Failed to read %s '%s': %s",
                      appOptions[OPT_MAP_FILE].name, map_file,
                      skPrefixMapStrerror(map_error));
        opened_map = NULL;
        return NULL;
    }
    return opened_map;
}


/*
 *  status = parseOutputTypes(type_list, &type_flags);
 *
 *    Parse the 'type_list', a comma separated list of the names from
 *    the output_type_names[] array, and set bits to HIGH in
 *    'type_flags' if the output type was requested.  Return 0 on
 *    success, or -1 on error.
 */
static int
parseOutputTypes(
    const char         *type_list,
    int                *output_type_flags)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_entry_t *map_entry;
    sk_stringmap_iter_t *iter = NULL;
    char *errmsg;
    int rv = -1;

    /* create a stringmap of the available output types */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintOutOfMemory("string map");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, output_type_names)!=SKSTRINGMAP_OK)
    {
        goto END;
    }

    /* attempt to match */
    if (skStringMapParse(str_map, type_list, SKSTRINGMAP_DUPES_REMOVE_SILENT,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_OUTPUT_TYPES].name, errmsg);
        goto END;
    }

    *output_type_flags = 0;

    while (skStringMapIterNext(iter, &map_entry, NULL) == SK_ITERATOR_OK) {
        *output_type_flags |= map_entry->id;
    }

    /* success */
    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/*
 *  printLabels(pmap);
 *
 *    Print the labels that appear in the prefix map 'pmap'.
 */
static void
printLabels(
    const skPrefixMap_t    *pmap)
{
    char label[DICTIONARY_ENTRY_BUFLEN];
    uint32_t label_count;
    uint32_t i;

    if (opt_country_codes) {
        return;
    }
    label_count = skPrefixMapDictionaryGetWordCount(pmap);
    if (label_count == 0) {
        skStreamPrint(stream_out, ("NO LABELS ARE PRESENT;"
                                   " VALUE IS APPLICATION DEPENDENT\n"));
        return;
    }

    if (!opt_flags.no_titles) {
        skStreamPrint(stream_out, "LABELS:\n");
    }
    for (i = 0; i < label_count; ++i) {
        skPrefixMapDictionaryGetEntry(pmap, i, label, sizeof(label));
        skStreamPrint(stream_out, "%s\n", label);
    }
}


/*
 *  printType(pmap);
 *
 *    Print the type of the prefix map 'pmap'.
 */
static void
printType(
    const skPrefixMap_t    *pmap)
{
    const char *type;

    if (opt_country_codes) {
        return;
    }

    type = skPrefixMapGetContentName(skPrefixMapGetContentType(pmap));

    skStreamPrint(stream_out, "%s%s\n",
                  ((opt_flags.no_titles) ? "" : "TYPE:  "), type);
}


/*
 *  printMapName(pmap);
 *
 *    Print the mapname that appears in the prefix map 'pmap'.
 */
static void
printMapName(
    const skPrefixMap_t    *pmap)
{
    const char *mapname;

    if (opt_country_codes) {
        return;
    }
    mapname = skPrefixMapGetMapName(pmap);
    if (NULL == mapname) {
        skStreamPrint(stream_out, "NO MAPNAME IS PRESENT\n");
        return;
    }
    skStreamPrint(stream_out, "%s%s\n",
                  ((opt_flags.no_titles) ? "" : "MAPNAME:  "), mapname);
}


/*
 *  printRangesIP(pmap);
 *
 *    Print the IP ranges and labels that appear in the prefix map
 *    'pmap'.
 */
static void
printRangesIP(
    const skPrefixMap_t    *pmap)
{
    skPrefixMapIterator_t iter;
    skipaddr_t addr_start;
    skipaddr_t addr_end;
    uint32_t label_val;
    char final_delim[] = {'\0', '\0'};
    int label_width = 0;
    int ip_width = 0;
    const char *label_title;
    char str_label[DICTIONARY_ENTRY_BUFLEN];
    char str_start[SKIPADDR_CIDR_STRLEN];
    char str_end[SKIPADDR_CIDR_STRLEN];
    int prefix;
    skipaddr_t next_addr;

    if ( !opt_flags.no_final_delimiter) {
        final_delim[0] = delimiter;
    }

    /* determine titles and widths for the columns */
    if (skPrefixMapDictionaryGetWordCount(pmap) == 0) {
        label_title = "value";
    } else {
        label_title = "label";
    }
    if (opt_flags.no_columns) {
        label_width = 1;
        ip_width = 1;
    } else {
        int is_v6 =
            (skPrefixMapGetContentType(pmap) == SKPREFIXMAP_CONT_ADDR_V6);
        if (opt_flags.no_cidr_blocks) {
            ip_width = skipaddrStringMaxlen(is_v6, ip_format);
        } else {
            ip_width = skipaddrCidrStringMaxlen(is_v6, ip_format);
        }
        if (opt_country_codes) {
            label_width = 2;
        } else {
            label_width = (int)skPrefixMapDictionaryGetMaxWordSize(pmap);
        }
        if (label_width < (int)strlen(label_title)) {
            label_width = (int)strlen(label_title);
        }
        if (opt_flags.left_justify_label) {
            label_width = -1 * label_width;
        }
    }

    /* print titles */
    if (!opt_flags.no_titles) {
        if (opt_flags.no_cidr_blocks) {
            skStreamPrint(stream_out, "%*s%c%*s%c%*s%s\n",
                          ip_width, "startIP", delimiter,
                          ip_width, "endIP", delimiter,
                          label_width, label_title, final_delim);
        } else {
            skStreamPrint(stream_out, "%*s%c%*s%s\n",
                          ip_width, "ipBlock", delimiter,
                          label_width, label_title, final_delim);
        }
    }

    skPrefixMapIteratorBind(&iter, pmap);

    while (skPrefixMapIteratorNext(&iter, &addr_start, &addr_end, &label_val)
           != SK_ITERATOR_NO_MORE_ENTRIES)
    {
        if (label_val == ignore_val) {
            continue;
        }

        if (opt_country_codes) {
            skCountryCodeToName(label_val, str_label, sizeof(str_label));
        } else {
            skPrefixMapDictionaryGetEntry(pmap, label_val,
                                          str_label, sizeof(str_label));
        }

        /* handle the case with no CIDR blocks */
        if (opt_flags.no_cidr_blocks) {
            skStreamPrint(stream_out, "%*s%c%*s%c%*s%s\n",
                          ip_width,
                          skipaddrString(str_start, &addr_start, ip_format),
                          delimiter, ip_width,
                          skipaddrString(str_end, &addr_end, ip_format),
                          delimiter, label_width, str_label, final_delim);
            continue;
        }

        do {
            prefix = skCIDRComputePrefix(&addr_start, &addr_end, &next_addr);
            skipaddrCidrString(str_start, &addr_start, prefix, ip_format),
            skStreamPrint(stream_out, "%*s%c%*s%s\n",
                          ip_width, str_start,
                          delimiter, label_width, str_label, final_delim);
            skipaddrCopy(&addr_start, &next_addr);
        } while (!skipaddrIsZero(&addr_start));
    }
}


/*
 *  printRangesProtoPort(pmap);
 *
 *    Print the Protocol/Port ranges and labels that appear in the
 *    prefix map 'pmap'.
 */
static void
printRangesProtoPort(
    const skPrefixMap_t    *pmap)
{
    skPrefixMapIterator_t iter;
    skPrefixMapProtoPort_t val_start;
    skPrefixMapProtoPort_t val_end;
    uint32_t label_val;
    const char *label_title;
    int label_width = 0;
    int value_width = 0;
    char str_label[DICTIONARY_ENTRY_BUFLEN];
    char str_start[SKIPADDR_STRLEN];
    char str_end[SKIPADDR_STRLEN];
    char final_delim[] = {'\0', '\0'};

    if ( !opt_flags.no_final_delimiter) {
        final_delim[0] = delimiter;
    }

    /* determine titles and widths for the columns */
    if (skPrefixMapDictionaryGetWordCount(pmap) == 0) {
        label_title = "value";
    } else {
        label_title = "label";
    }
    if (opt_flags.no_columns) {
        label_width = 1;
        value_width = 1;
    } else {
        /* size of "proto/port" = 3 + 1 + 5 ==> 9 */
        value_width = 9;
        label_width = (int)skPrefixMapDictionaryGetMaxWordSize(pmap);
        if (label_width < (int)strlen(label_title)) {
            label_width = (int)strlen(label_title);
        }
        if (opt_flags.left_justify_label) {
            label_width = -1 * label_width;
        }
    }

    /* print titles */
    if (!opt_flags.no_titles) {
        skStreamPrint(stream_out, "%*s%c%*s%c%*s%s\n",
                      value_width, "startPair", delimiter,
                      value_width, "endPair", delimiter,
                      label_width, label_title, final_delim);
    }

    skPrefixMapIteratorBind(&iter, pmap);
    while (skPrefixMapIteratorNext(&iter, &val_start, &val_end, &label_val)
           != SK_ITERATOR_NO_MORE_ENTRIES)
    {
        if (label_val == ignore_val) {
            continue;
        }

        skPrefixMapDictionaryGetEntry(pmap, label_val,
                                      str_label, sizeof(str_label));

        snprintf(str_start, sizeof(str_start), "%u/%u",
                 val_start.proto, val_start.port);
        snprintf(str_end, sizeof(str_end), "%u/%u",
                 val_end.proto, val_end.port);
        skStreamPrint(stream_out, "%*s%c%*s%c%*s%s\n",
                      value_width, str_start, delimiter,
                      value_width, str_end, delimiter,
                      label_width, str_label, final_delim);
    }
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);                       /* never returns on error */

    if (opt_country_codes) {
        if (output_types & OUTPUT_RANGES) {
            printRangesIP(skCountryGetPrefixMap());
            return 0;
        }
    }

    if (output_types & OUTPUT_TYPE) {
        printType(map);
    }
    if (output_types & OUTPUT_MAPNAME) {
        printMapName(map);
    }
    if (output_types & OUTPUT_LABELS) {
        printLabels(map);
        /* print newline if additional output follows */
        if (output_types & OUTPUT_RANGES) {
            skStreamPrint(stream_out, "\n");
        }
    }
    if (output_types & OUTPUT_RANGES) {
        switch (skPrefixMapGetContentType(map)) {
          case SKPREFIXMAP_CONT_ADDR_V4:
          case SKPREFIXMAP_CONT_ADDR_V6:
            printRangesIP(map);
            break;

          case SKPREFIXMAP_CONT_PROTO_PORT:
            printRangesProtoPort(map);
            break;
        }
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
