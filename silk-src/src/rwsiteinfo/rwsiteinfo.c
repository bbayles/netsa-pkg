/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
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
**  Prints information about SiLK site configurations
**
**  Michael Duggan
**  September 2011
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwsiteinfo.c c05ad63a27aa 2023-05-12 19:43:56Z mthomas $");

#include <silk/redblack.h>
#include <silk/skmempool.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/sksite.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include <ftw.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* max number of iterators is 4: flowtype, class, sensor, group */
#define RWS_MAX_ITERATOR_COUNT  4

/* size of memory pool */
#define RWS_MEMORY_POOL_SIZE    256

/* maximum number of file descriptors for nftw() to keep open */
#define RWS_MAX_FD_NFTW  16


/* Sub-iterator types */
typedef enum rws_iter_type_en {
    /* iterator is not set */
    RWS_NULL,
    /* iterates over flowtypes; NO active class iterator */
    RWS_FLOWTYPE,
    /* iterates over classes; NO active sensor iterator */
    RWS_CLASS,
    /* iterates over sensors; NO active class or group iterator */
    RWS_SENSOR,
    /* iterates over groups, NO active sensor iterator */
    RWS_GROUP,
    /* iterates over default classes */
    RWS_DEFAULT_CLASS,
    /* iterates over classes; sensor iterator is active */
    RWS_CLASS_FROM_SENSOR,
    /* iterates over sensors; class iterator is active */
    RWS_SENSOR_FROM_CLASS,
    /* iterates over groups; sensor iterator is active */
    RWS_GROUP_FROM_SENSOR,
    /* iterates over sensors; group iterator is active */
    RWS_SENSOR_FROM_GROUP,
    /* iterates over flowtypes; class iterator is active */
    RWS_FLOWTYPE_FROM_CLASS,
    /* iterates over default flowtypes; class iterator is active */
    RWS_DEFAULT_FLOWTYPE_FROM_CLASS
} rws_iter_type_t;

/* Site iterator */
typedef struct rws_iter_st {
    /* The iterators */
    sk_flowtype_iter_t      flowtype_iter;
    sk_class_iter_t         class_iter;
    sk_sensor_iter_t        sensor_iter;
    sk_sensorgroup_iter_t   group_iter;

    /* The values */
    sk_flowtype_id_t        flowtype_id;
    sk_class_id_t           class_id;
    sk_sensor_id_t          sensor_id;
    sk_sensorgroup_id_t     group_id;

    /* Order and type of iterators */
    rws_iter_type_t         order[RWS_MAX_ITERATOR_COUNT];

    /* Number of iterators  */
    int                     level;
    /* Highest bound iterator */
    int                     bound;
    /* Highest started iterator */
    int                     started;

    /* Emitted at a given level */
    int                     emitted[RWS_MAX_ITERATOR_COUNT];
    /* Lowest level at which information is emitted */
    int                     emit_level;

    /* Whether RWS_DEFAULT_FLOWTYPE_FROM_CLASS is one of the
     * iterators */
    unsigned                default_type : 1;

    /* Whether the group iterator should check that it contains a sensor which
     * is in the current class_id; set when a class or flowtype iterator
     * occurs before a group iterator without a sensor iterator */
    unsigned                group_check_class : 1;

    /* Whether the class or flowtype iterator should check that it contains a
     * sensor which is in the current group_id; set when a group iterator
     * occurs before a class or flowtype iterator without a sensor iterator */
    unsigned                class_check_group : 1;
} rws_iter_t;

/* Structure to hold information about files in the repository */
struct rws_repo_file_st {
    sktime_t            rf_mindate;
    sktime_t            rf_maxdate;
    uint32_t            rf_count;
    sk_sensor_id_t      rf_sensor;
    sk_flowtype_id_t    rf_flowtype;
    sk_class_id_t       rf_class;
};
typedef struct rws_repo_file_st rws_repo_file_t;


/* LOCAL VARIABLE DEFINITIONS */

/* Masks for flowtypes, classes, and sensors as set by the --classes, --types,
 * --flowtypes, --sensors, and --groups switches.  When the bitmap is NULL,
 * all values are printed; when the bitmap is not NULL, only values where the
 * bit is high are printed. */
static sk_bitmap_t *flowtype_mask = NULL;
static sk_bitmap_t *class_mask    = NULL;
static sk_bitmap_t *sensor_mask   = NULL;
static sk_bitmap_t *group_mask    = NULL;

/* paging program */
static const char *pager;

/* the output stream, set by --output-path or --pager */
static sk_fileptr_t output;

/* raw filter arguments */
static char *classes_arg   = NULL;
static char *types_arg     = NULL;
static char *flowtypes_arg = NULL;
static char *sensors_arg   = NULL;
static char *groups_arg    = NULL;

/* the fields to print; set by --fields; required */
static char *fields_arg    = NULL;

/* delimiters */
static char column_separator = '|';
static char list_separator   = ',';

/* how to format output */
static int no_columns         = 0;
static int no_final_delimiter = 0;
static int no_titles          = 0;

/* final delimiter */
static char final_delim[] = {'\0', '\0'};

/* how to print timestamps */
static uint32_t time_flags = 0;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags = SK_OPTION_TIMESTAMP_NEVER_MSEC;

/* memory pool of rws_repo_file_t structures */
static sk_mempool_t *mempool = NULL;

/* redblack tree of rws_repo_file_t structures keyed by the
 * rf_flowtype and rf_sensor members of that structure */
static struct rbtree *rb_repo = NULL;

/* pointer to a rws_repo_file_t used by the nftw() callback function.
 * there is no support in nftw() for a context pointer. */
static rws_repo_file_t *repo_new_file = NULL;

/* Field types */
typedef enum {
    RWST_CLASS,
    RWST_TYPE,
    RWST_FLOWTYPE,
    RWST_FLOWTYPE_ID,
    RWST_SENSOR,
    RWST_SENSOR_ID,
    RWST_SENSOR_DESC,
    RWST_GROUP,
    RWST_DEFAULT_CLASS,
    RWST_DEFAULT_TYPE,
    RWST_MARK_DEFAULTS,
    RWST_CLASS_LIST,
    RWST_TYPE_LIST,
    RWST_FLOWTYPE_LIST,
    RWST_FLOWTYPE_ID_LIST,
    RWST_SENSOR_LIST,
    RWST_SENSOR_ID_LIST,
    RWST_GROUP_LIST,
    RWST_DEFAULT_CLASS_LIST,
    RWST_DEFAULT_TYPE_LIST,
    RWST_REPO_START_DATE,
    RWST_REPO_END_DATE,
    RWST_REPO_FILE_COUNT,
    /* Number of field types */
    RWST_MAX_FIELD_COUNT
} rws_field_t;

/* Field names, types, descriptions, and titles.  MUST be in the same
 * order as the rws_field_t enumeration. */
static const sk_stringmap_entry_t field_map_entries[] = {
    {"class",              RWST_CLASS,
     "class name",                              "Class"},
    {"type",               RWST_TYPE,
     "type name",                               "Type"},
    {"flowtype",           RWST_FLOWTYPE,
     "flowtype name",                           "Flowtype"},
    {"id-flowtype",        RWST_FLOWTYPE_ID,
     "flowtype integer identifier",             "Flowtype-ID"},
    {"sensor",             RWST_SENSOR,
     "sensor name",                             "Sensor"},
    {"id-sensor",          RWST_SENSOR_ID,
     "sensor integer identifier",               "Sensor-ID"},
    {"describe-sensor",    RWST_SENSOR_DESC,
     "sensor description",                      "Sensor-Description"},
    {"group",              RWST_GROUP,
     "sensor-group name",                       "Group"},
    {"default-class",      RWST_DEFAULT_CLASS,
     "default class name",                      "Default-Class"},
    {"default-type",       RWST_DEFAULT_TYPE,
     "default type name",                       "Default-Type"},
    {"mark-defaults",      RWST_MARK_DEFAULTS,
     "'+' for default classes, '*' for types",  "Defaults"},
    {"class:list",         RWST_CLASS_LIST,
     "list of class names",                     "Class:list"},
    {"type:list",          RWST_TYPE_LIST,
     "list of type names",                      "Type:list"},
    {"flowtype:list",      RWST_FLOWTYPE_LIST,
     "list of flowtype names",                  "Flowtype:list"},
    {"id-flowtype:list",   RWST_FLOWTYPE_ID_LIST,
     "list of flowtype integer identifiers",    "Flowtype-ID:list"},
    {"sensor:list",        RWST_SENSOR_LIST,
     "list of sensor names",                    "Sensor:list"},
    {"id-sensor:list",     RWST_SENSOR_ID_LIST,
     "list of sensor integer identifiers",      "Sensor-ID:list"},
    {"group:list",         RWST_GROUP_LIST,
     "list of sensor-group names",              "Group:list"},
    {"default-class:list", RWST_DEFAULT_CLASS_LIST,
     "list of default class names",             "Default-Class:list"},
    {"default-type:list",  RWST_DEFAULT_TYPE_LIST,
     "list of default type names",              "Default-Type:list"},
    {"repo-start-date",    RWST_REPO_START_DATE,
     "date of earliest file in the repository", "Start-Date"},
    {"repo-end-date",      RWST_REPO_END_DATE,
     "date of latest file in the repository",   "End-Date"},
    {"repo-file-count",    RWST_REPO_FILE_COUNT,
     "number of files in the repository",       "File-Count"},
    SK_STRINGMAP_SENTINEL
};

/* Fields to print, in the order in which to print them */
static rws_field_t fields[RWST_MAX_FIELD_COUNT];

/* Number of fields in list */
static size_t num_fields = 0;

/* Width of the columns, where index is an rws_field_t. */
static int col_width[RWST_MAX_FIELD_COUNT];


/* OPTIONS SETUP */

typedef enum {
    OPT_HELP_FIELDS, OPT_FIELDS,
    OPT_CLASSES, OPT_TYPES, OPT_FLOWTYPES, OPT_SENSORS, OPT_GROUPS,
    OPT_NO_TITLES, OPT_NO_COLUMNS, OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER, OPT_DELIMITED, OPT_LIST_DELIMETER,
    OPT_OUTPUT_PATH, OPT_PAGER, OPT_DATA_ROOTDIR
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {"classes",             REQUIRED_ARG, 0, OPT_CLASSES},
    {"types",               REQUIRED_ARG, 0, OPT_TYPES},
    {"flowtypes",           REQUIRED_ARG, 0, OPT_FLOWTYPES},
    {"sensors",             REQUIRED_ARG, 0, OPT_SENSORS},
    {"groups",              REQUIRED_ARG, 0, OPT_GROUPS},
    /* timestamp-format gets inserted here */
    {"no-titles",           NO_ARG,       0, OPT_NO_TITLES},
    {"no-columns",          NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",  NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",           OPTIONAL_ARG, 0, OPT_DELIMITED},
    {"list-delimiter",      REQUIRED_ARG, 0, OPT_LIST_DELIMETER},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"pager",               REQUIRED_ARG, 0, OPT_PAGER},
    {"data-rootdir",        REQUIRED_ARG, 0, OPT_DATA_ROOTDIR},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each field and exit. Def. no",
    ("Print the fields named in this comma-separated list. Choices:"),
    ("Restrict the output using classes named in this comma-\n"
     "\tseparated list. Use '@' to designate the default class. Use @FILE to\n"
     "\tread class names from FILE, which may be a file path. Def. Print\n"
     "\tdata for all classes"),
    ("Restrict the output using the types named in this comma-\n"
     "\tseparated list. Use '@' to designate the default type(s) for a class.\n"
     "\tUse @FILE to read type names from FILE, which may be a file path.\n"
     "\tDef. Print data for all types"),
    ("Restrict the output using the class/type pairs named in\n"
     "\tthis comma-separated list. May use 'all' for class and/or type. Use\n"
     "\t@FILE to read class/type pairs from FILE, which may be a file path.\n"
     "\tThis is an alternate way to specify class/type; switch may not be\n"
     "\tused with --class or --type. Def. Print data for all class/type pairs"),
    ("Restrict the output using the sensors named in this comma-\n"
     "\tseparated list. Sensors may be designated by name, ID (integer),\n"
     "\tand/or ranges of IDs. Use @FILE to read sensors from FILE, which may\n"
     "\tbe a file path. Def. Print data for all sensors"),
    ("Restrict the output using sensor-groups named in this comma-\n"
     "\tseparated list. Use @FILE to read group names from FILE, which may\n"
     "\tbe a file path. Def. Print data for all sensor-groups"),
    ("Do not print column headers. Def. Print titles"),
    ("Disable fixed-width columnar output. Def. Columnar"),
    ("Use specified character between columns. Def. '|'"),
    ("Suppress column delimiter at end of line. Def. No"),
    ("Shortcut for --no-columns --no-final-del --column-sep=CHAR"),
    ("Use specified character between items in FIELD:list\n"
     "\tfields. Def. ','"),
    ("Write the output to this stream or file. Def. stdout"),
    ("Invoke this program to page output. Def. $SILK_PAGER or $PAGER"),
    ("Root of directory tree containing packed data."),
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void helpFields(FILE *fh);
static sk_stringmap_t *createStringmap(void);
static int rws_parse_fields(void);
static int rws_parse_restrictions(void);
static int rws_repo_scan(void);
static int rws_repo_file_compare(const void *a, const void *b, const void *c);
static int rws_print(FILE *fp, const char *format, ...) SK_CHECK_PRINTF(2, 3);
static int
rws_print_list_field(
    FILE               *fd,
    rws_iter_t         *iter,
    rws_field_t         field,
    int                 width);


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
#define MIN_TEXT_ON_LINE  15
#define MAX_TEXT_ON_LINE  72
#define USAGE_MSG                                                            \
    ("--fields=<FIELDS> [SWITCHES]\n"                                        \
     "\tPrint selected information about the classes, types, flowtypes,\n"   \
     "\tsensors, and groups defined in the SiLK site configuration file.\n"  \
     "\tBy default, the selected information is printed for every class,\n"  \
     "\ttype, sensor, and group defined in the file; to restrict the\n"      \
     "\toutput, specify one or more of --classes, --types, --flowtypes,\n"   \
     "\t--sensors or --groups.\n")

    FILE *fh = USAGE_FH;
    char *cp, *ep, *sp;
    char buf[2 * PATH_MAX];
    char path[PATH_MAX];
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ",
                appOptions[i].name, SK_OPTION_HAS_ARG(appOptions[i]));
        /* Print the static help text from the appHelp array */
        switch (appOptions[i].val) {
          case OPT_FIELDS:
            {
                sk_stringmap_t *map = createStringmap();
                if (map == NULL) {
                    skAppPrintErr("Error creating string map");
                    exit(EXIT_FAILURE);
                }
                fprintf(fh, "%s\n", appHelp[i]);
                skStringMapPrintUsage(map, fh, 8);
                skStringMapDestroy(map);
            }
            break;
          case OPT_GROUPS:
            fprintf(fh, "%s\n", appHelp[i]);
            /* print help for --timestamp-usage */
            skOptionsTimestampFormatUsage(fh);
            break;
          case OPT_DATA_ROOTDIR:
            fprintf(fh, "%s\n", appHelp[i]);
            /* put the text containing the current value into a
             * buffer, and then wrap the text in the buffer at space
             * characters. */
            snprintf(buf, sizeof(buf),
                     "Currently '%s'. Def. $%s or '%s'",
                     sksiteGetRootDir(path, sizeof(path)),
                     SILK_DATA_ROOTDIR_ENVAR, sksiteGetDefaultRootDir());
            sp = buf;
            while (strlen(sp) > MAX_TEXT_ON_LINE) {
                cp = &sp[MIN_TEXT_ON_LINE];
                while ((ep = strchr(cp+1, ' ')) != NULL) {
                    /* text is now too long */
                    if (ep - sp > MAX_TEXT_ON_LINE) {
                        if (cp == &sp[MIN_TEXT_ON_LINE]) {
                            /* this is the first space character we have
                             * on this line; so use it */
                            cp = ep;
                        }
                        break;
                    }
                    cp = ep;
                }
                if (cp == &sp[MIN_TEXT_ON_LINE]) {
                    /* no space characters anywhere on the line */
                    break;
                }
                assert(' ' == *cp);
                *cp = '\0';
                fprintf(fh, "\t%s\n", sp);
                sp = cp + 1;
            }
            if (*sp) {
                fprintf(fh, "\t%s\n", sp);
            }
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close the output file or process */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }

    skMemoryPoolDestroy(&mempool);
    if (rb_repo) {
        rbdestroy(rb_repo);
    }

    skBitmapDestroy(&flowtype_mask);
    skBitmapDestroy(&class_mask);
    skBitmapDestroy(&sensor_mask);
    skBitmapDestroy(&group_mask);

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
    size_t i;
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsTimestampFormatRegister(&time_flags, time_register_flags)
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

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    if (sksiteConfigure(1)) {
        exit(EXIT_FAILURE);
    }

    /* parse fields */
    if (rws_parse_fields()) {
        exit(EXIT_FAILURE);
    }

    /* parse restrictions (--classes, --types, etc) */
    if (rws_parse_restrictions()) {
        exit(EXIT_FAILURE);
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    /* scan the repository if requested */
    for (i = 0; i < num_fields && NULL == rb_repo; ++i) {
        switch (fields[i]) {
          case RWST_REPO_START_DATE:
          case RWST_REPO_END_DATE:
          case RWST_REPO_FILE_COUNT:
            if (rws_repo_scan()) {
                exit(EXIT_FAILURE);
            }
            break;
          default:
            break;
        }
    }

    /* initialize column widths */
    if (no_titles || no_columns) {
        memset(col_width, 0, sizeof(col_width));
    } else {
        for (i = 0; i < RWST_MAX_FIELD_COUNT; ++i) {
            col_width[i] = strlen((char *)field_map_entries[i].userdata);

            /* While looping through, verify that the
             * field_map_entries is in the same order as the
             * enumeration. */
            assert(i == field_map_entries[i].id);
        }
    }

    /* set the final delimiter, if used */
    if (!no_final_delimiter) {
        final_delim[0] = column_separator;
    }

    /* open the --output-path: the 'of_name' member is non-NULL when
     * the switch is given.  only invoke the pager when the user has
     * not specified the output-path, even if output-path is stdout */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Cannot open '%s': %s",
                          output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }
    } else {
        rv = skFileptrOpenPager(&output, pager);
        if (rv && rv != SK_FILEPTR_PAGER_IGNORED) {
            skAppPrintErr("Unable to invoke pager");
        }
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
    /* Complain that 'm_opt_index' was specified multiple times when
     * 'm_variable' is not NULL and return -1 to the caller. */
#define CHECK_MULTIPLE_USE(m_opt_index, m_variable)             \
    if ((m_variable) != NULL) {                                 \
        skAppPrintErr("Invalid %s: Switch used multiple times", \
                      appOptions[m_opt_index].name);            \
        return -1;                                              \
    }

    /* Complain that the argument to 'm_opt_index' is invalid when
     * 'm_variable' is the empty string and return -1 to the
     * caller. */
#define CHECK_EMPTY_STRING(m_opt_index, m_variable)             \
    if ('\0' == *(m_variable)) {                                \
        skAppPrintErr("Invalid %s: Value is the empty string",  \
                      appOptions[m_opt_index].name);            \
        return -1;                                              \
    }

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_DATA_ROOTDIR:
        CHECK_EMPTY_STRING(opt_index, opt_arg);
        if (!skDirExists(opt_arg)) {
            skAppPrintErr("Root data directory '%s' does not exist", opt_arg);
            return -1;
        }
        if (sksiteSetRootDir(opt_arg)) {
            skAppPrintErr("Unable to set root data directory to %s", opt_arg);
            return -1;
        }
        break;

      case OPT_CLASSES:
        CHECK_MULTIPLE_USE(opt_index, classes_arg);
        /* CHECK_EMPTY_STRING(opt_index, opt_arg); */
        classes_arg = opt_arg;
        break;

      case OPT_TYPES:
        CHECK_MULTIPLE_USE(opt_index, types_arg);
        /* CHECK_EMPTY_STRING(opt_index, opt_arg); */
        types_arg = opt_arg;
        break;

      case OPT_FLOWTYPES:
        CHECK_MULTIPLE_USE(opt_index, flowtypes_arg);
        /* CHECK_EMPTY_STRING(opt_index, opt_arg); */
        flowtypes_arg = opt_arg;
        break;

      case OPT_SENSORS:
        CHECK_MULTIPLE_USE(opt_index, sensors_arg);
        /* CHECK_EMPTY_STRING(opt_index, opt_arg); */
        sensors_arg = opt_arg;
        break;

      case OPT_GROUPS:
        CHECK_MULTIPLE_USE(opt_index, groups_arg);
        /* CHECK_EMPTY_STRING(opt_index, opt_arg); */
        groups_arg = opt_arg;
        break;

      case OPT_FIELDS:
        CHECK_MULTIPLE_USE(opt_index, fields_arg);
        CHECK_EMPTY_STRING(opt_index, opt_arg);
        fields_arg = opt_arg;
        break;

      case OPT_NO_TITLES:
        no_titles = 1;
        break;

      case OPT_NO_COLUMNS:
        no_columns = 1;
        break;

      case OPT_COLUMN_SEPARATOR:
        column_separator = opt_arg[0];
        break;

      case OPT_NO_FINAL_DELIMITER:
        no_final_delimiter = 1;
        break;

      case OPT_DELIMITED:
        no_columns = 1;
        no_final_delimiter = 1;
        if (opt_arg) {
            column_separator = opt_arg[0];
        }
        break;

      case OPT_LIST_DELIMETER:
        list_separator = opt_arg[0];
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
#define HELP_FIELDS                                                     \
    ("The following names may be used in the --%s switch. Names are\n"  \
     "case-insensitive and may be abbreviated to the shortest unique prefix.\n")

    sk_stringmap_t *map;

    map = createStringmap();
    if (NULL == map) {
        exit(EXIT_FAILURE);
    }

    fprintf(fh, HELP_FIELDS, appOptions[OPT_FIELDS].name);

    skStringMapPrintDetailedUsage(map, fh);
    skStringMapDestroy(map);
}


/*
 *  stringmap = createStringmap();
 *
 *    Create the string map that is used to parse the --fields
 *    paramater.
 */
static sk_stringmap_t *
createStringmap(
    void)
{
    sk_stringmap_t *field_map;

    /* Create the map */
    if (SKSTRINGMAP_OK != skStringMapCreate(&field_map)) {
        return NULL;
    }

    /* add entries */
    if (skStringMapAddEntries(field_map, -1, field_map_entries)
        != SKSTRINGMAP_OK)
    {
        skStringMapDestroy(field_map);
        return NULL;
    }

    return field_map;
}


/*
 *  status = rws_parse_fields();
 *
 *     Parse the --fields argument.  Return 0 on success, -1 on
 *     failure.
 */
static int
rws_parse_fields(
    void)
{
    sk_stringmap_t *field_map = NULL;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    char *errmsg;
    int rv = -1;

    if (fields_arg == NULL) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_FIELDS].name);
        return rv;
    }
    field_map = createStringmap();
    if (NULL == field_map) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* parse the field-list */
    if (skStringMapParse(field_map, fields_arg, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_FIELDS].name, errmsg);
        goto END;
    }

    /* add the selected fields to the 'fields[]' array */
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        assert(num_fields < RWST_MAX_FIELD_COUNT);
        fields[num_fields] = (rws_field_t)entry->id;
         ++num_fields;
    }

    rv = 0;

  END:
    if (iter != NULL) {
        skStringMapIterDestroy(iter);
    }
    if (field_map != NULL) {
        skStringMapDestroy(field_map);
    }
    return rv;
}


/*
 *  status = rws_parse_sensors(sn_bitmap);
 *
 *      Parse the --sensors argument from the global 'sensors_arg'.
 *      Set a bit in 'sn_bitmap' for each sensor we see.  Return 0 on
 *      success, or -1 if any invalid sensors are found.
 *
 *      Helper for rws_parse_restrictions().
 */
static int
rws_parse_sensors(
    sk_bitmap_t        *sn_bitmap)
{
    const unsigned int flags = (SKSITE_SENSORS_ALLOW_RANGE
                                | SKSITE_SENSORS_ALLOW_GROUP);
    sksite_error_iterator_t *error_iter = NULL;
    sk_vector_t *sensor_vec;
    sk_sensor_id_t id;
    size_t i;
    int rv;

    assert(sensors_arg);
    assert(sn_bitmap);
    assert(skBitmapGetSize(sn_bitmap) > sksiteSensorGetMaxID());

    sensor_vec = skVectorNew(sizeof(sk_sensor_id_t));
    if (NULL == sensor_vec) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }

    rv = sksiteParseSensorList(sensor_vec, sensors_arg, NULL, NULL, flags,
                               &error_iter);
    if (rv) {
        if (NULL == error_iter) {
            skAppPrintErr("Error parsing %s: Internal error parsing argument",
                          appOptions[OPT_SENSORS].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Error parsing %s '%s': %s",
                          appOptions[OPT_SENSORS].name, sensors_arg,
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Error parsing %s '%s': Found multiple errors:",
                          appOptions[OPT_SENSORS].name, sensors_arg);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
    } else if (0 == skVectorGetCount(sensor_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid sensor names found",
                      appOptions[OPT_SENSORS].name, sensors_arg);
        rv = -1;
    } else {
        for (i = 0; 0 == skVectorGetValue(&id, sensor_vec, i); ++i) {
            skBitmapSetBit(sn_bitmap, id);
        }
    }

    skVectorDestroy(sensor_vec);
    return rv;
}


/*
 *  status = rws_parse_groups(gr_bitmap);
 *
 *      Parse the --groups argument from the global 'groups_arg'.  Set a bit
 *      in 'gr_bitmap' for each group we see.  Return 0 on success, or -1 if
 *      any invalid groups are found.
 *
 *      Helper for rws_parse_restrictions().
 */
static int
rws_parse_groups(
    sk_bitmap_t        *gr_bitmap)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_vector_t *group_vec;
    sk_sensorgroup_id_t id;
    size_t i;
    int rv;

    assert(groups_arg);
    assert(gr_bitmap);
    assert(skBitmapGetSize(gr_bitmap) > sksiteSensorgroupGetMaxID());

    group_vec = skVectorNew(sizeof(sk_sensorgroup_id_t));
    if (NULL == group_vec) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }

    rv = sksiteParseSensorgroupList(group_vec, groups_arg, &error_iter);
    if (rv) {
        if (NULL == error_iter) {
            skAppPrintErr("Error parsing %s: Internal error parsing argument",
                          appOptions[OPT_GROUPS].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Error parsing %s '%s': %s",
                          appOptions[OPT_GROUPS].name, groups_arg,
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Error parsing %s '%s': Found multiple errors:",
                          appOptions[OPT_GROUPS].name, groups_arg);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
    } else if (0 == skVectorGetCount(group_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid group names found",
                      appOptions[OPT_GROUPS].name, groups_arg);
        rv = -1;
    } else {
        for (i = 0; 0 == skVectorGetValue(&id, group_vec, i); ++i) {
            skBitmapSetBit(gr_bitmap, id);
        }
    }

    skVectorDestroy(group_vec);
    return rv;
}


/*
 *  status = rws_parse_flowtypes(cl_bitmap, ft_bitmap);
 *
 *    Parse the --flowtypes argument from the global 'flowtypes_arg'.
 *    Set a bit on 'cl_bitmap' for each valid class and and a bit on
 *    'ft_bitmap' for each valid flowtype.  Return 0 on success, or -1
 *    on if any class/type value is not a valid pair.
 *
 *    Helper for rws_parse_restrictions().
 */
static int
rws_parse_flowtypes(
    sk_bitmap_t        *cl_bitmap,
    sk_bitmap_t        *ft_bitmap)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_vector_t *flowtypes_vec;
    sk_flowtype_id_t id;
    size_t i;
    int rv;

    assert(cl_bitmap);
    assert(ft_bitmap);

    flowtypes_vec = skVectorNew(sizeof(sk_flowtype_id_t));
    if (NULL == flowtypes_vec) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }

    rv = sksiteParseFlowtypeList(flowtypes_vec, flowtypes_arg, "all", "all",
                                 NULL, NULL, &error_iter);
    if (rv) {
        if (NULL == error_iter) {
            skAppPrintErr("Error parsing %s: Internal error parsing argument",
                          appOptions[OPT_FLOWTYPES].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Error parsing %s '%s': %s",
                          appOptions[OPT_FLOWTYPES].name, flowtypes_arg,
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Error parsing %s '%s': Found multiple errors:",
                          appOptions[OPT_FLOWTYPES].name, flowtypes_arg);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
    } else if (0 == skVectorGetCount(flowtypes_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid class/type pairs found",
                      appOptions[OPT_FLOWTYPES].name, flowtypes_arg);
        rv = -1;
    } else {
        for (i = 0; 0 == skVectorGetValue(&id, flowtypes_vec, i); ++i) {
            skBitmapSetBit(ft_bitmap, id);
            skBitmapSetBit(cl_bitmap, sksiteFlowtypeGetClassID(id));
        }
    }

    skVectorDestroy(flowtypes_vec);

    return ((rv) ? -1 : 0);
}


/*
 *  status = rws_parse_classes_and_types();
 *
 *    Parse the --classes and/or --types arguments from the globals
 *    'classes_arg' and 'types_arg'.  Set a bit on 'cl_bitmap' for
 *    each valid class and and a bit on 'ft_bitmap' for each valid
 *    flowtype.  Return 0 on success, or -1 on if any class/type value
 *    is not a valid pair.
 *
 *    Helper for rws_parse_restrictions().
 */
static int
rws_parse_classes_and_types(
    sk_bitmap_t        *cl_bitmap,
    sk_bitmap_t        *ft_bitmap)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_vector_t *classes_vec;
    sk_vector_t *flowtypes_vec;
    sk_class_id_t class_id;
    sk_flowtype_id_t id;
    size_t i;
    int rv;

    /* create vectors to hold the lists of classes and types */
    classes_vec = skVectorNew(sizeof(sk_class_id_t));
    flowtypes_vec = skVectorNew(sizeof(sk_flowtype_id_t));
    if (NULL == classes_vec || NULL == flowtypes_vec) {
        skAppPrintOutOfMemory(NULL);
        rv = -1;
        goto END;
    }

    /* parse the classes first */
    if (NULL == classes_arg) {
        /* fill classes_vec with all classes */
        assert(types_arg);
        rv = sksiteParseClassList(classes_vec, "__ALL__", "__ALL__", NULL,
                                  &error_iter);
    } else {
        rv = sksiteParseClassList(classes_vec, classes_arg, NULL, "@",
                                  &error_iter);
    }
    if (rv) {
        if (NULL == error_iter) {
            skAppPrintErr("Error parsing %s: Internal error parsing argument",
                          appOptions[OPT_CLASSES].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Error parsing %s '%s': %s",
                          appOptions[OPT_CLASSES].name, classes_arg,
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Error parsing %s '%s': Found multiple errors:",
                          appOptions[OPT_CLASSES].name, classes_arg);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
        rv = -1;
        goto END;
    }
    if (0 == skVectorGetCount(classes_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid class names found",
                      appOptions[OPT_CLASSES].name, classes_arg);
        rv = -1;
        goto END;
    }

    /* parse the types */
    if (NULL == types_arg) {
        /* use all types in the specified classes */
        assert(classes_arg);
        rv = sksiteParseTypeList(flowtypes_vec, "all", classes_vec,
                                 "all", NULL, &error_iter);
    } else {
        rv = sksiteParseTypeList(flowtypes_vec, types_arg, classes_vec,
                                 "all", "@", &error_iter);
    }
    if (rv) {
        if (NULL == error_iter) {
            skAppPrintErr("Error parsing %s: Internal error parsing argument",
                          appOptions[OPT_TYPES].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Error parsing %s '%s': %s",
                          appOptions[OPT_TYPES].name, types_arg,
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Error parsing %s '%s': Found multiple errors:",
                          appOptions[OPT_TYPES].name, types_arg);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
        rv = -1;
        goto END;
    }
    if (0 == skVectorGetCount(flowtypes_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid type names found",
                      appOptions[OPT_TYPES].name, types_arg);
        rv = -1;
        goto END;
    }

    /* fill the bitmaps */
    if (NULL == classes_arg) {
        /* set cl_bitmap based on flowtypes found */
        for (i = 0; 0 == skVectorGetValue(&id, flowtypes_vec, i); ++i) {
            skBitmapSetBit(ft_bitmap, id);
            skBitmapSetBit(cl_bitmap, sksiteFlowtypeGetClassID(id));
        }
    } else {
        for (i = 0; 0 == skVectorGetValue(&class_id, classes_vec, i); ++i) {
            skBitmapSetBit(cl_bitmap, class_id);
        }
        for (i = 0; 0 == skVectorGetValue(&id, flowtypes_vec, i); ++i) {
            skBitmapSetBit(ft_bitmap, id);
        }
    }

  END:
    skVectorDestroy(classes_vec);
    skVectorDestroy(flowtypes_vec);

    return rv;
}


/*
 *  status = rws_parse_restrictions();
 *
 *    Calls helper functions to parse the --classes, --types, --flowtypes,
 *    --sensors, and --groups options, then creates and fills bitmaps that
 *    restrict the output.
 *
 *    Returns 0 on success, -1 on error.
 */
static int
rws_parse_restrictions(
    void)
{
    sk_bitmap_iter_t bmap_iter;
    uint32_t bmap_val;
    sk_bitmap_t *sn_mask = NULL;
    sk_sensor_iter_t sensor_iter;
    sk_class_id_t class_id;
    sk_sensor_id_t sensor_id;
    sk_sensorgroup_id_t group_id;
    int rv;

    /* Check which restrcition arguments were given */
    if (flowtypes_arg) {
        if (classes_arg || types_arg) {
            /* error if --flowtypes used with --classes or --types */
            skAppPrintErr(
                "Cannot use --%s when either --%s or --%s is specified",
                appOptions[OPT_FLOWTYPES].name,
                appOptions[OPT_CLASSES].name,
                appOptions[OPT_TYPES].name);
            return -1;
        }
    } else if (NULL == classes_arg && NULL == types_arg
               && NULL == sensors_arg && NULL == groups_arg)
    {
        /* all are NULL; there is nothing to do */
        return 0;
    }

    /* Create the bitmaps */
    if (skBitmapCreate(&sensor_mask, 1 + sksiteSensorGetMaxID())) {
        skAppPrintOutOfMemory("sensor bitmap");
        return -1;
    }
    if (skBitmapCreate(&group_mask, 1 + sksiteSensorgroupGetMaxID())) {
        skAppPrintOutOfMemory("group bitmap");
        return -1;
    }
    if (skBitmapCreate(&class_mask, 1 + sksiteClassGetMaxID())) {
        skAppPrintOutOfMemory("class bitmap");
        return -1;
    }
    if (skBitmapCreate(&flowtype_mask, 1 + sksiteFlowtypeGetMaxID())) {
        skAppPrintOutOfMemory("flowtype bitmap");
        return -1;
    }

    /* Parse all --classes, --types, etc switches first; then return if an
     * error was encountered in any of them. */
    rv = 0;
    if (sensors_arg) {
        rv |= rws_parse_sensors(sensor_mask);
    }
    if (groups_arg) {
        rv |= rws_parse_groups(group_mask);
    }
    if (flowtypes_arg) {
        rv |= rws_parse_flowtypes(class_mask, flowtype_mask);
    }
    if (classes_arg || types_arg) {
        rv |= rws_parse_classes_and_types(class_mask, flowtype_mask);
    }
    if (rv) {
        rv = -1;
        goto END;
    }

    /* Assume error */
    rv = -1;

    /* Create a temporary sensor bitmap. (Other temp bitmaps are created in
     * their local block; this bitmaps is used multiple times.) */
    if (skBitmapCreate(&sn_mask, 1 + sksiteSensorGetMaxID())) {
        skAppPrintOutOfMemory("sensor bitmap");
        goto END;
    }

    /* if --groups was given, use it to update sensor_mask */
    if (groups_arg) {
        skBitmapIteratorBind(group_mask, &bmap_iter);
        while (skBitmapIteratorNext(&bmap_iter, &bmap_val) == SK_ITERATOR_OK) {
            group_id = (sk_sensorgroup_id_t)bmap_val;
            sksiteSensorgroupSensorIterator(group_id, &sensor_iter);
            while (sksiteSensorIteratorNext(&sensor_iter, &sensor_id)) {
                skBitmapSetBit(sn_mask, sensor_id);
            }
        }

        /* update the sensor_mask: intersect the bitmaps if sensors_arg
         * updated the sensor_mask; else union them */
        if (sensors_arg) {
            skBitmapIntersection(sensor_mask, sn_mask);
        } else {
            assert(0 == skBitmapGetHighCount(sensor_mask));
            skBitmapUnion(sensor_mask, sn_mask);
        }
        skBitmapClearAllBits(sn_mask);
    }

    /* if --sensors or --groups was given, update the class_mask and
     * flowtype_mask from the current sensor_mask */
    if (sensors_arg || groups_arg) {
        sk_bitmap_t *cl_mask = NULL;
        sk_bitmap_t *ft_mask = NULL;
        sk_class_iter_t class_iter;
        sk_flowtype_id_t flowtype_id;
        sk_flowtype_iter_t ft_iter;

        if (NULL == classes_arg && NULL == types_arg && NULL == flowtypes_arg)
        {
            /* set bits in class_mask and flowtype_mask directly */
            cl_mask = class_mask;
            ft_mask = flowtype_mask;
        } else {
            /* create temporary bitmaps for intersection */
            if (skBitmapCreate(&cl_mask, 1 + sksiteClassGetMaxID())) {
                skAppPrintOutOfMemory("class bitmap");
                goto END;
            }
            if (skBitmapCreate(&ft_mask, 1 + sksiteFlowtypeGetMaxID())) {
                skAppPrintOutOfMemory("flowtype bitmap");
                skBitmapDestroy(&cl_mask);
                goto END;
            }
        }

        /* for each sensor, gets its classes.  for each of those classes, set
         * a bit in the cl_mask and set bits in ft_mask for each type in the
         * class */
        skBitmapIteratorBind(sensor_mask, &bmap_iter);
        while (skBitmapIteratorNext(&bmap_iter, &bmap_val) == SK_ITERATOR_OK) {
            sensor_id = (sk_sensor_id_t)bmap_val;
            sksiteSensorClassIterator(sensor_id, &class_iter);
            while (sksiteClassIteratorNext(&class_iter, &class_id)) {
                if (!skBitmapGetBit(cl_mask, class_id)) {
                    skBitmapSetBit(cl_mask, class_id);
                    sksiteClassFlowtypeIterator(class_id, &ft_iter);
                    while (sksiteFlowtypeIteratorNext(&ft_iter, &flowtype_id)){
                        skBitmapSetBit(ft_mask, flowtype_id);
                    }
                }
            }
        }

        /* intersect the bitmaps and destroy temporaries */
        if (cl_mask != class_mask) {
            skBitmapIntersection(class_mask, cl_mask);
            skBitmapIntersection(flowtype_mask, ft_mask);
            skBitmapDestroy(&cl_mask);
            skBitmapDestroy(&ft_mask);
        }
    }

    /* if --classes, --types, or --flowtypes was given, update sensor_mask
     * from the class_mask */
    if (classes_arg || types_arg || flowtypes_arg) {
        skBitmapIteratorBind(class_mask, &bmap_iter);
        while (skBitmapIteratorNext(&bmap_iter, &bmap_val) == SK_ITERATOR_OK) {
            class_id = (sk_class_id_t)bmap_val;
            sksiteClassSensorIterator(class_id, &sensor_iter);
            while (sksiteSensorIteratorNext(&sensor_iter, &sensor_id)) {
                skBitmapSetBit(sn_mask, sensor_id);
            }
        }

        /* update the sensor_mask: intersect the bitmaps if either sensors_arg
         * or groups_arg updated the sensor_mask; else union them */
        if (sensors_arg || groups_arg) {
            skBitmapIntersection(sensor_mask, sn_mask);
        } else {
            assert(0 == skBitmapGetHighCount(sensor_mask));
            skBitmapUnion(sensor_mask, sn_mask);
        }
    }

    /* finally, if any non-group masks were set from the command line, update
     * group_mask based on values in the sensor_mask */
    if (classes_arg || types_arg || flowtypes_arg || sensors_arg) {
        sk_bitmap_t *gr_mask = NULL;
        sk_sensorgroup_iter_t group_iter;

        if (NULL == groups_arg) {
            /* set bits in group_mask directly */
            gr_mask = group_mask;
        } else {
            /* create a temporary bitmap for intersection */
            if (skBitmapCreate(&gr_mask, 1 + sksiteSensorgroupGetMaxID())) {
                skAppPrintOutOfMemory("group bitmap");
                goto END;
            }
        }

        skBitmapIteratorBind(sensor_mask, &bmap_iter);
        while (skBitmapIteratorNext(&bmap_iter, &bmap_val) == SK_ITERATOR_OK) {
            sensor_id = (sk_sensor_id_t)bmap_val;
            sksiteSensorSensorgroupIterator(sensor_id, &group_iter);
            while (sksiteSensorgroupIteratorNext(&group_iter, &group_id)) {
                skBitmapSetBit(gr_mask, group_id);
            }
        }

        /* intersect the bitmaps */
        if (gr_mask != group_mask) {
            skBitmapIntersection(group_mask, gr_mask);
            skBitmapDestroy(&gr_mask);
        }
    }

    rv = 0;

  END:
    skBitmapDestroy(&sn_mask);
    return rv;
}


/*
 *    Comparison function used by red-black tree.
 */
static int
rws_repo_file_compare(
    const void         *v_repo_file_a,
    const void         *v_repo_file_b,
    const void         *v_context)
{
    const rws_repo_file_t *repo_file_a = (const rws_repo_file_t*)v_repo_file_a;
    const rws_repo_file_t *repo_file_b = (const rws_repo_file_t*)v_repo_file_b;

    (void)v_context;
    if (repo_file_a->rf_flowtype < repo_file_b->rf_flowtype) {
        return -1;
    }
    if (repo_file_a->rf_flowtype > repo_file_b->rf_flowtype) {
        return 1;
    }
    if (repo_file_a->rf_sensor < repo_file_b->rf_sensor) {
        return -1;
    }
    return repo_file_a->rf_sensor > repo_file_b->rf_sensor;
}


/*
 *    Callback function invoked by nftw() for every entry in the
 *    repository hierachy.
 *
 *    If the entry is a file and its name parses as a SiLK data file,
 *    assume it is a valid file.
 *
 *    Use the flowtype and sensor from the file's name as the key into
 *    the red-black tree 'rb_repo'.  If the item does not exist in the
 *    tree, add it and set the min-time and max-time of the item to
 *    the time in the file's name and set its count to 1.
 *
 *    If the item does exist in the tree, increment the item's count
 *    and update its min time or max time if necessary using the time
 *    from the file'a name.
 */
static int
rws_repo_scan_callback(
    const char         *path,
    const struct stat  *st,
    int                 flag,
    struct FTW         *info)
{
    rws_repo_file_t *found;
    sktime_t startdate;

    /* UNUSED.  FIXME: Maybe reject files smaller than a certain
     * size? */
    (void)st;

    if (FTW_F != flag) {
        return 0;
    }
    if (sksiteParseFilename(
            &repo_new_file->rf_flowtype, &repo_new_file->rf_sensor,
            &startdate, NULL, &path[info->base])
        == SK_INVALID_FLOWTYPE)
    {
        return 0;
    }
    found = (rws_repo_file_t*)rbsearch(repo_new_file, rb_repo);
    if (NULL == found) {
        skAppPrintOutOfMemory("rbsearch");
        return 1;
    }
    if (found == repo_new_file) {
        /* inserted the entry */
        found->rf_mindate = found->rf_maxdate = startdate;
        found->rf_class = sksiteFlowtypeGetClassID(repo_new_file->rf_flowtype);
        found->rf_count = 0;
        repo_new_file = (rws_repo_file_t*)skMemPoolElementNew(mempool);
        if (NULL == repo_new_file) {
            skAppPrintOutOfMemory("skMemPoolElementNew");
            return 1;
        }
    } else if (startdate < found->rf_mindate) {
        found->rf_mindate = startdate;
    } else if (startdate > found->rf_maxdate) {
        found->rf_maxdate = startdate;
    }
    ++found->rf_count;
    return 0;
}


/*
 *    Create a memory-pool and a red-black tree to hold the attributes
 *    of the files in the repository, then walk over the files in the
 *    repository and invoke the rws_repo_scan_callback function for
 *    each entry.
 */
static int
rws_repo_scan(
    void)
{
    char root_dir[PATH_MAX];
    int rv;

    if (!sksiteGetRootDir(root_dir, sizeof(root_dir))) {
        return -1;
    }

    /* create memory pool and redblack tree */
    if (skMemoryPoolCreate(
            &mempool, sizeof(rws_repo_file_t), RWS_MEMORY_POOL_SIZE))
    {
        skAppPrintOutOfMemory("skMemoryPoolCreate");
        return -1;
    }
    rb_repo = rbinit(rws_repo_file_compare, NULL);
    if (NULL == rb_repo) {
        skAppPrintOutOfMemory("rbinit");
        return -1;
    }

    /* create initial file structure */
    repo_new_file = (rws_repo_file_t*)skMemPoolElementNew(mempool);

    /* walk the repository */
    rv = nftw(root_dir, rws_repo_scan_callback, RWS_MAX_FD_NFTW, 0);
    if (rv) {
        if (-1 == rv) {
            skAppPrintErr("Error while scanning repository '%s': %s",
                          root_dir, strerror(errno));
        } else {
            rv = -1;
        }
    }
    return rv;
}



/*
 *  rws_iter_bind(&iter, level);
 *
 *    Bind the sub-iterator of a site iterator at the given level.
 */
static void
rws_iter_bind(
    rws_iter_t         *iter,
    int                 level)
{
    assert(iter);
    assert(iter->level >= level);

    /* Negative level is for a non-iterable iterator.  This is used
     * for options that require no level iteration, like
     * --fields=class:list. */
    if (level >= 0) {
        switch (iter->order[level]) {
          case RWS_FLOWTYPE:
            sksiteFlowtypeIterator(&iter->flowtype_iter);
            iter->flowtype_id = SK_INVALID_FLOWTYPE;
            break;
          case RWS_CLASS:
            sksiteClassIterator(&iter->class_iter);
            iter->class_id = SK_INVALID_CLASS;
            break;
          case RWS_DEFAULT_CLASS:
            assert(level == 0);
            iter->class_id = SK_INVALID_CLASS;
            break;
          case RWS_SENSOR:
            sksiteSensorIterator(&iter->sensor_iter);
            iter->sensor_id = SK_INVALID_SENSOR;
            break;
          case RWS_GROUP:
            sksiteSensorgroupIterator(&iter->group_iter);
            iter->group_id = SK_INVALID_SENSORGROUP;
            break;
          case RWS_FLOWTYPE_FROM_CLASS:
            sksiteClassFlowtypeIterator(iter->class_id, &iter->flowtype_iter);
            iter->flowtype_id = SK_INVALID_FLOWTYPE;
            break;
          case RWS_CLASS_FROM_SENSOR:
            sksiteSensorClassIterator(iter->sensor_id, &iter->class_iter);
            iter->class_id = SK_INVALID_CLASS;
            break;
          case RWS_SENSOR_FROM_CLASS:
            sksiteClassSensorIterator(iter->class_id, &iter->sensor_iter);
            iter->sensor_id = SK_INVALID_SENSOR;
            break;
          case RWS_DEFAULT_FLOWTYPE_FROM_CLASS:
            sksiteClassDefaultFlowtypeIterator(
                iter->class_id, &iter->flowtype_iter);
            iter->flowtype_id = SK_INVALID_FLOWTYPE;
            iter->default_type = 1;
            break;
          case RWS_GROUP_FROM_SENSOR:
            sksiteSensorSensorgroupIterator(iter->sensor_id,
                                            &iter->group_iter);
            iter->group_id = SK_INVALID_SENSORGROUP;
            break;
          case RWS_SENSOR_FROM_GROUP:
            sksiteSensorgroupSensorIterator(iter->group_id,
                                            &iter->sensor_iter);
            iter->sensor_id = SK_INVALID_SENSOR;
            break;
          case RWS_NULL:
            skAbortBadCase(iter->order[level]);
            break;
        }
    }

    /* We are now bound at this level */
    iter->bound = level;

    /* But mark as not having stared iteration yet */
    iter->started = level - 1;

    /* Mark that we haven't emitted any data at this level yet */
    iter->emitted[level] = 0;
}


/*
 *  status = rws_iter_next(iter, level);
 *
 *    Site iterator iteration, at a particular sub-iterator level.
 *    Returns 1 on success, 0 if the iteration is complete at the
 *    given level.
 */
static int
rws_iter_next(
    rws_iter_t         *iter,
    const int           level)
{
    sk_sensor_iter_t s_iter;
    sk_sensor_id_t s_id;
    sk_class_id_t class_id;
    int done;
    int rv;

    assert(iter);
    assert(iter->level >= level);

    /* Prevent re-iteration after already having completed
     * iteration */
    if (iter->bound < level) {
        assert(level == 0);
        return 0;
    }
    if (level >= RWS_MAX_ITERATOR_COUNT) {
        skAbort();
    }

    do {
        /* Iterate at the next level if we've already started
         * iteration on this level */
        if (iter->started >= level && level < iter->level) {
            if (iter->bound == level) {
                rws_iter_bind(iter, level + 1);
            }
            rv = rws_iter_next(iter, level + 1);
            if (rv != 0) {
                /* Leaf iter succeeded */
                return 1;
            }
        }

        /* Iterate at the current level */
        switch (iter->order[level]) {
          case RWS_DEFAULT_CLASS:
            /* Pseudo-iterator for default class: toggle between the
             * default-class and SK_INVALID_CLASS */
            if (iter->class_id == SK_INVALID_CLASS) {
                iter->class_id = sksiteClassGetDefault();
            } else {
                iter->class_id = SK_INVALID_CLASS;
            }
            rv = (iter->class_id != SK_INVALID_CLASS);
            break;

          case RWS_FLOWTYPE:
          case RWS_FLOWTYPE_FROM_CLASS:
          case RWS_DEFAULT_FLOWTYPE_FROM_CLASS:
            /* Flowtype iteration */
            if (!iter->class_check_group) {
                while ((rv = sksiteFlowtypeIteratorNext(
                            &iter->flowtype_iter, &iter->flowtype_id))
                       && NULL != flowtype_mask
                       && !skBitmapGetBit(flowtype_mask, iter->flowtype_id))
                    ; /* empty */
            } else {
                /* This flowtype iteration must check whether the flowtype's
                 * class and the current iter->group_id share a sensor */
                done = 0;
                while (!done &&
                       (rv = sksiteFlowtypeIteratorNext(
                           &iter->flowtype_iter, &iter->flowtype_id)))
                {
                    if (NULL != flowtype_mask
                        && !skBitmapGetBit(flowtype_mask, iter->flowtype_id))
                    {
                        /* flowtype_mask is set and this flowtype is not in
                         * the set of flowtypes to print */
                        continue;
                    }
                    /* Visit sensors in the current flowtype's group (ignoring
                     * those sensors not in the sensor_mask) and see if the
                     * sensor is in this class */
                    class_id = sksiteFlowtypeGetClassID(iter->flowtype_id);
                    sksiteSensorgroupSensorIterator(iter->group_id, &s_iter);
                    while (sksiteSensorIteratorNext(&s_iter, &s_id)) {
                        if (NULL != sensor_mask
                            && !skBitmapGetBit(sensor_mask, s_id))
                        {
                            continue;
                        }
                        if (sksiteIsSensorInClass(s_id, class_id)) {
                            done = 1;
                            break;
                        }
                    }
                }
            }
            /* Set class from flowtype */
            if (rv) {
                iter->class_id = sksiteFlowtypeGetClassID(iter->flowtype_id);
            }
            break;

          case RWS_CLASS:
            if (iter->class_check_group) {
                /* This class iteration must check whether the class and the
                 * current iter->group_id share a sensor */
                done = 0;
                while (!done &&
                       (rv = sksiteClassIteratorNext(&iter->class_iter,
                                                     &iter->class_id)))
                {
                    if (NULL != class_mask
                        && !skBitmapGetBit(class_mask, iter->class_id))
                    {
                        /* A class_mask is set and the current class_id is not
                         * in the mask */
                        continue;
                    }
                    /* Visit sensors in the current group (ignoring those
                     * sensors not in the sensor_mask) and see if the sensor
                     * is in this class */
                    sksiteSensorgroupSensorIterator(iter->group_id, &s_iter);
                    while (sksiteSensorIteratorNext(&s_iter, &s_id)) {
                        if (NULL != sensor_mask
                            && !skBitmapGetBit(sensor_mask, s_id))
                        {
                            continue;
                        }
                        if (sksiteIsSensorInClass(s_id, iter->class_id)) {
                            done = 1;
                            break;
                        }
                    }
                }
                break;
            }
            /* FALLTHROUGH */

          case RWS_CLASS_FROM_SENSOR:
            /* Class iteration */
            while ((rv = sksiteClassIteratorNext(&iter->class_iter,
                                                 &iter->class_id))
                   && class_mask != NULL
                   && !skBitmapGetBit(class_mask, iter->class_id))
                ; /* empty */
            break;

          case RWS_SENSOR:
          case RWS_SENSOR_FROM_CLASS:
          case RWS_SENSOR_FROM_GROUP:
            /* Sensor iteration */
            while ((rv = sksiteSensorIteratorNext(&iter->sensor_iter,
                                                  &iter->sensor_id))
                   && sensor_mask != NULL
                   && !skBitmapGetBit(sensor_mask, iter->sensor_id))
                ; /* empty */
            break;

          case RWS_GROUP:
            if (iter->group_check_class) {
                /* This group iteration must check whether the group and the
                 * current iter->class_id share a sensor */
                done = 0;
                while (!done &&
                       (rv = sksiteSensorgroupIteratorNext(&iter->group_iter,
                                                           &iter->group_id)))
                {
                    if (NULL != group_mask
                        && !skBitmapGetBit(group_mask, iter->group_id))
                    {
                        /* A group_mask is set and the current group_id is not
                         * in the mask */
                        continue;
                    }
                    /* Visit sensors in the this group (ignoring those sensors
                     * not in the sensor_mask) and see if the sensor is in the
                     * current class */
                    sksiteSensorgroupSensorIterator(iter->group_id, &s_iter);
                    while (sksiteSensorIteratorNext(&s_iter, &s_id)) {
                        if (NULL != sensor_mask
                            && !skBitmapGetBit(sensor_mask, s_id))
                        {
                            continue;
                        }
                        if (sksiteIsSensorInClass(s_id, iter->class_id)) {
                            done = 1;
                            break;
                        }
                    }
                }
                break;
            }
            /* FALLTHROUGH */

          case RWS_GROUP_FROM_SENSOR:
            /* Group iteration */
            while ((rv = sksiteSensorgroupIteratorNext(&iter->group_iter,
                                                       &iter->group_id))
                   && group_mask != NULL
                   && !skBitmapGetBit(group_mask, iter->group_id))
                ; /* empty */
            break;

          default:
            skAbortBadCase(iter->order[level]);
        }

        /* Mark that we've started iterating at the current level */
        if (iter->started < level) {
            iter->started = level;
        }

        /* If iteration failed, but we haven't emitted anything at
         * this level yet, pretend it succeeded this once. */
        if (rv && level >= iter->emit_level) {
            iter->emitted[level] = 1;
        } else if (!rv && level != 0
                   && !iter->emitted[level]
                   && iter->emitted[level - 1])
        {
            iter->emitted[level] = 1;
            rv = 1;
        }

        if (rv && level == iter->level) {
            /* return success at leaf */
            return 1;
        }

        /* Iterate until a leaf iteration succeeds, or we fail to
         * iterate at this level. */
    } while (rv);

    /* Iteration is over.  We are no longer bound at this level.  */
    iter->bound = level - 1;

    return 0;
}


SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
/*
 *  len = rws_print(fd, format, ...);
 *
 *    If the file handle 'fd' is NULL, compute the number of
 *    characters that WOULD be printed using the format string
 *    'format' and argument list and return that length.
 *
 *    Otherwise, print the format string and its argument list to the
 *    file pointer 'fd' and return the number of characters printed.
 */
static int
rws_print(
    FILE               *fd,
    const char         *format,
    ...)
{
    va_list args;
    int len;

    va_start(args, format);
    if (fd) {
        len = vfprintf(fd, format, args);
    } else {
        char buf;
        len = vsnprintf(&buf, 0, format, args);
    }
    va_end(args);
    return len;
}
SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP


/*
 *  len = rws_print_repo_field(fd, iter, field, width);
 *
 *    Print a 'width'-wide column containing the value for 'field'
 *    (where 'field' is a repository field) to the FILE pointer 'fd',
 *    where 'iter' is the current context.
 *
 *    This function prints using rws_print(), meaning if 'fd' is NULL
 *    no output is generated and the length of the output is computed.
 *
 *    Return the number of characters printed.
 */
static int
rws_print_repo_field(
    FILE               *fd,
    rws_iter_t         *iter,
    rws_field_t         field,
    int                 width)
{
    char timebuf[SKTIMESTAMP_STRLEN];
    RBLIST *rb_iter;
    const rws_repo_file_t *file;
    sktime_t startdate = INT64_MAX;
    sktime_t enddate = 0;
    uint64_t count = 0;

    rb_iter = rbopenlist(rb_repo);
    while ((file = (const rws_repo_file_t*)rbreadlist(rb_iter)) != NULL) {
        if (iter->class_id != SK_INVALID_CLASS
            && iter->class_id != file->rf_class)
        {
            /* no match on class */
            continue;
        }
        if (iter->flowtype_id != SK_INVALID_FLOWTYPE
            && iter->flowtype_id != file->rf_flowtype)
        {
            /* no match on flowtype */
            continue;
        }
        if (iter->sensor_id != SK_INVALID_SENSOR
            && iter->sensor_id != file->rf_sensor)
        {
            /* no match on sensor */
            continue;
        }
        switch (field) {
          case RWST_REPO_START_DATE:
            if (file->rf_mindate < startdate) {
                startdate = file->rf_mindate;
            }
            break;
          case RWST_REPO_END_DATE:
            if (file->rf_maxdate > enddate) {
                enddate = file->rf_maxdate;
            }
            break;
          case RWST_REPO_FILE_COUNT:
            count += file->rf_count;
            break;
          default:
            skAbortBadCase(field);
        }
    }
    rbcloselist(rb_iter);

    switch (field) {
      case RWST_REPO_START_DATE:
        if (INT64_MAX == startdate) {
            return 0;
        }
        sktimestamp_r(timebuf, startdate, time_flags);
        return rws_print(fd, "%s", timebuf);
      case RWST_REPO_END_DATE:
        if (0 == enddate) {
            return 0;
        }
        sktimestamp_r(timebuf, enddate, time_flags);
        return rws_print(fd, "%s", timebuf);
      case RWST_REPO_FILE_COUNT:
        if (0 != width) {
            return rws_print(fd, "%*" PRIu64, width, count);
        }
        return rws_print(fd, "%" PRIu64, count);
      default:
        skAbortBadCase(field);
    }
}


/*
 *  len = rws_print_field(fd, iter, field, width);
 *
 *    Print a 'width'-wide column containing the value for 'field' to
 *    the FILE pointer 'fd', where 'iter' is the current context.
 *
 *    This function prints using rws_print(), meaning if 'fd' is NULL
 *    no output is generated and the length of the output is computed.
 *
 *    Return the number of characters printed.
 */
static int
rws_print_field(
    FILE               *fd,
    rws_iter_t         *iter,
    rws_field_t         field,
    int                 width)
{
    /* buffer large enough to hold a single sensor name or flowtype
     * name */
    char buf[SK_MAX_STRLEN_SENSOR + SK_MAX_STRLEN_FLOWTYPE];
    const char *s;
    int rv = 0;

    switch (field) {
      case RWST_CLASS:
        if (iter->class_id != SK_INVALID_CLASS) {
            sksiteClassGetName(buf, sizeof(buf), iter->class_id);
            rv = rws_print(fd, "%*s", width, buf);
        }
        break;

      case RWST_DEFAULT_TYPE:
        if (!iter->default_type) {
            if (iter->class_id != SK_INVALID_CLASS
                && iter->flowtype_id != SK_INVALID_FLOWTYPE)
            {
                sk_flowtype_iter_t fi;
                sk_flowtype_id_t ft;

                /* See if this type is a default for this class */
                sksiteClassDefaultFlowtypeIterator(iter->class_id, &fi);
                while (sksiteFlowtypeIteratorNext(&fi, &ft)) {
                    if (iter->flowtype_id == ft) {
                        sksiteFlowtypeGetType(buf, sizeof(buf), ft);
                        rv = rws_print(fd, "%*s", width, buf);
                        break;
                    }
                }
            }
            break;
        }
        /* Fall through */
      case RWST_TYPE:
        if (iter->flowtype_id != SK_INVALID_FLOWTYPE) {
            sksiteFlowtypeGetType(buf, sizeof(buf), iter->flowtype_id);
            rv = rws_print(fd, "%*s", width, buf);
        }
        break;

      case RWST_FLOWTYPE:
        if (iter->flowtype_id != SK_INVALID_FLOWTYPE) {
            sksiteFlowtypeGetName(buf, sizeof(buf), iter->flowtype_id);
            rv = rws_print(fd, "%*s", width, buf);
        }
        break;

      case RWST_FLOWTYPE_ID:
        if (iter->flowtype_id != SK_INVALID_FLOWTYPE) {
            rv = rws_print(fd, "%*" PRIu8, width, iter->flowtype_id);
        }
        break;

      case RWST_SENSOR:
        if (iter->sensor_id != SK_INVALID_SENSOR) {
            sksiteSensorGetName(buf, sizeof(buf), iter->sensor_id);
            rv = rws_print(fd, "%*s", width, buf);
        }
        break;

      case RWST_SENSOR_ID:
        if (iter->sensor_id != SK_INVALID_SENSOR) {
            rv = rws_print(fd, "%*" PRIu16, width, iter->sensor_id);
        }
        break;

      case RWST_SENSOR_DESC:
        if (iter->sensor_id != SK_INVALID_SENSOR) {
            s = sksiteSensorGetDescription(iter->sensor_id);
            if (s != NULL) {
                rv = rws_print(fd, "%*s", width, s);
            }
        }
        break;

      case RWST_GROUP:
        if (iter->group_id != SK_INVALID_SENSORGROUP) {
            sksiteSensorgroupGetName(buf, sizeof(buf), iter->group_id);
            rv = rws_print(fd, "%*s", width, buf);
        }
        break;

      case RWST_DEFAULT_CLASS:
      case RWST_DEFAULT_CLASS_LIST:
        if (field == RWST_DEFAULT_CLASS_LIST
            || iter->class_id == sksiteClassGetDefault())
        {
            sk_class_id_t cid = sksiteClassGetDefault();
            if (cid != SK_INVALID_CLASS) {
                sksiteClassGetName(buf, sizeof(buf), cid);
                rv = rws_print(fd, "%*s", width, buf);
            }
        }
        break;

      case RWST_MARK_DEFAULTS:
        {
            char mark[3] = {' ', ' ', '\0'};
            int i = 0;
            if (iter->class_id != SK_INVALID_CLASS) {
                if (no_columns) {
                    memset(mark, 0, sizeof(mark));
                }
                if (iter->class_id == sksiteClassGetDefault())
                {
                    mark[0] = '+';
                    ++i;
                }
                if (iter->flowtype_id != SK_INVALID_FLOWTYPE) {
                    sk_flowtype_iter_t fi;
                    sk_flowtype_id_t ft;

                    /* See if this type is a default for this class */
                    sksiteClassDefaultFlowtypeIterator(iter->class_id, &fi);
                    while (sksiteFlowtypeIteratorNext(&fi, &ft)) {
                        if (iter->flowtype_id == ft) {
                            mark[no_columns ? i : 1] = '*';
                            ++i;
                            break;
                        }
                    }
                }
            }
            rv = rws_print(fd, "%*s", width, mark);
        }
        break;

      case RWST_CLASS_LIST:
        rv = rws_print_list_field(fd, iter, RWST_CLASS, width);
        break;
      case RWST_TYPE_LIST:
        rv = rws_print_list_field(fd, iter, RWST_TYPE, width);
        break;
      case RWST_FLOWTYPE_LIST:
        rv = rws_print_list_field(fd, iter, RWST_FLOWTYPE, width);
        break;
      case RWST_FLOWTYPE_ID_LIST:
        rv = rws_print_list_field(fd, iter, RWST_FLOWTYPE_ID, width);
        break;
      case RWST_SENSOR_LIST:
        rv = rws_print_list_field(fd, iter, RWST_SENSOR, width);
        break;
      case RWST_SENSOR_ID_LIST:
        rv = rws_print_list_field(fd, iter, RWST_SENSOR_ID, width);
        break;
      case RWST_GROUP_LIST:
        rv = rws_print_list_field(fd, iter, RWST_GROUP, width);
        break;
      case RWST_DEFAULT_TYPE_LIST:
        rv = rws_print_list_field(fd, iter, RWST_DEFAULT_TYPE, width);
        break;

      case RWST_REPO_START_DATE:
      case RWST_REPO_END_DATE:
      case RWST_REPO_FILE_COUNT:
        rv = rws_print_repo_field(fd, iter, field, width);
        break;

      case RWST_MAX_FIELD_COUNT:
        skAbortBadCase(field);
    }

    /* Fill in any missing spaces. */
    if (rv < width) {
        rws_print(fd, "%*s", width - rv, "");
    }

    return rv;
}


/*
 *  len = rws_print_list_field(fd, iter, field, width);
 *
 *    Print a 'width'-wide column containing the value for 'field'
 *    (where 'field' represents a "FIELD:list" field) to the FILE
 *    pointer 'fd', where 'iter' is the current context.
 *
 *    This function prints using rws_print(), meaning if 'fd' is NULL
 *    no output is generated and the length of the output is computed.
 *
 *    Return the number of characters printed.
 */
static int
rws_print_list_field(
    FILE               *fd,
    rws_iter_t         *iter,
    rws_field_t         field,
    int                 width)
{
    int total = 0;
    int len;
    rws_iter_t subiter;
    int first;

    /* Create a site iterator containing a single sub-iterator of the
     * correct type.  */
    memset(&subiter, 0, sizeof(subiter));
    switch (field) {
      case RWST_CLASS:
        if (iter->sensor_id == SK_INVALID_SENSOR) {
            subiter.order[0] = RWS_CLASS;
        } else {
            subiter.order[0] = RWS_CLASS_FROM_SENSOR;
        }
        subiter.sensor_id = iter->sensor_id;
        break;

      case RWST_TYPE:
      case RWST_FLOWTYPE:
      case RWST_FLOWTYPE_ID:
        if (iter->class_id == SK_INVALID_CLASS) {
            subiter.order[0] = RWS_FLOWTYPE;
        } else {
            subiter.order[0] = RWS_FLOWTYPE_FROM_CLASS;
        }
        subiter.class_id = iter->class_id;
        subiter.flowtype_id = iter->flowtype_id;
        break;

      case RWST_SENSOR:
      case RWST_SENSOR_ID:
        /* FIXME: Iteraction of group and class */
        if (iter->class_id == SK_INVALID_CLASS) {
            if (iter->group_id == SK_INVALID_SENSORGROUP) {
                subiter.order[0] = RWS_SENSOR;
            } else {
                subiter.order[0] = RWS_SENSOR_FROM_GROUP;
            }
        } else {
            subiter.order[0] = RWS_SENSOR_FROM_CLASS;
        }
        subiter.class_id = iter->class_id;
        subiter.group_id = iter->group_id;
        break;

      case RWST_GROUP:
        if (iter->sensor_id == SK_INVALID_SENSOR) {
            subiter.order[0] = RWS_GROUP;
        } else {
            subiter.order[0] = RWS_GROUP_FROM_SENSOR;
        }
        subiter.sensor_id = iter->sensor_id;
        break;

      case RWST_DEFAULT_TYPE:
        if (iter->class_id == SK_INVALID_CLASS) {
            return 0;
        }
        subiter.order[0] = RWS_DEFAULT_FLOWTYPE_FROM_CLASS;
        subiter.class_id = iter->class_id;
        break;

      default:
        skAbortBadCase(field);
    }
    rws_iter_bind(&subiter, 0);

    /* Call ourself with a NULL FILE* to determine the number of
     * printed characters in this field, and then print the padding */
    if (width != 0) {
        len = rws_print_list_field(NULL, iter, field, 0);
        if (len < width) {
            total += rws_print(fd, "%*s", width - len, "");
        }
    }

    /* Iterate over the fields, printing each */
    first = 1;
    while (rws_iter_next(&subiter, 0)) {
        if (first) {
            first = 0;
        } else {
            len = rws_print(fd, "%c", list_separator);
            total += len;
        }
        len = rws_print_field(fd, &subiter, field, 0);
        total += len;
    }

    return total;
}


/*
 *  rws_print_row(iter);
 *
 *    Print a single row from an iterator.
 */
static void
rws_print_row(
    rws_iter_t         *iter)
{
    size_t i;

    for (i = 0; i < num_fields; ++i) {
        if (i > 0) {
            fprintf(output.of_fp, "%c", column_separator);
        }
        rws_print_field(output.of_fp, iter, fields[i], col_width[fields[i]]);
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  rws_calcsize_row(iter);
 *
 *    Update column sizes based on a single row that would be printed
 *    from the given iterator.
 */
static void
rws_calcsize_row(
    rws_iter_t         *iter)
{
    size_t i;
    int len;

    for (i = 0; i < num_fields; ++i) {
        len = rws_print_field(NULL, iter, fields[i], 0);
        if (len > col_width[fields[i]]) {
            col_width[fields[i]] = len;
        }
    }
}


/*
 *  rws_print_titles();
 *
 *    Print the column headings unless --no-titles was specified.
 */
static void
rws_print_titles(
    void)
{
    size_t i;

    if (no_titles) {
        return;
    }

    for (i = 0; i < num_fields; ++i) {
        if (i > 0) {
            fprintf(output.of_fp, "%c", column_separator);
        }
        fprintf(output.of_fp, "%*s", col_width[fields[i]],
                (char *)field_map_entries[fields[i]].userdata);
    }
    fprintf(output.of_fp, "%s\n", final_delim);
}


/*
 *  status = rws_setup_iter_from_fields(iter);
 *
 *    Set up the iterator for iterating based on the field list.
 *
 *    Return 0 for normal iteration.  Return -1 for no output (other
 *    than titles).  Return 1 for outputting a single non-iterated
 *    entry (e.g., a foo:list).
 */
static int
rws_setup_iter_from_fields(
    rws_iter_t         *iter)
{
    size_t i;
    /* Next iterator level to initialize */
    int level = 0;
    /* Boolean: class iterator set? */
    int class_set = 0;
    /* Boolean: flowtype iterator set? */
    int flowtype_set = 0;
    /* Boolean: group iterator set? */
    int group_set = 0;
    /* Boolean: sensor iterator set? */
    int sensor_set = 0;
    /* Default-type iterator set at this level (0 == none, since
     * default-type cannot exist at level 0. */
    int default_type = 0;
    /* Boolean: could be a non-iterable singleton */
    int singleton = 0;

    memset(iter, 0, sizeof(*iter));
    iter->level = -1;

    for (i = 0; i < num_fields; ++i) {
        switch (fields[i]) {
          case RWST_CLASS:
          case RWST_DEFAULT_CLASS:
          case RWST_DEFAULT_TYPE_LIST:
            /* Need classes to generate default types */
            if (class_set || flowtype_set) {
                break;
            }
            if (group_set && !sensor_set) {
                iter->class_check_group = 1;
            }
            if (sensor_set) {
                iter->order[level] = RWS_CLASS_FROM_SENSOR;
            } else if (fields[i] == RWST_DEFAULT_CLASS) {
                iter->order[level] = RWS_DEFAULT_CLASS;
            } else {
                iter->order[level] = RWS_CLASS;
            }
            iter->level = level;
            ++level;
            class_set = 1;
            break;

          case RWST_TYPE:
          case RWST_FLOWTYPE:
          case RWST_FLOWTYPE_ID:
            if (flowtype_set) {
                break;
            }
            if (group_set && !sensor_set) {
                iter->class_check_group = 1;
            }
            if (sensor_set && !class_set) {
                /* add a class iterator based on the sensor to limit the
                 * flowtypes to those matching the sensor */
                iter->order[level] = RWS_CLASS_FROM_SENSOR;
                ++level;
                iter->level = level;
                class_set = 1;
            }
            if (default_type) {
                /* Replace default type, as flowtype and default type
                 * is nonsensical */
                iter->order[default_type] =
                    class_set ? RWS_FLOWTYPE_FROM_CLASS : RWS_FLOWTYPE;
                default_type = 0;
            } else {
                iter->order[level] =
                    class_set ? RWS_FLOWTYPE_FROM_CLASS : RWS_FLOWTYPE;
                iter->level = level;
                ++level;
            }
            flowtype_set = 1;
            break;

          case RWST_SENSOR:
          case RWST_SENSOR_ID:
          case RWST_SENSOR_DESC:
            if (sensor_set) {
                break;
            }
            if (class_set || flowtype_set) {
                iter->order[level] = RWS_SENSOR_FROM_CLASS;
            } else if (group_set) {
                iter->order[level] = RWS_SENSOR_FROM_GROUP;
            } else {
                iter->order[level] = RWS_SENSOR;
            }
            iter->level = level;
            ++level;
            sensor_set = 1;
            break;

          case RWST_GROUP:
            if (group_set) {
                break;
            }
            if (sensor_set) {
                iter->order[level] = RWS_GROUP_FROM_SENSOR;
            } else {
                if (class_set || flowtype_set) {
                    iter->group_check_class = 1;
                }
                iter->order[level] = RWS_GROUP;
            }
            iter->level = level;
            ++level;
            group_set = 1;
            break;

          case RWST_DEFAULT_TYPE:
            assert(!default_type);
            if (flowtype_set) {
                break;
            }
            if (!class_set) {
                /* Default-type needs a class iterator, so add one */
                iter->order[level] =
                    sensor_set ? RWS_CLASS_FROM_SENSOR : RWS_CLASS;
                if (level == 0) {
                    iter->emit_level = 1;
                }
                ++level;
                class_set = 1;
            }
            iter->order[level] = RWS_DEFAULT_FLOWTYPE_FROM_CLASS;
            iter->level = level;
            ++level;
            default_type = level;
            break;

          case RWST_CLASS_LIST:
          case RWST_TYPE_LIST:
          case RWST_FLOWTYPE_LIST:
          case RWST_FLOWTYPE_ID_LIST:
          case RWST_SENSOR_LIST:
          case RWST_SENSOR_ID_LIST:
          case RWST_GROUP_LIST:
          case RWST_DEFAULT_CLASS_LIST:
          case RWST_REPO_START_DATE:
          case RWST_REPO_END_DATE:
          case RWST_REPO_FILE_COUNT:
            /* These fields can generate null-iterators with a single
             * row of output. */
            singleton = 1;
            break;

          case RWST_MARK_DEFAULTS:
            break;

          case RWST_MAX_FIELD_COUNT:
          default:
            skAbortBadCase(fields[i]);
        }
    }

    /* Bind the iterator (at level -1 if this is a null-iterator) */
    iter->flowtype_id = SK_INVALID_FLOWTYPE;
    iter->class_id    = SK_INVALID_CLASS;
    iter->sensor_id   = SK_INVALID_SENSOR;
    iter->group_id    = SK_INVALID_SENSORGROUP;
    rws_iter_bind(iter, level ? 0 : -1);

    if (level != 0) {
        /* Return 0 if this is not a null iterator */
        return 0;
    }

    /* Return 1 if this is a singleton null-iterator.  -1 otherwise */
    return singleton ? 1 : -1;
}


int main(int argc, char **argv)
{
    rws_iter_t iter;
    rws_iter_t calciter;
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    /* Set up site iterator */
    rv = rws_setup_iter_from_fields(&iter);
    if (rv == -1) {
        /* Nothing to do */
        rws_print_titles();
        return EXIT_SUCCESS;
    }

    if (!no_columns) {
        /* Calculate column sizes by generating the output using a
         * fake printer function that notes the column widths but does
         * not print the output. */
        calciter = iter;
        if (rv == 1) {
            /* Null iterator case */
            rws_calcsize_row(&calciter);
        } else {
            while (rws_iter_next(&calciter, 0)) {
                rws_calcsize_row(&calciter);
            }
        }
    }

    /* Print titles */
    rws_print_titles();

    /* Print rows */
    if (rv == 1) {
        /* Null iterator case */
        rws_print_row(&iter);
    } else {
        while (rws_iter_next(&iter, 0)) {
            rws_print_row(&iter);
        }
    }

    return EXIT_SUCCESS;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
