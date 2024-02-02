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
**  rwstatssetup.c
**
**  Application setup for rwstats and rwuniq.  See rwstats.c and
**  rwuniq.c for the applications' descriptions.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwstatssetup.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/silkpython.h>
#include <silk/skcountry.h>
#include <silk/skplugin.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include "rwstats.h"


/* TYPEDEFS AND DEFINES */

/* file handle for --help usage message */
#define USAGE_FH stdout

/* where to write filenames if --print-file specified */
#define PRINT_FILENAMES_FH  stderr

/* suffix for distinct fields */
#define DISTINCT_SUFFIX  "-Distinct"

/* default bin size to use when the --bin-time switch is provided
 * without an argument */
#define DEFAULT_BIN_TIME    60

#define PARSE_KEY_ELAPSED   (1 << 0)
#define PARSE_KEY_STIME     (1 << 1)
#define PARSE_KEY_ETIME     (1 << 2)
#define PARSE_KEY_ALL_TIMES (PARSE_KEY_ELAPSED|PARSE_KEY_STIME|PARSE_KEY_ETIME)

/* a number greater than the number of options defined in the
 * appOptions[] array; used to define an array */
#define STATSUNIQ_NUM_OPTIONS  64

/*
 *  These macros extract part of a field-list buffer to get a value,
 *  and then set that value on 'rec' by calling 'func'
 */
#define KEY_TO_REC(type, func, rec, field_buffer, field_list, field)    \
    {                                                                   \
        type k2r_val;                                                   \
        skFieldListExtractFromBuffer(field_list, field_buffer,          \
                                     field, (uint8_t*)&k2r_val);        \
        func((rec), k2r_val);                                           \
    }

#define KEY_TO_REC_08(func, rec, field_buffer, field_list, field)       \
    KEY_TO_REC(uint8_t, func, rec, field_buffer, field_list, field)

#define KEY_TO_REC_16(func, rec, field_buffer, field_list, field)       \
    KEY_TO_REC(uint16_t, func, rec, field_buffer, field_list, field)

#define KEY_TO_REC_32(func, rec, field_buffer, field_list, field)       \
    KEY_TO_REC(uint32_t, func, rec, field_buffer, field_list, field)


/* type of field being defined */
typedef enum field_type_en {
    FIELD_TYPE_KEY, FIELD_TYPE_VALUE, FIELD_TYPE_DISTINCT
} field_type_t;

/* builtin_field_t is a struct to hold information about built-in
 * aggregate value fields */
struct builtin_field_st {
    /* the title of this field */
    const char         *bf_title;
    /* the text width of the field for columnar output */
    int                 bf_text_len;
    /* the id for this column */
    sk_fieldid_t        bf_id;
    /* which application this field is associated with */
    statsuniq_program_t bf_program;
    /* whether the field is a distinct value */
    unsigned            bf_is_distinct  :1;
    /* whether this column is used for --all-counts, 1==yes */
    unsigned            bf_all_counts   :1;
    /* description of this field */
    const char         *bf_description;
};
/* typedef struct builtin_field_st builtin_field_t;  // rwstats.h */

/* thresholds (limits) for which bins get displayed by rwuniq */
typedef struct uniq_limit_st {
    uint64_t            minimum;
    uint64_t            maximum;
} uniq_limit_t;

/* threshold values entered by --threshold switch before integrating
 * with the --values switch */
typedef struct threshold_value_st {
    uint64_t                minimum;
    uint64_t                maximum;
    sk_stringmap_entry_t   *sm_entry;
    field_type_t            field_type;
} threshold_value_t;


/* EXPORTED VARIABLES */

/* define global variables used by this file to avoid needing to
 * define them in both rwstats and rwuniq. */

sk_unique_t *uniq;
sk_sort_unique_t *ps_uniq;

sk_fieldlist_t *key_fields;
sk_fieldlist_t *value_fields;
sk_fieldlist_t *distinct_fields;

/* to convert the key fields (as an rwRec) to ascii */
rwAsciiStream_t *ascii_str;

/* the real output */
sk_fileptr_t output;

/* user limit for this stat: N if top N or bottom N, threshold, or
 * percentage */
rwstats_limit_t limit;

/* whether rwstats is computing a top-N or a bottom-N */
rwstats_direction_t direction = RWSTATS_DIR_TOP;

/* the final delimiter on each line; assume none */
char final_delim[] = {'\0', '\0'};

/* delimiter between output columns */
char delimiter = '|';

/* flags set by the user options */
app_flags_t app_flags;

/* number of records read */
uint64_t record_count = 0;

/* Summation of whatever value (bytes, packets, flows) we are using.
 * When counting flows, this will be equal to record_count. */
uint64_t value_total = 0;

/* CIDR block mask for src and dest ips.  If 0, use all bits;
 * otherwise, the IP address should be bitwised ANDed with this
 * value. */
uint32_t cidr_sip = 0;
uint32_t cidr_dip = 0;

int width[RWSTATS_COLUMN_WIDTH_COUNT] = {
    15, /* WIDTH_KEY:   key */
    20, /* WIDTH_VAL:   count */
    10, /* WIDTH_INTVL: interval maximum */
    10, /* WIDTH_PCT:   percentage value */
};

/* non-zero when --overall-stats or --detail-proto-stats is given */
int proto_stats = 0;


/* LOCAL VARIABLES */

/* Information about each potential "value" field the user can choose
 * to compute and display.  Ensure these appear in same order as in
 * the OPT_BYTES...OPT_DIP_DISTINCT values in appOptionsEnum. */
static builtin_field_t builtin_values[] = {
    /* title, text_len, id,
     * application, is_distinct, is_in_all_counts,
     * description */
    {"Bytes",          20, SK_FIELD_SUM_BYTES,
     STATSUNIQ_PROGRAM_BOTH,   0, 1,
     "Sum of bytes for all flows in the group"},
    {"Packets",        15, SK_FIELD_SUM_PACKETS,
     STATSUNIQ_PROGRAM_BOTH,   0, 1,
     "Sum of packets for all flows in the group"},
    {"Records",        10, SK_FIELD_RECORDS,
     STATSUNIQ_PROGRAM_BOTH,   0, 1,
     "Number of flow records in the group"},
    {"sTime-Earliest", 19, SK_FIELD_MIN_STARTTIME,
     STATSUNIQ_PROGRAM_UNIQ,   0, 1,
     "Minimum starting time for flows in the group"},
    {"eTime-Latest",   19, SK_FIELD_MAX_ENDTIME,
     STATSUNIQ_PROGRAM_UNIQ,   0, 1,
     "Maximum ending time for flows in the group"},
    {"sIP-Distinct",   10, SK_FIELD_SIPv4,
     STATSUNIQ_PROGRAM_BOTH,   1, 0,
     "Number of distinct source IPs in the group"},
    {"dIP-Distinct",   10, SK_FIELD_DIPv4,
     STATSUNIQ_PROGRAM_BOTH,   1, 0,
     "Number of distinct destination IPs in the group"},
    {"Distinct",       10, SK_FIELD_CALLER,
     STATSUNIQ_PROGRAM_BOTH,   1, 0,
     "You must append a colon and a key field to count the number of"
     " distinct values seen for that field in the group"}
};

static const size_t num_builtin_values = (sizeof(builtin_values)/
                                          sizeof(builtin_field_t));

/* create aliases for exisitng value fields.  the struct contains the
 * name of the alias and an ID to match in the builtin_values[]
 * array */
static const struct builtin_value_aliases_st {
    const char     *ba_name;
    sk_fieldid_t    ba_id;
} builtin_value_aliases[] = {
    {"Flows",   SK_FIELD_RECORDS},
    {NULL,      (sk_fieldid_t)0}
};

/* key fields used when parsing the user's --fields switch */
static sk_stringmap_t *key_field_map = NULL;

/* available aggregate value fields */
static sk_stringmap_t *value_field_map = NULL;

/* the text the user entered for the --fields switch */
static const char *fields_arg = NULL;

/* the text the user entered for the --values switch */
static const char *values_arg = NULL;

/* the limits for the value fields in rwuniq; when limits are active,
 * there must be a limit for each value field */
static sk_vector_t *value_limits = NULL;

/* similar to 'value_limits' for the distinct fields */
static sk_vector_t *distinct_limits = NULL;

/* the string arguments to --threshold that the user enters */
static sk_vector_t *threshold_vec = NULL;

/* input checker */
static sk_options_ctx_t *optctx = NULL;

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

/* plug-ins to attempt to load at startup */
static const char *app_plugin_names[] = {
    NULL /* sentinel */
};

/* name of program to run to page output */
static char *pager;

/* where to copy the input to */
static skstream_t *copy_input = NULL;

/* how to handle IPv6 flows */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;

/* temporary directory */
static const char *temp_directory = NULL;

/* how to print IP addresses */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);

/* how to print timestamps */
static uint32_t timestamp_format = 0;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags =
    (SK_OPTION_TIMESTAMP_NEVER_MSEC | SK_OPTION_TIMESTAMP_OPTION_EPOCH
     | SK_OPTION_TIMESTAMP_OPTION_LEGACY);

/* the floor of the sTime and/or eTime, as a number of milliseconds,
 * set by the --bin-time switch */
static sktime_t bin_time = 0;

/* whether the bin_time includes fractional seconds */
static int bin_time_uses_msec = 0;

/* which of elapsed, sTime, and eTime were requested. uses the
 * PARSE_KEY_* values from rwstats.h.  this value will be used to
 * initialize 'time_fields_key'. */
static unsigned int time_fields;

/* which of elapsed, sTime, and eTime are part of the key. uses the
 * PARSE_KEY_* values from rwuniq.h */
static unsigned int time_fields_key = 0;

/* whether dPort is part of the key */
static unsigned int dport_key = 0;

/* non-zero if we are shutting down due to a signal; controls whether
 * errors are printed in appTeardown(). */
static int caught_signal = 0;

/* did user ask for legacy help? */
static int legacy_help_requested = 0;


/* OPTIONS */

/* statsuniq_option_t holds a struct option, its help text, and a flag
 * to indicate whether the option is for rwstats, rwuniq, or both */
struct statsuniq_option_st {
    statsuniq_program_t use_opt;
    struct option       opt;
    const char         *help;
};
typedef struct statsuniq_option_st statsuniq_option_t;

typedef enum {
    OPT_LEGACY_HELP,
    OPT_HELP_FIELDS,
    OPT_FIELDS,
    OPT_VALUES,
    OPT_PLUGIN,
    /* keep these in same order as stat_stat_type_t */
    OPT_COUNT,
    OPT_THRESHOLD,
    OPT_PERCENTAGE,
    /* direction in rwstats */
    OPT_TOP,
    OPT_BOTTOM,
    /* miscellaneous */
    OPT_PRESORTED_INPUT,
    OPT_SORT_OUTPUT,
    OPT_NO_PERCENTS,
    OPT_BIN_TIME,
    OPT_INTEGER_SENSORS,
    OPT_INTEGER_TCP_FLAGS,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_PRINT_FILENAMES,
    OPT_COPY_INPUT,
    OPT_OUTPUT_PATH,
    OPT_PAGER,
    /* legacy values switches in rwuniq */
    OPT_ALL_COUNTS,
    /* OPT_BYTES...OPT_DIP_DISTINCT must be contiguous and appear in
     * same order as in builtin_values[] */
    OPT_BYTES,
    OPT_PACKETS,
    OPT_FLOWS,
    OPT_STIME,
    OPT_ETIME,
    OPT_SIP_DISTINCT,
    OPT_DIP_DISTINCT
} appOptionsEnum;

static statsuniq_option_t appOptions[] = {
    /* --fields and --values */
    {STATSUNIQ_PROGRAM_BOTH,
     {"help-fields",         NO_ARG,       0, OPT_HELP_FIELDS},
     "Describe each possible field and value and exit. Def. no"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
     ("Use these fields as the grouping key. Specify fields as a\n"
      "\tcomma-separated list of names, IDs, and/or ID-ranges")},
    {STATSUNIQ_PROGRAM_BOTH,
     {"values",              REQUIRED_ARG, 0, OPT_VALUES},
     ("Compute these values for each group. Def. records.\n"
      "\tSpecify values as a comma-separated list of names")},
    {STATSUNIQ_PROGRAM_BOTH,
     {"plugin",              REQUIRED_ARG, 0, OPT_PLUGIN},
     ("Load given plug-in to add fields and/or values. Switch may\n"
      "\tbe repeated to load multiple plug-ins. Def. None")},

    /* limit number of rows to print in rwstats */
    {STATSUNIQ_PROGRAM_STATS,
     {"count",               REQUIRED_ARG, 0, OPT_COUNT},
     ("Print the specified number of bins. Use --count=0 to print\n"
      "\tall bins. Range 0-18446744073709551614")},
    {STATSUNIQ_PROGRAM_BOTH,
     {"threshold",           REQUIRED_ARG, 0, OPT_THRESHOLD},
     /* help varies by program */
     NULL},
    {STATSUNIQ_PROGRAM_STATS,
     {"percentage",          REQUIRED_ARG, 0, OPT_PERCENTAGE},
     ("Print bins where the primary value is greater-/less-than\n"
      "\tthis percentage of the total across all flows. Only allowed when the\n"
      "\tprimary value is Bytes, Packets, Records, or Distinct:FIELD.\n"
      "\tRange 0.00-100.00")},

    /* direction in rwstats */
    {STATSUNIQ_PROGRAM_STATS,
     {"top",                 NO_ARG,       0, OPT_TOP},
     ("Print the top N keys and their values. Def. Yes")},
    {STATSUNIQ_PROGRAM_STATS,
     {"bottom",              NO_ARG,       0, OPT_BOTTOM},
     ("Print the bottom N keys and their values. Def. No")},

    {STATSUNIQ_PROGRAM_STATS,
     {"legacy-help",         NO_ARG,       0, OPT_LEGACY_HELP},
     "Print help, including legacy switches"},

    {STATSUNIQ_PROGRAM_BOTH,
     {"presorted-input",     NO_ARG,       0, OPT_PRESORTED_INPUT},
     ("Assume input has been presorted using\n"
      "\trwsort invoked with the exact same --fields value. Def. No")},

    {STATSUNIQ_PROGRAM_UNIQ,
     {"sort-output",         NO_ARG,       0, OPT_SORT_OUTPUT},
     ("Present the output sorted by key. Def. No")},
    {STATSUNIQ_PROGRAM_STATS,
     {"no-percents",         NO_ARG,       0, OPT_NO_PERCENTS},
     ("Do not print the percentage columns. Def. Print percents")},

    {STATSUNIQ_PROGRAM_BOTH,
     {"bin-time",            OPTIONAL_ARG, 0, OPT_BIN_TIME},
     ("When using 'sTime' or 'eTime' as a key, adjust time(s) to\n"
      "\tthe floor of time-bins of this size, in seconds. May be fractional;\n"
      "\tuse 0.001 for millisecond timestamps. Def. 1.  When switch is used\n"
      "\twithout an argument, use a bin size of ")},
    {STATSUNIQ_PROGRAM_BOTH,
     {"integer-sensors",     NO_ARG,       0, OPT_INTEGER_SENSORS},
     "Print sensor as an integer. Def. Sensor name"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"integer-tcp-flags",   NO_ARG,       0, OPT_INTEGER_TCP_FLAGS},
     "Print TCP Flags as an integer. Def. No"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"no-titles",           NO_ARG,       0, OPT_NO_TITLES},
     "Do not print column titles. Def. Print titles"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"no-columns",          NO_ARG,       0, OPT_NO_COLUMNS},
     "Disable fixed-width columnar output. Def. Columnar"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"column-separator",    REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
     "Use specified character between columns. Def. '|'"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"no-final-delimiter",  NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
     "Suppress column delimiter at end of line. Def. No"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"delimited",           OPTIONAL_ARG, 0, OPT_DELIMITED},
     "Shortcut for --no-columns --no-final-del --column-sep=CHAR"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"print-filenames",     NO_ARG,       0, OPT_PRINT_FILENAMES},
     "Print names of input files as they are opened. Def. No"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"copy-input",          REQUIRED_ARG, 0, OPT_COPY_INPUT},
     "Copy all input SiLK Flows to given pipe or file. Def. No"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
     "Write the output to this stream or file. Def. stdout"},
    {STATSUNIQ_PROGRAM_BOTH,
     {"pager",               REQUIRED_ARG, 0, OPT_PAGER},
     "Invoke this program to page output. Def. $SILK_PAGER or $PAGER"},


    /* legacy values switches in rwuniq; also do thresholds */
    {STATSUNIQ_PROGRAM_UNIQ,
     {"all-counts",          NO_ARG,       0, OPT_ALL_COUNTS},
     ("DEPRECATED. Alias for\n"
      "\t--values=Bytes,Packets,Records,sTime-Earliest,eTime-Latest")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"bytes",               OPTIONAL_ARG, 0, OPT_BYTES},
     ("DEPRECATED. With no argument, add Bytes to --values;\n"
      "\twith argument, alias for --threshold=Bytes=MIN-MAX")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"packets",             OPTIONAL_ARG, 0, OPT_PACKETS},
     ("DEPRECATED. With no argument, add Packets to --values;\n"
      "\twith argument, alias for --threshold=Packets=MIN-MAX")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"flows",               OPTIONAL_ARG, 0, OPT_FLOWS},
     ("DEPRECATED. With no argument, add Records to --values;\n"
      "\twith argument, alias for --threshold=Records=MIN-MAX")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"stime",               NO_ARG,       0, OPT_STIME},
     ("DEPRECATED. Add sTime-Earliest to --values")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"etime",               NO_ARG,       0, OPT_ETIME},
     ("DEPRECATED. Add eTime-Latest to --values")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"sip-distinct",        OPTIONAL_ARG, 0, OPT_SIP_DISTINCT},
     ("DEPRECATED. With no argument, add Distinct:sIP to\n"
      "\t--values; with argument, alias for --threshold=Distinct:sIP=MIN-MAX")},
    {STATSUNIQ_PROGRAM_UNIQ,
     {"dip-distinct",        OPTIONAL_ARG, 0, OPT_DIP_DISTINCT},
     ("DEPRECATED. With no argument, add Distinct:dIP to\n"
      "\t--values; with argument, alias for --threshold=Distinct:dIP=MIN-MAX")},

    {STATSUNIQ_PROGRAM_BOTH,
     {0,0,0,0},              /* sentinel entry */
     NULL}
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void appHandleSignal(int sig);
static const char *appOptionName(int opt_index);

static void helpFields(FILE *fh);

static int  createStringmaps(void);
static int  parseKeyFields(const char *field_string);
static int  parseValueFieldsAndThresholds(const char *field_string);
static int
parseThreshold(
    char               *threshold_str,
    threshold_value_t  *threshold_value);
static int
appAddPlugin(
    skplugin_field_t   *pi_field,
    field_type_t        field_type);
static int
isFieldDuplicate(
    const sk_fieldlist_t   *flist,
    sk_fieldid_t            fid,
    const void             *fcontext);
static int  prepareFileForRead(skstream_t *stream);


/* FUNCTION DEFINITIONS */

/*
 *  statsAppUsageLong();
 *
 *    Print complete usage information to USAGE_FH.  Pass this
 *    function to skOptionsSetUsageCallback(); skOptionsParse() will
 *    call this funciton and then exit the program when the --help
 *    option is given.
 */
static void
statsAppUsageLong(
    void)
{
    FILE *fh = USAGE_FH;
    unsigned int i;

    /* use two macros to avoid CPP limit in c89 */
#define USAGE_MSG_STATS                                                       \
    ("<SWITCHES> [FILES]\n"                                                   \
     "\tSummarize SiLK Flow records by the specified field(s) into bins.\n"   \
     "\tFor each bin, compute the specified value(s), then display the\n"     \
     "\tresults as a Top-N or Bottom-N list based on the primary value.\n"    \
     "\tThe N may be a fixed value; some values allow the N to be a\n"        \
     "\tthreshold value or to be based on a percentage of the input.\n")
#define USAGE_MSG_STATS_2                                                     \
    ("\tAlternatively, provide statistics for each of bytes, packets, and\n"  \
     "\tbytes-per-packet giving minima, maxima, quartile, and interval\n"     \
     "\tflow-counts across all flows or across user-specified protocols.\n"   \
     "\tWhen no files are given on command line, flows are read from STDIN.\n")
#define THRESHOLD_HELP_STATS                                            \
    ("Print bins where the primary value is greater-/less-than\n"       \
     "\tthis threshold. Not allowed when the primary value field is\n"  \
     "\tdefined in a plug-in. Range 0-18446744073709551614\n")

    /* Create the string maps for --fields and --values */
    createStringmaps();

    fprintf(fh, "%s %s%s", skAppName(), USAGE_MSG_STATS, USAGE_MSG_STATS_2);
    protoStatsOptionsUsage(fh);

    for (i = 0; appOptions[i].opt.name; ++i) {
        if (0 == (this_program & appOptions[i].use_opt)) {
            continue;
        }
        switch ((appOptionsEnum)appOptions[i].opt.val) {
          case OPT_HELP_FIELDS:
            fprintf(fh, "\nTOP-N/BOTTOM-N SWITCHES:\n");
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
          case OPT_FIELDS:
            /* Dynamically build the help */
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            skStringMapPrintUsage(key_field_map, fh, 4);
            break;
          case OPT_VALUES:
            fprintf(fh, ("--%s %s. %s.\n\tThe first value will be used as"
                         " the basis for the Top-N/Bottom-N\n"),
                    appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            skStringMapPrintUsage(value_field_map, fh, 4);
            break;
          case OPT_COUNT:
            fprintf(fh, ("\nHow to determine the N for Top-/Bottom-N;"
                         " must specify one:\n"));
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
          case OPT_THRESHOLD:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt),THRESHOLD_HELP_STATS);
            break;
          case OPT_TOP:
            fprintf(fh, ("\nWhether to compute Top- or Bottom-N;"
                         " may specify one (top is default):\n"));
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
          case OPT_LEGACY_HELP:
            fprintf(fh, "\nMISCELLANEOUS SWITCHES:\n");
            skOptionsDefaultUsage(fh);
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
          case OPT_BIN_TIME:
            fprintf(fh, "--%s %s. %s%d.000 seconds\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help,
                    DEFAULT_BIN_TIME);
            skOptionsTimestampFormatUsage(fh);
            skOptionsIPFormatUsage(fh);
            break;
          default:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    skOptionsTempDirUsage(fh);
    sksiteOptionsUsage(fh);
    skPluginOptionsUsage(fh);
    if (legacy_help_requested) {
        legacyOptionsUsage(fh);
    }
}

static void
uniqAppUsageLong(
    void)
{
    FILE *fh = USAGE_FH;
    unsigned int i;

#define USAGE_MSG_UNIQ                                                        \
    ("--fields=N [SWITCHES] [FILES]\n"                                        \
     "\tSummarize SiLK Flow records into user-defined keyed bins specified\n" \
     "\twith the --fields switch.  For each keyed bin, print byte, packet,\n" \
     "\tand/or flow counts and/or the time window when key was active.\n"     \
     "\tWhen no files are given on command line, flows are read from STDIN.\n")
#define THRESHOLD_HELP_UNIQ                                                 \
    ("Given an argument of VALUE_FIELD=MIN-MAX, add VALUE_FIELD\n"          \
     "\tto --values and limit output to rows where its value is between\n"  \
     "\tMIN and MAX inclusive; MAX is optional and unlimited if not given")

    /* Create the string maps for --fields and --values */
    createStringmaps();

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG_UNIQ);

    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].opt.name; ++i) {
        if (0 == (this_program & appOptions[i].use_opt)) {
            continue;
        }
        switch ((appOptionsEnum)appOptions[i].opt.val) {
          case OPT_FIELDS:
            /* Dynamically build the help */
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            skStringMapPrintUsage(key_field_map, fh, 4);
            break;
          case OPT_VALUES:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            skStringMapPrintUsage(value_field_map, fh, 4);
            break;
          case OPT_THRESHOLD:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), THRESHOLD_HELP_UNIQ);
            break;
          case OPT_BIN_TIME:
            fprintf(fh, "--%s %s. %s%d.000\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help,
                    DEFAULT_BIN_TIME);
            skOptionsTimestampFormatUsage(fh);
            skOptionsIPFormatUsage(fh);
            break;
          case OPT_ALL_COUNTS:
          case OPT_BYTES:
          case OPT_PACKETS:
          case OPT_FLOWS:
          case OPT_STIME:
          case OPT_ETIME:
          case OPT_SIP_DISTINCT:
          case OPT_DIP_DISTINCT:
            /* ignore these here; print them below */
            break;
          default:
            /* Simple help text from the appHelp array */
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    skOptionsTempDirUsage(fh);
    sksiteOptionsUsage(fh);
    skPluginOptionsUsage(fh);

    for (i = 0; appOptions[i].opt.name; ++i) {
        switch ((appOptionsEnum)appOptions[i].opt.val) {
          case OPT_ALL_COUNTS:
          case OPT_BYTES:
          case OPT_PACKETS:
          case OPT_FLOWS:
          case OPT_STIME:
          case OPT_ETIME:
          case OPT_SIP_DISTINCT:
          case OPT_DIP_DISTINCT:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].opt.name,
                    SK_OPTION_HAS_ARG(appOptions[i].opt), appOptions[i].help);
            break;
          default:
            break;
        }
    }
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
    struct option app_options[STATSUNIQ_NUM_OPTIONS];
    unsigned int optctx_flags;
    rwstats_legacy_t leg;
    unsigned int i;
    unsigned int app_options_count;
    char *path;
    int rv;
    int j;

    assert(STATSUNIQ_PROGRAM_STATS == this_program
           || STATSUNIQ_PROGRAM_UNIQ == this_program);

    /* verify enough space to create an array of options */
    assert((sizeof(appOptions)/sizeof(appOptions[0])) < STATSUNIQ_NUM_OPTIONS);

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    if (STATSUNIQ_PROGRAM_STATS == this_program) {
        skOptionsSetUsageCallback(&statsAppUsageLong);
    } else {
        skOptionsSetUsageCallback(&uniqAppUsageLong);
    }

    /* initialize globals */
    memset(&app_flags, 0, sizeof(app_flags));
    memset(&output, 0, sizeof(output));
    output.of_fp = stdout;
    memset(&leg, 0, sizeof(rwstats_legacy_t));
    limit.type = RWSTATS_ALL;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS);

    /* create an array of struct option for this application */
    app_options_count = 0;
    memset(app_options, 0, sizeof(app_options));
    for (i = 0; appOptions[i].opt.name; ++i) {
        if (this_program & appOptions[i].use_opt) {
            assert(app_options_count < STATSUNIQ_NUM_OPTIONS);
            app_options[app_options_count] = appOptions[i].opt;
            ++app_options_count;
        }
    }

    /* initialize plugin library */
    if (STATSUNIQ_PROGRAM_STATS == this_program) {
        skPluginSetup(2, SKPLUGIN_APP_STATS_FIELD, SKPLUGIN_APP_STATS_VALUE);
    } else {
        skPluginSetup(2, SKPLUGIN_APP_UNIQ_FIELD, SKPLUGIN_APP_UNIQ_VALUE);
    }

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(app_options, &appOptionsHandler, NULL)
        || skOptionsTempDirRegister(&temp_directory)
        || skOptionsTimestampFormatRegister(
            &timestamp_format, time_register_flags)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags)
        || skIPv6PolicyOptionsRegister(&ipv6_policy)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        appExit(EXIT_FAILURE);
    }

    if (STATSUNIQ_PROGRAM_STATS == this_program) {
        if (protoStatsOptionsRegister() || legacyOptionsSetup(&leg)) {
            skAppPrintErr("Unable to register options");
            appExit(EXIT_FAILURE);
        }
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

    /* create threshold_vec to hold --threshold arguments */
    threshold_vec = skVectorNew(sizeof(char *));
    if (NULL == threshold_vec) {
        skAppPrintOutOfMemory("create vector");
        appExit(EXIT_FAILURE);
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

    /* make certain stdout is not being used for multiple outputs */
    if (copy_input
        && ((0 == strcmp(skStreamGetPathname(copy_input), "-"))
            || (0 == strcmp(skStreamGetPathname(copy_input), "stdout"))))
    {
        if ((NULL == output.of_name)
            || (0 == strcmp(output.of_name, "-"))
            || (0 == strcmp(output.of_name, "stdout")))
        {
            skAppPrintErr("May not use stdout for multiple output streams");
            exit(EXIT_FAILURE);
        }
    }

    /* set final delimeter */
    if (!app_flags.no_final_delimiter) {
        final_delim[0] = delimiter;
    }
    /* set width */
    if (app_flags.no_columns) {
        memset(width, 0, RWSTATS_COLUMN_WIDTH_COUNT * sizeof(width[0]));
    }

    /* jump to the near the end of this function when the requested
     * output is for protocol statistics */
    if (proto_stats) {
        goto OPEN_OUTPUT;
    }

    /* create the ascii stream and set its properties */
    if (rwAsciiStreamCreate(&ascii_str)) {
        skAppPrintErr("Unable to create ascii stream");
        appExit(EXIT_FAILURE);
    }
    rwAsciiSetDelimiter(ascii_str, delimiter);
    rwAsciiSetIPv6Policy(ascii_str, ipv6_policy);
    rwAsciiSetIPFormatFlags(ascii_str, ip_format);
    /* set time format after parsing --fields */
    if (app_flags.no_percents || STATSUNIQ_PROGRAM_UNIQ == this_program) {
        if (app_flags.no_final_delimiter) {
            rwAsciiSetNoFinalDelimiter(ascii_str);
        }
    } else {
        /* rwstats will be printing additional columns */
        assert(STATSUNIQ_PROGRAM_STATS == this_program);
        rwAsciiSetNoNewline(ascii_str);
        rwAsciiSetNoFinalDelimiter(ascii_str);
    }
    if (app_flags.no_titles) {
        rwAsciiSetNoTitles(ascii_str);
    }
    if (app_flags.no_columns) {
        rwAsciiSetNoColumns(ascii_str);
    }
    if (app_flags.integer_sensors) {
        rwAsciiSetIntegerSensors(ascii_str);
    }
    if (app_flags.integer_tcp_flags) {
        rwAsciiSetIntegerTcpFlags(ascii_str);
    }

    /* verify that we have an N for our top-N */
    if (!limit.seen && STATSUNIQ_PROGRAM_STATS == this_program) {
        /* remove this block if we want printing all bins to be the
         * default behavior of rwstats */
        skAppPrintErr(("No stopping condition was entered.\n"
                       "\tChoose one of --%s, --%s, or --%s"),
                      appOptionName(OPT_COUNT),
                      appOptionName(OPT_THRESHOLD),
                      appOptionName(OPT_PERCENTAGE));
        skAppUsage();
    }

    /* set up the key_field_map and value_field_map */
    if (createStringmaps()) {
        appExit(EXIT_FAILURE);
    }

    /* make sure the user specified the --fields switch */
    if (leg.fields) {
        if (fields_arg) {
            skAppPrintErr("Cannot use --%s and old style switches",
                          appOptionName(OPT_FIELDS));
            skAppUsage();
        }
        fields_arg = leg.fields;
    } else if (fields_arg == NULL || fields_arg[0] == '\0') {
        skAppPrintErr("The --%s switch is required",
                      appOptionName(OPT_FIELDS));
        skAppUsage();         /* never returns */
    }

    /* check for legacy values from rwstats */
    if (leg.values) {
        if (values_arg != NULL) {
            skAppPrintErr("Cannot use --%s and old style switches",
                          appOptionName(OPT_VALUES));
            skAppUsage();
        }
        values_arg = leg.values;
    }

    /* parse the --fields and --values switches */
    if (parseKeyFields(fields_arg)) {
        appExit(EXIT_FAILURE);
    }
    if (parseValueFieldsAndThresholds(values_arg)) {
        appExit(EXIT_FAILURE);
    }

    /* set time format on the ascii stream */
    if (bin_time_uses_msec) {
        /* remove the no-msec flag */
        timestamp_format &= ~SKTIMESTAMP_NOMSEC;
    }
    rwAsciiSetTimestampFlags(ascii_str, timestamp_format);

    /* create and initialize the uniq object */
    if (app_flags.presorted_input) {
        /* cannot use the --percentage limit when using
         * --presorted-input */
        if (RWSTATS_PERCENTAGE == limit.type) {
            skAppPrintErr(("The --%s limit is not supported"
                           " when --%s is active"),
                          appOptionName(OPT_PERCENTAGE),
                          appOptionName(OPT_PRESORTED_INPUT));
            appExit(EXIT_FAILURE);
        }

        if (skPresortedUniqueCreate(&ps_uniq)) {
            appExit(EXIT_FAILURE);
        }

        skPresortedUniqueSetTempDirectory(ps_uniq, temp_directory);

        if (skPresortedUniqueSetFields(ps_uniq, key_fields, distinct_fields,
                                       value_fields))
        {
            skAppPrintErr("Unable to set fields");
            appExit(EXIT_FAILURE);
        }
        if (limit.distinct) {
            if (skPresortedUniqueEnableTotalDistinct(ps_uniq)) {
                skAppPrintErr("Unable to set fields");
                appExit(EXIT_FAILURE);
            }
        }

        while ((rv = skOptionsCtxNextArgument(optctx, &path)) == 0) {
            skPresortedUniqueAddInputFile(ps_uniq, path);
        }
        if (rv < 0) {
            appExit(EXIT_FAILURE);
        }

        skPresortedUniqueSetPostOpenFn(ps_uniq, prepareFileForRead);
        if (bin_time > 1 || STATSUNIQ_PROGRAM_STATS == this_program) {
            skPresortedUniqueSetReadFn(ps_uniq, readRecord);
        }

    } else {
        if (skUniqueCreate(&uniq)) {
            appExit(EXIT_FAILURE);
        }
        if (app_flags.sort_output) {
            skUniqueSetSortedOutput(uniq);
        }

        skUniqueSetTempDirectory(uniq, temp_directory);

        rv = skUniqueSetFields(uniq, key_fields, distinct_fields, value_fields);
        if (0 == rv && limit.distinct) {
            rv = skUniqueEnableTotalDistinct(uniq);
        }
        if (0 == rv) {
            rv = skUniquePrepareForInput(uniq);
        }
        if (rv) {
            skAppPrintErr("Unable to set fields");
            appExit(EXIT_FAILURE);
        }
    }

  OPEN_OUTPUT:
    /* open the --output-path.  the 'of_name' member is NULL if user
     * didn't get an output-path. */
    if (output.of_name) {
        rv = skFileptrOpen(&output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Unable to open %s '%s': %s",
                          appOptionName(OPT_OUTPUT_PATH),
                          output.of_name, skFileptrStrerror(rv));
            appExit(EXIT_FAILURE);
        }
    }

    /* open the --copy-input destination */
    if (copy_input) {
        rv = skStreamOpen(copy_input);
        if (rv) {
            skStreamPrintLastErr(copy_input, rv, &skAppPrintErr);
            appExit(EXIT_FAILURE);
        }
    }

    /* set signal handler to clean up temp files on SIGINT, SIGTERM, etc */
    if (skAppSetSignalHandler(&appHandleSignal)) {
        appExit(EXIT_FAILURE);
    }

    return;                       /* OK */
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
    size_t i;
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    skUniqueDestroy(&uniq);
    skPresortedUniqueDestroy(&ps_uniq);

    /* destroy field lists */
    skFieldListDestroy(&key_fields);
    skFieldListDestroy(&distinct_fields);
    skFieldListDestroy(&value_fields);

    skVectorDestroy(value_limits);
    skVectorDestroy(distinct_limits);
    i = (NULL == threshold_vec) ? 0 : skVectorGetCount(threshold_vec);
    while (i) {
        char *str;
        --i;
        skVectorGetValue(&str, threshold_vec, i);
        if (str) { free(str); }
    }
    skVectorDestroy(threshold_vec);

    /* plugin teardown */
    skPluginRunCleanup(SKPLUGIN_FN_ANY);
    skPluginTeardown();

    /* destroy output */
    rwAsciiStreamDestroy(&ascii_str);

    /* close output */
    if (output.of_name) {
        skFileptrClose(&output, &skAppPrintErr);
    }
    /* close the --copy-input */
    if (copy_input) {
        rv = skStreamClose(copy_input);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(copy_input, rv, &skAppPrintErr);
        }
        skStreamDestroy(&copy_input);
    }

    /* destroy string maps for keys and values */
    if (key_field_map) {
        skStringMapDestroy(key_field_map);
        key_field_map = NULL;
    }
    if (value_field_map) {
        skStringMapDestroy(value_field_map);
        value_field_map = NULL;
    }

    skOptionsCtxDestroy(&optctx);
    skAppUnregister();
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
    static int saw_direction = 0;
    const builtin_field_t *bf;
    char buf[4096];
    char *cp;
    size_t i;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_FIELDS:
        if (fields_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptionName(opt_index));
            return 1;
        }
        fields_arg = opt_arg;
        break;

      case OPT_VALUES:
        if (values_arg) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptionName(opt_index));
            return 1;
        }
        values_arg = opt_arg;
        break;

      case OPT_TOP:
      case OPT_BOTTOM:
        if (saw_direction) {
            skAppPrintErr("May only specify one of --%s or --%s.",
                          appOptionName(OPT_TOP),
                          appOptionName(OPT_BOTTOM));
            return 1;
        }
        saw_direction = 1;
        if (OPT_TOP == opt_index) {
            direction = RWSTATS_DIR_TOP;
        } else {
            direction = RWSTATS_DIR_BOTTOM;
        }
        break;

      case OPT_THRESHOLD:
        if (STATSUNIQ_PROGRAM_UNIQ == this_program) {
            /* handle --threshold for rwuniq */
            cp = strdup(opt_arg);
            if (!cp || skVectorAppendValue(threshold_vec, &cp)) {
                free(cp);
                return 1;
            }
            break;
        }
        /* else handle --threshold for rwstats */
        /* FALLTHROUGH */
      case OPT_COUNT:
      case OPT_PERCENTAGE:
        if (limit.seen != 0) {
            skAppPrintErr("May only specify one of --%s, --%s, or --%s.",
                          appOptionName(OPT_COUNT),
                          appOptionName(OPT_THRESHOLD),
                          appOptionName(OPT_PERCENTAGE));
            return 1;
        }
        limit.type = ((rwstats_limit_type_t)
                      (RWSTATS_COUNT + (opt_index - OPT_COUNT)));
        if (OPT_PERCENTAGE == opt_index) {
            rv = skStringParseDouble(&limit.value[limit.type].d, opt_arg,
                                     0.0, 100.0);
        } else {
            rv = skStringParseUint64(&limit.value[limit.type].u64, opt_arg,
                                     0, 0);
        }
        if (rv) {
            goto PARSE_ERROR;
        }
        if (OPT_COUNT == opt_index && 0 == limit.value[limit.type].u64) {
            limit.type = RWSTATS_ALL;
        }
        limit.seen = 1;
        break;

      case OPT_ALL_COUNTS:
        for (i = 0, bf = builtin_values; i < num_builtin_values; ++i, ++bf) {
            if (bf->bf_all_counts) {
                snprintf(buf, sizeof(buf), "%s=0-0", bf->bf_title);
                cp = strdup(buf);
                if (!cp || skVectorAppendValue(threshold_vec, &cp)) {
                    free(cp);
                    return 1;
                }
            }
        }
        break;

      case OPT_STIME:
      case OPT_ETIME:
        snprintf(buf, sizeof(buf), "%s=0-0", appOptionName(opt_index));
        cp = strdup(buf);
        if (!cp || skVectorAppendValue(threshold_vec, &cp)) {
            free(cp);
            return 1;
        }
        break;

      case OPT_BYTES:
      case OPT_PACKETS:
      case OPT_FLOWS:
      case OPT_SIP_DISTINCT:
      case OPT_DIP_DISTINCT:
        if (NULL == opt_arg) {
            snprintf(buf, sizeof(buf), "%s=0-0", appOptionName(opt_index));
        } else {
            snprintf(buf, sizeof(buf), "%s=%s",
                     appOptionName(opt_index), opt_arg);
        }
        cp = strdup(buf);
        if (!cp || skVectorAppendValue(threshold_vec, &cp)) {
            free(cp);
            return 1;
        }
        break;

      case OPT_PLUGIN:
        if (skPluginLoadPlugin(opt_arg, 1) != 0) {
            skAppPrintErr("Unable to load %s as a plugin", opt_arg);
            return 1;
        }
        break;

      case OPT_BIN_TIME:
        if (opt_arg == NULL || opt_arg[0] == '\0') {
            /* no time given; use default */
            bin_time = sktimeCreate(DEFAULT_BIN_TIME, 0);
        } else {
            /* parse user's time */
            double d;
            rv = skStringParseDouble(&d, opt_arg, 0.001, INT32_MAX);
            if (rv) {
                goto PARSE_ERROR;
            }
            bin_time = (sktime_t)(1000.0 * d);
            if (bin_time && 0 != (bin_time % 1000)) {
                bin_time_uses_msec = 1;
            }
        }
        break;

      case OPT_PRESORTED_INPUT:
        app_flags.presorted_input = 1;
        break;

      case OPT_NO_PERCENTS:
        app_flags.no_percents = 1;
        break;

      case OPT_SORT_OUTPUT:
        app_flags.sort_output = 1;
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
        delimiter = opt_arg[0];
        break;

      case OPT_DELIMITED:
        app_flags.no_columns = 1;
        app_flags.no_final_delimiter = 1;
        if (opt_arg) {
            delimiter = opt_arg[0];
        }
        break;

      case OPT_PRINT_FILENAMES:
        app_flags.print_filenames = 1;
        break;

      case OPT_COPY_INPUT:
        if (copy_input) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptionName(opt_index));
            return 1;
        }
        if ((rv=skStreamCreate(&copy_input, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(copy_input, opt_arg)))
        {
            skStreamPrintLastErr(copy_input, rv, &skAppPrintErr);
            return 1;
        }
        break;

      case OPT_OUTPUT_PATH:
        if (output.of_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptionName(opt_index));
            return 1;
        }
        output.of_name = opt_arg;
        break;

      case OPT_PAGER:
        pager = opt_arg;
        break;

      case OPT_LEGACY_HELP:
        legacy_help_requested = 1;
        statsAppUsageLong();
        exit(EXIT_SUCCESS);
    }

    return 0;                     /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptionName(opt_index), opt_arg,
                  skStringParseStrerror(rv));
    return 1;
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
 *    Return the name of the option whose index is 'opt_index'.
 */
static const char *
appOptionName(
    int                 opt_index)
{
    unsigned int i;

    assert(opt_index >= 0);

    for (i = 0; appOptions[i].opt.name; ++i) {
        if (appOptions[i].opt.val == opt_index) {
            return appOptions[i].opt.name;
        }
    }
    skAppPrintErr("Bad option index %d", opt_index);
    skAbort();
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
        skAppPrintErr("Error while creating field lists.");
        appExit(EXIT_FAILURE);
    }

    fprintf(fh,
            ("The following names may be used in the --%s switch. Names are\n"
             "case-insensitive and may be abbreviated to the shortest"
             " unique prefix.\n"),
            appOptionName(OPT_FIELDS));
    skStringMapPrintDetailedUsage(key_field_map, fh);

    fprintf(fh,
            ("\n"
             "The following names may be used in the --%s switch. Names are\n"
             "case-insensitive and may be abbreviated to the shortest"
             " unique prefix.\n"),
            appOptionName(OPT_VALUES));
    skStringMapPrintDetailedUsage(value_field_map, fh);
}


/*
 *  builtin_value_get_title(buf, bufsize, field_entry);
 *
 *    Invoked by rwAsciiPrintTitles() to get the title for an
 *    aggregate value field represented by an sk_fieldid_t.
 *
 *    Fill 'buf' with the title for the column represented by the
 *    field list entry 'field_entry'.  This function should write no
 *    more than 'bufsize' characters to 'buf'.
 */
static void
builtin_value_get_title(
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    builtin_field_t *bf;

    bf = (builtin_field_t*)skFieldListEntryGetContext(fl_entry);
    strncpy(text_buf, bf->bf_title, text_buf_size - 1);
    text_buf[text_buf_size - 1] = '\0';
}

/*
 *  value_to_ascii(rwrec, buf, bufsize, field_entry, extra);
 *
 *    Invoked by rwAsciiPrintRecExtra() to get the value for an
 *    aggregate value field.  This function is called for built-in
 *    aggregate values as well as plug-in defined values.
 *
 *    Fill 'buf' with the value for the column represented by the
 *    aggregate value field list entry 'field_entry'.  'rwrec' is
 *    ignored; 'extra' is an array[3] that contains the buffers for
 *    the key, aggregate value, and distinct field-lists.  This
 *    function should write no more than 'bufsize' characters to
 *    'buf'.
 */
static int
value_to_ascii(
    const rwRec UNUSED(*rwrec),
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry,
    void               *v_outbuf)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    uint64_t val64;
    uint32_t val32;
    double d;
    uint8_t bin_buf[HASHLIB_MAX_VALUE_WIDTH];

    switch (skFieldListEntryGetId(fl_entry)) {
      case SK_FIELD_RECORDS:
      case SK_FIELD_SUM_BYTES:
      case SK_FIELD_SUM_PACKETS:
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, (uint8_t*)&val64);
        snprintf(text_buf, text_buf_size, ("%" PRIu64), val64);
        break;

      case SK_FIELD_SUM_ELAPSED:
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, (uint8_t*)&val32);
        snprintf(text_buf, text_buf_size, ("%" PRIu32), val32);
        break;

      case SK_FIELD_SUM_ELAPSED_MSEC:
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, (uint8_t*)&val64);
        d = (double)val64 / 1000;
        snprintf(text_buf, text_buf_size, ("%.3f"), d);
        break;

      case SK_FIELD_MIN_STARTTIME:
      case SK_FIELD_MAX_ENDTIME:
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, (uint8_t*)&val32);
        assert(text_buf_size > SKTIMESTAMP_STRLEN);
        sktimestamp_r(text_buf, sktimeCreate(val32, 0), timestamp_format);
        break;

      case SK_FIELD_MIN_STARTTIME_MSEC:
      case SK_FIELD_MAX_ENDTIME_MSEC:
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, (uint8_t*)&val64);
        assert(text_buf_size > SKTIMESTAMP_STRLEN);
        sktimestamp_r(text_buf, (sktime_t)val64, timestamp_format);
        break;

      case SK_FIELD_CALLER:
        /* get the binary value from the field-list */
        skFieldListExtractFromBuffer(value_fields, ((uint8_t**)v_outbuf)[1],
                                     fl_entry, bin_buf);
        /* call the plug-in to convert from binary to text */
        skPluginFieldRunBinToTextFn(
            (skplugin_field_t*)skFieldListEntryGetContext(fl_entry),
            text_buf, text_buf_size, bin_buf);
        break;

      default:
        skAbortBadCase(skFieldListEntryGetId(fl_entry));
    }

    return 0;
}

/*
 *  builtin_distinct_get_title(buf, bufsize, field_entry);
 *
 *    Invoked by rwAsciiPrintTitles() to get the title for a distinct
 *    field represented by an sk_fieldid_t.
 *
 *    Fill 'buf' with the title for the column represented by the
 *    field list entry 'field_entry'.  This function should write no
 *    more than 'bufsize' characters to 'buf'.
 */
static void
builtin_distinct_get_title(
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    int id;
    size_t sz;

    id = skFieldListEntryGetId(fl_entry);
    switch (id) {
      case SK_FIELD_SIPv4:
      case SK_FIELD_SIPv6:
        rwAsciiGetFieldName(text_buf, text_buf_size, RWREC_FIELD_SIP);
        break;
      case SK_FIELD_DIPv4:
      case SK_FIELD_DIPv6:
        rwAsciiGetFieldName(text_buf, text_buf_size, RWREC_FIELD_DIP);
        break;
      case SK_FIELD_NHIPv4:
      case SK_FIELD_NHIPv6:
        rwAsciiGetFieldName(text_buf, text_buf_size, RWREC_FIELD_NHIP);
        break;
      default:
        rwAsciiGetFieldName(text_buf, text_buf_size,
                            (rwrec_printable_fields_t)id);
        break;
    }
    sz = strlen(text_buf);
    if (sz < text_buf_size) {
        strncpy(text_buf+sz, DISTINCT_SUFFIX, text_buf_size-sz);
    }
    text_buf[text_buf_size-1] = '\0';
}

/*
 *  distinct_to_ascii(rwrec, buf, bufsize, field_entry, extra);
 *
 *    Invoked by rwAsciiPrintRecExtra() to get the value for a
 *    distinct field.  This function is called for built-in distinct
 *    fields as well as those from a plug-in.
 *
 *    Fill 'buf' with the value for the column represented by the
 *    distinct field list entry 'field_entry'.  'rwrec' is ignored;
 *    'extra' is an array[3] that contains the buffers for the key,
 *    aggregate value, and distinct field-lists.  This function should
 *    write no more than 'bufsize' characters to 'buf'.
 */
static int
distinct_to_ascii(
    const rwRec UNUSED(*rwrec),
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry,
    void               *v_outbuf)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    size_t len;
    union value_un {
        uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
        uint64_t  u64;
        uint32_t  u32;
        uint16_t  u16;
        uint8_t   u8;
    } value;

    len = skFieldListEntryGetBinOctets(fl_entry);
    switch (len) {
      case 1:
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, &value.u8);
        snprintf(text_buf, text_buf_size, ("%" PRIu8), value.u8);
        break;
      case 2:
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, (uint8_t*)&value.u16);
        snprintf(text_buf, text_buf_size, ("%" PRIu16), value.u16);
        break;
      case 4:
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, (uint8_t*)&value.u32);
        snprintf(text_buf, text_buf_size, ("%" PRIu32), value.u32);
        break;
      case 8:
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, (uint8_t*)&value.u64);
        snprintf(text_buf, text_buf_size, ("%" PRIu64), value.u64);
        break;

      case 3:
        value.u64 = 0;
#if SK_BIG_ENDIAN
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, &value.ar[8 - len]);
#else
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, &value.ar[0]);
#endif  /* #else of #if SK_BIG_ENDIAN */
        snprintf(text_buf, text_buf_size, ("%" PRIu64), value.u64);
        break;

      case 5:
      case 6:
      case 7:
        value.u64 = 0;
#if SK_BIG_ENDIAN
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, &value.ar[8 - len]);
#else
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, &value.ar[0]);
#endif  /* #else of #if SK_BIG_ENDIAN */
        snprintf(text_buf, text_buf_size, ("%" PRIu64), value.u64);
        break;

      default:
        skFieldListExtractFromBuffer(distinct_fields, ((uint8_t**)v_outbuf)[2],
                                     fl_entry, value.ar);
        snprintf(text_buf, text_buf_size, ("%" PRIu64), value.u64);
        break;
    }

    return 0;
}

/*
 *    Return the width required for a distinct count of a field entry.
 */
static uint32_t
distinct_get_width(
    const sk_fieldentry_t  *fl_entry)
{
    size_t len;

    len = skFieldListEntryGetBinOctets(fl_entry);
    switch (len) {
      case 1:
        return 3;
      case 2:
        return 5;
      case 3:
      case 4:
        return 10;
    }
    return 20;
}

/*
 *  plugin_get_title(buf, buf_size, field_entry);
 *
 *    Invoked by rwAsciiPrintTitles() to get the title for a key or
 *    aggregate value field defined by a plug-in.
 *
 *    Fill 'buf' with the title for the column represented by the
 *    plug-in associated with 'field_entry'.  This function should
 *    write no more than 'bufsize' characters to 'buf'.
 */
static void
plugin_get_title(
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    const char *title;

    skPluginFieldTitle(
        (skplugin_field_t*)skFieldListEntryGetContext(fl_entry), &title);
    strncpy(text_buf, title, text_buf_size - 1);
    text_buf[text_buf_size - 1] = '\0';
}

/*
 *  plugin_distinct_get_title(buf, bufsize, field_entry);
 *
 *    Invoked by rwAsciiPrintTitles() to get the title for a distinct
 *    field.
 *
 *    Fill 'buf' with the title for the column represented by a
 *    distinct count over the plug-in associated with 'field_entry'.
 *    This function should write no more than 'bufsize' characters to
 *    'buf'.
 */
static void
plugin_distinct_get_title(
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    const char *title;

    skPluginFieldTitle(
        (skplugin_field_t*)skFieldListEntryGetContext(fl_entry), &title);
    snprintf(text_buf, text_buf_size, ("%s" DISTINCT_SUFFIX), title);
}

/*
 *  plugin_key_to_ascii(rwrec, buf, bufsize, keyfield, extra);
 *
 *    Invoked by rwAsciiPrintRecExtra() to get the value for a key
 *    field that is defined by a plug-in.
 *
 *    Fill 'buf' with a textual representation of the key for the
 *    column represented by the plug-in associated with 'field_entry'.
 *    'rwrec' is ignored; 'extra' is an array[3] that contains the
 *    buffers for the key, aggregate value, and distinct field-lists.
 *    This function should write no more than 'bufsize' characters to
 *    'buf'.
 */
static int
plugin_key_to_ascii(
    const rwRec UNUSED(*rwrec),
    char               *text_buf,
    size_t              text_buf_size,
    void               *v_fl_entry,
    void               *v_outbuf)
{
    sk_fieldentry_t *fl_entry = (sk_fieldentry_t*)v_fl_entry;
    uint8_t bin_buf[HASHLIB_MAX_KEY_WIDTH];

    /* get the binary value from the field-list */
    skFieldListExtractFromBuffer(key_fields, ((uint8_t**)v_outbuf)[0],
                                 fl_entry, bin_buf);

    /* call the plug-in to convert from binary to text */
    skPluginFieldRunBinToTextFn(
        (skplugin_field_t*)skFieldListEntryGetContext(fl_entry),
        text_buf, text_buf_size, bin_buf);

    return 0;
}

/*
 *  plugin_rec_to_bin(rwrec, out_buf, plugin_field);
 *
 *    Invoked by skFieldListRecToBinary() to get the binary value,
 *    based on the given 'rwrec', for a key field that is defined by a
 *    plug-in.
 *
 *    The size of 'out_buf' was specified when the field was added to
 *    the field-list.
 */
static void
plugin_rec_to_bin(
    const rwRec        *rwrec,
    uint8_t            *out_buf,
    void               *v_pi_field)
{
    skPluginFieldRunRecToBinFn((skplugin_field_t*)v_pi_field,
                               out_buf, rwrec, NULL);
}

/*
 *  plugin_add_rec_to_bin(rwrec, in_out_buf, plugin_field);
 *
 *    Invoked by skFieldListAddRecToBinary() to get the binary value,
 *    based on the given 'rwrec' and merge that with the current
 *    binary value for a key field that is defined by a plug-in.
 *
 *    The size of 'out_buf' was specified when the field was added to
 *    the field-list.
 */
static void
plugin_add_rec_to_bin(
    const rwRec        *rwrec,
    uint8_t            *in_out_buf,
    void               *v_pi_field)
{
    skPluginFieldRunAddRecToBinFn((skplugin_field_t*)v_pi_field,
                                  in_out_buf, rwrec, NULL);
}

/*
 *  plugin_bin_compare(buf1, buf2, plugin_field);
 *
 *    Invoked by skFieldListCompareBuffers() to compare current value
 *    of the key or aggregate value fields specified by 'buf1' and
 *    'buf2'.
 *
 *    The size of 'buf1' and 'buf2' were specified when the field was
 *    added to the field-list.
 */
static int
plugin_bin_compare(
    const uint8_t      *buf1,
    const uint8_t      *buf2,
    void               *v_pi_field)
{
    int val = 0;
    skPluginFieldRunBinCompareFn((skplugin_field_t*)v_pi_field,
                                 &val, buf1, buf2);
    return val;
}

/*
 *  plugin_bin_merge(in_out_buf, in_buf, plugin_field);
 *
 *    Invoked by skFieldListMergeBuffers() to merge the current values
 *    of the key or aggregate value fields specified by 'in_out_buf'
 *    and 'in_buf'.  The merged value should be placed into
 *    'in_out_buf'.
 *
 *    The size of 'in_out_buf' and 'in_buf' were specified when the
 *    field was added to the field-list.
 */
static void
plugin_bin_merge(
    uint8_t            *in_out_buf,
    const uint8_t      *in_buf,
    void               *v_pi_field)
{
    skPluginFieldRunBinMergeFn((skplugin_field_t*)v_pi_field,
                               in_out_buf, in_buf);
}


/*
 *  ok = createStringmaps();
 *
 *    Create the string-maps to assist in parsing the --fields and
 *    --values switches.
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
    size_t                 i;
    size_t                 j;

    /* initialize string-map of field identifiers: add default fields,
     * then remove millisec fields, since unique-ing over them makes
     * little sense.
     *
     * Note that although we remove the MSEC fields from the available
     * fields here, the remainder of the code still supports MSEC
     * fields---which are mapped onto the non-MSEC versions of the
     * fields. */
    if (rwAsciiFieldMapAddDefaultFields(&key_field_map)) {
        skAppPrintErr("Unable to setup fields stringmap");
        return -1;
    }
    (void)skStringMapRemoveByID(key_field_map, RWREC_FIELD_STIME_MSEC);
    (void)skStringMapRemoveByID(key_field_map, RWREC_FIELD_ETIME_MSEC);
    (void)skStringMapRemoveByID(key_field_map, RWREC_FIELD_ELAPSED_MSEC);
    max_id = RWREC_PRINTABLE_FIELD_COUNT - 1;

    /* add "icmpTypeCode" field */
    ++max_id;
    if (rwAsciiFieldMapAddIcmpTypeCode(key_field_map, max_id)) {
        skAppPrintErr("Unable to add icmpTypeCode");
        return -1;
    }

    /* add --fields from the plug-ins */
    if (STATSUNIQ_PROGRAM_STATS == this_program) {
        pi_err = (skPluginFieldIteratorBind(
                      &pi_iter, SKPLUGIN_APP_STATS_FIELD, 1));
    } else {
        pi_err = (skPluginFieldIteratorBind(
                      &pi_iter, SKPLUGIN_APP_UNIQ_FIELD, 1));
    }

    if (pi_err != SKPLUGIN_OK) {
        assert(pi_err == SKPLUGIN_OK);
        skAppPrintErr("Unable to bind plugin field iterator");
        return -1;
    }

    while (skPluginFieldIteratorNext(&pi_iter, &pi_field)) {
        skPluginFieldName(pi_field, &field_names);
        ++max_id;

        /* Add keys to the key_field_map */
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

    max_id = 0;

    /* create the string-map for value field identifiers */
    if (skStringMapCreate(&value_field_map)) {
        skAppPrintErr("Unable to create map for values");
        return -1;
    }

    /* add the built-in names */
    for (i = 0; i < num_builtin_values; ++i) {
        if (this_program & builtin_values[i].bf_program) {
            memset(&sm_entry, 0, sizeof(sk_stringmap_entry_t));
            sm_entry.name = builtin_values[i].bf_title;
            sm_entry.id = i;
            sm_entry.description = builtin_values[i].bf_description;
            sm_err = skStringMapAddEntries(value_field_map, 1, &sm_entry);
            if (sm_err) {
                skAppPrintErr("Unable to add value field named '%s': %s",
                              sm_entry.name, skStringMapStrerror(sm_err));
                return -1;
            }
            if (sm_entry.id > max_id) {
                max_id = sm_entry.id;
            }
        }
    }

    /* add aliases for built-in fields */
    for (j = 0; builtin_value_aliases[j].ba_name; ++j) {
        for (i = 0; i < num_builtin_values; ++i) {
            if (builtin_value_aliases[j].ba_id == builtin_values[i].bf_id) {
                if (this_program & builtin_values[i].bf_program) {
                    memset(&sm_entry, 0, sizeof(sk_stringmap_entry_t));
                    sm_entry.name = builtin_value_aliases[j].ba_name;
                    sm_entry.id = i;
                    sm_err = skStringMapAddEntries(value_field_map, 1,
                                                   &sm_entry);
                    if (sm_err) {
                        skAppPrintErr(
                            "Unable to add value field named '%s': %s",
                            sm_entry.name, skStringMapStrerror(sm_err));
                        return -1;
                    }
                }
                break;
            }
        }
        if (i == num_builtin_values) {
            skAppPrintErr("No field found with id %d",
                          builtin_value_aliases[j].ba_id);
            return -1;
        }
    }

    /* add the value fields from the plugins */
    if (STATSUNIQ_PROGRAM_STATS == this_program) {
        pi_err = (skPluginFieldIteratorBind(
                      &pi_iter, SKPLUGIN_APP_STATS_VALUE, 1));
    } else {
        pi_err = (skPluginFieldIteratorBind(
                      &pi_iter, SKPLUGIN_APP_UNIQ_VALUE, 1));
    }
    assert(pi_err == SKPLUGIN_OK);

    while (skPluginFieldIteratorNext(&pi_iter, &pi_field)) {
        skPluginFieldName(pi_field, &field_names);
        ++max_id;

        /* Add value names to the field_map */
        for (name = field_names; *name; ++name) {
            memset(&sm_entry, 0, sizeof(sm_entry));
            sm_entry.name = *name;
            sm_entry.id = max_id;
            sm_entry.userdata = pi_field;
            skPluginFieldDescription(pi_field, &sm_entry.description);
            sm_err = skStringMapAddEntries(value_field_map, 1, &sm_entry);
            if (sm_err != SKSTRINGMAP_OK) {
                const char *plugin_name;
                skPluginFieldGetPluginName(pi_field, &plugin_name);
                skAppPrintErr(("Plug-in cannot add value named '%s': %s."
                               " Plug-in file: %s"),
                              *name, skStringMapStrerror(sm_err),plugin_name);
                return -1;
            }
        }
    }

    return 0;
}


/*
 *  status = parseKeyFields(field_string);
 *
 *    Parse the string that represents the key fields the user wishes
 *    to bin by, create and fill in the global sk_fieldlist_t
 *    'key_fields', and add columns to the rwAsciiStream.  Return 0 on
 *    success or non-zero on error.
 */
static int
parseKeyFields(
    const char         *field_string)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry = NULL;
    sk_fieldentry_t *fl_entry;
    int field_id;

    /* keep track of which time field we see last; uses the
     * RWREC_FIELD_* values from rwascii.h */
    rwrec_printable_fields_t final_time_field = (rwrec_printable_fields_t)0;

    /* keep track of which ICMP field(s) we see */
    int have_icmp_type_code = 0;

    /* return value; assume failure */
    int rv = -1;

    /* error message generated when parsing fields */
    char *errmsg;

    /* parse the --fields argument */
    if (skStringMapParse(key_field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &sm_iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptionName(OPT_FIELDS), errmsg);
        goto END;
    }

    /* create the field-list */
    if (skFieldListCreate(&key_fields)) {
        skAppPrintErr("Unable to create key field list");
        goto END;
    }

    /* see which time fields and ICMP fields are requested */
    while (skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK) {
        switch (sm_entry->id) {
          case RWREC_FIELD_DPORT:
            dport_key = 1;
            break;
          case RWREC_FIELD_STIME:
            time_fields |= PARSE_KEY_STIME;
            final_time_field = (rwrec_printable_fields_t)sm_entry->id;
            break;
          case RWREC_FIELD_ELAPSED:
            time_fields |= PARSE_KEY_ELAPSED;
            final_time_field = (rwrec_printable_fields_t)sm_entry->id;
            break;
          case RWREC_FIELD_ETIME:
            time_fields |= PARSE_KEY_ETIME;
            final_time_field = (rwrec_printable_fields_t)sm_entry->id;
            break;
          case RWREC_FIELD_ICMP_TYPE:
          case RWREC_FIELD_ICMP_CODE:
            have_icmp_type_code |= 1;
            break;
          case RWREC_PRINTABLE_FIELD_COUNT:
            have_icmp_type_code |= 2;
            break;
          case RWREC_FIELD_STIME_MSEC:
          case RWREC_FIELD_ELAPSED_MSEC:
          case RWREC_FIELD_ETIME_MSEC:
            skAbortBadCase(sm_entry->id);
          default:
            break;
        }
    }

    /* set 'time_fields_key' to the time fields that will be in the
     * key.  since only two of the three time fields are independent,
     * when all three are requested only the first two fields are put
     * into the key. */
    time_fields_key = time_fields;
    if (PARSE_KEY_ALL_TIMES == time_fields_key) {
        switch (final_time_field) {
          case RWREC_FIELD_STIME:
            time_fields_key &= ~PARSE_KEY_STIME;
            break;
          case RWREC_FIELD_ELAPSED:
            time_fields_key &= ~PARSE_KEY_ELAPSED;
            break;
          case RWREC_FIELD_ETIME:
            time_fields_key &= ~PARSE_KEY_ETIME;
            break;
          default:
            skAbortBadCase(final_time_field);
        }
    }

    /* when binning by time was requested, see if time fields make sense */
    if (bin_time > 1) {
        switch (time_fields) {
          case 0:
          case PARSE_KEY_ELAPSED:
            bin_time = (bin_time_uses_msec) ? 1 : 0;
            break;
          case PARSE_KEY_ALL_TIMES:
            /* must adjust elapsed to be eTime-sTime */
            if (FILEIsATty(stderr)) {
                skAppPrintErr("Warning: Modifying duration field "
                              "to be difference of eTime and sTime");
            }
            break;
        }
    }

    /* warn when using --presorted-input and multiple time fields are
     * present or when the time field is not the final field */
    if (app_flags.presorted_input && bin_time > 1 && FILEIsATty(stderr)) {
        switch (time_fields) {
          case 0:
            /* no time fields present */
            break;
          case PARSE_KEY_ELAPSED:
          case PARSE_KEY_STIME:
          case PARSE_KEY_ETIME:
            /* one field is present.  see if it is last.  note that
             * 'sm_entry' is still pointed at the final entry */
            switch (sm_entry->id) {
              case RWREC_FIELD_STIME:
              case RWREC_FIELD_ELAPSED:
              case RWREC_FIELD_ETIME:
                /* one field is present and it is last */
                break;
              default:
                /* one field is present but it is not last */
                skAppPrintErr(("Warning: Suggest putting '%s' last in --%s"
                               " when using --%s due to millisecond"
                               " truncation"),
                              ((PARSE_KEY_ELAPSED == time_fields)
                               ? "elapsed"
                               : ((PARSE_KEY_STIME == time_fields)
                                  ? "sTime"
                                  : "eTime")),
                              appOptionName(OPT_FIELDS),
                              appOptionName(OPT_PRESORTED_INPUT));
                break;
            }
            break;
          default:
            /* multiple time fields present */
            skAppPrintErr(("Warning: Using multiple time-related key"
                           " fields with\n\t--%s may lead to unexpected"
                           " results due to millisecond truncation"),
                          appOptionName(OPT_PRESORTED_INPUT));
            break;
        }
    }

    /* handle legacy icmpTypeCode field */
    if (3 == have_icmp_type_code) {
        skAppPrintErr("Invalid %s: May not mix field %s with %s or %s",
                      appOptionName(OPT_FIELDS),
                      skStringMapGetFirstName(
                          key_field_map, RWREC_PRINTABLE_FIELD_COUNT),
                      skStringMapGetFirstName(
                          key_field_map, RWREC_FIELD_ICMP_TYPE),
                      skStringMapGetFirstName(
                          key_field_map, RWREC_FIELD_ICMP_CODE));
        goto END;
    }

    skStringMapIterReset(sm_iter);

    /* add the key fields to the field-list and to the ascii stream. */
    while (skStringMapIterNext(sm_iter, &sm_entry, NULL) == SK_ITERATOR_OK) {
        if (sm_entry->userdata) {
            assert(sm_entry->id > RWREC_PRINTABLE_FIELD_COUNT);
            if (appAddPlugin((skplugin_field_t*)(sm_entry->userdata),
                             FIELD_TYPE_KEY))
            {
                skAppPrintErr("Error adding key field '%s' from plugin",
                              sm_entry->name);
                goto END;
            }
            continue;
        }
        if (sm_entry->id == RWREC_PRINTABLE_FIELD_COUNT) {
            /* handle the icmpTypeCode field */
            rwrec_printable_fields_t icmp_fields[] = {
                RWREC_FIELD_ICMP_TYPE, RWREC_FIELD_ICMP_CODE
            };
            char name_buf[128];
            size_t k;

            for (k = 0; k < sizeof(icmp_fields)/sizeof(icmp_fields[0]); ++k) {
                if (rwAsciiAppendOneField(ascii_str, icmp_fields[k])
                    || !skFieldListAddKnownField(key_fields, icmp_fields[k],
                                                 NULL))
                {
                    rwAsciiGetFieldName(name_buf, sizeof(name_buf),
                                        icmp_fields[k]);
                    skAppPrintErr("Error adding key field '%s' to stream",
                                  name_buf);
                    goto END;
                }
            }
            continue;
        }
        /* else handle a standard key field */
        assert(sm_entry->id < RWREC_PRINTABLE_FIELD_COUNT);
        if (rwAsciiAppendOneField(ascii_str, sm_entry->id)) {
            skAppPrintErr("Error adding key field '%s' to stream",
                          sm_entry->name);
            goto END;
        }
        if (PARSE_KEY_ALL_TIMES == time_fields
            && (rwrec_printable_fields_t)sm_entry->id == final_time_field)
        {
            /* when all time fields were requested, do not include
             * the final one that was seen as part of the key */
            continue;
        }
        switch ((rwrec_printable_fields_t)sm_entry->id) {
          case RWREC_FIELD_SIP:
#if SK_ENABLE_IPV6
            if (ipv6_policy >= SK_IPV6POLICY_MIX) {
                field_id = SK_FIELD_SIPv6;
            } else
#endif
            {
                field_id = SK_FIELD_SIPv4;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
            if (ipv6_policy >= SK_IPV6POLICY_MIX) {
                field_id = SK_FIELD_DIPv6;
            } else
#endif
            {
                field_id = SK_FIELD_DIPv4;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          case RWREC_FIELD_NHIP:
#if SK_ENABLE_IPV6
            if (ipv6_policy >= SK_IPV6POLICY_MIX) {
                field_id = SK_FIELD_NHIPv6;
            } else
#endif
            {
                field_id = SK_FIELD_NHIPv4;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          case RWREC_FIELD_STIME:
            if (bin_time_uses_msec) {
                field_id = RWREC_FIELD_STIME_MSEC;
            } else {
                field_id = RWREC_FIELD_STIME;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          case RWREC_FIELD_ELAPSED:
            if (bin_time_uses_msec) {
                field_id = RWREC_FIELD_ELAPSED_MSEC;
            } else {
                field_id = RWREC_FIELD_ELAPSED;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          case RWREC_FIELD_ETIME:
            if (bin_time_uses_msec) {
                field_id = RWREC_FIELD_ETIME_MSEC;
            } else {
                field_id = RWREC_FIELD_ETIME;
            }
            fl_entry = skFieldListAddKnownField(key_fields, field_id, NULL);
            break;
          default:
            fl_entry = skFieldListAddKnownField(key_fields, sm_entry->id,NULL);
            break;
        }
        if (NULL == fl_entry) {
            skAppPrintErr("Error adding key field '%s' to field list",
                          sm_entry->name);
            goto END;
        }
    }

    /* successful */
    rv = 0;

  END:
    if (rv != 0) {
        /* something went wrong.  clean up */
        if (key_fields) {
            skFieldListDestroy(&key_fields);
            key_fields = NULL;
        }
    }
    /* do standard clean-up */
    if (sm_iter != NULL) {
        skStringMapIterDestroy(sm_iter);
    }

    return rv;
}


/*
 *    Parse the argument to the --values switch contained in
 *    'value_string' and store its corresponding string-map entry in
 *    the vector 'value_vec', which is a vector of threshold_value_t
 *    structures.  Return 0 on success and -1 on error.
 */
static int
parseValueFields(
    const char         *value_string,
    sk_vector_t        *value_vec)
{
    sk_stringmap_iter_t *sm_iter = NULL;
    sk_stringmap_entry_t *sm_entry;
    sk_stringmap_status_t sm_err;
    const char *sm_attr;
    threshold_value_t threshold_value;
    char buf[64];

    /* return value; assume failure */
    int rv = -1;

    /* error message generated when parsing fields */
    char *errmsg;

    builtin_field_t *bf;

    assert(value_vec);
    assert(sizeof(threshold_value_t) == skVectorGetElementSize(value_vec));

    memset(&threshold_value, 0, sizeof(threshold_value));

    /* parse the --values field list */
    if (skStringMapParseWithAttributes(value_field_map, value_string,
                                       SKSTRINGMAP_DUPES_KEEP, &sm_iter,
                                       &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptionName(OPT_VALUES), errmsg);
        goto END;
    }

    /* check for attributes and handle them as necessary; store all
     * entries in a vector */
    while (skStringMapIterNext(sm_iter, &sm_entry, &sm_attr)==SK_ITERATOR_OK) {
        if (sm_entry->userdata) {
            /* this is a values field that comes from a plug-in */
            if (sm_attr[0]) {
                skAppPrintErr("Invalid %s: Extra text after field name ':%s'",
                              appOptionName(OPT_VALUES), sm_attr);
                goto END;
            }
            threshold_value.field_type = FIELD_TYPE_VALUE;
        } else if (sm_entry->id >= num_builtin_values
                   || (NULL == (bf = &builtin_values[sm_entry->id])))
        {
            /* expected field to be built-in but it is not */
            skAppPrintErr("Invalid id %u", sm_entry->id);
            skAbort();
        } else if (0 == bf->bf_is_distinct) {
            /* this is a built-in values field; must have no attribute */
            if (sm_attr[0]) {
                skAppPrintErr("Invalid %s: Extra text after field name ':%s'",
                              appOptionName(OPT_VALUES), sm_attr);
                goto END;
            }
            threshold_value.field_type = FIELD_TYPE_VALUE;
        } else {
            if (SK_FIELD_CALLER != bf->bf_id) {
                /* one of the old sip-distinct,dip-distinct fields;
                 * must have no attribute */
                if (sm_attr[0]) {
                    skAppPrintErr(
                        "Invalid %s: Extra text after field name ':%s'",
                        appOptionName(OPT_VALUES), sm_attr);
                    goto END;
                }
                /* copy the "sip" or "dip" prefix into 'buf' and
                 * assign sm_attr to buf */
                snprintf(buf, sizeof(buf), "%cip", bf->bf_title[0]);
                sm_attr = buf;
            } else {
                /* got a distinct:KEY field */
                if (!sm_attr[0]) {
                    skAppPrintErr(
                        "Invalid %s: Must provide a field name for disinct'",
                        appOptionName(OPT_VALUES));
                    goto END;
                }
            }
            /* need to parse KEY as a key field */
            sm_err = skStringMapGetByName(key_field_map, sm_attr, &sm_entry);
            if (sm_err) {
                if (strchr(sm_attr, ',')) {
                    skAppPrintErr(
                        "Invalid %s: May only distinct over a single field",
                        appOptionName(OPT_VALUES));
                } else {
                    skAppPrintErr("Invalid %s: Bad distinct field '%s': %s",
                                  appOptionName(OPT_VALUES), sm_attr,
                                  skStringMapStrerror(sm_err));
                }
                goto END;
            }
            threshold_value.field_type = FIELD_TYPE_DISTINCT;
        }

        threshold_value.sm_entry = sm_entry;
        skVectorAppendValue(value_vec, &threshold_value);
    }

    rv = 0;

  END:
    skStringMapIterDestroy(sm_iter);
    return rv;
}


/*
 *  ok = parseValueFieldsAndThresholds(field_string);
 *
 *    Parse the string that represents the aggregate value and
 *    distinct fields the user wishes to compute, parse the field name
 *    and ranges given by the --threshold arguments, create and fill
 *    in the global sk_fieldlist_t 'value_fields' and
 *    'distinct_fields', and add columns to the rwAsciiStream.
 *
 *    Return 0 on success, or non-zero on error.
 */
static int
parseValueFieldsAndThresholds(
    const char         *value_string)
{
    sk_stringmap_id_t sm_entry_id;
    sk_vector_t *value_vec = NULL;
    threshold_value_t threshold_value;
    const threshold_value_t *tv;
    threshold_value_t *vv;
    size_t i;

    /* return value; assume failure */
    int rv = -1;

    builtin_field_t *bf = NULL;
    sk_fieldentry_t *fl_entry = NULL;

    /*
     *  make changes to the built-in values depending on other command
     *  line switches:
     *
     *  --Maybe change distinct-ip fields to IPv6
     *  --Maybe change min/max time fields to use milliseconds
     *  --Maybe change width of time fields
     */
#if SK_ENABLE_IPV6
    if (ipv6_policy >= SK_IPV6POLICY_MIX) {
        for (i = 0, bf = builtin_values; i < num_builtin_values; ++i, ++bf) {
            switch (bf->bf_id) {
              case SK_FIELD_SIPv4:
                bf->bf_id = SK_FIELD_SIPv6;
                break;
              case SK_FIELD_DIPv4:
                bf->bf_id = SK_FIELD_DIPv6;
                break;
              default:
                break;
            }
        }
    }
#endif  /* SK_ENABLE_IPV6 */
    if (timestamp_format & SKTIMESTAMP_EPOCH) {
        for (i = 0, bf = builtin_values; i < num_builtin_values; ++i, ++bf) {
            switch (bf->bf_id) {
              case SK_FIELD_MIN_STARTTIME:
              case SK_FIELD_MAX_ENDTIME:
                bf->bf_text_len = 10;
                break;
              default:
                break;
            }
        }
    }
    if (bin_time_uses_msec) {
        for (i = 0, bf = builtin_values; i < num_builtin_values; ++i, ++bf) {
            switch (bf->bf_id) {
              case SK_FIELD_MIN_STARTTIME:
                bf->bf_id = SK_FIELD_MIN_STARTTIME_MSEC;
                bf->bf_text_len += 4;
                break;
              case SK_FIELD_MAX_ENDTIME:
                bf->bf_id = SK_FIELD_MAX_ENDTIME_MSEC;
                bf->bf_text_len += 4;
                break;
              default:
                break;
            }
        }
    }

    /* create a vector to hold the string-map entries */
    value_vec = skVectorNew(sizeof(threshold_value_t));
    if (NULL == value_vec) {
        skAppPrintOutOfMemory("create vector");
        goto END;
    }

    /* parse the --values and put values into the 'value_vec' */
    if (value_string || 0 == skVectorGetCount(threshold_vec)) {
        if (NULL == value_string) {
            /* when no values given, default to counting records */
            for (i = 0, bf = builtin_values; i < num_builtin_values; ++i, ++bf)
            {
                if (SK_FIELD_RECORDS == bf->bf_id) {
                    value_string = bf->bf_title;
                    break;
                }
            }
        }
        if (parseValueFields(value_string, value_vec)) {
            goto END;
        }
    }

    /* parse the threshold values */
    for (i = 0; i < skVectorGetCount(threshold_vec); ++i) {
        char *threshold_str;
        int seen = 0;

        skVectorGetValue(&threshold_str, threshold_vec, i);
        if (parseThreshold(threshold_str, &threshold_value)) {
            goto END;
        }

        /* if it exists in value_vec, update it; otherwise add it */
        for (i = 0; i < skVectorGetCount(value_vec); ++i) {
            vv = (threshold_value_t *)skVectorGetValuePointer(value_vec, i);
            if (vv->sm_entry->id == threshold_value.sm_entry->id
                && vv->field_type == threshold_value.field_type)
            {
                seen = 1;
                /* If the new limits are 0, ignore this new value.  This
                 * allows "--bytes=1 --all-counts" to work. */
                if (0 == threshold_value.minimum
                    && 0 == threshold_value.maximum)
                {
                    rv = 0;
                    break;
                }
                /* If the old limits are 0, update the old entry.  This
                 * allows "--all-counts --bytes=1" to work. */
                if (vv->minimum == 0 && vv->maximum == 0) {
                    vv->minimum = threshold_value.minimum;
                    vv->maximum = threshold_value.maximum;
                    break;
                }
                skAppPrintErr(
                    "Invalid %s '%s': Threshold for field already set",
                    appOptionName(OPT_THRESHOLD), threshold_str);
                goto END;
            }
        }

        if (!seen) {
            /* add new entry */
            if (skVectorAppendValue(value_vec, &threshold_value)) {
                skAppPrintOutOfMemory("vector append");
                goto END;
            }
        }
    }

    /* done with the threshold_vec */
    i = skVectorGetCount(threshold_vec);
    while (i) {
        char *str;
        --i;
        skVectorGetValue(&str, threshold_vec, i);
        if (str) { free(str); }
    }
    skVectorDestroy(threshold_vec);
    threshold_vec = NULL;

    if (app_flags.check_limits) {
        value_limits = skVectorNew(sizeof(uniq_limit_t));
        distinct_limits = skVectorNew(sizeof(uniq_limit_t));
        if (!value_limits || !distinct_limits) {
            skAppPrintOutOfMemory("create vector");
            goto END;
        }
    }

    /* create the field-lists */
    if (skFieldListCreate(&value_fields)) {
        skAppPrintErr("Unable to create value field list");
        goto END;
    }
    if (skFieldListCreate(&distinct_fields)) {
        skAppPrintErr("Unable to create distinct field list");
        goto END;
    }

    /* process the entries in the 'value_vec' */
    for (i = 0; i < skVectorGetCount(value_vec); ++i) {
        tv = (threshold_value_t *)skVectorGetValuePointer(value_vec, i);
        assert(tv);

        if (FIELD_TYPE_VALUE == tv->field_type) {
            if (tv->sm_entry->userdata) {
                /* this is a values field that comes from a plug-in */
                if (isFieldDuplicate(value_fields, SK_FIELD_CALLER,
                                     tv->sm_entry->userdata))
                {
                    skAppPrintErr(
                        "Invalid %s: Duplicate name '%s'",
                        appOptionName(OPT_VALUES), tv->sm_entry->name);
                    goto END;
                }
                if (appAddPlugin((skplugin_field_t*)(tv->sm_entry->userdata),
                                 tv->field_type))
                {
                    skAppPrintErr("Error adding value field '%s' from plugin",
                                  tv->sm_entry->name);
                    goto END;
                }
            } else {
                assert(tv->sm_entry->id < num_builtin_values);
                bf = &builtin_values[tv->sm_entry->id];
                assert(bf);
                assert(0 == bf->bf_is_distinct);
                if (isFieldDuplicate(value_fields, bf->bf_id, NULL)) {
                    skAppPrintErr("Invalid %s: Duplicate name '%s'",
                                  appOptionName(OPT_VALUES), bf->bf_title);
                    goto END;
                }
                fl_entry = skFieldListAddKnownField(value_fields, bf->bf_id,
                                                    bf);
                if (NULL == fl_entry) {
                    skAppPrintErr("Error adding value field '%s' to field list",
                                  tv->sm_entry->name);
                    goto END;
                }
                if (rwAsciiAppendCallbackFieldExtra(ascii_str,
                                                    &builtin_value_get_title,
                                                    &value_to_ascii,
                                                    fl_entry, bf->bf_text_len))
                {
                    skAppPrintErr("Error adding value field '%s' to stream",
                                  tv->sm_entry->name);
                    goto END;
                }
            }
        } else {
            assert(FIELD_TYPE_DISTINCT == tv->field_type);
            if (tv->sm_entry->userdata) {
                /* distinct:KEY where KEY is from a plug-in */
                if (isFieldDuplicate(distinct_fields, SK_FIELD_CALLER,
                                     tv->sm_entry->userdata))
                {
                    skAppPrintErr(
                        "Invalid %s: Duplicate distinct '%s'",
                        appOptionName(OPT_VALUES), tv->sm_entry->name);
                    goto END;
                }
                if (appAddPlugin((skplugin_field_t*)(tv->sm_entry->userdata),
                                 tv->field_type))
                {
                    skAppPrintErr(
                        "Error adding distinct field '%s' from plugin",
                        tv->sm_entry->name);
                    goto END;
                }
            } else if (isFieldDuplicate(distinct_fields,
                                        (sk_fieldid_t)tv->sm_entry->id, NULL))
            {
                skAppPrintErr("Invalid %s: Duplicate distinct '%s'",
                              appOptionName(OPT_VALUES), tv->sm_entry->name);
                goto END;
            } else if (tv->sm_entry->id == RWREC_PRINTABLE_FIELD_COUNT) {
                skAppPrintErr("Invalid %s: May not count distinct '%s' entries",
                              appOptionName(OPT_VALUES), tv->sm_entry->name);
                goto END;
            } else {
                sm_entry_id = tv->sm_entry->id;
#if SK_ENABLE_IPV6
                if (ipv6_policy >= SK_IPV6POLICY_MIX) {
                    /* make certain field can hold an IPv6 address */
                    switch (sm_entry_id) {
                      case SK_FIELD_SIPv4:
                        sm_entry_id = SK_FIELD_SIPv6;
                        break;
                      case SK_FIELD_DIPv4:
                        sm_entry_id = SK_FIELD_DIPv6;
                        break;
                      case SK_FIELD_NHIPv4:
                        sm_entry_id = SK_FIELD_NHIPv6;
                        break;
                    }
                }
#endif  /* #if SK_ENABLE_IPV6 */
                fl_entry = skFieldListAddKnownField(distinct_fields,
                                                    sm_entry_id, NULL);
                if (NULL == fl_entry) {
                    skAppPrintErr(
                        "Error adding distinct field '%s' to field list",
                        tv->sm_entry->name);
                    goto END;
                }
                if (rwAsciiAppendCallbackFieldExtra(
                        ascii_str, &builtin_distinct_get_title,
                        &distinct_to_ascii, fl_entry,
                        distinct_get_width(fl_entry)))
                {
                    skAppPrintErr("Error adding distinct field '%s' to stream",
                                  tv->sm_entry->name);
                    goto END;
                }
            }
        }

        if (app_flags.check_limits) {
            uniq_limit_t uniq_limit;
            uniq_limit.minimum = tv->minimum;
            uniq_limit.maximum = tv->maximum;
            if (FIELD_TYPE_VALUE == tv->field_type) {
                skVectorAppendValue(value_limits, &uniq_limit);
            } else {
                assert(FIELD_TYPE_DISTINCT == tv->field_type);
                skVectorAppendValue(distinct_limits, &uniq_limit);
            }
        }

        /* in rwstats, the first value field determines the order of
         * the output rows */
        if (STATSUNIQ_PROGRAM_STATS == this_program && NULL == limit.fl_entry){
            limit.fl_entry = fl_entry;
            limit.fl_id = (sk_fieldid_t)skFieldListEntryGetId(fl_entry);
            limit.bf_value = bf;
            limit.distinct = (FIELD_TYPE_DISTINCT == tv->field_type);
            if (limit.distinct) {
                builtin_distinct_get_title(limit.title, sizeof(limit.title),
                                           fl_entry);
            } else {
                builtin_value_get_title(limit.title, sizeof(limit.title),
                                        fl_entry);
            }
        }
    }

    rv = 0;

  END:
    /* do standard clean-up */
    skVectorDestroy(value_vec);
    if (rv != 0) {
        /* something went wrong. do additional clean-up */
        if (value_fields) {
            skFieldListDestroy(&value_fields);
            value_fields = NULL;
        }
        if (distinct_fields) {
            skFieldListDestroy(&distinct_fields);
            distinct_fields = NULL;
        }
    }

    return rv;
}


/*
 *    Parse 'threshold_str' which is a string representing a single
 *    argument to the --threshold switch.  The string must have a
 *    field-name, and equals-sign, and either a range or a single
 *    number acting as the lower bound of a range.  Store the
 *    string-map entry for the field and the bounds of the range in
 *    'threshold_value'.  Return 0 on success and -1 on failure.
 */
static int
parseThreshold(
    char               *threshold_str,
    threshold_value_t  *threshold_value)
{
    const char sep_char = '=';
    sk_stringmap_entry_t *sm_entry;
    sk_stringmap_status_t sm_err;
    const builtin_field_t *bf;
    char sm_attr[512];
    char *cp;
    char *eq;
    int rv = -1;

    assert(threshold_str);
    memset(threshold_value, 0, sizeof(*threshold_value));

    /* find the '=' */
    eq = strchr(threshold_str, sep_char);
    if (NULL == eq) {
        skAppPrintErr("Invalid %s '%s': Unable to find '%c' character",
                      appOptionName(OPT_THRESHOLD), threshold_str, sep_char);
        goto END;
    }

    /* ensure a threshold is given */
    cp = eq + 1;
    while (*cp && isspace((int)*cp)) {
        ++cp;
    }
    if ('\0' == *cp) {
        skAppPrintErr("Invalid %s '%s': No threshold specified for field",
                      appOptionName(OPT_THRESHOLD), threshold_str);
        goto END;
    }

    /* split into name and threshold range */
    *eq = '\0';

    /* parse the range */
    if (0 == strcmp(cp, "0-0")) {
        threshold_value->minimum = threshold_value->maximum = 0;
    } else {
        int parse_err = skStringParseRange64(&threshold_value->minimum,
                                             &threshold_value->maximum,
                                             cp, 0, 0,
                                             SKUTILS_RANGE_MAX_SINGLE);
        if (parse_err) {
            skAppPrintErr("Invalid %s: Error parsing range '%s': %s",
                          appOptionName(OPT_THRESHOLD), cp,
                          skStringParseStrerror(parse_err));
            goto END;
        }
        app_flags.check_limits = 1;
    }

    /* find the field with that name */
    sm_err = skStringMapGetByNameWithAttributes(
        value_field_map, threshold_str, &sm_entry, sm_attr, sizeof(sm_attr));
    if (sm_err) {
        skAppPrintErr("Invalid %s: Unable to find a field named '%s': %s",
                      appOptionName(OPT_THRESHOLD), threshold_str,
                      skStringMapStrerror(sm_err));
        goto END;
    }

    if (sm_entry->userdata) {
        /* this is a values field that comes from a plug-in */
        if (sm_attr[0]) {
            skAppPrintErr("Invalid %s: Extra text after field name ':%s'",
                          appOptionName(OPT_THRESHOLD), sm_attr);
            goto END;
        }
        *eq = sep_char;
        skAppPrintErr(("Invalid %s '%s':"
                       " Thresholds not supported for plug-in fields"),
                      appOptionName(OPT_THRESHOLD), threshold_str);
        goto END;
    }
    assert(sm_entry->id < num_builtin_values);
    bf = &builtin_values[sm_entry->id];
    if (0 == bf->bf_is_distinct) {
        /* this is a built-in values field; must have no attribute */
        if (sm_attr[0]) {
            skAppPrintErr("Invalid %s: Extra text after field name ':%s'",
                          appOptionName(OPT_THRESHOLD), sm_attr);
            goto END;
        }
        threshold_value->field_type = FIELD_TYPE_VALUE;
    } else {
        if (SK_FIELD_CALLER != bf->bf_id) {
            /* one of the old sip-distinct,dip-distinct fields; must
             * have no attribute */
            if (sm_attr[0]) {
                skAppPrintErr("Invalid %s: Extra text after field name ':%s'",
                              appOptionName(OPT_THRESHOLD), sm_attr);
                goto END;
            }
            /* copy the "sip" or "dip" prefix into sm_attr */
            snprintf(sm_attr, sizeof(sm_attr), "%cip", bf->bf_title[0]);
        } else {
            /* got a distinct:KEY field */
            if (!sm_attr[0]) {
                skAppPrintErr(("Invalid %s:"
                               " Must provide a field name for disinct'"),
                              appOptionName(OPT_THRESHOLD));
                goto END;
            }
        }
        /* need to parse KEY as a key field */
        sm_err = skStringMapGetByName(key_field_map, sm_attr, &sm_entry);
        if (sm_err) {
            if (strchr(sm_attr, ',')) {
                skAppPrintErr(("Invalid %s:"
                               " May only distinct over a single field"),
                              appOptionName(OPT_THRESHOLD));
            } else {
                skAppPrintErr("Invalid %s: Bad distinct field '%s': %s",
                              appOptionName(OPT_THRESHOLD), sm_attr,
                              skStringMapStrerror(sm_err));
            }
            goto END;
        }
        threshold_value->field_type = FIELD_TYPE_DISTINCT;
    }

    threshold_value->sm_entry = sm_entry;
    rv = 0;

  END:
    if (eq) {
        *eq = sep_char;
    }
    return rv;
}


/*
 *  status = appAddPlugin(plugin_field, field_type);
 *
 *    Given a key, an aggregate value, or distinct(key) field defined
 *    in a plug-in, activate that field and get the information from
 *    the field that the application requires.  field_type indicates
 *    whether the field represents a key, an aggregate value, or a
 *    distinct field.
 *
 *    The function adds the field to the approprirate sk_fieldlist_t
 *    ('key_fields', 'value_fields', 'distinct_fields') and to the
 *    rwAsciiStream.
 */
static int
appAddPlugin(
    skplugin_field_t   *pi_field,
    field_type_t        field_type)
{
    uint8_t bin_buf[HASHLIB_MAX_VALUE_WIDTH];
    sk_fieldlist_entrydata_t regdata;
    sk_fieldentry_t *fl_entry;
    size_t text_width;
    skplugin_err_t pi_err;

    /* set the regdata for the sk_fieldlist_t */
    memset(&regdata, 0, sizeof(regdata));
    regdata.bin_compare = plugin_bin_compare;
    regdata.add_rec_to_bin = plugin_add_rec_to_bin;
    regdata.bin_merge = plugin_bin_merge;
    /* regdata.bin_output; */

    /* activate the field (so cleanup knows about it) */
    pi_err = skPluginFieldActivate(pi_field);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }

    /* initialize this field */
    pi_err = skPluginFieldRunInitialize(pi_field);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }

    /* get the required textual width of the column */
    pi_err = skPluginFieldGetLenText(pi_field, &text_width);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }
    if (0 == text_width) {
        const char *title;
        skPluginFieldTitle(pi_field, &title);
        skAppPrintErr("Plug-in field '%s' has a textual width of 0",
                      title);
        return -1;
    }

    /* get the bin width for this field */
    pi_err = skPluginFieldGetLenBin(pi_field, &regdata.bin_octets);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }
    if (0 == regdata.bin_octets) {
        const char *title;
        skPluginFieldTitle(pi_field, &title);
        skAppPrintErr("Plug-in field '%s' has a binary width of 0",
                      title);
        return -1;
    }
    if (regdata.bin_octets > HASHLIB_MAX_VALUE_WIDTH) {
        return -1;
    }

    memset(bin_buf, 0, sizeof(bin_buf));
    pi_err = skPluginFieldGetInitialValue(pi_field, bin_buf);
    if (pi_err != SKPLUGIN_OK) {
        return -1;
    }
    regdata.initial_value = bin_buf;

    switch (field_type) {
      case FIELD_TYPE_KEY:
        regdata.rec_to_bin = plugin_rec_to_bin;
        fl_entry = skFieldListAddField(key_fields, &regdata, (void*)pi_field);
        break;
      case FIELD_TYPE_VALUE:
        fl_entry = skFieldListAddField(value_fields, &regdata,(void*)pi_field);
        break;
      case FIELD_TYPE_DISTINCT:
        regdata.rec_to_bin = plugin_rec_to_bin;
        fl_entry = skFieldListAddField(distinct_fields, &regdata,
                                       (void*)pi_field);
        break;
      default:
        skAbortBadCase(field_type);
    }
    if (NULL == fl_entry) {
        skAppPrintErr("Unable to add field to field list");
        return -1;
    }

    if (STATSUNIQ_PROGRAM_STATS == this_program
        && FIELD_TYPE_KEY != field_type && NULL == limit.fl_entry)
    {
        /* first aggregate value/distinct field */

        /* ensure that the limit-type is valid */
        if ((FIELD_TYPE_VALUE == field_type)
            && (RWSTATS_PERCENTAGE == limit.type
                || RWSTATS_THRESHOLD == limit.type))
        {
            skAppPrintErr(("Only the --%s limit is supported when the"
                           " primary values field is from a plug-in"),
                          appOptionName(OPT_COUNT));
            return -1;
        }

        limit.pi_field = pi_field;
        limit.fl_entry = fl_entry;
        limit.fl_id = (sk_fieldid_t)skFieldListEntryGetId(fl_entry);
        limit.distinct = (FIELD_TYPE_DISTINCT == field_type);

        if (limit.distinct) {
            plugin_distinct_get_title(limit.title, sizeof(limit.title),
                                      fl_entry);
        } else {
            plugin_get_title(limit.title, sizeof(limit.title), fl_entry);
        }
    }

    switch (field_type) {
      case FIELD_TYPE_KEY:
        return rwAsciiAppendCallbackFieldExtra(ascii_str, &plugin_get_title,
                                               &plugin_key_to_ascii, fl_entry,
                                               text_width);
      case FIELD_TYPE_VALUE:
        return rwAsciiAppendCallbackFieldExtra(ascii_str, &plugin_get_title,
                                               &value_to_ascii, fl_entry,
                                               text_width);
      case FIELD_TYPE_DISTINCT:
        return rwAsciiAppendCallbackFieldExtra(ascii_str,
                                               &plugin_distinct_get_title,
                                               &distinct_to_ascii,
                                               fl_entry, text_width);
      default:
        skAbortBadCase(field_type);
    }

    return -1;                  /* NOTREACHED */
}


/*
 *  is_duplicate = isFieldDuplicate(flist, fid, fcontext);
 *
 *    Return 1 if the field-id 'fid' appears in the field-list
 *    'flist'.  If 'fid' is SK_FIELD_CALLER, return 1 when a field in
 *    'flist' has the id SK_FIELD_CALLER and its context object points
 *    to 'fcontext'.  Return 0 otherwise.
 *
 *    In this function, IPv4 and IPv6 fields are considered
 *    equivalent; that is, you cannot have both SK_FIELD_SIPv4 and
 *    SK_FIELD_SIPv6, and multiple SK_FIELD_CALLER fields are allowed.
 */
static int
isFieldDuplicate(
    const sk_fieldlist_t   *flist,
    sk_fieldid_t            fid,
    const void             *fcontext)
{
    sk_fieldlist_iterator_t fl_iter;
    sk_fieldentry_t *fl_entry;

    skFieldListIteratorBind(flist, &fl_iter);
    switch (fid) {
      case SK_FIELD_SIPv4:
      case SK_FIELD_SIPv6:
        while ((fl_entry = skFieldListIteratorNext(&fl_iter)) != NULL) {
            switch (skFieldListEntryGetId(fl_entry)) {
              case SK_FIELD_SIPv4:
              case SK_FIELD_SIPv6:
                return 1;
              default:
                break;
            }
        }
        break;

      case SK_FIELD_DIPv4:
      case SK_FIELD_DIPv6:
        while ((fl_entry = skFieldListIteratorNext(&fl_iter)) != NULL) {
            switch (skFieldListEntryGetId(fl_entry)) {
              case SK_FIELD_DIPv4:
              case SK_FIELD_DIPv6:
                return 1;
              default:
                break;
            }
        }
        break;

      case SK_FIELD_NHIPv4:
      case SK_FIELD_NHIPv6:
        while ((fl_entry = skFieldListIteratorNext(&fl_iter)) != NULL) {
            switch (skFieldListEntryGetId(fl_entry)) {
              case SK_FIELD_NHIPv4:
              case SK_FIELD_NHIPv6:
                return 1;
              default:
                break;
            }
        }
        break;

      case SK_FIELD_CALLER:
        while ((fl_entry = skFieldListIteratorNext(&fl_iter)) != NULL) {
            if ((skFieldListEntryGetId(fl_entry) == (uint32_t)fid)
                && (skFieldListEntryGetContext(fl_entry) == fcontext))
            {
                return 1;
            }
        }
        break;

      default:
        while ((fl_entry = skFieldListIteratorNext(&fl_iter)) != NULL) {
            if (skFieldListEntryGetId(fl_entry) == (uint32_t)fid) {
                return 1;
            }
        }
        break;
    }
    return 0;
}


/*
 *    If requested, print the name of the stream to the standard
 *    error.  Enable copying of the stream's content to the
 *    'copy_input' stream if needed.  Set the IPv6 policy of the
 *    stream.
 */
static int
prepareFileForRead(
    skstream_t         *stream)
{
    if (app_flags.print_filenames) {
        fprintf(PRINT_FILENAMES_FH, "%s\n", skStreamGetPathname(stream));
    }
    if (copy_input) {
        skStreamSetCopyInput(stream, copy_input);
    }
    skStreamSetIPv6Policy(stream, ipv6_policy);

    return 0;
}


/*
 *    When time binning is requested, adjust the time fields on the
 *    record.
 */
static void
adjustTimeFields(
    rwRec              *rwrec)
{
    sktime_t sTime;
    sktime_t sTime_mod;
    uint32_t elapsed;

    switch (time_fields) {
      case PARSE_KEY_STIME:
      case (PARSE_KEY_STIME | PARSE_KEY_ELAPSED):
        /* adjust start time */
        sTime = rwRecGetStartTime(rwrec);
        sTime_mod = sTime % bin_time;
        rwRecSetStartTime(rwrec, (sTime - sTime_mod));
        break;
      case PARSE_KEY_ALL_TIMES:
      case (PARSE_KEY_STIME | PARSE_KEY_ETIME):
        /* adjust sTime and elapsed/duration */
        sTime = rwRecGetStartTime(rwrec);
        sTime_mod = sTime % bin_time;
        rwRecSetStartTime(rwrec, (sTime - sTime_mod));
        /*
         * the following sets elapsed to:
         * ((eTime - (eTime % bin_size)) - (sTime - (sTime % bin_size)))
         */
        elapsed = rwRecGetElapsed(rwrec);
        elapsed = (elapsed + sTime_mod
                   - ((sTime + elapsed) % bin_time));
        rwRecSetElapsed(rwrec, elapsed);
        break;
      case PARSE_KEY_ETIME:
      case (PARSE_KEY_ETIME | PARSE_KEY_ELAPSED):
        /* want to set eTime to (eTime - (eTime % bin_size)), but
         * eTime is computed as (sTime + elapsed) */
        sTime = rwRecGetStartTime(rwrec);
        rwRecSetStartTime(rwrec, (sTime - ((sTime + rwRecGetElapsed(rwrec))
                                           % bin_time)));
        break;
      case 0:
      case PARSE_KEY_ELAPSED:
      default:
        skAbortBadCase(time_fields);
    }
}


/*
 *  status = readRecord(stream, rwrec);
 *
 *    Fill 'rwrec' with a SiLK Flow record read from 'stream'.  Modify
 *    the times on the record if the user has requested time binning.
 *    Modify the IPs if the user has specified CIDR blocks.
 *
 *    Return the status of reading the record.
 */
int
readRecord(
    skstream_t         *stream,
    rwRec              *rwrec)
{
    int rv;

    rv = skStreamReadRecord(stream, rwrec);
    if (SKSTREAM_OK == rv) {
        ++record_count;
        switch (limit.fl_id) {
          case SK_FIELD_RECORDS:
            ++value_total;
            break;
          case SK_FIELD_SUM_BYTES:
            value_total += rwRecGetBytes(rwrec);
            break;
          case SK_FIELD_SUM_PACKETS:
            value_total += rwRecGetPkts(rwrec);
            break;
          default:
            break;
        }

        if (cidr_sip) {
            rwRecSetSIPv4(rwrec, rwRecGetSIPv4(rwrec) & cidr_sip);
        }
        if (cidr_dip) {
            rwRecSetDIPv4(rwrec, rwRecGetDIPv4(rwrec) & cidr_dip);
        }
        if (bin_time > 1) {
            adjustTimeFields(rwrec);
        }
    }

    return rv;
}


/*
 *  int = appNextInput(&stream);
 *
 *    Fill 'stream' with the next input file to read.  Return 0 if
 *    'stream' was successfully opened, 1 if there are no more input
 *    files, or -1 if an error was encountered.
 */
int
appNextInput(
    skstream_t        **stream)
{
    char *path = NULL;
    int rv;

    rv = skOptionsCtxNextArgument(optctx, &path);
    if (0 == rv) {
        rv = skStreamOpenSilkFlow(stream, path, SK_IO_READ);
        if (rv) {
            skStreamPrintLastErr(*stream, rv, &skAppPrintErr);
            skStreamDestroy(stream);
            return -1;
        }

        (void)prepareFileForRead(*stream);
    }

    return rv;
}


/*
 *  setOutputHandle();
 *
 *    If using the pager, enable it and bind it to the Ascii stream.
 */
void
setOutputHandle(
    void)
{
    int rv;

    /* only invoke the pager when the user has not specified the
     * output-path, even if output-path is stdout */
    if (NULL == output.of_name) {
        /* invoke the pager */
        rv = skFileptrOpenPager(&output, pager);
        if (rv && rv != SK_FILEPTR_PAGER_IGNORED) {
            skAppPrintErr("Unable to invoke pager");
        }
    }

    /* bind the Ascii Stream to the output */
    if (ascii_str) {
        rwAsciiSetOutputHandle(ascii_str, output.of_fp);
    }
}


/*
 *  writeAsciiRecord();
 *
 *    Unpacks the fields from 'key' and the value fields from 'value'.
 *    Prints the key fields and the value fields to the global output
 *    stream 'output.of_fp'.
 */
void
writeAsciiRecord(
    uint8_t           **outbuf)
{
    rwRec rwrec;
    uint32_t val32;
    uint64_t val64;
    sktime_t eTime = 0;
    uint16_t dport = 0;
    sk_fieldlist_iterator_t fl_iter;
    sk_fieldentry_t *field;
    int id;

#if  SK_ENABLE_IPV6
    /* whether IPv4 addresses have been added to a record */
    int added_ipv4 = 0;
    uint8_t ipv6[16];
#endif

    /* in mixed IPv4/IPv6 setting, keep record as IPv4 unless an IPv6
     * address forces us to use IPv6. */
#define KEY_TO_REC_IPV6(func_v6, func_v4, rec, field_buf, field_list, field) \
    skFieldListExtractFromBuffer(key_fields, field_buf, field, ipv6);   \
    if (rwRecIsIPv6(rec)) {                                             \
        /* record is already IPv6 */                                    \
        func_v6((rec), ipv6);                                           \
    } else if (SK_IPV6_IS_V4INV6(ipv6)) {                               \
        /* record is IPv4, and so is the IP */                          \
        func_v4((rec), ntohl(*(uint32_t*)(ipv6 + SK_IPV6_V4INV6_LEN))); \
        added_ipv4 = 1;                                                 \
    } else {                                                            \
        /* address is IPv6, but record is IPv4 */                       \
        if (added_ipv4) {                                               \
            /* record has IPv4 addrs; must convert */                   \
            rwRecConvertToIPv6(rec);                                    \
        } else {                                                        \
            /* no addresses on record yet */                            \
            rwRecSetIPv6(rec);                                          \
        }                                                               \
        func_v6((rec), ipv6);                                           \
    }

    /* Zero out rwrec to avoid display errors---specifically with msec
     * fields and eTime. */
    RWREC_CLEAR(&rwrec);

    /* Initialize the protocol to 1 (ICMP), so that if the user has
     * requested ICMP type/code but the protocol is not part of the
     * key, we still get ICMP values. */
    rwRecSetProto(&rwrec, IPPROTO_ICMP);

#if SK_ENABLE_IPV6
    if (ipv6_policy > SK_IPV6POLICY_MIX) {
        /* Force records to be in IPv6 format */
        rwRecSetIPv6(&rwrec);
    }
#endif /* SK_ENABLE_IPV6 */

    /* unpack the key into 'rwrec' */
    skFieldListIteratorBind(key_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        id = skFieldListEntryGetId(field);
        switch (id) {
#if SK_ENABLE_IPV6
          case SK_FIELD_SIPv6:
            KEY_TO_REC_IPV6(rwRecMemSetSIPv6, rwRecSetSIPv4, &rwrec,
                            outbuf[0], key_fields, field);
            break;
          case SK_FIELD_DIPv6:
            KEY_TO_REC_IPV6(rwRecMemSetDIPv6, rwRecSetDIPv4, &rwrec,
                            outbuf[0], key_fields, field);
            break;
          case SK_FIELD_NHIPv6:
            KEY_TO_REC_IPV6(rwRecMemSetNhIPv6, rwRecSetNhIPv4, &rwrec,
                            outbuf[0], key_fields, field);
            break;
#endif  /* SK_ENABLE_IPV6 */

          case SK_FIELD_SIPv4:
            KEY_TO_REC_32(rwRecSetSIPv4, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_DIPv4:
            KEY_TO_REC_32(rwRecSetDIPv4, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_NHIPv4:
            KEY_TO_REC_32(rwRecSetNhIPv4, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_SPORT:
            KEY_TO_REC_16(rwRecSetSPort, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_DPORT:
            /* just extract dPort; we will set it later to ensure
             * dPort takes precedence over ICMP type/code */
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&dport);
            break;
          case SK_FIELD_ICMP_TYPE:
            KEY_TO_REC_08(rwRecSetIcmpType, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_ICMP_CODE:
            KEY_TO_REC_08(rwRecSetIcmpCode, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_PROTO:
            KEY_TO_REC_08(rwRecSetProto, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_PACKETS:
            KEY_TO_REC_32(rwRecSetPkts, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_BYTES:
            KEY_TO_REC_32(rwRecSetBytes, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_FLAGS:
            KEY_TO_REC_08(rwRecSetFlags, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_SID:
            KEY_TO_REC_16(rwRecSetSensor, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_INPUT:
            KEY_TO_REC_16(rwRecSetInput, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_OUTPUT:
            KEY_TO_REC_16(rwRecSetOutput, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_INIT_FLAGS:
            KEY_TO_REC_08(rwRecSetInitFlags, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_REST_FLAGS:
            KEY_TO_REC_08(rwRecSetRestFlags, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_TCP_STATE:
            KEY_TO_REC_08(rwRecSetTcpState, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_APPLICATION:
            KEY_TO_REC_16(rwRecSetApplication, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_FTYPE_CLASS:
          case SK_FIELD_FTYPE_TYPE:
            KEY_TO_REC_08(rwRecSetFlowType, &rwrec, outbuf[0],
                          key_fields, field);
            break;
          case SK_FIELD_STARTTIME:
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val32);
            rwRecSetStartTime(&rwrec, sktimeCreate(val32, 0));
            break;
          case SK_FIELD_ELAPSED:
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val32);
            rwRecSetElapsed(&rwrec, val32 * 1000);
            break;
          case SK_FIELD_ENDTIME:
            /* just extract eTime; we will set it later */
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val32);
            eTime = sktimeCreate(val32, 0);
            break;
          case SK_FIELD_STARTTIME_MSEC:
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val64);
            rwRecSetStartTime(&rwrec, (sktime_t)val64);
            break;
          case SK_FIELD_ELAPSED_MSEC:
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val32);
            rwRecSetElapsed(&rwrec, val32);
            break;
          case SK_FIELD_ENDTIME_MSEC:
            /* just extract eTime; we will set it later */
            skFieldListExtractFromBuffer(key_fields, outbuf[0],
                                         field, (uint8_t*)&val64);
            eTime = (sktime_t)val64;
            break;
          default:
            assert(skFieldListEntryGetId(field) == SK_FIELD_CALLER);
            break;
        }
    }

    if (dport_key) {
        rwRecSetDPort(&rwrec, dport);
    }

    switch (time_fields_key) {
      case PARSE_KEY_ETIME:
        /* etime only; just set sTime to eTime--elapsed is already 0 */
        rwRecSetStartTime(&rwrec, eTime);
        break;
      case (PARSE_KEY_ELAPSED | PARSE_KEY_ETIME):
        /* etime and elapsed; set start time based on end time and elapsed */
        val64 = rwRecGetElapsed(&rwrec);
        rwRecSetStartTime(&rwrec, eTime - val64);
        break;
      case (PARSE_KEY_STIME | PARSE_KEY_ETIME):
        /* etime and stime; set elapsed as their difference */
        val64 = rwRecGetStartTime(&rwrec);
        assert(val64 <= (uint64_t)eTime);
        rwRecSetElapsed(&rwrec, eTime - val64);
        break;
      case PARSE_KEY_ALL_TIMES:
        /* 'time_fields_key' should contain 0, 1, or 2 time values */
        skAbortBadCase(time_fields_key);
      default:
        assert(0 == time_fields_key
               || PARSE_KEY_STIME == time_fields_key
               || PARSE_KEY_ELAPSED == time_fields_key
               || (PARSE_KEY_STIME | PARSE_KEY_ELAPSED) == time_fields_key);
        break;
    }

    /* print everything */
    rwAsciiPrintRecExtra(ascii_str, &rwrec, outbuf);
}


/*
 *    Check for values for the aggregate value and distinct fields are
 *    within the specified limites.  If so, call writeRecord() to
 *    print the contents of the bin.  If not, ignore the bin.
 */
void
checkLimitsWriteRecord(
    uint8_t           **outbuf)
{
    sk_fieldlist_iterator_t fl_iter;
    sk_fieldentry_t *field;
    uniq_limit_t *tv;
    union value_un {
        uint8_t   ar[HASHLIB_MAX_VALUE_WIDTH];
        uint64_t  u64;
        uint32_t  u32;
        uint16_t  u16;
        uint8_t   u8;
    } value;
#if  SK_ENABLE_IPV6
    union ipv6_distinct_un {
        uint64_t count;
        uint8_t  ip[16];
    } val_ip6;
#endif
    size_t len;
    size_t i;

    i = 0;
    skFieldListIteratorBind(value_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        tv = (uniq_limit_t *)skVectorGetValuePointer(value_limits, i);
        ++i;
        if (0 == tv->minimum && 0 == tv->maximum) {
            continue;
        }
        len = skFieldListEntryGetBinOctets(field);
        switch (len) {
          case 1:
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, &value.u8);
            if (value.u8 < tv->minimum || value.u8 > tv->maximum) {
                return;
            }
            break;
          case 2:
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, (uint8_t*)&value.u16);
            if (value.u16 < tv->minimum || value.u16 > tv->maximum) {
                return;
            }
            break;
          case 4:
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, (uint8_t*)&value.u32);
            if (value.u32 < tv->minimum || value.u32 > tv->maximum) {
                return;
            }
            break;
          case 8:
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, (uint8_t*)&value.u64);
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
          case 3:
          case 5:
          case 6:
          case 7:
            value.u64 = 0;
#if SK_BIG_ENDIAN
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, &value.ar[8 - len]);
#else
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, &value.ar[0]);
#endif  /* #else of #if SK_BIG_ENDIAN */
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
          default:
            skFieldListExtractFromBuffer(value_fields, outbuf[1],
                                         field, value.ar);
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
        }
    }

    i = 0;
    skFieldListIteratorBind(distinct_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        tv = (uniq_limit_t *)skVectorGetValuePointer(distinct_limits, i);
        ++i;
        if (0 == tv->minimum) {
            continue;
        }
        len = skFieldListEntryGetBinOctets(field);
        switch (len) {
          case 1:
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, &value.u8);
            if (value.u8 < tv->minimum || value.u8 > tv->maximum) {
                return;
            }
            break;
          case 2:
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, (uint8_t*)&value.u16);
            if (value.u16 < tv->minimum || value.u16 > tv->maximum) {
                return;
            }
            break;
          case 4:
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, (uint8_t*)&value.u32);
            if (value.u32 < tv->minimum || value.u32 > tv->maximum) {
                return;
            }
            break;
          case 8:
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, (uint8_t*)&value.u64);
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
          case 3:
          case 5:
          case 6:
          case 7:
            value.u64 = 0;
#if SK_BIG_ENDIAN
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, &value.ar[8 - len]);
#else
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, &value.ar[0]);
#endif  /* #else of #if SK_BIG_ENDIAN */
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
          case 16:
#if  SK_ENABLE_IPV6
            if (SK_FIELD_SIPv6 == skFieldListEntryGetId(field)
                || SK_FIELD_DIPv6 == skFieldListEntryGetId(field)
                || SK_FIELD_NHIPv6 == skFieldListEntryGetId(field))
            {
                skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                             field, val_ip6.ip);
                if (val_ip6.count < tv->minimum || val_ip6.count > tv->maximum)
                {
                    return;
                }
                break;
            }
#endif  /* SK_ENABLE_IPV6 */
            /* FALLTHROUGH */
          default:
            skFieldListExtractFromBuffer(distinct_fields, outbuf[2],
                                         field, value.ar);
            if (value.u64 < tv->minimum || value.u64 > tv->maximum) {
                return;
            }
            break;
        }
    }

    writeAsciiRecord(outbuf);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
