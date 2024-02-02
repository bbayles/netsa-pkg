%{
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
 *  rwgeoip2ccmap.l
 *
 *    Create a country code prefixmap (pmap) file from textual CSV
 *    input or binary input in the GeoIP Legacy format.
 *
 *
 *    The lexer expects each line of the input to have six
 *    comma-separated values (six values and five commas), where every
 *    value is wrapped in double-quotes.  Optional whitespace may
 *    surround a value.  The values are
 *
 *    0. Starting IP address in the canonical form
 *
 *    1. Ending IP address in the canonical form
 *
 *    2. Starting IP address as an integer
 *
 *    3. Ending IP address as an integer
 *
 *    4. Two letter country code abbreviation
 *
 *    5. Country name.
 *
 *
 *  Mark Thomas
 *  March 2016
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwgeoip2ccmap.l b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/redblack.h>
#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skprefixmap.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#ifdef SK_ENABLE_LIBMAXMINDDB
#include <maxminddb.h>
#endif

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* label to use for unknown ranges */
#define DEFAULT_LABEL   "--"

/* for the legacy CSV input, the number of columns (fields, values)
 * expected on each line */
#define LEGACY_CSV_COLUMNS  6

/*
 *  Values for "country" that the legacy GeoIP databases used for
 *  anonymizing services and satellite providers.  These are macros
 *  since they are used to initialize a struct.
 */
#define COUNTRY_ANON    (('a' << 8) | '1')
#define COUNTRY_SATL    (('a' << 8) | '2')

/* type of input to expect */
enum geoip2ccmap_mode_en {
    GEOIP2CCMAP_MODE_AUTO,
    GEOIP2CCMAP_MODE_IPV6,
    GEOIP2CCMAP_MODE_IPV4,
    GEOIP2CCMAP_MODE_CSV,
    GEOIP2CCMAP_MODE_BINARY,
    GEOIP2CCMAP_MODE_GEOIP2,
    GEOIP2CCMAP_MODE_LEGACY
};
typedef enum geoip2ccmap_mode_en geoip2ccmap_mode_t;

/* information for the current line of a legacy CSV file */
typedef struct pmap_legacy_st {
    skipaddr_t          range[2];
    uint32_t            country;
} pmap_legacy_t;

/* information for the current line of a GeoIP2 ipblocks file */
typedef struct pmap_ipblocks_st {
    skipaddr_t          ip;
    uint32_t            prefix;
    /* geoname_id, registered_country_geoname_id,
     * represented_country_geoname_id */
    uint32_t            geoname[3];
    uint16_t            is_anonymous;
    uint16_t            is_satellite;
} pmap_ipblocks_t;

/* information for the current line of a GeoIP2 location file.  this
 * is also the type of the objects stored in the 'geomap' redblack
 * tree. */
typedef struct pmap_location_st {
    /* the integer key */
    uint32_t            geoname;
    /* the two letter country code converted to an integer, or the two
     * letter continent code if no country */
    uint32_t            country;
    /* true if the 'country' value is a country code */
    uint32_t            is_country;
} pmap_location_t;

/* fields from the GeoIP2 files that are allowed to be checked for a
 * valid country code.  may be selected by the --fields switch. */
typedef enum pmap_fields_en {
    PMAP_FIELD_LOCATION = 0,
    PMAP_FIELD_REGISTERED = 1,
    PMAP_FIELD_REPRESENTED = 2,
    PMAP_FIELD_CONTINENT = 3,
    PMAP_FIELD_FLAGS = 4,
    PMAP_FIELD_END = 0xff
} pmap_fields_t;


/* LOCAL VARIABLE DEFINITIONS */

/* the pmap that we create */
static skPrefixMap_t *map = NULL;

/* information for the current legacy statement */
static pmap_legacy_t legacy;

/* names of the columns (fields, values) that appear in the
 * GeoLite2-Country-Blocks-IPv{4,6}.csv files */
static const char *ipblocks_columns[] = {
    "network", "geoname_id",
    "registered_country_geoname_id", "represented_country_geoname_id",
    "is_anonymous_proxy", "is_satellite_provider"
};

/* names of the columns (fields, values) that appear in the
 * GeoLite2-Country-Locations-en.csv file */
static const char *location_columns[] = {
    "geoname_id", "locale_code", "continent_code",
    "continent_name", "country_iso_code", "country_name"
    /* ignore this column that we do not use: "is_in_european_union" */
};

/* number of columns in a GeoIP2 CSV Blocks file.  The value set here
 * is a minimum, and the value will be set according to the number of
 * column titles actually read from the file.  Every data line after
 * the title must contain the same number of fields as the title. */
static unsigned int ipblocks_columns_count =
    sizeof(ipblocks_columns)/sizeof(ipblocks_columns[0]);

/* similar to 'ipblocks_columns_count' for the location columns */
static unsigned int location_columns_count =
    sizeof(location_columns)/sizeof(location_columns[0]);

/* information for the current GeoIP2 ipblocks statement */
static pmap_ipblocks_t ipblocks;

/* information for the current GeoIP2 location statement */
static pmap_location_t location;

/* the default order in which the geoname_id values from the GeoIP2
 * files are selected */
static pmap_fields_t fields[6] = {
    PMAP_FIELD_LOCATION, PMAP_FIELD_REGISTERED, PMAP_FIELD_REPRESENTED,
    PMAP_FIELD_CONTINENT, PMAP_FIELD_FLAGS, PMAP_FIELD_END
};

/* mapping from field names to values; used to parse the argument to
 * the --fields switch */
static sk_stringmap_entry_t fields_map_entries[] = {
    {"location",        PMAP_FIELD_LOCATION,
     "Value of the geoname_id field", NULL},
    {"registered",      PMAP_FIELD_REGISTERED,
     "Value of the registered_country_geoname_id field", NULL},
    {"represented",     PMAP_FIELD_REPRESENTED,
     "Value of the represented_country_geoname_id field", NULL},
    {"continent",       PMAP_FIELD_CONTINENT,
     "Use the first continent value found across all fields", NULL},
    {"flags",           PMAP_FIELD_FLAGS,
     "Value of is_anonymous_proxy and is_satellite_provider flags", NULL},
    SK_STRINGMAP_SENTINEL
};

/* the string-map for field names */
static sk_stringmap_t *fields_map = NULL;

/* mapping from geoname_id to country code. this is filled with the
 * data read from the location file */
static struct rbtree *geomap = NULL;

/* parser state to use with BEGIN after handling an error */
static int next_state;

/* which line of input we are reading */
static unsigned int linenum = 1;

/* which column (field, value) number of the current input line are we
 * reading.  first column is 0 */
static unsigned int column = 0;

/* number of errors encountered during processing */
static unsigned int error_count = 0;

/* the type of the input varies in three ways: ipv4 vs ipv6, csv vs
 * binary, GeoIP2 vs legacy.  by default, the type is determined by
 * reading a bit of the input */
static struct mode_st {
    geoip2ccmap_mode_t ipv6_ipv4;
    geoip2ccmap_mode_t csv_binary;
    geoip2ccmap_mode_t geoip2_legacy;
} mode = {
    GEOIP2CCMAP_MODE_AUTO, GEOIP2CCMAP_MODE_AUTO, GEOIP2CCMAP_MODE_AUTO
};

/* default country code value */
static uint32_t default_value;

/* structure to map between mode names and mode IDs; used when parsing
 * the --mode switch */
static const sk_stringmap_entry_t mode_map_entries[] = {
    {"auto",       GEOIP2CCMAP_MODE_AUTO,
     "Automatically determine the type of input",               NULL},
    {"ipv6",       GEOIP2CCMAP_MODE_IPV6,
#if SK_ENABLE_IPV6
     "Create an IPv6 country code prefix map",
#else
     "Exit with error; IPv6 support not available",
#endif  /* SK_ENABLE_IPV6 */
     NULL},
    {"ipv4",       GEOIP2CCMAP_MODE_IPV4,
     "Create an IPv6 country code prefix map",                  NULL},
    {"csv",        GEOIP2CCMAP_MODE_CSV,
     "Read textual input containing comma-separated values",    NULL},
    {"binary",     GEOIP2CCMAP_MODE_BINARY,
#ifdef SK_ENABLE_LIBMAXMINDDB
     "Read MaxMind binary input",
#else
     "Read MaxMind Legacy binary input (GeoIP2 unsupported)",
#endif  /* SK_ENABLE_LIBMAXMINDDB */
     NULL},
    {"geoip2",     GEOIP2CCMAP_MODE_GEOIP2,
#ifdef SK_ENABLE_LIBMAXMINDDB
     "Read input in the GeoIP2 binary or CSV formats",
#else
     "Read input in the GeoIP2 CSV format (binary unsupported)",
#endif  /* SK_ENABLE_LIBMAXMINDDB */
     NULL},
    {"legacy",     GEOIP2CCMAP_MODE_LEGACY,
     "Read input in the GeoIP Legacy format",                   NULL},
    SK_STRINGMAP_SENTINEL
};

/* the stringmap created from the mode_map_entries */
static sk_stringmap_t *mode_map = NULL;

/* the current input stream.  may be one of the files in the
 * csv2_directory or a MaxMind Legacy GeoIP file containing either CSV
 * data or binary data */
static sk_fileptr_t in_stream;

#ifdef SK_ENABLE_LIBMAXMINDDB
/* the GeoIP2 binary database file */
static const char *mmdb_path = NULL;
#endif  /* SK_ENABLE_LIBMAXMINDDB */

/* directory containing the MaxMind GeoIP2 CSV files */
static const char *csv2_directory = NULL;

/* values to prepend onto the names in csv2_files[] below */
static const char *csv2_products[] = {"GeoIP2", "GeoLite2", NULL};

/* for CSV GoeIP2 data, the input-path is a directory, and this struct
 * contains the back half of names of the files in the directory.
 * These values are prefixed by one of the values from the
 * csv2_products[] array.  If the 'mode' member of this struct is
 * auto, the file is always processed.  Otherwise the global mode must
 * match the 'mode' member. */
static const struct csv2_files_st {
    geoip2ccmap_mode_t  mode;
    const char         *path;
} csv2_files[] = {
    {GEOIP2CCMAP_MODE_AUTO,     "-Country-Locations-en.csv"},
    {GEOIP2CCMAP_MODE_IPV6,     "-Country-Blocks-IPv6.csv"},
    {GEOIP2CCMAP_MODE_AUTO,     "-Country-Blocks-IPv4.csv"},
    {GEOIP2CCMAP_MODE_BINARY,   NULL} /* sentinel */
};

/* the name of the csv2 product; points into csv2_products */
static const char *csv2_prod = NULL;

/* an index into csv2_files[] pointing at the next file to use */
static unsigned int csv2_index = 0;

/* output stream for the resulting prefix map */
static skstream_t *out_stream = NULL;

/* do not write the output file; simply check syntax of the input.
 * set by --dry-run */
static int dry_run = 0;

/* do not record the command line invocation in the generated prefix
 * map file. set by --invocation-strip */
static int invocation_strip = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_INPUT_PATH,
    OPT_OUTPUT_PATH,
    OPT_MODE,
    OPT_DRY_RUN,
    OPT_INVOCATION_STRIP,
    OPT_FIELDS,
    OPT_CSV_INPUT,
    OPT_V6_CSV_INPUT,
    OPT_ENCODED_INPUT
} appOptionsEnum;

/* how to map old input switches to modes. keep in sync! */
static const char *input_modes[] = {
     /* OPT_CSV_INPUT     */    "ipv4,csv,legacy",
     /* OPT_V6_CSV_INPUT  */    "ipv6,csv,legacy",
     /* OPT_ENCODED_INPUT */    "binary,legacy"
};

static struct option appOptions[] = {
    {"input-path",          REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"mode",                REQUIRED_ARG, 0, OPT_MODE},
    {"dry-run",             NO_ARG,       0, OPT_DRY_RUN},
    {"invocation-strip",    NO_ARG,       0, OPT_INVOCATION_STRIP},
    {"fields",              REQUIRED_ARG, 0, OPT_FIELDS},
    {0,0,0,0}               /* sentinel entry */
};


static const char *appHelp[] = {
    ("Read the MaxMind country code data from this location.\n"
     "\tFor GeoIP2 CSV data, must be the directory containing the files.\n"
     "\tGeoIP Legacy data may be read from the standard input"),
    ("Write the binary country code prefix map to this file or\n"
     "\tto the standard output when the switch is not provided"),
    ("Set the type of the input and the type country code file to\n"
     "\tcreate. By default, the type of prefix map is determined by the\n"
     "\tfirst IP address seen."),
    "Parse the input but do not write the output file",
    ("Strip invocation history from the prefix map file.\n"
     "\tDef. Record command used to create the file"),
    ("Choose which of the fields provided by GeoIP2 data files\n"
     "\tare checked for a valid country code.\n"),
    (char *)NULL
};

static struct option deprecatedOptions[] = {
    {"csv-input",       NO_ARG,       0, OPT_CSV_INPUT},
    {"v6-csv-input",    NO_ARG,       0, OPT_V6_CSV_INPUT},
    {"encoded-input",   NO_ARG,       0, OPT_ENCODED_INPUT},
    {"input-file",      REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"output-file",     REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {0,0,0,0}           /* sentinel entry */
};

static const char *deprecatedHelp[] = {
    ("Replace with --mode=ipv4,csv,legacy.\n"
     "\tAssume the input is the CSV GeoIP Legacy country code data for IPv4"),
    ("Replace with --mode=ipv6,csv,legacy.\n"
     "\tAssume the input is the CSV GeoIP Legacy country code data for IPv6"),
    ("Replace with --mode=binary,legacy.\n"
     "\tAssume the input is binary GeoIP Legacy country code data for either\n"
     "\tIPv4 or IPv6"),
    ("Replace with --input-path.\n"
     "\tRead the GeoIP country code data from this file"),
    ("Replace with --output-path.\n"
     "\tWrite the binary prefix map to this file"),
    (char *)NULL
};

/* allow the shortest unique prefixes for input-{path,file} and
 * output-{path,file} */
static struct option deprecatedOptionsShort[] = {
    /* --inp is required due to --invocation-strip */
    {"input-",          REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"input",           REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"inpu",            REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"inp",             REQUIRED_ARG, 0, OPT_INPUT_PATH},
    /* --o is sufficient */
    {"output-",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"output",          REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"outpu",           REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"outp",            REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"out",             REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"ou",              REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"o",               REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {0,0,0,0}           /* sentinel entry */
};


/* LOCAL FUNCTION PROTOTYPES */

static int appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int parseFields(int idx, const char *str);
static int parseMode(int idx, const char *str);
static const char *modeToName(geoip2ccmap_mode_t m);
static int resolveInputModes(void);
#ifdef TEST_PRINTF_FORMATS
#define scanWarn printf
#else
static int scanWarn(const char *fmt, ...)
    SK_CHECK_PRINTF(1, 2);
#endif  /* TEST_PRINTF_FORMATS */
#define scanErr  ++error_count; scanWarn

static int csv2NextFile(void);

static int  legacyColumn(const char *string);
static void legacyCreateEntry(void);
static void legacyReset(void);

static int  csv2Column(const char *string);
static void csv2CreateEntry(void);
static void csv2Reset(void);

/* to keep gcc quiet  */
int yylex(void);


SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

/*  *****  LEX INPUT FOLLOWS  *****  */

%}

%option prefix="geoip2ccmap_" outfile="lex.yy.c"
%option never-interactive
%option noinput nounput noreject

    /* %option noyywrap  -- use a function to avoid gcc warning */
    /* %option noyyget_extra noyyset_extra noyyget_leng noyyget_text */
    /* %option noyyget_lineno noyyset_lineno noyyget_in noyyset_in */
    /* %option noyyget_out noyyset_out noyyget_lval noyyset_lval */
    /* %option noyyget_lloc noyyset_lloc noyyget_debug noyyset_debug */

%x ST_CSV2
%x ST_CSV2_DQ
%x ST_CSV2_NEXT
%x ST_CSV2_ERROR

%x ST_LEG_ENTRY
%x ST_LEG_CLOSE_ENTRY
%x ST_LEG_NEXT_ENTRY
%x ST_LEG_ERROR

ws_opt      [ \t\r]*

nl          [ \t\r]*\n

dq          \"
not_dq      [^\"\r\n]+

not_comma   [^,\r\n]

unquoted    [^,\"\r\n]+

%%

<ST_CSV2>{unquoted}                   { if (csv2Column(yytext)) {
                                            BEGIN(ST_CSV2_ERROR);
                                        } else {
                                            BEGIN(ST_CSV2_NEXT);
                                        } }

<ST_CSV2_DQ>{not_dq}                  { if (csv2Column(yytext)) {
                                            next_state = ST_CSV2;
                                            BEGIN(ST_CSV2_ERROR);
                                        } }

<ST_CSV2>{dq}                         { BEGIN(ST_CSV2_DQ); }
<ST_CSV2_DQ>{dq}                      { BEGIN(ST_CSV2_NEXT); }
<ST_CSV2_NEXT>,+                      { column += yyleng;
                                        BEGIN(ST_CSV2); }

<ST_CSV2_NEXT>,+{nl}                  |
<ST_CSV2_NEXT>{nl}                    { column += yyleng;
                                        csv2CreateEntry();
                                        ++linenum;
                                        csv2Reset();
                                        BEGIN(ST_CSV2); }

<ST_CSV2><<EOF>>                      { if (column) {
                                            csv2CreateEntry();
                                        }
                                        if (csv2NextFile()) {
                                            return 0;
                                        }
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }
<ST_CSV2_NEXT><<EOF>>                 { /* unusual */
                                        if (column) {
                                            ++column;
                                            csv2CreateEntry();
                                        }
                                        if (csv2NextFile()) {
                                            return 0;
                                        }
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }

<ST_CSV2>{nl}                         { /* probably an error */
                                        if (column) {
                                            csv2CreateEntry();
                                        }
                                        ++linenum;
                                        csv2Reset();
                                      }

<ST_CSV2_DQ>{nl}                      { scanErr("Closing quote not found");
                                        ++linenum;
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }
<ST_CSV2_DQ><<EOF>>                   { scanErr("Closing quote not found");
                                        if (csv2NextFile()) {
                                            return 0;
                                        }
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }

<ST_CSV2,ST_CSV2_NEXT>{ws_opt}        ;
<ST_CSV2_NEXT>{not_comma}             { scanErr("Expected ',', found %c",
                                                *yytext);
                                        next_state = ST_CSV2;
                                        BEGIN(ST_CSV2_ERROR);
                                      }

<ST_CSV2_ERROR>.+                     ;
<ST_CSV2_ERROR>{nl}                   { ++linenum;
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }
<ST_CSV2_ERROR><<EOF>>                { if (csv2NextFile()) {
                                            return 0;
                                        }
                                        csv2Reset();
                                        BEGIN(ST_CSV2);
                                      }



<INITIAL>{nl}                         { ++linenum; legacyReset(); }
<INITIAL>{ws_opt}{dq}                 { BEGIN(ST_LEG_ENTRY); }

<ST_LEG_ENTRY>{not_dq}                { if (legacyColumn(yytext)) {
                                            BEGIN(ST_LEG_ERROR);
                                        } else {
                                            BEGIN(ST_LEG_CLOSE_ENTRY);
                                        } }

<ST_LEG_CLOSE_ENTRY>{dq}              { BEGIN(ST_LEG_NEXT_ENTRY); }
<ST_LEG_NEXT_ENTRY>,                  { ++column; }
<ST_LEG_NEXT_ENTRY>{dq}               { BEGIN(ST_LEG_ENTRY); }
<ST_LEG_NEXT_ENTRY>{ws_opt}           ;

<ST_LEG_NEXT_ENTRY>{nl}               |
<ST_LEG_NEXT_ENTRY><<EOF>>            { ++column;
                                        legacyCreateEntry();
                                        ++linenum;
                                        legacyReset();
                                        BEGIN(INITIAL); }

<ST_LEG_ENTRY>{dq}                    { scanErr("Column %u is empty string",
                                                column);
                                        BEGIN(ST_LEG_ERROR);
                                      }

<ST_LEG_ENTRY,ST_LEG_CLOSE_ENTRY>\n   { scanErr(("Unexpected end-of-line"
                                                 " found in column %u"),
                                                column);
                                        ++linenum;
                                        legacyReset();
                                        BEGIN(INITIAL); }

<ST_LEG_ENTRY,ST_LEG_CLOSE_ENTRY><<EOF>> {
                                        scanErr(("Unexpected end-of-stream"
                                                 " found in column %u"),
                                                column);
                                        return 0; }

.                                     { scanErr("Unexpected input '%c'",
                                                *yytext);
                                        BEGIN(ST_LEG_ERROR); }

<ST_LEG_ERROR>.*                      ;
<ST_LEG_ERROR>\n                      { ++linenum;
                                        legacyReset();
                                        BEGIN(INITIAL); }

<INITIAL,ST_LEG_ERROR><<EOF>>         { return 0; }

%%

SK_DIAGNOSTIC_IGNORE_POP("-Wwrite-strings")

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
#define USAGE_MSG1                                                            \
    ("[SWITCHES]\n"                                                           \
     "\tCreate a binary prefix map file from country code data in the\n"      \
     "\tMaxMind GeoIP2 or GeoIP Legacy formats or the GeoLite versions of\n")
#ifdef SK_ENABLE_LIBMAXMINDDB
#define USAGE_MSG2                                                            \
    ("\teither. The comma-separated value (CSV) and binary formats of all\n"  \
     "\tMaxMind formats is available.\n")
#else
#define USAGE_MSG2                                                            \
    ("\teither. The comma-separated value (CSV) of all formats is\n"          \
     "\tsupported as are GeoIP Legacy binary files; GeoIP2 binary file\n"     \
     "\tsupport is not available due to a missing separate library.\n")
#endif  /* SK_ENABLE_LIBMAXMINDDB */
#define USAGE_MSG3                                                            \
    ("\tThe data is read from the named input-path or from the standard\n"    \
     "\tinput. The prefix map file is written to the named output-path or\n"  \
     "\tto the standard output when it is not connected to a terminal.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;
    unsigned int j;
    const char *name;

#define FILL_FIELD_NAME(m)                                              \
    name = skStringMapGetFirstName(fields_map, (sk_stringmap_id_t)m);   \
    if (NULL == name) {                                                 \
        skAppPrintErr("Unknown field value %d", (int)m);                \
        skAbort();                                                      \
    }

    fprintf(fh, "%s %s%s%s", skAppName(), USAGE_MSG1, USAGE_MSG2, USAGE_MSG3);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        switch (appOptions[i].val) {
          case OPT_MODE:
            fprintf(fh, "--%s %s. %s\tDef. %s. Choices:\n",
                    appOptions[i].name,
                    SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i],
                    modeToName(GEOIP2CCMAP_MODE_AUTO));
            skStringMapPrintDetailedUsage(mode_map, fh);
            break;

          case OPT_FIELDS:
            FILL_FIELD_NAME(fields[0])
            fprintf(fh, "--%s %s. %s\tDef. %s",
                    appOptions[i].name,
                    SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i], name);
            for (j = 1; j < sizeof(fields)/sizeof(fields[0]); ++j) {
                if (PMAP_FIELD_END == fields[j]) {
                    break;
                }
                FILL_FIELD_NAME(fields[j])
                fprintf(fh, ",%s", name);
            }
            fprintf(fh, ". Choices:\n");
            skStringMapPrintDetailedUsage(fields_map, fh);
            break;

          case OPT_INVOCATION_STRIP:
            /* include the help for --notes before
             * --invocation-strip */
            skOptionsNotesUsage(fh);
            /* FALLTHROUGH */

          default:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                    SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
            break;
        }
    }

    fprintf(fh, "\nDEPRECATED SWITCHES:\n");
    for (i = 0; deprecatedOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", deprecatedOptions[i].name,
                SK_OPTION_HAS_ARG(deprecatedOptions[i]), deprecatedHelp[i]);
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

    /* close streams; destroy prefix map */
    skFileptrClose(&in_stream, NULL);
    skStreamDestroy(&out_stream);
    if (map) {
        skPrefixMapDelete(map);
    }

    if (geomap) {
        pmap_location_t *entry;
        RBLIST *iter;

        iter = rbopenlist(geomap);
        while ((entry = (pmap_location_t *)rbreadlist(iter)) != NULL) {
            free(entry);
        }
        rbcloselist(iter);
        rbdestroy(geomap);
    }

    skStringMapDestroy(mode_map);
    skStringMapDestroy(fields_map);
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
    ssize_t rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);
    memset(&in_stream, 0, sizeof(in_stream));

    /* initialize */
    default_value = skCountryNameToCode(DEFAULT_LABEL);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(deprecatedOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(deprecatedOptionsShort, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL))
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

    /* create the string maps */
    if ((rv = skStringMapCreate(&mode_map))
        || (rv = skStringMapAddEntries(mode_map, -1, mode_map_entries)))
    {
        skAppPrintErr("Unable to create mode string map: %s",
                      skStringMapStrerror(rv));
        exit(EXIT_FAILURE);
    }
    if ((rv = skStringMapCreate(&fields_map))
        || (rv = skStringMapAddEntries(fields_map, -1, fields_map_entries)))
    {
        skAppPrintErr("Unable to create fields string map: %s",
                      skStringMapStrerror(rv));
        exit(EXIT_FAILURE);
    }

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage(); /* never returns */
    }

    /* complain about extra args on command line */
    if (arg_index != argc) {
        skAppPrintErr("Too many or unrecognized argument specified: '%s'",
                      argv[arg_index]);
        exit(EXIT_FAILURE);
    }

    /* determine the input modes (CSV vs binary, GeoIP2 vs legacy).
     * Set csv2_directory or mmdb_path for GeoIP2 input, or open input
     * file if in legacy mode */
    if (resolveInputModes()) {
        exit(EXIT_FAILURE);
    }
    assert(GEOIP2CCMAP_MODE_AUTO != mode.csv_binary);
    assert(GEOIP2CCMAP_MODE_AUTO != mode.geoip2_legacy);
    assert(NULL == csv2_directory
           || (GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy
               && GEOIP2CCMAP_MODE_CSV == mode.csv_binary));
#ifdef SK_ENABLE_LIBMAXMINDDB
    assert(NULL == mmdb_path
           || (GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy
               && GEOIP2CCMAP_MODE_BINARY == mode.csv_binary));
#endif  /* SK_ENABLE_LIBMAXMINDDB */

    /* output is "stdout" if none specified.  do not bind to stdout
     * when --dry-run is active */
    if (!out_stream && !dry_run) {
        if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
            || (rv = skStreamBind(out_stream, "stdout")))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    return; /* OK */
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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    ssize_t rv;
    int idx;

    SK_UNUSED_PARAM(cData);

    switch ((appOptionsEnum)opt_index) {
      case OPT_INPUT_PATH:
        if (in_stream.of_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        in_stream.of_name = opt_arg;
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
            skStreamDestroy(&out_stream);
            return 1;
        }
        break;

      case OPT_MODE:
        if (parseMode(opt_index, opt_arg)) {
            return 1;
        }
        break;

      case OPT_FIELDS:
        if (parseFields(opt_index, opt_arg)) {
            return 1;
        }
        break;

      case OPT_DRY_RUN:
        dry_run = 1;
        break;

      case OPT_INVOCATION_STRIP:
        invocation_strip = 1;
        break;

      case OPT_CSV_INPUT:
      case OPT_V6_CSV_INPUT:
      case OPT_ENCODED_INPUT:
        idx = opt_index - OPT_CSV_INPUT;
        if (idx >= (int)(sizeof(input_modes)/sizeof(input_modes[0]))
            || idx < 0)
        {
            skAppPrintErr("Programmer error: Invalid mode %d", idx);
            skAbort();
        }
        rv = parseMode(opt_index, input_modes[idx]);
        if (rv) {
            if (1 == rv) {
                skAppPrintErr("Programmer error: Invalid mode %s",
                              input_modes[idx]);
                skAbort();
            }
            return 1;
        }
        break;
    }

    return 0; /* OK */
}


/*
 *    Parse the value in 'string' as a comma-separated list of the
 *    geoname_id fields to use from the GeoIP2 files and set the
 *    appropriate global variables.
 *
 *    Return 0 on success.  Return 1 if the fields has already been
 *    set.  Return -1 if 'string' does not match a valid field.
 */
static int
parseFields(
    int                 opt_index,
    const char         *string)
{
    static int fields_switch_seen = 0;
    sk_stringmap_entry_t *map_entry;
    sk_stringmap_iter_t *iter = NULL;
    unsigned int i;
    char *errmsg;
    int rv = -1;

    if (fields_switch_seen) {
        skAppPrintErr("Invalid %s: Attempting to set fields multiple times",
                      appOptions[opt_index].name);
        return 1;
    }
    fields_switch_seen = 1;

    if (skStringMapParse(fields_map, string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[opt_index].name, errmsg);
        goto END;
    }
    i = 0;
    while (skStringMapIterNext(iter, &map_entry, NULL) == SK_ITERATOR_OK) {
        assert(i < sizeof(fields)/sizeof(fields[0]));
        fields[i] = (pmap_fields_t)map_entry->id;
        ++i;
    }
    assert(i < sizeof(fields)/sizeof(fields[0]));
    fields[i] = PMAP_FIELD_END;

    /* success */
    rv = 0;

  END:
    skStringMapIterDestroy(iter);
    return rv;
}


/*
 *    Parse the value in 'string' as a comma-separated list of the
 *    names input/output modes and set the appropriate global
 *    variables.
 *
 *    Return 0 on success.  Return 1 if the mode has already been set.
 *    Return -1 if 'string' does not match a mode.
 */
static int
parseMode(
    int                 opt_index,
    const char         *string)
{
    static int mode_switch_seen = 0;
    sk_stringmap_entry_t *map_entry;
    sk_stringmap_iter_t *iter = NULL;
    char *errmsg;
    int rv = -1;
    int seen_ipv6_ipv4 = 0;
    int seen_csv_binary = 0;
    int seen_geoip2_legacy = 0;

#define CHECK_CHOICE(m_var, m_choice1, m_choice2)                       \
    if (!m_var) {                                                       \
        m_var = 1;                                                      \
    } else {                                                            \
        skAppPrintErr("Invalid %s: Conflicting choices: %s vs %s",      \
                      appOptions[opt_index].name,                       \
                      modeToName(m_choice1), modeToName(m_choice2));    \
        goto END;                                                       \
    }

    if (mode_switch_seen) {
        skAppPrintErr("Invalid %s: Attempting to set mode multiple times",
                      appOptions[opt_index].name);
        return 1;
    }
    mode_switch_seen = 1;

    if (skStringMapParse(mode_map, string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[opt_index].name, errmsg);
        goto END;
    }
    while (skStringMapIterNext(iter, &map_entry, NULL) == SK_ITERATOR_OK) {
        switch ((geoip2ccmap_mode_t)map_entry->id) {
          case GEOIP2CCMAP_MODE_IPV6:
          case GEOIP2CCMAP_MODE_IPV4:
            CHECK_CHOICE(seen_ipv6_ipv4,
                         GEOIP2CCMAP_MODE_IPV6, GEOIP2CCMAP_MODE_IPV4);
            mode.ipv6_ipv4 = (geoip2ccmap_mode_t)map_entry->id;
            continue;
          case GEOIP2CCMAP_MODE_BINARY:
          case GEOIP2CCMAP_MODE_CSV:
            CHECK_CHOICE(seen_csv_binary,
                         GEOIP2CCMAP_MODE_BINARY, GEOIP2CCMAP_MODE_CSV);
            mode.csv_binary = (geoip2ccmap_mode_t)map_entry->id;
            continue;
          case GEOIP2CCMAP_MODE_GEOIP2:
          case GEOIP2CCMAP_MODE_LEGACY:
            CHECK_CHOICE(seen_geoip2_legacy,
                         GEOIP2CCMAP_MODE_GEOIP2, GEOIP2CCMAP_MODE_LEGACY);
            mode.geoip2_legacy = (geoip2ccmap_mode_t)map_entry->id;
            continue;
          case GEOIP2CCMAP_MODE_AUTO:
            continue;
        }
        skAbortBadCase(map_entry->id);
    }

#if !SK_ENABLE_IPV6
    if (GEOIP2CCMAP_MODE_IPV6 == mode.ipv6_ipv4) {
        skAppPrintErr(("Unsupported %s: This SiLK installation was"
                       " built without IPv6 address support"),
                      appOptions[opt_index].name);
        goto END;
    }
#endif  /* !SK_ENABLE_IPV6 */
#if !defined(SK_ENABLE_LIBMAXMINDDB)
    if (GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy
        && GEOIP2CCMAP_MODE_BINARY == mode.csv_binary)
    {
        skAppPrintErr(("Unsupported %s: This SiLK installation was"
                      " built without support for GeoIP2 binary files"),
                      appOptions[opt_index].name);
        goto END;
    }
#endif  /* !SK_ENABLE_LIBMAXMINDDB */

    /* success */
    rv = 0;

  END:
    skStringMapIterDestroy(iter);
    return rv;
}


/*
 *  name = modeToName(mode);
 *
 *    Return the string that presents the mode 'mode'.  Abort if
 *    'mode' is not a valid mode.
 */
static const char *
modeToName(
    geoip2ccmap_mode_t  m)
{
    const char *name;

    name = skStringMapGetFirstName(mode_map, (sk_stringmap_id_t)m);
    if (NULL == name) {
        skAppPrintErr("Unknown mode value %d", (int)m);
        skAbort();
    }
    return name;
}


/*
 *    Check that the string the user provided as the directory
 *    containing the GeoIP2 files is a directory and contains the
 *    necessary files.
 *
 *    This function sets the global 'csv2_prod' to the proper prefix
 *    depending on the files that it finds.
 */
static int
csv2CheckDirectory(
    void)
{
    char path[PATH_MAX];
    unsigned int found = 0;
    unsigned int i, j;
    ssize_t sz;

    errno = 0;
    if (!skDirExists(csv2_directory)) {
        skAppPrintErr("Invalid %s for %s=%s,%s '%s': %s",
                      appOptions[OPT_INPUT_PATH].name,
                      appOptions[OPT_MODE].name,
                      modeToName(GEOIP2CCMAP_MODE_GEOIP2),
                      modeToName(GEOIP2CCMAP_MODE_CSV), csv2_directory,
                      ((0 == errno) ? "Is not a directory" : strerror(errno)));
        return 1;
    }

    for (j = 0; (csv2_prod = csv2_products[j]) != NULL; ++j) {
        found = 0;
        for (i = 0; csv2_files[i].path != NULL; ++i) {
            sz = snprintf(path, sizeof(path), "%s/%s%s",
                          csv2_directory, csv2_prod, csv2_files[i].path);
            if ((size_t)sz >= sizeof(path)) {
                skAppPrintErr(("File path for %s too long (%" SK_PRIuZ
                               " < %" SK_PRIdZ ")"),
                              csv2_files[i].path, sizeof(path), sz);
                return 1;
            }
            if (skFileExists(path)) {
                ++found;
            } else if (0 == found) {
                break;
            } else {
                skAppPrintErr(
                    "Invalid %s: Expected file %s%s not found: %s",
                    appOptions[OPT_INPUT_PATH].name,
                    csv2_prod, csv2_files[i].path,
                    ((0 == errno) ? "Is not a file" : strerror(errno)));
                return 1;
            }
        }
        if (1u + found == sizeof(csv2_files)/sizeof(csv2_files[0])) {
            break;
        }
    }
    if (NULL == csv2_prod) {
        /* FIXME: do not assume 2 csv2_products */
        skAppPrintErr("Invalid %s: Expected file %s%s or %s%s not found",
                      appOptions[OPT_INPUT_PATH].name,
                      csv2_products[0], csv2_files[0].path,
                      csv2_products[1], csv2_files[0].path);
        return 1;
    }

    return 0;
}


/*
 *    Determine the input modes (GeoIP2 vs legacy, CSV vs binary).
 *
 *    Set 'csv2_directory' for GeoIP2+CSV; set 'mmdb_path' for
 *    GeoIP2+binary input, or open input file if in either legacy
 *    mode.
 *
 *    Return 0 on success, or -1 on failure.
 */
static int
resolveInputModes(
    void)
{
    const char *errmsg = NULL;
    size_t len;
    ssize_t rv;
    int c;

#define SET_MODE_IF_AUTO(m_member, m_mode, m_reason)                    \
    if (GEOIP2CCMAP_MODE_AUTO == mode.m_member) {                       \
        TRACEMSG(("Setting mode." #m_member " to " #m_mode ": %s",      \
                  m_reason));                                           \
        mode.m_member = m_mode;                                         \
    }

    if (GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy) {
        if (NULL == in_stream.of_name) {
            skAppPrintErr("Must specify --%s for --%s=%s",
                          appOptions[OPT_INPUT_PATH].name,
                          appOptions[OPT_MODE].name,
                          modeToName(GEOIP2CCMAP_MODE_GEOIP2));
            return -1;
        }
        len = strlen(in_stream.of_name);
        if (0 == strcmp("stdin", in_stream.of_name)
            || 0 == strcmp("-", in_stream.of_name))
        {
            errmsg = "May not use the standard input";
        } else if (len > 3 && 0 == strcmp(&in_stream.of_name[len-3], ".gz")) {
            errmsg = "May not use a compressed stream";
        } else if (isFIFO(in_stream.of_name)) {
            errmsg = "May not use a named pipe";
        }
        if (errmsg) {
            skAppPrintErr("Invalid %s for --%s=%s '%s': %s",
                          appOptions[OPT_INPUT_PATH].name,
                          appOptions[OPT_MODE].name,
                          modeToName(GEOIP2CCMAP_MODE_GEOIP2),
                          in_stream.of_name, errmsg);
            return -1;
        }
        if (GEOIP2CCMAP_MODE_CSV == mode.csv_binary
            || (GEOIP2CCMAP_MODE_AUTO == mode.csv_binary
                && skDirExists(in_stream.of_name)))
        {
            SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_CSV,
                             "input-path is directory");
            csv2_directory = in_stream.of_name;
            if (csv2CheckDirectory()) {
                return -1;
            }
        } else
#ifndef SK_ENABLE_LIBMAXMINDDB
        {
            if (GEOIP2CCMAP_MODE_BINARY == mode.csv_binary) {
                skAppPrintErr(("Unsupported %s: This SiLK installation lacks"
                               " support for GeoIP2 binary files"),
                              appOptions[OPT_MODE].name);
            } else {
                assert(GEOIP2CCMAP_MODE_AUTO == mode.csv_binary);
                skAppPrintErr("Invalid %s '%s': %s",
                              appOptions[OPT_INPUT_PATH].name,
                              in_stream.of_name,
                              ((0 == errno)
                               ? ("Is not a directory and GeoIP2 binary"
                                  " file support is not available")
                               : strerror(errno)));
            }
            return -1;
        }
#else  /* SK_ENABLE_LIBMAXMINDDB */
        {
            SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_BINARY,
                             "input-path is not directory");
            if (!skFileExists(in_stream.of_name)) {
                skAppPrintErr("Invalid %s for --%s=%s '%s': %s",
                              appOptions[OPT_INPUT_PATH].name,
                              appOptions[OPT_MODE].name,
                              modeToName(GEOIP2CCMAP_MODE_BINARY),
                              in_stream.of_name,
                              ((0 == errno)
                               ? "Is not a file" : strerror(errno)));
                return -1;
            }
            mmdb_path = in_stream.of_name;
        }
#endif  /* #else of #ifndef SK_ENABLE_LIBMAXMINDDB */
        in_stream.of_name = NULL;
        assert(GEOIP2CCMAP_MODE_AUTO != mode.csv_binary);
    } else {
        /* a NULL input-path forces legacy mode */
        if (NULL == in_stream.of_name) {
            SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                             "input-path is NULL");
            if (FILEIsATty(stdin)) {
                skAppPrintErr("Specify '--%s=-' to read from the terminal",
                              appOptions[OPT_INPUT_PATH].name);
                return -1;
            }
            in_stream.of_name = "-";
        }
        rv = skFileptrOpen(&in_stream, SK_IO_READ);
        if (rv) {
            skAppPrintErr("Unable to open %s '%s': %s",
                          appOptions[OPT_INPUT_PATH].name,
                          in_stream.of_name, skFileptrStrerror(rv));
            return -1;
        }
        if (SK_FILEPTR_IS_STDIO == in_stream.of_type
            || SK_FILEPTR_IS_PROCESS == in_stream.of_type)
        {
            SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                             "input-path is stdio/process");
        }

        /* read first char to see if stream is binary */
        c = getc(in_stream.of_fp);
        if (EOF == c) {
            /* error or stream is empty */
            if (ferror(in_stream.of_fp)) {
                int saved = errno;
                if (GEOIP2CCMAP_MODE_BINARY == mode.csv_binary
                    || GEOIP2CCMAP_MODE_LEGACY == mode.geoip2_legacy
                    || (EISDIR != errno && EBADF != errno))
                {
                    skAppPrintErr("Unable to read from '%s': %s",
                                  in_stream.of_name, strerror(saved));
                    return -1;
                }
                assert(GEOIP2CCMAP_MODE_AUTO == mode.geoip2_legacy);
                if (in_stream.of_type != SK_FILEPTR_IS_STDIO
                    && skDirExists(in_stream.of_name))
                {
                    csv2_directory = in_stream.of_name;
                    if (csv2CheckDirectory()) {
                        return -1;
                    }
                    SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_GEOIP2,
                                     "is a directory");
                    SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_CSV,
                                     "is a directory");
                    skFileptrClose(&in_stream, NULL);
                    in_stream.of_fp = NULL;
                    in_stream.of_name = NULL;
                } else {
                    skAppPrintErr("Unable to read from '%s': %s",
                                  in_stream.of_name, strerror(saved));
                    return -1;
                }
            } else {
                /* file is empty; treat as legacy CSV */
                SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_CSV,
                                 "file is empty");
                SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                                 "file is empty");
            }
        } else {
            /* is a readable stream */
            if (!isprint(c) && !isspace(c)) {
                /* assume it is a binary stream */
                SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_BINARY,
                                 "read non-printable char");
                if (GEOIP2CCMAP_MODE_BINARY != mode.csv_binary) {
                    skAppPrintErr("Invalid %s for --%s=%s '%s': %s",
                                  appOptions[OPT_INPUT_PATH].name,
                                  appOptions[OPT_MODE].name,
                                  modeToName(GEOIP2CCMAP_MODE_CSV),
                                  in_stream.of_name,
                                  "File contains binary characters");
                    return -1;
                }
            } else {
                /* assume it is a text stream */
                SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                                 "read printable char; cannot be directory");
                SET_MODE_IF_AUTO(csv_binary, GEOIP2CCMAP_MODE_CSV,
                                 "read printable char");
                if (GEOIP2CCMAP_MODE_CSV != mode.csv_binary) {
                    skAppPrintErr("Invalid %s for --%s=%s '%s': %s",
                                  appOptions[OPT_INPUT_PATH].name,
                                  appOptions[OPT_MODE].name,
                                  modeToName(GEOIP2CCMAP_MODE_BINARY),
                                  in_stream.of_name,
                                  "File does not have correct content type");
                    return -1;
                }
            }
            if (-1 == fseek(in_stream.of_fp, 0, SEEK_SET)) {
                SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                                 "cannot fseek()");
                c = ungetc(c, in_stream.of_fp);
                if (EOF == c) {
                    skAppPrintErr("Unable to put back character");
                    return -1;
                }
            }
            if (GEOIP2CCMAP_MODE_BINARY == mode.csv_binary
                && GEOIP2CCMAP_MODE_AUTO == mode.geoip2_legacy)
#ifndef SK_ENABLE_LIBMAXMINDDB
            {
                SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                                 "GeoIP2 binary support not available");
            }
#else  /* SK_ENABLE_LIBMAXMINDDB */
            {
                /* attempt to open it has a GeoIP2 binary stream */
                MMDB_s mmdb;
                int status;

                status = MMDB_open(in_stream.of_name, MMDB_MODE_MMAP, &mmdb);
                if (MMDB_SUCCESS == status) {
                    SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_GEOIP2,
                                     "Opened file with MMDB_open()");
                    MMDB_close(&mmdb);
                    mmdb_path = in_stream.of_name;
                    skFileptrClose(&in_stream, NULL);
                    in_stream.of_fp = NULL;
                    in_stream.of_name = NULL;
                } else {
                    TRACEMSG(("Unable to open '%s' with MMDB_open(): %s",
                              in_stream.of_name,
                              ((MMDB_IO_ERROR == status)
                               ? strerror(errno) : MMDB_strerror(status))));
                    SET_MODE_IF_AUTO(geoip2_legacy, GEOIP2CCMAP_MODE_LEGACY,
                                     "Unable to open file with MMDB_open()");
                }
            }
#endif  /* #else of #ifndef SK_ENABLE_LIBMAXMINDDB */
        }
    }

    return 0;
}

#ifndef TEST_PRINTF_FORMATS
/*
 *    Above:  #define scanErr  ++error_count; scanWarn
 */

/*
 *    Print a message preceded by the application name, the file being
 *    parsed, and the current line number of that file.
 */
static int
scanWarn(
    const char         *fmt,
    ...)
{
    char buf[3 * PATH_MAX];
    va_list args;
    ssize_t sz;

    va_start(args, fmt);
    sz = snprintf(buf, sizeof(buf), "%s:%u: ",
                  ((in_stream.of_name) ? in_stream.of_name : "?"), linenum);
    assert((size_t)sz < sizeof(buf));
    vsnprintf(buf + sz, sizeof(buf) - sz, fmt, args);
    va_end(args);
    skAppPrintErr("%s", buf);
    return 0;
}
#endif  /* TEST_PRINTF_FORMATS */


/*
 *    Write the prefix map file to the output stream.  The program's
 *    arguments are written into the output file's header.
 */
static void
writeOutput(
    int         argc,
    char      **argv)
{
    ssize_t rv;

    if (error_count) {
        skAppPrintErr("Encountered %u error%s during processing.%s",
                      error_count, ((error_count > 1) ? "s" : ""),
                      (dry_run ? "  Output not written." : ""));
    }
    if (dry_run) {
        exit((error_count) ? EXIT_FAILURE : EXIT_SUCCESS);
    }

    /* add invocation */
    if (!invocation_strip) {
        rv = skHeaderAddInvocation(skStreamGetSilkHeader(out_stream), 1,
                                   argc, argv);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* add notes if given */
    rv = skOptionsNotesAddToStream(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    skOptionsNotesTeardown();

    /* write output */
    rv = skStreamOpen(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    rv = skPrefixMapWrite(map, out_stream);
    if (rv != SKPREFIXMAP_OK) {
        if (rv == SKPREFIXMAP_ERR_IO) {
            skStreamPrintLastErr(out_stream,
                                 skStreamGetLastReturnValue(out_stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Unable to write prefix map to '%s': %s",
                          skStreamGetPathname(out_stream),
                          skPrefixMapStrerror(rv));
        }
        exit(EXIT_FAILURE);
    }

    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
}


/* we could handle this with "%option noyywrap", but defining this as
 * a function eliminates a compiler warning. */
int
yywrap(
    void)
{
    return 1;
}

/*
 *    Prepare to process a new line of input from a CSV file that uses
 *    the legacy format.
 */
static void
legacyReset(
    void)
{
    memset(&legacy, 0, sizeof(legacy));
    column = 0;
}

/*
 *    Handle a single column of the current line of legacy input.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
legacyColumn(
    const char         *string)
{
    int rv;

    switch (column) {
      case 0:
      case 1:
        /* starting IP, ending IP */
        rv = skStringParseIP(&legacy.range[column], string);
        if (rv) {
            scanErr("Invalid IP '%s': %s", string, skStringParseStrerror(rv));
            return -1;
        }
        break;
      case 4:
        /* country code as upper case characters */
        legacy.country = (uint32_t)skCountryNameToCode(string);
        if (SK_COUNTRYCODE_INVALID == legacy.country) {
            scanErr("Invalid country code '%s'", string);
            return -1;
        }
        break;
#if 0
      case 2:
      case 3:
        /* starting or ending IP as an integer */
        break;
      case 5:
        /* country name */
        break;
#endif  /* 0 */
    }

    return 0;
}


/*
 *    Combine the data for all columns on this line into a single
 *    entry and add it to the prefix map.
 */
static void
legacyCreateEntry(
    void)
{
    static int first_entry = 1;
    skPrefixMapErr_t rv;

    if (column != LEGACY_CSV_COLUMNS) {
        scanErr("Expected %d CSV values, found %u",
                LEGACY_CSV_COLUMNS, column);
        if (1 == first_entry) {
            exit(EXIT_FAILURE);
        }
        return;
    }
    if (first_entry) {
        first_entry = 0;
        if (GEOIP2CCMAP_MODE_AUTO == mode.ipv6_ipv4) {
            skPrefixMapContent_t content;
            if (skipaddrIsV6(&legacy.range[0])) {
                mode.ipv6_ipv4 = GEOIP2CCMAP_MODE_IPV6;
                content = SKPREFIXMAP_CONT_ADDR_V6;
            } else {
                mode.ipv6_ipv4 = GEOIP2CCMAP_MODE_IPV4;
                content = SKPREFIXMAP_CONT_ADDR_V4;
            }
            skPrefixMapSetContentType(map, content);
        }
    }

    if (skipaddrCompare(&legacy.range[0], &legacy.range[1]) > 0) {
        scanErr("Invalid IP range: start is greater then end");
        return;
    }

#if SK_ENABLE_IPV6
    if (GEOIP2CCMAP_MODE_IPV4 == mode.ipv6_ipv4) {
        uint32_t ipv4;
        if (skipaddrGetAsV4(&legacy.range[0], &ipv4)
            || skipaddrGetAsV4(&legacy.range[1], &ipv4))
        {
            TRACEMSG(("%s:%d: Ignoring IPv6 address in IPv4 mode",
                      in_stream.of_name, linenum));
            return;
        }
    }
#endif  /* SK_ENABLE_IPV6 */

    rv = skPrefixMapAddRange(map, &legacy.range[0], &legacy.range[1],
                             legacy.country);
    if (rv) {
        scanErr("Unable to add entry to prefix map: %s",
                skPrefixMapStrerror(rv));
    }
}


/*
 *    Read the data from a textual CSV file that uses the legacy
 *    maxmind format, add it to a prefix map, and write the prefix map
 *    to disk.
 *
 *    The format contains six columns, each value wrapped in double
 *    quote characters.  The columns are (0)starting ip in canonical
 *    form, (1)ending ip in canonical form, (2)starting ip as an
 *    integer, (3)ending ip as an integer, (4)two letter country code,
 *    (5)country name.
 *
 *    The file does not have a title line.
 */
static void
legacyCSVRead(
    int                 argc,
    char              **argv)
{
    ssize_t rv;

    /* Create the output prefix map */
    if (skPrefixMapCreate(&map) != SKPREFIXMAP_OK) {
        skAppPrintErr("Unable to create prefix map");
        exit(EXIT_FAILURE);
    }

    /* set the content type to the current mode, or to IPv4 if the
     * mode is "auto"; if auto, the content type may be changed once
     * we have the first line of input */
    switch (mode.ipv6_ipv4) {
      case GEOIP2CCMAP_MODE_IPV6:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V6);
        break;
      case GEOIP2CCMAP_MODE_IPV4:
      case GEOIP2CCMAP_MODE_AUTO:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V4);
        break;
      default:
        skAbortBadCase(mode.ipv6_ipv4);
    }

    rv = skPrefixMapSetDefaultVal(map, default_value);
    if (rv) {
        skAppPrintErr("Unable to set prefix map's default value: %s",
                      skPrefixMapStrerror(rv));
        exit(EXIT_FAILURE);
    }

    legacyReset();

    /* Process input */
    yyin = in_stream.of_fp;
    yylex();

    /* finished scanning.  clean up flex's state */
#ifdef SK_HAVE_YYLEX_DESTROY
    yylex_destroy();
#else
    yy_delete_buffer(YY_CURRENT_BUFFER);
#endif

    writeOutput(argc, argv);
}


/*
 *    Normalize the two character continent code in 'string' to a
 *    "country" code that is consistent with that used by the legacy
 *    GeoIP code.  Store the value in the referent of 'country'.
 *
 *    Return 0 if the string was a legal and expected value.  Return
 *    -1 if it was legal but unexpected.  Return
 *    SK_COUNTRYCODE_INVALID if the string is invalid.
 */
static int
continentToCountry(
    const char         *string,
    uint32_t           *country)
{
    /*
     *  For GeoLite2, mapping from continent code to fake country
     *  code.  This is done since some locations specify only a
     *  continent (as of this writing (2018.04.02) only Europe and
     *  Asia/Pacific are used without a more specific country).
     *
     *    XF <== AF,Africa
     *    XA <== AN,Antarctica
     *    AP <== AS,Asia  -- for consistency w/ GeoIP Legacy
     *    EU <== EU,Europe
     *    XN <== NA,"North America"
     *    XO <== OC,Oceania
     *    XS <== SA,"South America"
     */
    const uint32_t AF = ('x' << 8) | 'f';
    const uint32_t AN = ('x' << 8) | 'a';
    const uint32_t AS = ('a' << 8) | 'p';
    const uint32_t EU = ('e' << 8) | 'u';
    const uint32_t NA = ('x' << 8) | 'n';
    const uint32_t OC = ('x' << 8) | 'o';
    const uint32_t SA = ('x' << 8) | 's';

    switch (skCountryNameToCode(string)) {
      case (('a' << 8) | 'f'):
        *country = AF;
        break;
      case (('a' << 8) | 'n'):
        *country = AN;
        break;
      case (('a' << 8) | 's'):
        *country = AS;
        break;
      case (('e' << 8) | 'u'):
        *country = EU;
        break;
      case (('n' << 8) | 'a'):
        *country = NA;
        break;
      case (('o' << 8) | 'c'):
        *country = OC;
        break;
      case (('s' << 8) | 'a'):
        *country = SA;
        break;
      case SK_COUNTRYCODE_INVALID:
        *country = SK_COUNTRYCODE_INVALID;
        return SK_COUNTRYCODE_INVALID;
      default:
        *country = skCountryNameToCode(string);
        return -1;
    }
    return 0;
}


/*
 *  status = ipblocksColumn(string);
 *
 *    Handle a single column of the current line of input in a
 *    Geo*2-Country-Blocks-IPv*.csv file.
 *
 *    Return 0 on success or -1 for failure.
 *
 *    This is a helper function for csv2Column().
 */
static int
ipblocksColumn(
    const char         *string)
{
    int rv;

    if (1 == linenum) {
        /* to make this more robust to changes that maxmind may make
         * to the data files, we should ensure we have the columns we
         * need and dynamically determine the position of those
         * columns */
        if (column >= (sizeof(ipblocks_columns)/sizeof(ipblocks_columns[0]))) {
            TRACEMSG(("%s:%d: Ignoring additional title column #%u '%s'",
                      in_stream.of_name, linenum, 1u + column, string));
            ++ipblocks_columns_count;
            return 0;
        }
        if (0 != strcmp(string, ipblocks_columns[column])) {
            scanErr("Expected title column %u to have name '%s', found '%s'",
                    1u + column, ipblocks_columns[column], string);
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    switch (column) {
      case 0:
        /* network */
        rv = skStringParseCIDR(&ipblocks.ip, &ipblocks.prefix, string);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;
      case 1:
      case 2:
      case 3:
        /* geoname_id, registered_country_geoname_id,
         * represented_country_geoname_id */
        rv = skStringParseUint32(&ipblocks.geoname[column-1], string, 0, 0);
        if (rv) {
            ipblocks.geoname[column-1] = 0;
            goto PARSE_ERROR;
        }
        break;
      case 4:
        /* is_anonymous_proxy */
        if ('1' == string[0]) {
            ipblocks.is_anonymous = 1;
        }
        break;
      case 5:
        /* is_satellite_provider */
        if ('1' == string[0]) {
            ipblocks.is_satellite = 1;
        }
        break;
    }

    return 0;

  PARSE_ERROR:
    scanErr("Invalid %s '%s': %s",
            ipblocks_columns[column], string, skStringParseStrerror(rv));
    return -1;
}


/*
 *    Combine the data for all columns on this line into a single
 *    entry and add it to the prefix map.
 *
 *    This is a helper function for csv2CreateEntry().
 */
static void
ipblocksCreateEntry(
    void)
{
    char ipbuf[SKIPADDR_STRLEN];
    const pmap_location_t *continent;
    const pmap_location_t *found;
    int want_continent;
    pmap_location_t entry;
    skipaddr_t first, final;
    skPrefixMapErr_t rv;
    unsigned int i;
    uint32_t country;

    if (column != ipblocks_columns_count) {
        scanErr("Expected %u CSV %s, found %u",
                ipblocks_columns_count,
                ((1 == linenum) ? "title columns" : "values"), column);
        if (1 == linenum) {
            exit(EXIT_FAILURE);
        }
        return;
    }
    if (1 == linenum) {
        return;
    }

    if (skCIDR2IPRange(&ipblocks.ip, ipblocks.prefix, &first, &final)) {
        scanErr("Unable to convert %s/%u to an IP address range",
                skipaddrString(ipbuf, &ipblocks.ip, 0), ipblocks.prefix);
        return;
    }

    country = 0;
    continent = NULL;
    want_continent = 0;

    for (i = 0; !country && i < sizeof(fields)/sizeof(fields[0]); ++i) {
        switch (fields[i]) {
          case PMAP_FIELD_LOCATION:
          case PMAP_FIELD_REGISTERED:
          case PMAP_FIELD_REPRESENTED:
            entry.geoname = ipblocks.geoname[fields[i]];
            found = (pmap_location_t *)rbfind(&entry, geomap);
            if (found) {
                if (found->is_country || want_continent) {
                    country = found->country;
                } else if (!continent) {
                    continent = found;
                }
            }
            break;

          case PMAP_FIELD_CONTINENT:
            if (continent) {
                country = continent->country;
            } else {
                want_continent = 1;
            }
            break;

          case PMAP_FIELD_FLAGS:
            if (ipblocks.is_anonymous) {
                country = COUNTRY_ANON;
            } else if (ipblocks.is_satellite) {
                country = COUNTRY_SATL;
            }
            break;

          case PMAP_FIELD_END:
            return;
        }
    }
    if (!country) {
        skAppPrintErr("PMAP_FIELD_END not found");
        return;
    }

    rv = skPrefixMapAddRange(map, &first, &final, country);
    if (rv) {
        scanErr("Unable to add entry to prefix map: %s",
                skPrefixMapStrerror(rv));
    }
}


/*
 *  status = locationColumn(string);
 *
 *    Handle a single column of the current line of input in the
 *    Geo*2-Country-Locations-en.csv file.
 *
 *    Return 0 on success or -1 for failure.
 *
 *    This is a helper function for csv2Column().
 */
static int
locationColumn(
    const char         *string)
{
    int rv;

    if (1 == linenum) {
        /* see note in ipblocksColumn() regarding robustness */
        if (column >= (sizeof(location_columns)/sizeof(location_columns[0]))) {
            TRACEMSG(("%s:%d: Ignoring additional title column #%u '%s'",
                      in_stream.of_name, linenum, 1u + column, string));
            ++location_columns_count;
            return 0;
        }
        if (0 != strcmp(string, location_columns[column])) {
            scanErr("Expected title column %u to have name '%s', found '%s'",
                    1u + column, location_columns[column], string);
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    switch (column) {
      case 2:
        /* continent_code */
        switch (continentToCountry(string, &location.country)) {
          case 0:
            break;
          case SK_COUNTRYCODE_INVALID:
            scanErr("Invalid continent code '%s'", string);
            return -1;
          default:
            scanWarn("Unexpected continent code '%s'", string);
            break;
        }
        break;
      case 0:
        /* geoname_id */
        rv = skStringParseUint32(&location.geoname, string, 0, 0);
        if (rv) {
            scanErr("Invalid %s '%s': %s",
                    location_columns[column], string,
                    skStringParseStrerror(rv));
            return -1;
        }
        break;
      case 4:
        /* country_iso_code */
        location.country = (uint32_t)skCountryNameToCode(string);
        if (SK_COUNTRYCODE_INVALID == location.country) {
            scanErr("Invalid country code '%s'", string);
            return -1;
        }
        location.is_country = 1;
        break;
#if 0
      case 1:
      case 3:
      case 5:
      case 6:
        /* locale_code,...,continent_name,...,country_name,
         * is_in_european_union */
        break;
#endif  /* 0 */
    }

    return 0;
}


/*
 *    Use the data for the columns on this line to create a entry in
 *    the red-black tree that maps from a geoname_id location code to
 *    a country code (or to a continent code if no country).
 *
 *    This is a helper function for csv2CreateEntry().
 */
static void
locationCreateEntry(
    void)
{
    const pmap_location_t *exists;
    pmap_location_t *entry;

    if (column != location_columns_count) {
        scanErr("Expected %u CSV %s, found %u",
                location_columns_count,
                ((1 == linenum) ? "title columns" : "values"), column);
        if (1 == linenum) {
            exit(EXIT_FAILURE);
        }
        return;
    }
    if (1 == linenum) {
        return;
    }

    if (0 == location.country) {
        scanWarn("Ignoring line with no country/continent code");
        return;
    }

    entry = (pmap_location_t *)malloc(sizeof(pmap_location_t));
    if (NULL == entry) {
        skAppPrintOutOfMemory("redblack tree entry");
        exit(EXIT_FAILURE);
    }
    *entry = location;

    exists = (pmap_location_t *)rbsearch(entry, geomap);
    if (exists != entry) {
        scanWarn("Duplicate geoname_id '%u' found", entry->geoname);
        free(entry);
    }
}


/*
 *    Open the next (or the first) file that is needed to process the
 *    files in a maxmind country v2 directory.  Return 0 if the file
 *    was opened.  Return 1 if there are no more files.  Exit the
 *    program on errror.
 */
static int
csv2NextFile(
    void)
{
    static char path[PATH_MAX];
    ssize_t sz;
    ssize_t rv;

    assert(csv2_prod);

    linenum = 1;

    TRACEMSG(("calling csv2NextFile(); current file is %s",
              in_stream.of_name ? in_stream.of_name : "<none>"));

    skFileptrClose(&in_stream, NULL);
    memset(&in_stream, 0, sizeof(in_stream));

    if (NULL == csv2_directory || NULL == csv2_files[csv2_index].path) {
        TRACEMSG(("csv2NextFile() returns 1"));
        return 1;
    }
    /* skip files marked IPv6 if the global mode is not IPv6 */
    while (csv2_files[csv2_index].mode != GEOIP2CCMAP_MODE_AUTO
           && csv2_files[csv2_index].mode != mode.ipv6_ipv4)
    {
        TRACEMSG(("skipping file %s%s",csv2_prod,csv2_files[csv2_index].path));
        ++csv2_index;
        if (NULL == csv2_files[csv2_index].path) {
            TRACEMSG(("csv2NextFile() returns 1"));
            return 1;
        }
    }

    sz = snprintf(path, sizeof(path), "%s/%s%s",
                  csv2_directory, csv2_prod, csv2_files[csv2_index].path);
    if ((size_t)sz >= sizeof(path)) {
        skAppPrintErr("Path length (%" SK_PRIdZ ") exceeds maximum %" SK_PRIuZ,
                      sz, sizeof(path));
        exit(EXIT_FAILURE);
    }

    in_stream.of_name = path;
    rv = skFileptrOpen(&in_stream, SK_IO_READ);
    if (rv) {
        skAppPrintErr("Unable to open input file '%s': %s",
                      in_stream.of_name, skFileptrStrerror(rv));
        exit(EXIT_FAILURE);
    }
    yyin = in_stream.of_fp;
    TRACEMSG(("csv2NextFile() opened file '%s'", in_stream.of_name));

    ++csv2_index;

    TRACEMSG(("csv2NextFile() returns 0"));
    return 0;
}


/*
 *    Prepare to read the next line of a GeoIP2 Location or Blocks
 *    file.
 */
static void
csv2Reset(
    void)
{
    memset(&location, 0, sizeof(location));
    memset(&ipblocks, 0, sizeof(ipblocks));
    column = 0;
}

/*
 *    Handle a single column of the current line of input.
 */
static int
csv2Column(
    const char         *string)
{
    return (1 == csv2_index) ? locationColumn(string) : ipblocksColumn(string);
}

/*
 *    Combine the columns on the current line to create an entry.
 */
static void
csv2CreateEntry(
    void)
{
    (1 == csv2_index) ? locationCreateEntry() : ipblocksCreateEntry();
}


/*
 *    Return -1, 0, or 1 depending on whether the geoname_id of 'v_a'
 *    is less than, equal to, or greater than the geoname_id of 'v_b'.
 *
 *    This is the comparison function for the red-black tree 'geomap'.
 */
static int
compareGeomapEntry(
    const void         *v_a,
    const void         *v_b,
    const void         *v_c)
{
    SK_UNUSED_PARAM(v_c);
    return ((int64_t)(((const pmap_location_t *)v_a)->geoname)
            - (int64_t)(((const pmap_location_t *)v_b)->geoname));
}

/*
 *    Process the files in the directory that contain a mapping from
 *    geoname_id to country and from IP blocks to geoname_id.
 */
static void
csv2ReadDirectory(
    int                 argc,
    char              **argv)
{
    ssize_t rv;

    /* change the initial start state */
    BEGIN(ST_CSV2);

    /* Create the output prefix map and set its default value */
    if (skPrefixMapCreate(&map) != SKPREFIXMAP_OK) {
        skAppPrintErr("Unable to create prefix map");
        exit(EXIT_FAILURE);
    }
    rv = skPrefixMapSetDefaultVal(map, default_value);
    if (rv) {
        skAppPrintErr("Unable to set prefix map's default value: %s",
                      skPrefixMapStrerror(rv));
        exit(EXIT_FAILURE);
    }

    /* set the content type to the current mode.  If auto, set 'mode'
     * to either IPv4 or IPv6---use IPv6 is SiLK supports it;
     * otherwise IPv4 */
    if (GEOIP2CCMAP_MODE_AUTO == mode.ipv6_ipv4) {
        mode.ipv6_ipv4 = ((SK_ENABLE_IPV6)
                          ? GEOIP2CCMAP_MODE_IPV6 : GEOIP2CCMAP_MODE_IPV4);
    }
    switch (mode.ipv6_ipv4) {
      case GEOIP2CCMAP_MODE_IPV6:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V6);
        break;
      case GEOIP2CCMAP_MODE_IPV4:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V4);
        break;
      default:
        skAbortBadCase(mode.ipv6_ipv4);
    }

    /* create the mapping from geoname_id to country code */
    geomap = rbinit(compareGeomapEntry, NULL);
    if (NULL == geomap) {
        skAppPrintOutOfMemory("redblack tree");
        exit(EXIT_FAILURE);
    }

    /* open the first file that maps geoname_id to country */
    csv2_index = 0;
    csv2NextFile();

    /* Process all the files */
    yylex();

    /* finished scanning.  clean up flex's state */
#ifdef SK_HAVE_YYLEX_DESTROY
    yylex_destroy();
#else
    yy_delete_buffer(YY_CURRENT_BUFFER);
#endif

    writeOutput(argc, argv);
}


/*
 *    Read the binary GeoIP Legacy format and create a prefix map.
 *
 *    Each node in input consists of 6 bytes: two 24-bit,
 *    little-endian numbers representing the left and right branches
 *    of the tree.  If the most significant 16 bits of the input value
 *    are all high, that value is a leaf and the least-significant
 *    btye is an index into the country code look-up table.
 *
 */
/* number of country codes */
#define NUM_CC          256

/* how our prefixmap code marks a leaf */
#define PMAP_LEAF_BIT   UINT32_C(0x80000000)

/* how the input marks a leaf */
#define INPUT_LEAF_MASK UINT32_C(0x00ffff00)

static void
legacyBinaryRead(
    int                 argc,
    char              **argv)
{
    /* known to be in sync with MaxMind API 1.6.12 */
    const char cc[NUM_CC][3] = {
        "--", "ap", "eu", "ad", "ae", "af", "ag", "ai",
        "al", "am", "cw", "ao", "aq", "ar", "as", "at",
        "au", "aw", "az", "ba", "bb", "bd", "be", "bf",
        "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br",

        "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc",
        "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm",
        "cn", "co", "cr", "cu", "cv", "cx", "cy", "cz",
        "de", "dj", "dk", "dm", "do", "dz", "ec", "ee",

        "eg", "eh", "er", "es", "et", "fi", "fj", "fk",
        "fm", "fo", "fr", "sx", "ga", "gb", "gd", "ge",
        "gf", "gh", "gi", "gl", "gm", "gn", "gp", "gq",
        "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm",

        "hn", "hr", "ht", "hu", "id", "ie", "il", "in",
        "io", "iq", "ir", "is", "it", "jm", "jo", "jp",
        "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr",
        "kw", "ky", "kz", "la", "lb", "lc", "li", "lk",

        "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc",
        "md", "mg", "mh", "mk", "ml", "mm", "mn", "mo",
        "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw",
        "mx", "my", "mz", "na", "nc", "ne", "nf", "ng",

        "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
        "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm",
        "pn", "pr", "ps", "pt", "pw", "py", "qa", "re",
        "ro", "ru", "rw", "sa", "sb", "sc", "sd", "se",

        "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn",
        "so", "sr", "st", "sv", "sy", "sz", "tc", "td",
        "tf", "tg", "th", "tj", "tk", "tm", "tn", "to",
        "tl", "tr", "tt", "tv", "tw", "tz", "ua", "ug",

        "um", "us", "uy", "uz", "va", "vc", "ve", "vg",
        "vi", "vn", "vu", "wf", "ws", "ye", "yt", "rs",
        "za", "zm", "me", "zw", "a1", "a2", "o1", "ax",
        "gg", "im", "je", "bl", "mf", "bq", "ss", "o1"
    };
    uint32_t leaf_cc[NUM_CC];
    sk_file_header_t *hdr;
    sk_vector_t *vec;
    uint8_t buf[6];
    size_t i;
    size_t j;
    uint32_t count;
    ssize_t rv;
    uint32_t node[2];
    int is_ipv6;

    /* convert string country codes to leaf values */
    for (i = 0; i < NUM_CC; ++i) {
        assert(skCountryNameToCode(cc[i]) != SK_COUNTRYCODE_INVALID);
        leaf_cc[i] = PMAP_LEAF_BIT | skCountryNameToCode(cc[i]);
    }

    /* create a vector to hold the nodes */
    vec = skVectorNew(sizeof(node));
    if (NULL == vec) {
        skAppPrintOutOfMemory("vector");
        exit(EXIT_FAILURE);
    }

    /* read input and add nodes to the vector */
    while (fread(buf, sizeof(buf), 1, in_stream.of_fp)) {
        for (i = 0, j = 0; i < 2; ++i, j += 3) {
            node[i] = ((buf[j+2] << 16) | (buf[j+1] << 8) | buf[j]);
            if (node[i] >= INPUT_LEAF_MASK) {
                node[i] = leaf_cc[buf[j]];
            }
        }
        if (skVectorAppendValue(vec, &node)) {
            skAppPrintOutOfMemory("vector elements");
            exit(EXIT_FAILURE);
        }
    }

    /* finished reading the input; verify the tree */

    /* visit each node until we find a node that points to a node
     * outside the tree; set the number of nodes to the index of the
     * node that points outside the tree */
    count = skVectorGetCount(vec);
    for (i = 0; i < count; ++i) {
        skVectorGetValue(&node, vec, i);
        if (((node[0] >= count) && !(node[0] & PMAP_LEAF_BIT))
            || ((node[1] >= count) && !(node[1] & PMAP_LEAF_BIT)))
        {
            count = i;
            break;
        }
    }
    if (0 == count) {
        skAppPrintErr("No valid nodes read from input");
        exit(EXIT_FAILURE);
    }

    /* detemine whether the input is IPv4 by looking over all paths
     * and recording the maximum depth */
    is_ipv6 = 0;
    {
#define MAX_DEPTH           128
#define LEAF_VALUE(leaf)    (((leaf) & ~PMAP_LEAF_BIT) & UINT32_MAX)

#if TRACEMSG_LEVEL > 0
        const char isleaf[2] = {' ', 'L'};
#endif
        uint32_t path[MAX_DEPTH];
        uint8_t lr[MAX_DEPTH];
        uint32_t n;
        int depth;
        int max_seen;

        depth = max_seen = 0;
        lr[depth] = 0;
        path[depth] = 0;
        while (depth >= 0) {
            if (lr[depth] > 1) {
                /* done with this level */
                TRACEMSG(("%4d  %8u  %u", depth, path[depth], lr[depth]));
                --depth;
            } else {
                skVectorGetValue(&node, vec, path[depth]);
                TRACEMSG(("%4d  %8u  %u  %8u%c  %8u%c",
                          depth, path[depth], lr[depth],
                          LEAF_VALUE(node[0]), isleaf[ node[0]>>31 ],
                          LEAF_VALUE(node[1]), isleaf[ node[1]>>31 ]));
                n = node[lr[depth]];
                ++lr[depth];
                if (!(n & PMAP_LEAF_BIT)) {
                    /* add a level */
                    ++depth;
                    if (depth > max_seen) {
                        max_seen = depth;
                        if (depth >= MAX_DEPTH) {
                            skAppPrintErr(
                                "Tree is malformed; tree is too deep");
                            exit(EXIT_FAILURE);
                        }
                    }
                    /* initialize the level */
                    lr[depth] = 0;
                    path[depth] = n;
                    if (n >= count) {
                        skAppPrintErr(("Tree is malformed; value %" PRIu32
                                       " is larger than tree size %" PRIu32),
                                      n, count);
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
        TRACEMSG(("max depth is %d", max_seen));
        if (max_seen > 31) {
            is_ipv6 = 1;
        }
    }

    /* we finished with verification; prepare and write the output */
    if (dry_run) {
        return;
    }

    /* initialize the stream's header (from skprefixmap.c) */
    hdr = skStreamGetSilkHeader(out_stream);
    skHeaderSetFileFormat(hdr, FT_PREFIXMAP);
    /* Country Code file versions: IPv4 is v1; IPv6 is v5 */
    skHeaderSetRecordVersion(hdr, (is_ipv6 ? 5 : 1));
    skHeaderSetCompressionMethod(hdr, SK_COMPMETHOD_NONE);
    skHeaderSetRecordLength(hdr, 1);

    /* add invocation */
    if (!invocation_strip) {
        rv = skHeaderAddInvocation(hdr, 1, argc, argv);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* add notes */
    rv = skOptionsNotesAddToStream(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    skOptionsNotesTeardown();

    /* open the output and write the header output */
    if ((rv = skStreamOpen(out_stream))
        || (rv = skStreamWriteSilkHeader(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* write the number of nodes, then write each node */
    if (skStreamWrite(out_stream, &count, sizeof(count)) == -1) {
        skStreamPrintLastErr(out_stream, -1, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < count; ++i) {
        skVectorGetValue(&node, vec, i);
        if (skStreamWrite(out_stream, &node, sizeof(node)) == -1) {
            skStreamPrintLastErr(out_stream, -1, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    skVectorDestroy(vec);

    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
}


#ifdef SK_ENABLE_LIBMAXMINDDB
/*
 *    Given an IP and its netblock prefix that refer to a MaxMind data
 *    entry, query the entry to get the country code, or the continent
 *    code, or its anonymous/satellite flag and add an appropriate
 *    entry to the global prefix map.
 *
 *    If we are in IPv4 mode, only the first four bytes of 'ip' are
 *    used.
 */
static void
binary2AddEntry(
    const uint8_t       ip[],
    int                 prefix,
    MMDB_entry_s       *entry)
{
    static const char *lookup_arrays[7][3] = {
        {"country", "iso_code", NULL},
        {"registered_country", "iso_code", NULL},
        {"represented_country", "iso_code", NULL},
        {"continent", "code", NULL},
        {"traits", "is_anonymous_proxy", NULL},
        {"traits", "is_satellite_provider", NULL},
        {NULL, NULL, NULL}
    };
    skipaddr_t first;
    skipaddr_t final;
    MMDB_entry_data_s entry_data;
    char buf[64];
    size_t i, j;
    int status;
    ssize_t rv;
    uint32_t country;

#if TRACEMSG_LEVEL > 0
    char netblock_buf[64];
    snprintf(netblock_buf, sizeof(netblock_buf),
             ("%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
              "%02x%02x:%02x%02x:%02x%02x:%02x%02x/%3d"),
             ip[0], ip[1], ip[ 2], ip[ 3], ip[ 4], ip[ 5], ip[ 6], ip[ 7],
             ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
             prefix);
#endif  /* TRACEMSG_LEVEL > 0 */

    assert(prefix > 0);

#if SK_ENABLE_IPV6
    if (GEOIP2CCMAP_MODE_IPV6 == mode.ipv6_ipv4) {
        skipaddrSetV6(&first, ip);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        uint32_t ipv4 = (ip[0] << 24)| (ip[1] << 16)| (ip[2] << 8) | ip[3];
        skipaddrSetV4(&first, &ipv4);
        assert(prefix <= 32);
    }

    if (skCIDR2IPRange(&first, prefix, &first, &final)) {
        char ipbuf[SKIPADDR_STRLEN];
        skAppPrintErr("Unable to convert %s/%u to an IP address range",
                      skipaddrString(ipbuf, &ipblocks.ip, 0), ipblocks.prefix);
        return;
    }

    country = 0;
    for (i = 0; !country && i < sizeof(fields)/sizeof(fields[0]); ++i) {
        switch (fields[i]) {
          case PMAP_FIELD_LOCATION:
          case PMAP_FIELD_REGISTERED:
          case PMAP_FIELD_REPRESENTED:
            status = MMDB_aget_value(entry, &entry_data,
                                     lookup_arrays[fields[i]]);
            if (MMDB_SUCCESS != status || !entry_data.has_data) {
                break;
            }
            if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
                skAppPrintErr("Unexpected data type %d", entry_data.type);
                break;
            }
            if (entry_data.data_size != 2) {
                skAppPrintErr("Unexpected data length %u",
                              entry_data.data_size);
                break;
            }
            strncpy(buf, entry_data.utf8_string, entry_data.data_size);
            buf[entry_data.data_size] = '\0';
            TRACEMSG(("%s  '%s'", netblock_buf, buf));
            country = skCountryNameToCode(buf);
            break;

          case PMAP_FIELD_CONTINENT:
            status = MMDB_aget_value(entry, &entry_data,
                                     lookup_arrays[fields[i]]);
            if (MMDB_SUCCESS != status || !entry_data.has_data) {
                break;
            }
            if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
                skAppPrintErr("Unexpected data type %d", entry_data.type);
                break;
            }
            if (entry_data.data_size != 2) {
                skAppPrintErr("Unexpected data length %u",
                              entry_data.data_size);
                break;
            }
            strncpy(buf, entry_data.utf8_string, entry_data.data_size);
            buf[entry_data.data_size] = '\0';
            TRACEMSG(("%s  '%s'*", netblock_buf, buf));
            switch (continentToCountry(buf, &country)) {
              case 0:
                break;
              case SK_COUNTRYCODE_INVALID:
                skAppPrintErr("Invalid continent code '%s'", buf);
                return;
              default:
                skAppPrintErr("Unexpected continent code '%s'", buf);
                return;
            }
            break;

          case PMAP_FIELD_FLAGS:
            for (j = 4; !country && j <= 5; ++j) {
                status = MMDB_aget_value(entry, &entry_data, lookup_arrays[j]);
                if (MMDB_SUCCESS != status || !entry_data.has_data) {
                    continue;
                }
                if (entry_data.type != MMDB_DATA_TYPE_BOOLEAN) {
                    skAppPrintErr("Unexpected data type %d", entry_data.type);
                    continue;
                }
                /* value should be "a1" or "a2" */
                TRACEMSG(("%s  'a%d'", netblock_buf, j - 3));
                country = (j == 4) ? COUNTRY_ANON : COUNTRY_SATL;
            }
            break;

          case PMAP_FIELD_END:
            return;
        }
    }
    if (!country) {
        skAppPrintErr("PMAP_FIELD_END not found");
        return;
    }

    rv = skPrefixMapAddRange(map, &first, &final, country);
    if (rv) {
        skAppPrintErr("Error adding to prefix map: %s",
                      skPrefixMapStrerror(rv));
        exit(EXIT_FAILURE);
    }
}


/*
 *    Process a binary GeoIP2 database file using the libmaxminddb C
 *    API and create a prefix map.  This code iterates over all the
 *    nodes of the tree.
 *
 *    By iterating over all the nodes, we end up with multiple copies
 *    of IPv4 country codes in our output file.  This is because the
 *    database includes the IPv4 country codes at the following
 *    locations:
 *
 *    ::0:0/96               (we use this fact when in ipv4 mode)
 *    ::ffff:0:0/96          (IPv6 mapped IPv4 addresses)
 *    2001:0:a.b.c.d:0:0:0:0 (Teredo)
 *    2002:a.b.c.d:0:0:0:0:0 (6to4)
 *
 *    It would be nice to reduce this duplication.
 */
static void
binary2Read(
    int                 argc,
    char              **argv)
{
    MMDB_s mmdb;
    int status;
#define PENDING_DEPTH 129
    MMDB_search_node_s node[PENDING_DEPTH];
    int depth;
    uint32_t node_num;
    uint8_t ip[16];
    unsigned int ip_idx;
    unsigned int ip_bit;
    skPrefixMapErr_t rv;

    assert(mmdb_path);

    /* Create the output prefix map */
    if (skPrefixMapCreate(&map) != SKPREFIXMAP_OK) {
        skAppPrintErr("Unable to create prefix map");
        exit(EXIT_FAILURE);
    }

    /* set the content type to the current mode.  If auto, set 'mode'
     * to either IPv4 or IPv6---use IPv6 is SiLK supports it;
     * otherwise IPv4 */
    if (GEOIP2CCMAP_MODE_AUTO == mode.ipv6_ipv4) {
        mode.ipv6_ipv4 = ((SK_ENABLE_IPV6)
                          ? GEOIP2CCMAP_MODE_IPV6 : GEOIP2CCMAP_MODE_IPV4);
    }
    switch (mode.ipv6_ipv4) {
      case GEOIP2CCMAP_MODE_IPV6:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V6);
        break;
      case GEOIP2CCMAP_MODE_IPV4:
        skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V4);
        break;
      default:
        skAbortBadCase(mode.ipv6_ipv4);
    }

    rv = skPrefixMapSetDefaultVal(map, default_value);
    if (rv) {
        skAppPrintErr("Unable to set prefix map's default value: %s",
                      skPrefixMapStrerror(rv));
        exit(EXIT_FAILURE);
    }

    /* open the MaxMind database */
    status = MMDB_open(mmdb_path, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS != status) {
        skAppPrintErr("Unable to open datbase file '%s': %s",
                      mmdb_path,
                      ((MMDB_IO_ERROR == status)
                       ? strerror(errno) : MMDB_strerror(status)));
        exit(EXIT_FAILURE);
    }

    memset(ip, 0, sizeof(ip));
    node_num = 0;
    depth = 0;

    if (GEOIP2CCMAP_MODE_IPV4 == mode.ipv6_ipv4) {
        /* to limit to IPv4 (::0:0/96), descend down the left hand
         * branch until the depth is 96, and then reset depth to 0 */
        do {
            status = MMDB_read_node(&mmdb, node_num, &node[depth]);
            if (MMDB_INVALID_NODE_NUMBER_ERROR == status) {
                skAppPrintErr(("Error reading database file:"
                               " Unexpected error getting node %u: %s"),
                              node_num, MMDB_strerror(status));
                goto ERROR;
            }
            if (MMDB_RECORD_TYPE_SEARCH_NODE != node[depth].left_record_type) {
                skAppPrintErr(("Error finding IPv4 branch of database:"
                               " Left most branch has depth %d, expected 96"),
                              depth);
                goto ERROR;
            }
            node_num = node[depth].left_record;
            ++depth;
        } while (depth < 96);
        depth = 0;
    }

    do {
        /* descend down left hand branch until we get to a node that
         * does not point at another node */
        for (;;) {
            if (depth >= PENDING_DEPTH) {
                skAppPrintErr("Error reading database file: Tree is too deep");
                goto ERROR;
            }
            status = MMDB_read_node(&mmdb, node_num, &node[depth]);
            if (MMDB_INVALID_NODE_NUMBER_ERROR == status) {
                skAppPrintErr(("Error reading database file:"
                               " Unexpected error getting node %u: %s"),
                              node_num, MMDB_strerror(status));
                goto ERROR;
            }
            if (MMDB_RECORD_TYPE_SEARCH_NODE != node[depth].left_record_type) {
                break;
            }
            node_num = node[depth].left_record;
            ++depth;
        }

        /* handle the left hand side's data */
        switch (node[depth].left_record_type) {
          case MMDB_RECORD_TYPE_INVALID:
            /* The record is invalid.  Either an invalid node was
             * looked up or the database is corrupt. */
            skAppPrintErr("Error reading database file:"
                          " Node contains an invalid left child");
            goto ERROR;
          case MMDB_RECORD_TYPE_EMPTY:
            /* The record is a placeholder that indicates there is no
             * data for the IP address.  The search should end
             * here. */
            break;
          case MMDB_RECORD_TYPE_DATA:
            /* The record is for data in the data section of the
             * database.  Use the entry for the record when
             * looking up the data for the record. */
            binary2AddEntry(ip, 1+depth, &node[depth].left_record_entry);
            break;
          case MMDB_RECORD_TYPE_SEARCH_NODE:
            /* The record points to the next search node */
            /* this was handled above and should never occur here */
            skAbortBadCase(node[depth].left_record_type);
        }

        /* handle the right hand side */
        do {
            ip_idx = (depth >> 3);
            ip_bit = UINT8_C(1) << (7 - (depth & 0x7));
            TRACEMSG(("set bit %d (ip[%u] |= (1u << %u))",
                      1+depth, ip_idx, (7 - (depth & 0x7))));
            ip[ip_idx] |= ip_bit;
            if (MMDB_RECORD_TYPE_SEARCH_NODE == node[depth].right_record_type) {
                node_num = node[depth].right_record;
                ++depth;
                break;
            }
            switch (node[depth].right_record_type) {
              case MMDB_RECORD_TYPE_INVALID:
                skAppPrintErr("Error reading database file:"
                              " Node contains an invalid right child");
                goto ERROR;
              case MMDB_RECORD_TYPE_EMPTY:
                break;
              case MMDB_RECORD_TYPE_DATA:
                binary2AddEntry(ip, 1+depth, &node[depth].right_record_entry);
                break;
              case MMDB_RECORD_TYPE_SEARCH_NODE:
                skAbortBadCase(node[depth].right_record_type);
            }
            /* travel up the right hand side until we find a node
             * whose right hand side has not been visited yet, or we
             * reach the root of the tree */
            do {
                TRACEMSG(("clear bit %d (ip[%u] &= ~(1u << %u))",
                          1+depth, ip_idx, (7 - (depth & 0x7))));
                ip[ip_idx] &= ~(ip_bit);
                --depth;
                if (depth < 0) {
                    break;
                }
                ip_idx = (depth >> 3);
                ip_bit = UINT8_C(1) << (7 - (depth & 0x7));
            } while (ip[ip_idx] & ip_bit);
        } while (depth >= 0);
    } while (depth >= 0);

    MMDB_close(&mmdb);
    writeOutput(argc, argv);
    return;

  ERROR:
    MMDB_close(&mmdb);
    exit(EXIT_FAILURE);
}
#endif  /* SK_ENABLE_LIBMAXMINDDB */

int main(
    int         argc,
    char      **argv)
{
    appSetup(argc, argv);       /* never returns on error */

    if (GEOIP2CCMAP_MODE_CSV == mode.csv_binary) {
        if (csv2_directory) {
            assert(GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy);
            csv2ReadDirectory(argc, argv);
        } else {
            assert(GEOIP2CCMAP_MODE_LEGACY == mode.geoip2_legacy);
            legacyCSVRead(argc, argv);
        }
    } else {
        assert(GEOIP2CCMAP_MODE_BINARY == mode.csv_binary);
#ifdef SK_ENABLE_LIBMAXMINDDB
        if (mmdb_path) {
            assert(GEOIP2CCMAP_MODE_GEOIP2 == mode.geoip2_legacy);
            binary2Read(argc, argv);
        } else
#endif  /* SK_ENABLE_LIBMAXMINDDB */
        {
            assert(GEOIP2CCMAP_MODE_LEGACY == mode.geoip2_legacy);
            legacyBinaryRead(argc, argv);
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
