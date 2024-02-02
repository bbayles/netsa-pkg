%{
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
**  rwpmapbuild.l
**
**  Create a prefixmap (pmap) file from textual input.
**
**  Mark Thomas
**  September 2007
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwpmapbuild.l b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/skprefixmap.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* label to use for unknown ranges if the user does not provide one */
#define DEFAULT_LABEL  "UNKNOWN"

/* default mode to use */
#define DEFAULT_MODE  SKPREFIXMAP_CONT_ADDR_V4

/* types of statements that we can parse */
typedef enum {
    STMT_DEFAULT, STMT_LABEL, STMT_CIDR, STMT_IPS, STMT_NUMBERS, STMT_PROPORTS
} pmap_stmt_type_t;

/* information for the current statement */
typedef struct pmap_stmt_st {
    pmap_stmt_type_t   type;
    uint32_t           value;
    union range_start_un {
        skPrefixMapProtoPort_t  pp;
        skipaddr_t              addr;
    }                  range_start;
    union range_end_un {
        skPrefixMapProtoPort_t  pp;
        skipaddr_t              addr;
    }                  range_end;
} pmap_stmt_t;

/* how the 'mode' can be set */
typedef enum {
    /* has the default value prior to parsing a range */
    MODE_SET_DEFAULT,
    /* has the default value after parsing a range */
    MODE_SET_RANGE,
    /* set via mode statement in input */
    MODE_SET_STMT,
    /* set via command-line switch */
    MODE_SET_SWITCH
} mode_set_t;


/* LOCAL VARIABLE DEFINITIONS */

/* the pmap that we will create */
static skPrefixMap_t *map = NULL;

/* information for the current statement */
static pmap_stmt_t stmt;

/* which line of input we are reading */
static int linenum = 1;

/* number of errors encountered during processing */
static int error_count = 0;

/* label statements may only appear in the input file prior to a
 * default statement or a range statement.  this variable says whether
 * a label statement is allowed.  */
static int label_stmt_allowed = 1;

/* use of labels is an all-or-nothing thing.  that is, when label
 * statements are present, we do not automatically add entries to the
 * dictionary.  */
static int label_stmt_seen = 0;

/* whether the default statement has been seen */
static int default_set = 0;

/* type of input: ipv4, ipv6, proto-port.  See also mode_set. */
static skPrefixMapContent_t mode = DEFAULT_MODE;

/* how the 'mode' variable got its value */
static mode_set_t mode_set = MODE_SET_DEFAULT;

/* structure to map between mode names and mode IDs */
static struct mode_name_id_map_st {
    const char            *name;
    skPrefixMapContent_t   id;
} mode_name_id_map[] = {
    {"proto-port", SKPREFIXMAP_CONT_PROTO_PORT},
    {"ipv6",       SKPREFIXMAP_CONT_ADDR_V6},
    {"ipv4",       SKPREFIXMAP_CONT_ADDR_V4}
};

/* number of entries in 'mode_name_id_map' */
static const size_t mode_name_id_map_len
    = sizeof(mode_name_id_map)/sizeof(mode_name_id_map[0]);

/* input stream for reading the prefix map text */
static sk_fileptr_t in_stream;

/* output stream for the resulting prefix map */
static skstream_t *out_stream = NULL;

/* do not write the output file; simply check syntax of the input.
 * set by --dry-run */
static int dry_run = 0;

/* ignore errors during parsing and write the output file anyway.  set
 * by --ignore-errors */
static int ignore_errors = 0;

/* do not record the command line invocation in the generated prefix
 * map file. set by --invocation-strip */
static int invocation_strip = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_INPUT_PATH,
    OPT_OUTPUT_PATH,
    OPT_MODE,
    OPT_DRY_RUN,
    OPT_IGNORE_ERRORS,
    OPT_INVOCATION_STRIP
} appOptionsEnum;

static struct option appOptions[] = {
    {"input-path",          REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"mode",                REQUIRED_ARG, 0, OPT_MODE},
    {"dry-run",             NO_ARG,       0, OPT_DRY_RUN},
    {"ignore-errors",       NO_ARG,       0, OPT_IGNORE_ERRORS},
    {"invocation-strip",    NO_ARG,       0, OPT_INVOCATION_STRIP},
    {0,0,0,0}               /* sentinel entry */
};


static const char *appHelp[] = {
    "Read the prefix map definition from this file",
    "Write the binary prefix map to this file",
    ("Set the type of the input; this must agree with any 'mode'\n"
     "\tstatement in the input."),
    "Do not write the output file",
    "Write the output file despite any errors in the input",
    ("Strip invocation history from the prefix map file.\n"
     "\tDef. Record command used to create the file"),
    (char *)NULL
};

static struct option deprecatedOptions[] = {
    {"input-file",      REQUIRED_ARG, 0, OPT_INPUT_PATH},
    {"output-file",     REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {0,0,0,0}           /* sentinel entry */
};

static const char *deprecatedHelp[] = {
    ("DEPRECATED. Read the prefix map definition from this\n"
     "\tfile.  Replace with --input-path"),
    ("DEPRECATED. Write the binary prefix map to this file.\n"
     "\tReplace with --output-path"),
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

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseMode(const char *string, skPrefixMapContent_t *new_mode);
static const char *modeToName(skPrefixMapContent_t m);

static int stmtDefault(int state, char *string);
static int stmtMode(int state, char *string);
static int stmtLabel(int state, char *string);
static int stmtMapName(int state, char *string);
static int stmtCIDR(int state, char *string);
static int stmtIPs(int state, char *string);
static int stmtNumbers(int state, char *string);
static int stmtProPorts(int state, char *string);
static int gotLabel(char *string);

/* to keep gcc quiet  */
int yylex(void);


SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

/*  *****  LEX INPUT FOLLOWS  *****  */

%}

%option prefix="pmapbuild_" outfile="lex.yy.c"
%option never-interactive
%option noinput nounput noreject

    /* %option noyywrap  -- use a function to avoid gcc warning */
    /* %option noyyget_extra noyyset_extra noyyget_leng noyyget_text */
    /* %option noyyget_lineno noyyset_lineno noyyget_in noyyset_in */
    /* %option noyyget_out noyyset_out noyyget_lval noyyset_lval */
    /* %option noyyget_lloc noyyset_lloc noyyget_debug noyyset_debug */


%s ST_EOL
%s ST_ERROR
%s ST_GETLABEL
%s ST_IPS
%s ST_LABEL
%s ST_MAPNAME
%s ST_MODE
%s ST_NUMBERS
%s ST_PROPORTS


ws_opt  [ \t\r]*
ws      [ \t\r]+

nl      [ \t\r]*(#.*)?\n

number  [0-9]+

ip      [0-9A-Fa-f]*[\:\.][0-9A-Fa-f\:\.]+

cidr    {ip}"/"[0-9]+

label   [^# \t\r\n]|[^# \t\r\n][^#\r\n]*[^# \t\r\n]

mapname [^#:, \t\r\n]+

%%

<INITIAL>mode{ws}                 { BEGIN(ST_MODE); }

<ST_MODE>{mapname}                { if (stmtMode(0, yytext)) {
                                        ++error_count;
                                        return 0;
                                    }
                                    BEGIN(ST_EOL); }


<INITIAL>map-name{ws}             { BEGIN(ST_MAPNAME); }

<ST_MAPNAME>{mapname}             { if (stmtMapName(0, yytext)) {
                                        ++error_count;
                                    }
                                    BEGIN(ST_EOL); }


<INITIAL>default{ws}              { if (stmtDefault(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_GETLABEL);
                                    } }

<INITIAL>label{ws}                { if (stmtLabel(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_LABEL);
                                    } }

<ST_LABEL>{number}{ws}            { if (stmtLabel(1, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_GETLABEL);
                                    } }

<INITIAL>{cidr}{ws}               { if (stmtCIDR(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_GETLABEL);
                                    } }

<INITIAL>{ip}{ws}                 { if (stmtIPs(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_IPS);
                                    } }

<ST_IPS>{ip}{ws}                  { if (stmtIPs(1, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_GETLABEL);
                                    } }

<INITIAL>{number}"/"{number}{ws}  { if (stmtProPorts(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_PROPORTS);
                                    } }

<ST_PROPORTS>{number}"/"{number}{ws}  { if (stmtProPorts(1, yytext)) {
                                            ++error_count;
                                            BEGIN(ST_ERROR);
                                        } else {
                                            BEGIN(ST_GETLABEL);
                                        } }

<INITIAL>{number}{ws}             { if (stmtNumbers(0, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_NUMBERS);
                                    } }

<ST_NUMBERS>{number}{ws}          { if (stmtNumbers(1, yytext)) {
                                        ++error_count;
                                        BEGIN(ST_ERROR);
                                    } else {
                                        BEGIN(ST_GETLABEL);
                                    } }

<ST_GETLABEL>{label}              { if (gotLabel(yytext)) {
                                        ++error_count;
                                    }
                                    BEGIN(ST_EOL); }

<INITIAL,ST_EOL>{nl}      { ++linenum; BEGIN(INITIAL); }

{ws}                      ;

<INITIAL>(mode|map-name|default|label){nl} {
                            skAppPrintErr("Incomplete %s statement on line %d",
                                          yytext, linenum);
                            ++error_count;
                            ++linenum; }

<ST_LABEL,ST_GETLABEL,ST_IPS,ST_PROPORTS,ST_NUMBERS,ST_MAPNAME>\n  {
                            skAppPrintErr("Incomplete statement on line %d",
                                          linenum);
                            ++error_count;
                            ++linenum;
                            BEGIN(INITIAL); }

<ST_EOL>{label}           { skAppPrintErr(("Too many arguments in statement"
                                           " on line %d"),
                                          linenum);
                            ++error_count;
                            BEGIN(ST_ERROR); }

.                         { skAppPrintErr("Unrecognized input on line %d",
                                          linenum);
                            ++error_count;
                            BEGIN(ST_ERROR); }

<ST_ERROR>.*\n            { ++linenum; BEGIN(INITIAL); }

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
#define USAGE_MSG                                                             \
    ("[SWITCHES]\n"                                                           \
     "\tCreate a binary prefix map file from a textual input file.  The\n"    \
     "\tinput is read from the named input file or from the standard\n"       \
     "\tinput.  The prefix map file is written to the named location or\n"    \
     "\tto the standard output if stdout is not connected to a terminal.\n")

    FILE *fh = USAGE_FH;
    int i;
    size_t j;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        switch (appOptions[i].val) {
          case OPT_MODE:
            fprintf(fh, "--%s %s. %s Def. %s. Choices: %s",
                    appOptions[i].name,
                    SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i],
                    modeToName(DEFAULT_MODE), mode_name_id_map[0].name);
            for (j = 1; j < mode_name_id_map_len; ++j) {
#if !SK_ENABLE_IPV6
                if (SKPREFIXMAP_CONT_ADDR_V6 == mode_name_id_map[j].id) {
                    continue;
                }
#endif  /* !SK_ENABLE_IPV6 */
                fprintf(fh, ", %s", mode_name_id_map[j].name);
            }
            fprintf(fh, "\n");
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
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);
    memset(&in_stream, 0, sizeof(in_stream));

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

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage(); /* never returns */
    }

    /* Complain about extra args on command line */
    if (arg_index != argc) {
        skAppPrintErr("Too many or unrecognized argument specified: '%s'",
                      argv[arg_index]);
        exit(EXIT_FAILURE);
    }

    /* check for input; if none specified, use stdin */
    if (!in_stream.of_name) {
        if (FILEIsATty(stdin)) {
            skAppPrintErr("Specify '--%s=-' to read from the terminal",
                          appOptions[OPT_INPUT_PATH].name);
            exit(EXIT_FAILURE);
        }
        in_stream.of_name = "-";
    }

    /* open input stream */
    rv = skFileptrOpen(&in_stream, SK_IO_READ);
    if (rv) {
        skAppPrintErr("Unable to open input '%s': %s",
                      in_stream.of_name, skFileptrStrerror(rv));
        exit(EXIT_FAILURE);
    }

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
    int rv;

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
        if (MODE_SET_DEFAULT != mode_set) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        mode_set = MODE_SET_SWITCH;
        if (parseMode(opt_arg, &mode)) {
            skAppPrintErr("Invalid %s '%s': Unrecognized mode name",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
#if !SK_ENABLE_IPV6
        if (SKPREFIXMAP_CONT_ADDR_V6 == mode) {
            skAppPrintErr(("Unsupported %s '%s': This SiLK installation was"
                           " built without IPv6 address support"),
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
#endif  /* !SK_ENABLE_IPV6 */
        break;

      case OPT_DRY_RUN:
        dry_run = 1;
        break;

      case OPT_IGNORE_ERRORS:
        ignore_errors = 1;
        break;

      case OPT_INVOCATION_STRIP:
        invocation_strip = 1;
        break;
    }

    return 0; /* OK */
}


/*
 *  ok = parseMode(string, &new_mode);
 *
 *    Parse the value in 'string' as the name of a mode and put the
 *    mode's value in 'new_mode'.
 *
 *    Return 0 on success, or -1 if 'string' does not match a mode.
 */
static int
parseMode(
    const char             *string,
    skPrefixMapContent_t   *new_mode)
{
    size_t j;

    for (j = 0; j < mode_name_id_map_len; ++j) {
        if (0 == strcmp(string, mode_name_id_map[j].name)) {
            *new_mode = mode_name_id_map[j].id;
            return 0;
        }
    }
    return -1;
}


/*
 *  name = modeToName(mode);
 *
 *    Return the string that presents the mode 'mode'.  Abort if
 *    'mode' is not a valid mode.
 */
static const char *
modeToName(
    skPrefixMapContent_t    m)
{
    size_t j;

    for (j = 0; j < mode_name_id_map_len; ++j) {
        if (m == mode_name_id_map[j].id) {
            return mode_name_id_map[j].name;
        }
    }

    skAppPrintErr("Unknown mode value %d", (int)m);
    skAbort();
}


static int
checkRange(
    void)
{
    switch (mode) {
      case SKPREFIXMAP_CONT_PROTO_PORT:
        if ((stmt.range_start.pp.proto > stmt.range_end.pp.proto)
            || ((stmt.range_start.pp.proto == stmt.range_end.pp.proto)
                && (stmt.range_start.pp.port > stmt.range_end.pp.port)))
        {
            skAppPrintErr("Invalid range on line %d: start is greater then end",
                          linenum);
            return -1;
        }
        break;

      case SKPREFIXMAP_CONT_ADDR_V4:
        if (skipaddrCompare(&stmt.range_start.addr,
                            &stmt.range_end.addr) > 0)
        {
            skAppPrintErr("Invalid range on line %d: start is greater then end",
                          linenum);
            return -1;
        }
#if SK_ENABLE_IPV6
        {
            uint32_t ipv4;
            if (skipaddrGetAsV4(&stmt.range_start.addr, &ipv4)
                || skipaddrGetAsV4(&stmt.range_end.addr, &ipv4))
            {
                skAppPrintErr(("Invalid IP on line %d:"
                               " IPv6 address not allowed in %s prefix map"),
                              linenum, modeToName(mode));
                return -1;
            }
        }
#endif  /* SK_ENABLE_IPV6 */
        break;

      case SKPREFIXMAP_CONT_ADDR_V6:
#if SK_ENABLE_IPV6
        if (skipaddrCompare(&stmt.range_start.addr,
                            &stmt.range_end.addr) > 0)
        {
            skAppPrintErr("Invalid range on line %d: start is greater then end",
                          linenum);
            return -1;
        }
#endif  /* SK_ENABLE_IPV6 */
        break;

      default:
        skAbortBadCase(mode);
    }

    return 0;
}


/*
 *  status = stmtCIDR(state, string);
 *
 *    Set the global 'stmt' to STMT_CIDR and parse the CIDR address in
 *    'string'.  The 'state' parameter is ignored.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
stmtCIDR(
    int                 state,
    char               *string)
{
    skipaddr_t ip;
    uint32_t cidr;
    int rv;

    SK_UNUSED_PARAM(state);

    stmt.type = STMT_CIDR;

    /* parse the CIDR block */
    rv = skStringParseCIDR(&ip, &cidr, string);
    if (rv) {
        skAppPrintErr("Invalid CIDR block on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&ip)) {
        if (mode != SKPREFIXMAP_CONT_ADDR_V6) {
            skAppPrintErr(("Invalid IP on line %d:"
                           " IPv6 address not allowed in %s prefix map"),
                          linenum, modeToName(mode));
            return -1;
        }
    }
#endif /* SK_ENABLE_IPV6 */

    skCIDR2IPRange(&ip, cidr, &stmt.range_start.addr, &stmt.range_end.addr);
    return 0;
}


/*
 *  status = stmtDefault(state, string);
 *
 *    Set the global 'stmt' to STMT_DEFAULT.  The paremters are
 *    ignored.  Return 0.
 */
static int
stmtDefault(
    int                 state,
    char               *string)
{
    SK_UNUSED_PARAM(state);
    SK_UNUSED_PARAM(string);

    if (default_set) {
        skAppPrintErr(("Invalid default on line %d: "
                       " Multiple default statements or"
                       " setting default in non-empty map"),
                      linenum);
        return -1;
    }
    stmt.type = STMT_DEFAULT;
    return 0;
}


/*
 *  status = stmtIPs(state, string);
 *
 *    Set the global 'stmt' to STMT_IPS and parse the IP address in
 *    'string'.  The 'state' parameter is 0 for the first IP on the
 *    line, and 1 for the second IP.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
stmtIPs(
    int                 state,
    char               *string)
{
    skipaddr_t ip;
    int rv;

    assert(state == 0 || stmt.type == STMT_IPS);
    stmt.type = STMT_IPS;

    rv = skStringParseIP(&ip, string);
    if (rv) {
        skAppPrintErr("Invalid IP on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&ip)) {
        if (mode != SKPREFIXMAP_CONT_ADDR_V6) {
            skAppPrintErr(("Invalid IP on line %d:"
                           " IPv6 address not allowed in %s prefix map"),
                          linenum, modeToName(mode));
            return -1;
        }
    }
#endif /* SK_ENABLE_IPV6 */

    if (state == 0) {
        skipaddrCopy(&stmt.range_start.addr, &ip);
    } else {
        skipaddrCopy(&stmt.range_end.addr, &ip);
    }
    return 0;
}


/*
 *  status = stmtLabel(state, string);
 *
 *    Label statements are not permitted once the default statement is
 *    seen or the parsing of ranges begins, so return -1 if labels are
 *    no longer allowed.
 *
 *    Otherwise, set the global 'stmt' to STMT_LABEL.  If 'state' is 0
 *    return immediately; if state is 1, parse the label-id in
 *    'string'.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
stmtLabel(
    int                 state,
    char               *string)
{
    uint32_t val;
    int rv;

    assert(state == 0 || stmt.type == STMT_LABEL);
    if (0 == state) {
        if (!label_stmt_allowed) {
            skAppPrintErr(("Invalid label on line %d:"
                           " label only permitted before 'default'"
                           " and range statements"),
                          linenum);
            return -1;
        }
        stmt.type = STMT_LABEL;
        label_stmt_seen = 1;
        return 0;
    }

    /* parse the identifier */
    rv = skStringParseUint32(&val, string, 0, SKPREFIXMAP_MAX_VALUE);
    if (rv) {
        skAppPrintErr("Invalid label on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }

    stmt.value = val;
    return 0;
}


/*
 *  status = stmtMapName(state, string);
 *
 *    Set the prefix map name to 'string'.  Return 0 on success or -1
 *    for failure.
 */
static int
stmtMapName(
    int                 state,
    char               *string)
{
    skPrefixMapErr_t rv;

    SK_UNUSED_PARAM(state);
    if (skPrefixMapGetMapName(map) != NULL) {
        skAppPrintErr("Multiple map-names specified in input");
        return -1;
    }
    rv = skPrefixMapSetMapName(map, string);
    if (rv) {
        skAppPrintErr("Error setting prefix map name to '%s': %s",
                      string, skPrefixMapStrerror(rv));
        return -1;
    }
    return 0;
}


/*
 *  status = stmtMode(state, string);
 *
 *    Determine whether 'string' represents the name of a mode.  If
 *    so, set the global 'mode' to new_mode, unless the mode has
 *    previously been set to another value.
 *
 *    Return 0 on success or -1 for conflicting mode definitions or
 *    invalid mode string.
 */
static int
stmtMode(
    int                 state,
    char               *string)
{
    skPrefixMapContent_t new_mode;

    SK_UNUSED_PARAM(state);
    if (parseMode(string, &new_mode)) {
        /* Allow 'ip' as an alias for 'ipv4' */
        if (0 == strcmp(string, "ip")) {
            new_mode = SKPREFIXMAP_CONT_ADDR_V4;
        } else {
            skAppPrintErr("Invalid mode '%s' given on line %d",
                          string, linenum);
            return -1;
        }
    }
#if !SK_ENABLE_IPV6
    if (SKPREFIXMAP_CONT_ADDR_V6 == new_mode) {
        skAppPrintErr(("Unsupported mode '%s' given on line %d: This SiLK"
                       " installation was built without IPv6 address support"),
                      string, linenum);
        return -1;
    }
#endif  /* !SK_ENABLE_IPV6 */

    if (MODE_SET_DEFAULT == mode_set) {
        /* not explicitly set yet */
        mode_set = MODE_SET_STMT;
        mode = new_mode;
        skPrefixMapSetContentType(map, (skPrefixMapContent_t)mode);
    } else if (mode != new_mode) {
        const char *err_string = "UNKNOWN";
        switch (mode_set) {
          case MODE_SET_STMT:
            err_string = "Mode does not match previous mode statement";
            break;
          case MODE_SET_SWITCH:
            err_string = "Mode does not match mode specified on command line";
            break;
          case MODE_SET_RANGE:
            err_string = "Cannot change mode after processing a range";
            break;
          case MODE_SET_DEFAULT:
            skAbortBadCase(mode_set);
        }
        skAppPrintErr("Mode conflict on line %d: %s",
                      linenum, err_string);
        return -1;
    }

    return 0;
}


/*
 *  status = stmtNumbers(state, string);
 *
 *    Set the global 'stmt' to STMT_NUMBERS and, depending on the
 *    global 'mode', parse the text in 'string' as an IP address or as
 *    a protocol.  The 'state' parameter is 0 for the first number on
 *    the line, and 1 for the second number.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
stmtNumbers(
    int                 state,
    char               *string)
{
    skipaddr_t ip;
    uint32_t tmp32;
    int rv;

    assert(state == 0 || stmt.type == STMT_NUMBERS);
    stmt.type = STMT_NUMBERS;

    if (MODE_SET_DEFAULT == mode_set) {
        mode_set = MODE_SET_RANGE;
    }

    if (mode == SKPREFIXMAP_CONT_PROTO_PORT) {
        rv = skStringParseUint32(&tmp32, string, 0, 255);
        if (rv) {
            skAppPrintErr("Invalid protocol on line %d '%s': %s",
                          linenum, string, skStringParseStrerror(rv));
            return -1;
        }

        if (state == 0) {
            stmt.range_start.pp.proto = tmp32;
            stmt.range_start.pp.port = 0;
        } else {
            stmt.range_end.pp.proto = tmp32;
            stmt.range_end.pp.port = UINT16_MAX;
        }
        return 0;
    }

    rv = skStringParseIP(&ip, string);
    if (rv) {
        skAppPrintErr("Invalid IP on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }

    if (state == 0) {
        skipaddrCopy(&stmt.range_start.addr, &ip);
    } else {
        skipaddrCopy(&stmt.range_end.addr, &ip);
    }
    return 0;
}


/*
 *  status = stmtIPs(state, string);
 *
 *    Set the global 'stmt' to STMT_PROPORTS and parse the proto/port
 *    pair in 'string'.  The 'state' parameter is 0 for the first
 *    proto/port pair on the line, and 1 for the second pair.
 *
 *    Return 0 on success or -1 for failure.
 */
static int
stmtProPorts(
    int                 state,
    char               *string)
{
    uint32_t proto;
    uint32_t port;
    int rv;

    assert(state == 0 || stmt.type == STMT_PROPORTS);
    stmt.type = STMT_PROPORTS;

    /* protocol */
    rv = skStringParseUint32(&proto, string, 0, 255);
    if (rv < 0) {
        skAppPrintErr("Invalid protocol on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }

    if (rv == 0) {
        skAppPrintErr("Missing port value on line %d",
                      linenum);
        return -1;
    }

    /* rv is location of the '/' */
    string += rv + 1;

    /* port */
    rv = skStringParseUint32(&port, string, 0, UINT16_MAX);
    if (rv) {
        skAppPrintErr("Invalid port on line %d '%s': %s",
                      linenum, string, skStringParseStrerror(rv));
        return -1;
    }

    if (state == 0) {
        stmt.range_start.pp.proto = proto;
        stmt.range_start.pp.port = port;
    } else {
        stmt.range_end.pp.proto = proto;
        stmt.range_end.pp.port = port;
    }
    return 0;
}


/*
 *  status = gotLabel(label);
 *
 *    Use the global 'stmt' to decide what needs to be done with the
 *    label in 'label'.
 *
 *    Return 0 on success or non-zero for failure.
 */
static int
gotLabel(
    char               *string)
{
    static int dict_num_entries = 0;
    uint32_t dict_val;
    int rv = -1;

    /* Create an dictionary entry with a specific value */
    if (stmt.type == STMT_LABEL) {
        rv = skPrefixMapDictionaryInsert(map, stmt.value, string);
        if (rv) {
            skAppPrintErr(("Invalid label on line %d '%" PRIu32 " %s': %s"),
                          linenum, stmt.value, string,
                          skPrefixMapStrerror(rv));
        }
        dict_num_entries = skPrefixMapDictionaryGetWordCount(map);
        return rv;
    }

    /* we either have a default statement or a range, so label
     * statements are no longer permitted in the input */
    label_stmt_allowed = 0;

    /* check if we need to initialize the mode and default */
    if (stmt.type != STMT_DEFAULT) {
        if (MODE_SET_DEFAULT == mode_set) {
            mode_set = MODE_SET_RANGE;
        }
        if (default_set == 0) {
            rv = skPrefixMapDictionarySearch(map, DEFAULT_LABEL, &dict_val);
            if (rv != SKPREFIXMAP_OK) {
                skAppPrintErr("Unable to create default value: %s",
                              skPrefixMapStrerror(rv));
                return rv;
            }
            rv = skPrefixMapSetDefaultVal(map, dict_val);
            if (rv != SKPREFIXMAP_OK) {
                skAppPrintErr("Unable to set default: %s",
                              skPrefixMapStrerror(rv));
                return rv;
            }
            default_set = 1;
        }
    }

    /* if a label statement was seen, the value in 'string' must be
     * the ID or the text of an existing label */
    if (label_stmt_seen) {
        if (0 == dict_num_entries) {
            skAppPrintErr("No label statements successfully parsed. Exiting");
            exit(EXIT_FAILURE);
        }
        /* try to parse 'string' as a number that maps into
         * dictionary.  if that fails, try to find 'string' in the
         * dictionary */
        if (skStringParseUint32(&dict_val, string, 0, dict_num_entries-1)) {
            dict_val = skPrefixMapDictionaryLookup(map, string);
            if (SKPREFIXMAP_NOT_FOUND == dict_val) {
                skAppPrintErr("Using unknown label on line %d '%s'",
                              linenum, string);
                return -1;
            }
        }
    } else {
        /* search-for or add the label */
        rv = skPrefixMapDictionarySearch(map, string, &dict_val);
        if (rv) {
            skAppPrintErr("Invalid label on line %d '%s': %s",
                          linenum, string, skPrefixMapStrerror(rv));
            return rv;
        }
    }

    switch (stmt.type) {
      case STMT_DEFAULT:
        if (dict_val >= skPrefixMapDictionaryGetWordCount(map)) {
            skAppPrintErr("Default set to undefined index '%s'",
                          string);
            return -1;
        }
        rv = skPrefixMapSetDefaultVal(map, dict_val);
        if (rv) {
            skAppPrintErr("Invalid default on line %d: %s",
                          linenum, skPrefixMapStrerror(rv));
            return -1;
        }
        default_set = 1;
        break;

      case STMT_CIDR:
      case STMT_IPS:
        if ((mode != SKPREFIXMAP_CONT_ADDR_V4)
            && (mode != SKPREFIXMAP_CONT_ADDR_V6))
        {
            skAppPrintErr(("Invalid IP on line %d:"
                           " IP address not allowed in %s prefix map"),
                          linenum, modeToName(mode));
            return -1;
        }
        /* FALLTHROUGH */

      case STMT_NUMBERS:
        if (checkRange()) {
            return -1;
        }
        if (dry_run) {
            break;
        }
        rv = skPrefixMapAddRange(map, &stmt.range_start, &stmt.range_end,
                                 dict_val);
        if (rv) {
            skAppPrintErr("Cannot add entry on line %d to prefix map: %s",
                          linenum, skPrefixMapStrerror(rv));
            return -1;
        }
        break;

      case STMT_PROPORTS:
        if (mode != SKPREFIXMAP_CONT_PROTO_PORT) {
            skAppPrintErr(("Invalid proto/port input on line %d in "
                           "IP prefix map input file"),
                          linenum);
            return -1;
        }
        if (checkRange()) {
            return -1;
        }
        if (dry_run) {
            break;
        }
        rv = skPrefixMapAddRange(map, &stmt.range_start, &stmt.range_end,
                                 dict_val);
        if (rv) {
            skAppPrintErr("Cannot add entry on line %d to prefix map: %s",
                          linenum, skPrefixMapStrerror(rv));
            return -1;
        }
        break;

      case STMT_LABEL:
        /* this was handled above; we can't get here */
        skAbortBadCase(stmt.type);
    }

    return 0;
}


/* we could handle this with "%option noyywrap", but defining this as
 * a function eliminates an unreachable-code compiler warning. */
int
yywrap(
    void)
{
    return 1;
}


int main(
    int         argc,
    char      **argv)
{
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    /* Create the global prefix map */
    if (skPrefixMapCreate(&map) != SKPREFIXMAP_OK) {
        skAppPrintErr("Error creating prefix map");
        exit(EXIT_FAILURE);
    }

    /* set the content type to the current value of mode; this can be
     * changed at a later time */
    skPrefixMapSetContentType(map, mode);

    /* Process input */
    yyin = in_stream.of_fp;
    yylex();

    /* finished scanning.  clean up flex's state */
#ifdef SK_HAVE_YYLEX_DESTROY
    yylex_destroy();
#else
    yy_delete_buffer(YY_CURRENT_BUFFER);
#endif

    if (error_count) {
        const char *not_written = "  Output not written.";
        if (dry_run || ignore_errors) {
            not_written = "";
        }

        skAppPrintErr("Encountered %d warning%s during processing.%s",
                      error_count, ((error_count > 1) ? "s" : ""),
                      not_written);
        if (dry_run || !ignore_errors) {
            exit(EXIT_FAILURE);
        }
    }

    if (dry_run) {
        appTeardown();
        return 0;
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
            skAppPrintErr("Error writing prefix map to '%s': %s",
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

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
