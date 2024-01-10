/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
 *  rwmatch
 *
 *
 *    rwmatch reads records from two SORTED input files and attempts
 *    to label the records that form a match.
 *
 *    The fields from each file over which to match are specified by
 *    the --relate command line switch.  This switch accepts two
 *    fields separated by a comma.  The --relate switch may be
 *    repeated so that multiple fields on the two records are tested
 *    to determine if they match.
 *
 *    For the rwmatch algorithm to work, the first file should be
 *    sorted by the first value in each of the --relate pairs in the
 *    order in which the --relate pairs are specified, and the second
 *    file should be sorted by the second value in each relate pair.
 *    The final value for the sort key for each input file should be
 *    the start time.
 *
 *    rwmatch reads records from each file and attempts to establish a
 *    match.  Records are considered to match when, for each pair of
 *    fields, say (F1,F2) in each of the --relate switches, the value
 *    of field F1 on the record read from the first file has the same
 *    value as the value of field F2 on the record read from the
 *    second file and the records must be within a time window.  The
 *    default time window is that the second record's start time must
 *    occur within the time that the first record was active, that is
 *
 *      rec1.stime <= rec2.stime <= rec1.etime
 *
 *    The --time-delta switch extends end-point of the time window by
 *    the specified number of seconds.  When the --symmetric-delta
 *    switch is specified, records are also considered a match when
 *    the first record begins within the time when the second record
 *    was active, plus and --time-delta, that is:
 *
 *      rec2.stime <= rec1.stime <= rec2.etime + time_delta.
 *
 *    Once a match is established, the match is assigned the next
 *    match_id.
 *
 *    In order to determine if additional records should be considered
 *    part of the same match, the record with the earlier start time
 *    is used as a base-record.  If the two records that established
 *    the match have the same start time, a heuristic is used to
 *    attempt to determine the base record.  If the heuristic fails,
 *    the record from the first file is used as the base record.
 *
 *    Records from each file are compared to the base record.  If the
 *    fields specified in the --relate pairs for the candidate record
 *    match the base record and if the candidate record is within a
 *    time window (described below), the candidate record is added to
 *    the match.  When the base record and candidate record come from
 *    the same file, only one side of the --relate pair values is
 *    used.
 *
 *    When adding a record to an existing match, the time window can
 *    be altered by the use of the --absolute-delta, --relative-delta,
 *    and --infinite-delta switches.  With --infinite-delta, time is
 *    ignored and candidate records are added to the match as long as
 *    the --relate fields match.  With --absolute-delta, the
 *    candidate's start time must occur while the base record is
 *    active or within --time-delta seconds of the base record's
 *    end-time.  When --relative-delta is specified, the time-window
 *    ends --time-delta seconds beyond the maximum end-time for all
 *    the records that comprise the match.
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwmatch.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>


/* TYPEDEFS AND DEFINES */

/* Where to send --help output */
#define USAGE_FH stdout

/* Maximum number of --relate pairs allowed */
#define RELATE_COUNT_MAX 128u

typedef enum {
    MATCH_QUERY = 0,
    MATCH_RESPONSE = 1
} match_rec_t;

/* make certain these are kept in same order as options */
typedef enum {
    ABSOLUTE_DELTA, RELATIVE_DELTA, INFINITE_DELTA
} delta_enum_t;

/* val_t is used when comparing values */
struct val_st {
    skipaddr_t  ip;
    uint32_t    u32;
    int32_t     is_ipv6;
};
typedef struct val_st val_t;


/* LOCAL VARIABLES */

/* input and output streams */
static skstream_t *query_stream = NULL;
static skstream_t *response_stream = NULL;
static skstream_t *matched_stream = NULL;

/* ipv6-policy */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;

/* available fields; rwAsciiFieldMapAddDefaultFields() fills this */
static sk_stringmap_t *field_map = NULL;

/* the pairs of fields to match on as set by --relate */
static unsigned int relate_count;
static rwrec_printable_fields_t relate[RELATE_COUNT_MAX][2];

/* time difference between query and response in milliseconds */
static sktime_t delta_msec = 0;

/* whether to allow the "response" to precede the "query"; for
 * handling traffic where either side may initiate the connection. */
static int symmetric_delta = 0;

/* whether to write unmatched queries/responses in match file */
static int write_unmatched_query = 0;
static int write_unmatched_response = 0;

/* time-delta policy and flags */
static delta_enum_t delta_policy = ABSOLUTE_DELTA;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;


/* OPTIONS SETUP */

typedef enum {
    OPT_HELP_RELATE,
    OPT_RELATE,
    OPT_TIME_DELTA,
    OPT_SYMMETRIC_DELTA,
    /* next three must be in same order as delta_enum_t */
    OPT_ABSOLUTE_DELTA,
    OPT_RELATIVE_DELTA,
    OPT_INFINITE_DELTA,
    OPT_UNMATCHED
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-relate",     NO_ARG,       0, OPT_HELP_RELATE},
    {"relate",          REQUIRED_ARG, 0, OPT_RELATE},
    {"time-delta",      REQUIRED_ARG, 0, OPT_TIME_DELTA},
    {"symmetric-delta", NO_ARG,       0, OPT_SYMMETRIC_DELTA},
    {"absolute-delta",  NO_ARG,       0, OPT_ABSOLUTE_DELTA},
    {"relative-delta",  NO_ARG,       0, OPT_RELATIVE_DELTA},
    {"infinite-delta",  NO_ARG,       0, OPT_INFINITE_DELTA},
    {"unmatched",       REQUIRED_ARG, 0, OPT_UNMATCHED},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe potential fields for --relate and exit. Def. no",
    NULL,  /* generate dynamically */
    ("Permit this time difference (in seconds) between two\n"
     "\trecords when creating a match. May be fractional. Def. 0.000"),
    ("Also match response records that precede query records\n"
     "\tby up to time-delta seconds. Def. No"),
    ("Do not include potentially matching flows that start\n"
     "\tmore than time-delta seconds after the end of the initial flow\n"
     "\tof the current match. Def. Yes"),
    ("Continue match with flows that start within time-delta\n"
     "\tseconds of the greatest end time seen for previous\n"
     "\tmembers of the current match. Def. No."),
    ("After forming the initial pair of the match, continue\n"
     "\tmatching on fields alone, ignoring time. Def. No."),
    ("Include unmatched records from QUERY_FILE and/or\n"
     "\tRESPONSE_FILE in OUTPUT_FILE.  Parameter is one of [QqRrBb], where:\n"
     "\tQ / q - query file; R / r - response file, B / b - both"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseRelateFields(const char *relate_pair);
static void helpFields(FILE *fh);


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
    ("--relate=FIELD_PAIR QUERY_FILE RESPONSE_FILE OUTPUT_FILE\n"        \
     "\tRead SiLK Flow records from the QUERY_FILE and RESPONSE_FILE,\n" \
     "\tuse the FIELD_PAIR(s) to group the records as queries and\n"     \
     "\tresponses, and write the matched records to OUTPUT_FILE.\n")

#define RELATE_FIELD_USAGE \
    ("Match this pair of fields across records. Specify the fields\n"       \
     "\tas '<query field>,<response field>'. Repeat the switch to relate\n" \
     "\tmultiple fields. The switch may be repeated %u times.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (i) {
          case OPT_RELATE:
            fprintf(fh, RELATE_FIELD_USAGE, RELATE_COUNT_MAX);
            skStringMapPrintUsage(field_map, fh, 4);
            break;
          default:
            assert(appHelp[i]);
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }

    skIPv6PolicyUsage(fh);
    skCompMethodOptionsUsage(fh);
    skOptionsNotesUsage(fh);
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

    if (field_map) {
        skStringMapDestroy(field_map);
    }

    rv = skStreamDestroy(&query_stream);
    if (rv) {
        skStreamPrintLastErr(query_stream, rv, &skAppPrintErr);
    }

    rv = skStreamDestroy(&response_stream);
    if (rv) {
        skStreamPrintLastErr(response_stream, rv, &skAppPrintErr);
    }

    rv = skStreamDestroy(&matched_stream);
    if (rv) {
        skStreamPrintLastErr(matched_stream, rv, &skAppPrintErr);
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
    sk_file_header_t *matched_hdr;
    sk_file_format_t fmt = FT_RWGENERIC;
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
    relate_count = 0;

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE)
        || skIPv6PolicyOptionsRegister(&ipv6_policy))
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

    /* initialize string-map of field identifiers, then remove the
     * time fields */
    if (rwAsciiFieldMapAddDefaultFields(&field_map)) {
        skAppPrintErr("Unable to create fields stringmap");
        exit(EXIT_FAILURE);
    }
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_NHIP);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_STIME);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ETIME);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ELAPSED);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_STIME_MSEC);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ETIME_MSEC);
    (void)skStringMapRemoveByID(field_map, RWREC_FIELD_ELAPSED_MSEC);

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();             /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* verify that related pairs were given */
    if (0 == relate_count) {
        skAppPrintErr("At least one --%s pair must be given",
                      appOptions[OPT_RELATE].name);
        skAppUsage();             /* never returns */
    }

    /* get the file arguments */
    if (arg_index == argc) {
        skAppPrintErr("Missing QUERY_FILE argument");
        skAppUsage();             /* never returns */
    }
    if ((rv = skStreamCreate(&query_stream, SK_IO_READ, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(query_stream, argv[arg_index])))
    {
        skStreamPrintLastErr(query_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    arg_index++;

    if (arg_index == argc) {
        skAppPrintErr("Missing RESPONSE_FILE argument");
        skAppUsage();             /* never returns */
    }
    if ((rv = skStreamCreate(&response_stream,SK_IO_READ,SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(response_stream, argv[arg_index])))
    {
        skStreamPrintLastErr(response_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    arg_index++;

    if (arg_index == argc) {
        skAppPrintErr("Missing OUTPUT_FILE argument");
        skAppUsage();             /* never returns */
    }
    if ((rv = skStreamCreate(&matched_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(matched_stream, argv[arg_index])))
    {
        skStreamPrintLastErr(matched_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    arg_index++;

    /* check for extra options */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage(); /* never returns */
    }

    /* Now, open the files */
    if ((rv = skStreamSetIPv6Policy(query_stream, ipv6_policy))
        || (rv = skStreamOpen(query_stream))
        || (rv = skStreamReadSilkHeader(query_stream, NULL)))
    {
        skStreamPrintLastErr(query_stream, rv, &skAppPrintErr);
        skStreamDestroy(&query_stream);
        skAppPrintErr("Cannot open QUERY_FILE. Exiting.");
        exit(EXIT_FAILURE);
    }

    if ((rv = skStreamSetIPv6Policy(response_stream, ipv6_policy))
        || (rv = skStreamOpen(response_stream))
        || (rv = skStreamReadSilkHeader(response_stream, NULL)))
    {
        skStreamPrintLastErr(response_stream, rv, &skAppPrintErr);
        skStreamDestroy(&response_stream);
        skAppPrintErr("Cannot open RESPONSE_FILE. Exiting.");
        exit(EXIT_FAILURE);
    }

#if SK_ENABLE_IPV6
    /* Determine the file format; use the IPv6 format if the user
     * wants to process IPs as IPv6 or if either input file is in an
     * IPv6 format */
    if (ipv6_policy > SK_IPV6POLICY_MIX) {
        fmt = FT_RWIPV6ROUTING;
    } else {
        sk_file_header_t *hdr[2];
        unsigned i;

        hdr[0] = skStreamGetSilkHeader(query_stream);
        hdr[1] = skStreamGetSilkHeader(response_stream);
        for (i = 0; i < 2; ++i) {
            switch (skHeaderGetFileFormat(hdr[i])) {
              case FT_RWIPV6ROUTING:
              case FT_RWIPV6:
                fmt = FT_RWIPV6ROUTING;
                i = 2;
                break;
            }
        }
    }
#endif  /* SK_ENABLE_IPV6 */

    matched_hdr = skStreamGetSilkHeader(matched_stream);

    if ((rv = skHeaderSetFileFormat(matched_hdr, fmt))
        || (rv = skHeaderSetCompressionMethod(matched_hdr, comp_method))
        || (rv = skHeaderAddInvocation(matched_hdr, 1, argc, argv))
        || (rv = skOptionsNotesAddToStream(matched_stream))
        || (rv = skStreamOpen(matched_stream))
        || (rv = skStreamWriteSilkHeader(matched_stream)))
    {
        skStreamPrintLastErr(matched_stream, rv, &skAppPrintErr);
        skStreamDestroy(&matched_stream);
        skAppPrintErr("Cannot open OUTPUT_FILE. Exiting.");
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
    static int delta_seen = 0;
    double opt_double;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_HELP_RELATE:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_RELATE:
        if (parseRelateFields(opt_arg)) {
            return 1;
        }
        break;

      case OPT_TIME_DELTA:
        rv = skStringParseDouble(&opt_double, opt_arg, 0.001, INT32_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        delta_msec = (sktime_t)(1000.0 * opt_double);
        break;

      case OPT_SYMMETRIC_DELTA:
        symmetric_delta = 1;
        break;

      case OPT_ABSOLUTE_DELTA:
      case OPT_RELATIVE_DELTA:
      case OPT_INFINITE_DELTA:
        /* May only specify once */
        if (delta_seen) {
            skAppPrintErr("May only specify one of --%s, --%s, or --%s",
                          appOptions[OPT_ABSOLUTE_DELTA].name,
                          appOptions[OPT_RELATIVE_DELTA].name,
                          appOptions[OPT_INFINITE_DELTA].name);
            return 1;
        }
        delta_seen = 1;
        delta_policy = (delta_enum_t)(opt_index - OPT_ABSOLUTE_DELTA);
        break;

      case OPT_UNMATCHED:
        if (strlen(opt_arg) != 1) {
            skAppPrintErr(("Invalid %s '%s': "
                           "argument must be one of \"q,r,b\""),
                          appOptions[opt_index].name, opt_arg);
            return 1;
        } else {
            switch (opt_arg[0]) {
              case 'Q':
              case 'q':
                write_unmatched_query = 1;
                break;
              case 'R':
              case 'r':
                write_unmatched_response = 1;
                break;
              case 'B':
              case 'b':
                write_unmatched_query = 1;
                write_unmatched_response = 1;
                break;
              default:
                skAppPrintErr(("Invalid %s '%s': "
                               "argument must be one of \"qrb\""),
                              appOptions[opt_index].name, opt_arg);
                return 1;
            }
        }
        break;
    }

    return 0; /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  status = parseRelateFields(relate_pair);
 *
 *    Parse the user's option for the --relate switch and
 *    update the globals relate[] and relate_count.  Return 0 on
 *    success; -1 on failure.
 */
static int
parseRelateFields(
    const char         *relate_pair)
{
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    char *errmsg;
    unsigned int i;
    int rv = -1;

    /* ensure there is space for this pair */
    if (relate_count == RELATE_COUNT_MAX) {
        skAppPrintErr(("Invalid %s: Total number of pairs specified"
                       " exceeds maximum (%u)"),
                      appOptions[OPT_RELATE].name, RELATE_COUNT_MAX);
        goto END;
    }

    /* parse this pair */
    if (skStringMapParse(field_map, relate_pair, SKSTRINGMAP_DUPES_KEEP,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      appOptions[OPT_RELATE].name, errmsg);
        goto END;
    }

    /* fill the next pair IDs */
    i = 0;
    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (i == 2) {
            /* break the while() and handle too many fields */
            i = 3;
            break;
        }
        if (entry->id >= RWREC_PRINTABLE_FIELD_COUNT) {
            skAbort();
        }
        relate[relate_count][i] = (rwrec_printable_fields_t)entry->id;
        ++i;
    }
    if (i != 2) {
        skAppPrintErr("Invalid %s '%s': Exactly two fields must be specified",
                      appOptions[OPT_RELATE].name, relate_pair);
        goto END;
    }

    /* success */
    ++relate_count;
    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    return rv;
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
    fprintf(fh,
            ("The following names may be used in the --%s switch. Names are\n"
             "case-insensitive and may be abbreviated to the shortest"
             " unique prefix.\n"),
            appOptions[OPT_RELATE].name);

    skStringMapPrintDetailedUsage(field_map, fh);
}


/*
 *    Read a record from 'stream' and fill 'rwrec'.  Return 1 if the
 *    read was successful.  If the read was not successful, print an
 *    error message if the error was unexpected and return 0.
 */
static int
read_record(
    skstream_t         *stream,
    rwRec              *rwrec)
{
    ssize_t rv;

    rv = skStreamReadRecord(stream, rwrec);
    if (SKSTREAM_OK == rv) {
        return 1;
    }
    if (SKSTREAM_ERR_EOF != rv) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
    }
    return 0;
}


/*
 *    Write the record 'rwrec' to the match stream, setting the lower
 *    three octets of the next-hop IP of the record to 'match_id' and
 *    the highest octet based on the source_stream.  Exit the
 *    application if the write fails.
 */
static void
write_record(
    rwRec              *rwrec,
    uint32_t            match_id,
    match_rec_t         source_stream)
{
    skipaddr_t ip;
    ssize_t rv;

    if (MATCH_RESPONSE == source_stream) {
        match_id |= 0xFF000000;
    }
    skipaddrSetV4(&ip, &match_id);
    rwRecMemSetNhIP(rwrec, &ip);
    rv = skStreamWriteRecord(matched_stream, rwrec);
    if (SKSTREAM_ERROR_IS_FATAL(rv)) {
        skStreamPrintLastErr(matched_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
}


/*
 *    Given a record and a field ID, file 'value' with the value of
 *    the field for that record.
 */
static void
getField(
    const rwRec                *current_rec,
    rwrec_printable_fields_t    field_id,
    val_t                      *value)
{
    value->is_ipv6 = 0;

    switch (field_id) {
      case RWREC_FIELD_SIP:
#if SK_ENABLE_IPV6
        if (rwRecIsIPv6(current_rec)) {
            value->is_ipv6 = 1;
            rwRecMemGetSIP(current_rec, &value->ip);
        } else
#endif  /*  SK_ENABLE_IPV6 */
        {
            value->u32 = rwRecGetSIPv4(current_rec);
        }
        break;
      case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
        if (rwRecIsIPv6(current_rec)) {
            value->is_ipv6 = 1;
            rwRecMemGetDIP(current_rec, &value->ip);
        } else
#endif  /*  SK_ENABLE_IPV6 */
        {
            value->u32 = rwRecGetDIPv4(current_rec);
        }
        break;
      case RWREC_FIELD_SPORT:
        value->u32 = rwRecGetSPort(current_rec);
        break;
      case RWREC_FIELD_DPORT:
        value->u32 = rwRecGetDPort(current_rec);
        break;
      case RWREC_FIELD_PROTO:
        value->u32 = rwRecGetProto(current_rec);
        break;
      case RWREC_FIELD_PKTS:
        value->u32 = rwRecGetPkts(current_rec);
        break;
      case RWREC_FIELD_BYTES:
        value->u32 = rwRecGetBytes(current_rec);
        break;
      case RWREC_FIELD_FLAGS:
        value->u32 = rwRecGetFlags(current_rec);
        break;
      case RWREC_FIELD_SID:
        value->u32 = rwRecGetSensor(current_rec);
        break;
      case RWREC_FIELD_INPUT:
        value->u32 = rwRecGetInput(current_rec);
        break;
      case RWREC_FIELD_OUTPUT:
        value->u32 = rwRecGetOutput(current_rec);
        break;
      case RWREC_FIELD_INIT_FLAGS:
        value->u32 = rwRecGetInitFlags(current_rec);
        break;
      case RWREC_FIELD_REST_FLAGS:
        value->u32 = rwRecGetRestFlags(current_rec);
        break;
      case RWREC_FIELD_TCP_STATE:
        value->u32 = rwRecGetTcpState(current_rec);
        break;
      case RWREC_FIELD_APPLICATION:
        value->u32 = rwRecGetApplication(current_rec);
        break;
      case RWREC_FIELD_FTYPE_CLASS:
        value->u32 = sksiteFlowtypeGetClassID(rwRecGetFlowType(current_rec));
        break;
      case RWREC_FIELD_FTYPE_TYPE:
        value->u32 = rwRecGetFlowType(current_rec);
        break;
      case RWREC_FIELD_ICMP_TYPE:
        value->u32 = rwRecGetIcmpType(current_rec);
        break;
      case RWREC_FIELD_ICMP_CODE:
        value->u32 = rwRecGetIcmpCode(current_rec);
        break;
      default:
        skAbortBadCase(field_id);
    }
}


/*
 *    Compare the records 'rec_1' and 'rec_2' based on the fields
 *    specified by the --relate pairs, where 'type_1' and 'type_2'
 *    specify the type of the records, respectively.
 *
 *    Return 0 if the records are equal.  Return -1 is 'rec_1' is less
 *    than 'rec_2'.  Return 1 if 'rec_2' is less than 'rec_1'.
 *
 *    The records may be from the same input file or different input
 *    files.  When the records are from the same input file, only one
 *    side of the --relate pair values are used.
 */
static int
compareFields(
    const rwRec        *rec_1,
    match_rec_t         type_1,
    const rwRec        *rec_2,
    match_rec_t         type_2)
{
#if SK_ENABLE_IPV6
    skipaddr_t tmp_ip;
    int rv;
#endif
    unsigned int i;
    val_t val_1;
    val_t val_2;

    assert(type_1 == MATCH_QUERY || type_1 == MATCH_RESPONSE);
    assert(type_2 == MATCH_QUERY || type_2 == MATCH_RESPONSE);

    for (i = 0; i < relate_count; ++i) {
        getField(rec_1, relate[i][type_1], &val_1);
        getField(rec_2, relate[i][type_2], &val_2);
#if SK_ENABLE_IPV6
        if (val_1.is_ipv6) {
            if (val_2.is_ipv6) {
                /* val_1 and val_2 are IPv6; compare IPs */
                rv = skipaddrCompare(&val_1.ip, &val_2.ip);
                if (rv) { return rv; }
            } else {
                /* val_2 is a number. make it an IP and compare*/
                skipaddrSetV4(&tmp_ip, &val_2.u32);
                rv = skipaddrCompare(&val_1.ip, &tmp_ip);
                if (rv) { return rv; }
            }
        } else if (val_2.is_ipv6) {
            /* val_1 is a number. make it an IP and compare*/
            skipaddrSetV4(&tmp_ip, &val_1.u32);
            rv = skipaddrCompare(&tmp_ip, &val_2.ip);
            if (rv) { return rv; }
        } else
#endif  /* SK_ENABLE_IPV6 */
        {
            /* compare two numbers */
            if (val_1.u32 < val_2.u32) {
                return -1;
            } else if (val_1.u32 > val_2.u32) {
                return 1;
            }
        }
    }
    return 0;
}


/*
 *    Attempt to determine who started the conversation that is
 *    represented by the match pair 'query_rec' and
 *    'response_rec'. The function returns one of MATCH_QUERY or
 *    MATCH_RESPONSE.
 *
 *    This function should only be invoked when the start times of the
 *    two records are identical.  When the records have different
 *    start times, the caller should assume the record with the
 *    earlier start time began the conversation.
 *
 *    If the protocol is TCP or UDP, we see if one of the query ports
 *    is in the range 0-1023 and the other in the range 1024-65535. If
 *    this is the case, assume the flow is in the direction of the low
 *    port.
 *
 *    This could be supplemented by using a set to define a set of
 *    service ports and using them in the same way.  Other techniques
 *    could be based on, e.g. first flags for TCP, etc.
 *
 *    If all else fails, the default is that the query side is favored
 *    and MATCH_QUERY is returned.
 */
static match_rec_t
guessQueryDirection(
    const rwRec        *query_rec,
    const rwRec UNUSED(*response_rec))
{
    /* Times equal, make a guess */
    if ((rwRecGetProto(query_rec) == 6) || (rwRecGetProto(query_rec) == 17)) {
        if (rwRecGetDPort(query_rec) < 1024) {
            if (rwRecGetSPort(query_rec) > 1023) {
                return MATCH_QUERY;
            }
        } else {
            if (rwRecGetSPort(query_rec) < 1024) {
                return MATCH_RESPONSE;
            }
        }
    }

    /* default */
    return MATCH_QUERY;
}


/*
 *    Check whether the 'query_rec' and the 'response_rec' establish a
 *    match.
 *
 *    If they do, return 0 and set 'base_type' to the record that
 *    should be considered the "basis" for the match.  The basis is
 *    the record that has the earlier start time.  If the start times
 *    are identical, the heuristics specified in guessQueryDirection()
 *    are used.
 *
 *    When the records do not establish a match, return -1 if
 *    'query_rec' is "less than" the 'response_rec' or 1 if
 *    'response_rec' is "less than" the 'query_rec'.
 */
static int
checkForMatch(
    const rwRec        *query_rec,
    const rwRec        *response_rec,
    match_rec_t        *base_type)
{
    sktime_t query_stime;
    sktime_t response_stime;
    int rv;

    /* First check whether the fields match, since files should be
     * sorted by the fields in the --relate list */
    rv = compareFields(query_rec, MATCH_QUERY, response_rec, MATCH_RESPONSE);
    if (rv) {
        /* if fields different, cannot establish a match */
        return rv;
    }

    query_stime = rwRecGetStartTime(query_rec);
    response_stime = rwRecGetStartTime(response_rec);

    if (query_stime == response_stime) {
        /* Same start time establishes a match */
        /* Since times are equal, use a heuristic to decide the
         * base_type */
        *base_type = guessQueryDirection(query_rec, response_rec);
        return 0;
    }

    /* Check the asymmetric case: response must start within the
     * time-window defined by the query */
    if (query_stime < response_stime) {
        if (response_stime <= (rwRecGetEndTime(query_rec) + delta_msec)) {
            /* Since query starts first, it becomes the base_rec */
            *base_type = MATCH_QUERY;
            return 0;
        }
        /* Query record is too early */
        return -1;
    }

    if (symmetric_delta) {
        /* Check the symmetric case: query must start within the
         * time-window defined by the response; we already know
         * response begins before query */
        if (query_stime <= (rwRecGetEndTime(response_rec) + delta_msec)) {
            /* Since response starts first, it becomes the base_rec */
            *base_type = MATCH_RESPONSE;
            return 0;
        }
    }

    /* Response record is too early */
    return 1;
}


int main(int argc, char **argv)
{
    rwRec query_rec;
    rwRec response_rec;
    rwRec base_rec;
    uint32_t match_id;
    int have_query;
    int have_response;
    int have_match_query;
    int have_match_response;
    ssize_t rv;
    match_rec_t base_type;
    match_rec_t match_lead;
    sktime_t max_time;

#define MATCH_TRACE(mt_result)                                  \
    TRACEMSG(("(%c%c)   %c  %s",                                \
              (have_match_query ? 'Q' : ' '),                   \
              (have_match_response ? 'R' : ' '),                \
              ((MATCH_QUERY == match_lead) ? 'Q' : 'R'),       \
              mt_result))

    appSetup(argc, argv); /* never returns on error */

    match_id = 0;
    max_time = INT64_MAX;
    base_type = MATCH_QUERY;

    /*
     * The revised version of this application requires
     * sorted data that matches the mating.  So this means
     * that we're going to have records sorted slightly
     * differently (if we match 2/1, we sort --field=2,9 and
     * --field=1,9) on the two applications.
     *
     * The loop always begins with a reference input record and an
     * output record.  As long as we have both, we continue to loop,
     * flushing the "earlier" or "later" records and processing
     * matches as we find them.
     */
    rv = skStreamReadRecord(query_stream, &query_rec);
    if (SKSTREAM_OK == rv) {
        have_query = 1;
    } else if (SKSTREAM_ERR_EOF == rv) {
        /* QUERY_FILE is empty */
        have_query = 0;
    } else {
        skStreamPrintLastErr(query_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    rv = skStreamReadRecord(response_stream, &response_rec);
    if (SKSTREAM_OK == rv) {
        have_response = 1;
    } else if (SKSTREAM_ERR_EOF == rv) {
        /* RESPONSE_FILE is empty */
        have_response = 0;
    } else {
        skStreamPrintLastErr(response_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    while (have_query && have_response) {
        rv = checkForMatch(&query_rec, &response_rec, &base_type);

        if (rv < 0) {
            /* QUERY is too early; read next query */

            /* if we are including unmatched queries, write the
             * record, after clearing the NHIP field to indicate lack
             * of match */
            if (write_unmatched_query) {
                write_record(&query_rec, 0, MATCH_QUERY);
            }
            have_query = read_record(query_stream, &query_rec);

        } else if (rv > 0) {
            /* RESPONSE is too early; read next response */

            /* if we are including unmatched responses, write them out
             * now, after settting the NHIP field to indicate lack of
             * match */
            if (write_unmatched_response) {
                write_record(&response_rec, 0, MATCH_RESPONSE);
            }
            have_response = read_record(response_stream, &response_rec);

        } else {
            /* RECORDS MATCH. */
            ++match_id;
            have_match_query = 1;
            have_match_response = 1;

            /* The first 'match_lead' is the base record. */
            match_lead = base_type;
            if (base_type == MATCH_QUERY) {
                RWREC_COPY(&base_rec, &query_rec);
            } else {
                RWREC_COPY(&base_rec, &response_rec);
            }
            /* The maximum time-window to use for this match; if the
             * delta_policy is RELATIVE_DELTA, this window will move
             * as additional records are added to the match. */
            if (INFINITE_DELTA != delta_policy) {
                max_time = rwRecGetEndTime(&base_rec) + delta_msec;
            }

            /* sanity check and debugging */
            assert((base_type == MATCH_QUERY)
                   || (base_type == MATCH_RESPONSE));
            TRACEMSG(("M %d %s", match_id,
                      (base_type == MATCH_QUERY ? "RWM_Q" : "RWM_R")));

            /* Now we have the base and we have both match sides. We
             * loop as long as we have at least one record that
             * matches the base */
            for (;;) {
                /* Need to decide which to process */
                if (MATCH_QUERY == match_lead) {
                    /* write the query and read a new one, testing for
                     * a match */
                    write_record(&query_rec, match_id, match_lead);
                    have_query = read_record(query_stream, &query_rec);
                    if (!have_query) {
                        /* EOF on query - No more match pairs */
                        MATCH_TRACE("eof");
                        have_match_query = 0;
                    } else if (0 != compareFields(&base_rec, base_type,
                                                  &query_rec, MATCH_QUERY))
                    {
                        /* No match on fields - No more match pairs */
                        MATCH_TRACE("nF");
                        have_match_query = 0;
                    } else if (rwRecGetStartTime(&query_rec) > max_time) {
                        /* Match on fields but not on time */
                        MATCH_TRACE("nT");
                        have_match_query = 0;
                    } else {
                        /* We have a match on fields and times */
                        MATCH_TRACE("FT");
                        if ((delta_policy == RELATIVE_DELTA)
                            && (max_time
                                < rwRecGetEndTime(&query_rec)+delta_msec))
                        {
                            /* update max_time */
                            max_time = rwRecGetEndTime(&query_rec)+delta_msec;
                        }
                    }

                } else {
                    /* a mirror of the above for 'response' */

                    assert(MATCH_RESPONSE == match_lead);
                    /* write the response and read a new one, testing
                     * for a match */
                    write_record(&response_rec, match_id, match_lead);
                    have_response = read_record(response_stream,&response_rec);
                    if (!have_response) {
                        /* EOF on response - No more match pairs */
                        MATCH_TRACE("eof");
                        have_match_response = 0;
                    } else if (0 != compareFields(&base_rec, base_type,
                                                  &response_rec,
                                                  MATCH_RESPONSE))
                    {
                        /* No match on fields - No more match pairs */
                        MATCH_TRACE("nF");
                        have_match_response = 0;
                    } else if (rwRecGetStartTime(&response_rec) > max_time) {
                        /* Match on fields but not on time */
                        MATCH_TRACE("nT");
                        have_match_response = 0;
                    } else {
                        /* We have a match on fields and times */
                        MATCH_TRACE("FT");
                        if ((delta_policy == RELATIVE_DELTA)
                            && (max_time
                                < rwRecGetEndTime(&response_rec)+delta_msec))
                        {
                            /* update max_time */
                            max_time=rwRecGetEndTime(&response_rec)+delta_msec;
                        }
                    }
                }

                /* when we have matching records from both streams,
                 * use the earlier record as the match_lead; if only
                 * one matching side, we need to use it */
                if (!have_match_query) {
                    if (!have_match_response) {
                        break;
                    }
                    match_lead = MATCH_RESPONSE;
                } else if (!have_match_response) {
                    match_lead = MATCH_QUERY;
                } else if (rwRecGetStartTime(&query_rec)
                           < rwRecGetStartTime(&response_rec))
                {
                    match_lead = MATCH_QUERY;
                } else if (rwRecGetStartTime(&query_rec)
                           > rwRecGetStartTime(&response_rec))
                {
                    match_lead = MATCH_RESPONSE;
                } else {
                    /* default for time tie */
                    match_lead = base_type;
                }
            }
        }
    }

    /* write the remaining unmatched records */
    if (write_unmatched_query) {
        while (have_query) {
            write_record(&query_rec, 0, MATCH_QUERY);
            have_query = read_record(query_stream, &query_rec);
        }
    }
    if (write_unmatched_response) {
        while (have_response) {
            write_record(&response_rec, 0, MATCH_RESPONSE);
            have_response = read_record(response_stream, &response_rec);
        }
    }

    if (matched_stream) {
        skStreamDestroy(&matched_stream);
    }

    /* done */
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
