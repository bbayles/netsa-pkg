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
**  rwipfix2silk.c
**
**    IPFIX to SiLK translation filter application
**
**    Brian Trammell
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwipfix2silk.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/libflowsource.h>
#include <silk/rwrec.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* where to write --print-stat output */
#define STATS_FH stderr

/* default value for --log-destination */
#define LOG_DESTINATION_DEFAULT  "none"


/* LOCAL VARIABLE DEFINITIONS */

/* for looping over input */
static sk_options_ctx_t *optctx = NULL;

/* the SiLK flow file to write (--silk-output) */
static skstream_t *silk_output = NULL;

/* where to write log messages (--log-destination) */
static char log_destination[PATH_MAX];

/* whether to print statistics (--print-statistics) */
static int print_statistics = 0;

/* log-flags to use for the probe we create */
static const char *log_flags = NULL;

/* whether to decode vlan values (--interface-values) */
static int decode_vlan = 0;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* required to process the IPFIX records */
static skpc_probe_t *probe;


/* OPTIONS SETUP */

typedef enum {
    OPT_SILK_OUTPUT,
    OPT_INTERFACE_VALUES,
    OPT_PRINT_STATISTICS,
    OPT_LOG_DESTINATION,
    OPT_LOG_FLAGS
} appOptionsEnum;

static struct option appOptions[] = {
    {"silk-output",             REQUIRED_ARG, 0, OPT_SILK_OUTPUT},
    {"interface-values",        REQUIRED_ARG, 0, OPT_INTERFACE_VALUES},
    {"print-statistics",        NO_ARG,       0, OPT_PRINT_STATISTICS},
    {"log-destination",         REQUIRED_ARG, 0, OPT_LOG_DESTINATION},
    {"log-flags",               REQUIRED_ARG, 0, OPT_LOG_FLAGS},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    ("Write the SiLK Flow records to the specified stream or\n"
     "\tfile path. Def. stdout"),
    ("Specify the value to store in the 'input' and\n"
     "\t'output' fields.  Def. snmp.  Choices: snmp, vlan"),
    "Print the number of records written. Def. No",
    ("Write messages about number of records read from each\n"
     "\tinput and messages about ignored IPFIX records to the specified\n"
     "\tlocation. Def. none. Choices: none, stdout, stderr, or a filename"),
    ("Specify additional messages for the log-destination.\n"
     "\tChoices: none, all, record-timestamps, sampling. Def. none"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int parseInterfaceValue(const char *if_value_choice);
static int parseLogFlags(const char *log_flags_str);
static size_t logprefix(char *buffer, size_t bufsize);


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
    ("[SWITCHES] [IPFIX_FILES]\n"                                             \
     "\tReads IPFIX records from files named on the command line or from\n"   \
     "\tthe standard input, converts them to the SiLK format, and writes\n"   \
     "\tthe SiLK records to the named file or to the standard output.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsCtxOptionsUsage(optctx, fh);
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
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close SiLK flow output file */
    if (silk_output) {
        rv = skStreamClose(silk_output);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(silk_output, rv, &skAppPrintErr);
        }
        skStreamDestroy(&silk_output);
    }

    skpcTeardown();

    /* set level to "warning" to avoid the "Stopped logging" message */
    sklogSetLevel("warning");
    sklogTeardown();

    skOptionsNotesTeardown();
    skOptionsCtxDestroy(&optctx);
    skIPFIXSourcesTeardown();
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
    sk_file_header_t *silk_hdr;
    int logmask;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    optctx_flags = (SK_OPTIONS_CTX_INPUT_BINARY | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* enable the logger */
    sklogSetup(0);
    sklogSetStampFunction(&logprefix);

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    if ('\0' == log_destination[0]) {
        strncpy(log_destination, LOG_DESTINATION_DEFAULT,
                sizeof(log_destination));
    } else {
        sklogSetLevel("debug");
    }
    sklogSetDestination(log_destination);

    /* set up libflowsource */
    skIPFIXSourcesSetup();

    /* default output is "stdout" */
    if (!silk_output) {
        if ((rv =skStreamCreate(&silk_output,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(silk_output, "-")))
        {
            skStreamPrintLastErr(silk_output, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
    }

    /* get the header */
    silk_hdr = skStreamGetSilkHeader(silk_output);

    /* open the output */
    if ((rv = skHeaderSetCompressionMethod(silk_hdr, comp_method))
        || (rv = skOptionsNotesAddToStream(silk_output))
        || (rv = skHeaderAddInvocation(silk_hdr, 1, argc, argv))
        || (rv = skStreamOpen(silk_output))
        || (rv = skStreamWriteSilkHeader(silk_output)))
    {
        skStreamPrintLastErr(silk_output, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    if (skpcSetup()) {
        exit(EXIT_FAILURE);
    }
    if (skpcProbeCreate(&probe, PROBE_ENUM_IPFIX)) {
        exit(EXIT_FAILURE);
    }
    skpcProbeSetName(probe, skAppName());
    skpcProbeSetPollDirectory(probe, "/dev/null");
    if (parseLogFlags(log_flags)) {
        exit(EXIT_FAILURE);
    }
    if (decode_vlan) {
        skpcProbeSetInterfaceValueType(probe, SKPC_IFVALUE_VLAN);
    }
    if (skpcProbeVerify(probe, 0)) {
        exit(EXIT_FAILURE);
    }

    /* set level to "warning" to avoid the "Started logging" message */
    logmask = sklogGetMask();
    sklogSetLevel("warning");
    sklogOpen();
    sklogSetMask(logmask);

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
    size_t sz;
    ssize_t rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_SILK_OUTPUT:
        if (silk_output) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv =skStreamCreate(&silk_output,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(silk_output, opt_arg)))
        {
            skStreamPrintLastErr(silk_output, rv, &skAppPrintErr);
            exit(EXIT_FAILURE);
        }
        break;

      case OPT_PRINT_STATISTICS:
        print_statistics = 1;
        break;

      case OPT_INTERFACE_VALUES:
        if (parseInterfaceValue(opt_arg)) {
            return 1;
        }
        break;

      case OPT_LOG_DESTINATION:
        if ('\0' != log_destination[0]) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
        }
        if ('\0' == opt_arg[0]) {
            skAppPrintErr("Invalid %s: Path name is required",
                          appOptions[opt_index].name);
            return 1;
        }
        if (0 == strcmp("stdout", opt_arg)
            || 0 == strcmp("stderr", opt_arg)
            || 0 == strcmp("none", opt_arg))
        {
            strncpy(log_destination, opt_arg, sizeof(log_destination) - 1);
            break;
        }
        if ('/' == opt_arg[0]) {
            if (strlen(opt_arg) >= sizeof(log_destination)) {
                skAppPrintErr("Invalid %s: Name is too long",
                              appOptions[opt_index].name);
                return 1;
            }
            strncpy(log_destination, opt_arg, sizeof(log_destination));
            break;
        }
        if (NULL == getcwd(log_destination, sizeof(log_destination))) {
            skAppPrintSyserror("Unable to get current directory");
            return 1;
        }
        sz = strlen(log_destination);
        if (sz + strlen(opt_arg) + 1 >= sizeof(log_destination)) {
            skAppPrintErr("Invalid %s: Name is too long",
                          appOptions[opt_index].name);
            return 1;
        }
        snprintf(log_destination + sz, sizeof(log_destination) - sz, "/%s",
                 opt_arg);
        break;

      case OPT_LOG_FLAGS:
        if (log_flags) {
            skAppPrintErr("Invaild %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        log_flags = opt_arg;
        break;
    }

    return 0;  /* OK */
}


/*
 *  ok = parseInterfaceValue(choice);
 *
 *    Parse the user's choice for the --interface-values switch and
 *    set the global variable 'decode_vlan' appropriately.  Return 0
 *    on success, or -1 if the user's choice is not valid.
 */
static int
parseInterfaceValue(
    const char         *if_value_choice)
{
    const sk_stringmap_entry_t if_values[] = {
        {"snmp", 0, NULL, NULL},
        {"vlan", 1, NULL, NULL},
        SK_STRINGMAP_SENTINEL
    };
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *map_entry;
    int rv = -1;

    /* create a stringmap of the available interface values */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, if_values) != SKSTRINGMAP_OK) {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, if_value_choice, &map_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        decode_vlan = map_entry->id;
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s: Ambiguous value '%s'",
                      appOptions[OPT_INTERFACE_VALUES].name, if_value_choice);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr(("Invalid %s: Unrecognized value '%s'"),
                      appOptions[OPT_INTERFACE_VALUES].name, if_value_choice);
        break;

      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      rv_map);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/*
 *    Parse the argument to the --log-flags switch.
 */
static int
parseLogFlags(
    const char         *log_flags_str)
{
    char *log_flags_copy = NULL;
    char *flag_next;
    char *flag;
    int rv = -1;

    skpcProbeClearLogFlags(probe);

    if (NULL == log_flags_str) {
        return 0;
    }

    /* create a copy of the input string and maintain a reference to
     * it so we can free it */
    log_flags_copy = strdup(log_flags_str);
    flag_next = log_flags_copy;
    if (NULL == log_flags_copy) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* parse the flags as a comma separated list of tokens */
    while ((flag = strsep(&flag_next, ",")) != NULL) {
        /* check for empty token (e.g., double comma) */
        if ('\0' == *flag) {
            continue;
        }
        switch (skpcProbeAddLogFlag(probe, flag)) {
          case 0:
            break;
          case -1:
            skAppPrintErr("Invalid %s: Unrecognized value '%s'",
                          appOptions[OPT_LOG_FLAGS].name, flag);
            goto END;
          case -2:
            skAppPrintErr("Invalid %s: Cannot mix 'none' with other value",
                          appOptions[OPT_LOG_FLAGS].name);
            goto END;
          default:
            skAppPrintErr("Bad return value from skpcProbeAddLogFlag()");
            skAbort();
        }
    }

    rv = 0;

  END:
    free(log_flags_copy);
    return rv;
}


/*
 *    Prefix any log messages from libflowsource with the program name
 *    instead of the standard logging tag.
 */
static size_t
logprefix(
    char               *buffer,
    size_t              bufsize)
{
    return (size_t)snprintf(buffer, bufsize, "%s: ", skAppName());
}


/*
 *  count = ipfix2silk(filename);
 *
 *    Read IPFIX records from 'filename' and write records to the
 *    global 'silk_output' file.  Return number of records processed,
 *    or -1 on error.
 */
static int64_t
ipfix2silk(
    const char         *filename)
{
    static unsigned int file_count = 0;
    char probe_name[128];
    skIPFIXSource_t *ipfix_src;
    skFlowSourceParams_t params;
    int64_t count;
    rwRec rwrec;
    int rv;

    ++file_count;
    snprintf(probe_name, sizeof(probe_name), "input%04u", file_count);

    params.path_name = filename;
    skpcProbeSetName(probe, probe_name);
    ipfix_src = skIPFIXSourceCreate(probe, &params);
    if (ipfix_src == NULL) {
        return -1;
    }

    count = 0;
    while (-1 != skIPFIXSourceGetGeneric(ipfix_src, &rwrec)) {
        /* remove any firewallEvent, NF_F_FW_EVENT, NF_F_FW_EXT_EVENT
         * value stored by libflowsource */
        rwRecSetMemo(&rwrec, 0);
        ++count;
        rv = skStreamWriteRecord(silk_output, &rwrec);
        if (rv) {
            skStreamPrintLastErr(silk_output, rv, &skAppPrintErr);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                exit(EXIT_FAILURE);
            }
        }
    }

    skIPFIXSourceLogStatsAndClear(ipfix_src);
    skIPFIXSourceDestroy(ipfix_src);

    return count;
}


int main(int argc, char **argv)
{
    char *path;
    int64_t total_count;
    int64_t count;
    int rv;

    appSetup(argc, argv);       /* never returns on failure */

    total_count = 0;

    /* process each file on the command line */
    while ((rv = skOptionsCtxNextArgument(optctx, &path)) == 0) {
        count = ipfix2silk(path);
        if (count < 0) {
            exit(EXIT_FAILURE);
        }
        total_count += count;
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    if (print_statistics) {
        fprintf(STATS_FH, ("%s: Wrote %" PRIu64 " records to '%s'\n"),
                skAppName(), total_count, skStreamGetPathname(silk_output));
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
