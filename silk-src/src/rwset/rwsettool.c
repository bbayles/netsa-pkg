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
 *
 *  rwsettool.c
 *
 *    Manipulate IPset files to produce a new IPset.  Supports
 *    operations such as union, intersection, difference, and
 *    sampling.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsettool.c 85f668b7b9ff 2023-07-14 16:29:48Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout

/* structure used when walking over the elements in an IPset to
 * generate a sampled IPset */
typedef struct sample_state_st {
    uint64_t   sample_remain;
    uint64_t   set_remain;
    skipset_t *ipset;
    long       frac;
} sample_state_t;

/*
 * How to handle command line history in the output file.  If <0, do
 * not write any invocation to the output file.  If 0, record this
 * invocation, but do not copy the invocation from the input file(s).
 * If >0, copy the command line histories from the input file and
 * record this invocation.  WARNING: A value >0 can quickly cause the
 * output files to become HUGE.
 */
#ifndef RWSETTOOL_INVOCATION_HISTORY
#define RWSETTOOL_INVOCATION_HISTORY 0
#endif


/* LOCAL VARIABLES */

/* index of first option that is not handled by the options handler.
 * If this is equal to argc, then input is from stdin. */
static int arg_index = 0;

/* where to write the resulting set */
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

/* the appOptionsEnum value for the operation being executed. */
static int operation = -1;

/* the appOptionsEnum value indicating whether --sample should select
 * based on a target sample size, or a ratio of the set size */
static int sample_type = 0;

/* the random sample size from the --size switch */
static uint64_t sample_size;

/* the random sample ratio from the --ratio switch */
static double sample_ratio;

/* the seed for the pseudo-random number generator */
static uint32_t sample_seed;

/* group IPs into CIDR blocks of this size */
static uint32_t mask = 0;

/* when masking, whether the CIDR blocks should be full */
static int fill_blocks = 0;

/* options for writing the IPset */
static skipset_options_t set_options;


/* OPTIONS SETUP */

#define FINAL_OPERATION_OPT   (unsigned int)OPT_SAMPLE_RATIO

typedef enum {
    OPT_UNION,
    OPT_INTERSECT,
    OPT_DIFFERENCE,
    OPT_SYMMETRIC_DIFFERENCE,
    OPT_MASK,
    OPT_FILL_BLOCKS,
    OPT_SAMPLE,
    OPT_SAMPLE_SIZE,
    OPT_SAMPLE_RATIO,
    OPT_SAMPLE_SEED,
    OPT_OUTPUT_PATH,
    OPT_MODIFY_INPLACE,
    OPT_BACKUP_PATH
} appOptionsEnum;

static struct option appOptions[] = {
    {"union",           NO_ARG,       0, OPT_UNION},
    {"intersect",       NO_ARG,       0, OPT_INTERSECT},
    {"difference",      NO_ARG,       0, OPT_DIFFERENCE},
    {"symmetric-difference",  NO_ARG, 0, OPT_SYMMETRIC_DIFFERENCE},
    {"mask",            REQUIRED_ARG, 0, OPT_MASK},
    {"fill-blocks",     REQUIRED_ARG, 0, OPT_FILL_BLOCKS},
    {"sample",          NO_ARG,       0, OPT_SAMPLE},
    {"size",            REQUIRED_ARG, 0, OPT_SAMPLE_SIZE},
    {"ratio",           REQUIRED_ARG, 0, OPT_SAMPLE_RATIO},
    {"seed",            REQUIRED_ARG, 0, OPT_SAMPLE_SEED},
    {"output-path",     REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"modify-inplace",  NO_ARG,       0, OPT_MODIFY_INPLACE},
    {"backup-path",     REQUIRED_ARG, 0, OPT_BACKUP_PATH},
    {0, 0, 0, 0}        /* sentinel entry */
};

static const char *appHelp[] = {
    ("Create an IPset that contains the IP addresses that are members\n"
     "\tof ANY of the input IPsets"),
    ("Create an IPset that contains the IP addresses that are\n"
     "\tmembers of ALL the input IPsets"),
    ("Create an IPset that contains the IP addresses that are\n"
     "\tmembers of the first IPset but not members of any subsequent IPset"),
    ("Create an IPset that contains the IP addresses\n"
     "\tthat are members of either the first or second IPset but not both"),
    ("Create an IPset that contains, for each block of this network\n"
     "\tmask length, a single IP address when any of the input IPsets have\n"
     "\tone or more IP address members in the block"),
    ("Create an IPset that contains, for each block of this\n"
     "\tnetwork mask length, a completely filled block when any of the input\n"
     "\tIPsets have one more more IP address members in the block"),
    ("Create an IPset that contains the union of a random sample of\n"
     "\tIP addresses from all input IPsets.  Requires --size or --ratio"),

    ("Create an IPset that contains the union of randomly selecting\n"
     "\texactly this number of IP addresses from each input IPset.\n"
     "\tMay only be used with the --sample switch"),

    ("Create an IPset where the probability of including each IP\n"
     "\taddress of each input is given by this value, a floating point value\n"
     "\tbetween 0.0 and 1.0.  May only be used with the --sample switch"),

    ("Specify the seed for the pseudo-random number generator used by\n"
     "\tthe --sample operation"),
    ("Write the resulting IPset to this location. Def. stdout"),
    ("Allow overwriting an existing file and properly handle\n"
     "\tthe case when --output-path names an input file"),
    ("Move the existing OUTPUT-PATH to this location prior to\n"
     "\toverwriting when --modify-inplace is given"),
    (char *) NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void setUpModifyInplace(void);


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
    ("<OPERATION> [SWITCHES] IPSET [IPSET...]\n"                           \
     "\tPerforms the specified OPERATION, one of --union, --intersect,\n"  \
     "\t--difference, --symmetric-difference, --mask, --fill-blocks, or\n" \
     "\t--sample, on the input IPset file(s) and creates a new IPset file.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nOPERATION:\n");
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n",
                appOptions[i].name, SK_OPTION_HAS_ARG(appOptions[i]),
                appHelp[i]);
        if (FINAL_OPERATION_OPT == i) {
            fprintf(fh, "\nSWITCHES:\n");
            skOptionsDefaultUsage(fh);
        }
    }
    skIPSetOptionsUsage(fh);
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

    skStreamDestroy(&out_stream);
    skIPSetOptionsTeardown();
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
    assert((sizeof(appHelp) / sizeof(char *)) ==
           (sizeof(appOptions) / sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(&set_options, 0, sizeof(skipset_options_t));
    set_options.existing_silk_files = 1;
#if RWSETTOOL_INVOCATION_HISTORY >= 0
    set_options.argc = argc;
    set_options.argv = argv;
#endif

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skIPSetOptionsRegister(&set_options))
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
        skAppUsage();                            /* never returns */
    }

    /* verify that we have something to do */
    if (operation == -1) {
        skAppPrintErr(("One of --%s, --%s, --%s, --%s,"
                       " --%s, --%s, or --%s is required"),
                      appOptions[OPT_UNION].name,
                      appOptions[OPT_INTERSECT].name,
                      appOptions[OPT_DIFFERENCE].name,
                      appOptions[OPT_SYMMETRIC_DIFFERENCE].name,
                      appOptions[OPT_MASK].name,
                      appOptions[OPT_FILL_BLOCKS].name,
                      appOptions[OPT_SAMPLE].name);
        skAppUsage();
    }

    /* either need name of set file(s) after options or a set file on stdin */
    if ((arg_index == argc) && (FILEIsATty(stdin))) {
        skAppPrintErr("No files on the command line and"
                      " stdin is connected to a terminal");
        skAppUsage();
    }

    /* verify that we have a sample size or ratio and seed the random
     * number generator */
    if (operation == OPT_SAMPLE) {
        if (!sample_type) {
            skAppPrintErr(("The --%s switch requires a valid --%s or --%s "
                           "argument"),
                          appOptions[OPT_SAMPLE].name,
                          appOptions[OPT_SAMPLE_SIZE].name,
                          appOptions[OPT_SAMPLE_RATIO].name);
            skAppUsage();
        }
        if (!sample_seed) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            sample_seed = (uint32_t)tv.tv_sec + (uint32_t)tv.tv_usec;
        }
        srandom((unsigned long)sample_seed);
    }

    /* default to stdout if no --output-path */
    if (NULL == output_path) {
        output_path = "stdout";
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

    /* Handle the typical (not modify-inplace) case */
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

    return;                                      /* OK */
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
    int rv;

    switch ((appOptionsEnum) opt_index) {
      case OPT_INTERSECT:
      case OPT_DIFFERENCE:
      case OPT_SYMMETRIC_DIFFERENCE:
      case OPT_SAMPLE:
        if ((operation >= 0) && (operation != opt_index)) {
            skAppPrintErr("Switches --%s and --%s are incompatible",
                          appOptions[operation].name,
                          appOptions[opt_index].name);
            return 1;
        }
        operation = opt_index;
        break;

      case OPT_UNION:
        if ((operation >= 0) && (operation != opt_index)
            && (operation != OPT_MASK) && (operation != OPT_FILL_BLOCKS))
        {
            skAppPrintErr("Switches --%s and --%s are incompatible",
                          appOptions[operation].name,
                          appOptions[opt_index].name);
            return 1;
        }
        operation = opt_index;
        break;

      case OPT_FILL_BLOCKS:
        fill_blocks = 1;
        /* FALLTHROUGH */
      case OPT_MASK:
        if ((operation >= 0) && (operation != opt_index)
            && (operation != OPT_UNION))
        {
            skAppPrintErr("Switches --%s and --%s are incompatible",
                          appOptions[operation].name,
                          appOptions[opt_index].name);
            return 1;
        }
        operation = opt_index;
#if SK_ENABLE_IPV6
        rv = skStringParseUint32(&mask, opt_arg, 1, 128);
#else
        rv = skStringParseUint32(&mask, opt_arg, 1, 32);
#endif
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SAMPLE_SIZE:
        if (sample_type == opt_index) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (sample_type) {
            skAppPrintErr("Switches --%s and --%s are incompatible",
                          appOptions[sample_type].name,
                          appOptions[opt_index].name);
            return 1;
        }
        sample_type = opt_index;
        rv = skStringParseUint64(&sample_size, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }

        break;

      case OPT_SAMPLE_RATIO:
        if (sample_type == opt_index) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if (sample_type) {
            skAppPrintErr("Switches %s and %s are incompatible",
                          appOptions[sample_type].name,
                          appOptions[opt_index].name);
            return 1;
        }
        sample_type = opt_index;
        rv = skStringParseDouble(&sample_ratio, opt_arg, 0.0, 1.0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SAMPLE_SEED:
        rv = skStringParseUint32(&sample_seed, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
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
 *  ok = appNextInput(argc, argv, &stream);
 *
 *    Opens the next input.
 *
 *    Gets the name of the next input (either a file name from the command
 *    line or the standard input if no files names were given), opens it as an
 *    skstream_t.
 *
 *    Stores the stream in the referent of `stream` and returns 1 if the
 *    stream was successfully opened.  Returns 0 if no more inputs.  If there
 *    is an error opening the stream, prints an error and returns -1.
 */
static int
appNextInput(
    int                 argc,
    char              **argv,
    skstream_t        **stream)
{
    static int initialized = 0;
    char errbuf[2 * PATH_MAX];
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
        skStreamLastErrMessage((*stream), rv, errbuf, sizeof(errbuf));
        skAppPrintErr("Unable to read IPset from '%s': %s",
                      fname, errbuf);
        skStreamDestroy(stream);
        return -1;
    }

    /* copy invocation and notes (annotations) from the input files to
     * the output file; these headers will not be written to the
     * output if --invocation-strip or --notes-strip was specified. */
    rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream), hdr,
                             SK_HENTRY_ANNOTATION_ID);
#if RWSETTOOL_INVOCATION_HISTORY > 0
    if (0 == rv) {
        rv = skHeaderCopyEntries(skStreamGetSilkHeader(out_stream), hdr,
                                 SK_HENTRY_INVOCATION_ID);
    }
#endif
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&(*stream));
        return -1;
    }

    return 1;
}


/*
 *    Read the IPset from 'stream' into memory and return a pointer to
 *    it.  Return NULL on error.
 */
static skipset_t *
readSet(
    skstream_t         *stream)
{
    char errbuf[2 * PATH_MAX];
    skipset_t *ipset;
    int rv;

    rv = skIPSetRead(&ipset, stream);
    if (SKIPSET_OK == rv) {
        return ipset;
    }
    if (SKIPSET_ERR_FILEIO == rv) {
        skStreamLastErrMessage(stream,
                               skStreamGetLastReturnValue(stream),
                               errbuf, sizeof(errbuf));
    } else {
        strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
        errbuf[sizeof(errbuf) - 1] = '\0';
    }
    skAppPrintErr("Unable to read IPset from '%s': %s",
                  skStreamGetPathname(stream), errbuf);
    return NULL;
}


/*
 *  status = sampleRatioCallback(ipaddr, prefix, &state);
 *
 *    Callback used by sampleSets() when the --ratio option was
 *    specified.
 *
 *    Visit each IP in the CIDR block and determine whether it should
 *    be added to the output IPset contained in 'state'.
 */
static int
sampleRatioCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_state)
{
    sample_state_t *state = (sample_state_t*)v_state;
    skipaddr_t end_ip;
    int rv = 0;

    skCIDR2IPRange(ipaddr, prefix, ipaddr, &end_ip);

    for (;;) {
        if (random() < state->frac) {
            rv = skIPSetInsertAddress(state->ipset, ipaddr, 0);
            if (rv) {
                break;
            }
        }

        if (skipaddrCompare(ipaddr, &end_ip) == 0) {
            return 0;
        }

        skipaddrIncrement(ipaddr);
    }

    skAppPrintErr("Error inserting into IPset: %s",
                  skIPSetStrerror(rv));
    return -1;
}


/*
 *  status = sampleSizeCallback(ipaddr, prefix, &state);
 *
 *    Callback used by sampleSets() when the --size option was
 *    specified.
 *
 *    Visit each IP in the CIDR block and determine whether it should
 *    be added to the output IPset contained in 'state'.
 */
static int
sampleSizeCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_state)
{
    sample_state_t *state = (sample_state_t*)v_state;
    skipaddr_t end_ip;
    double frac;
    int rv;

    if (state->set_remain == state->sample_remain) {
        /* must add this entire block to the result set */
        rv = skIPSetInsertAddress(state->ipset, ipaddr, prefix);
        if (rv) {
            goto ERROR;
        }
        return 0;
    }

    /* process the remaining IPs in this CIDR block */
    skCIDR2IPRange(ipaddr, prefix, ipaddr, &end_ip);

    while (state->set_remain > state->sample_remain) {
        /* chance of selecting an IP is number of IPs we still require
         * divided by number of IPs that are still available */
        frac = ((double)RAND_MAX * state->sample_remain / state->set_remain);
        --state->set_remain;

        if ((double)random() < frac) {
            rv = skIPSetInsertAddress(state->ipset, ipaddr, 0);
            if (rv) {
                goto ERROR;
            }
            --state->sample_remain;
            if (0 == state->sample_remain) {
                /* we've met the quota and can stop */
                return 1;
            }
        }

        if (skipaddrCompare(ipaddr, &end_ip) == 0) {
            /* no more IPs in this CIDR block */
            return 0;
        }

        skipaddrIncrement(ipaddr);
    }

    /* must add all remaining IPs to the result set */
    while ((rv = skIPSetInsertAddress(state->ipset, ipaddr, 0))
           == 0)
    {
        if (skipaddrCompare(ipaddr, &end_ip) == 0) {
            return 0;
        }
        skipaddrIncrement(ipaddr);
    }

  ERROR:
    skAppPrintErr("Error inserting into IPset: %s",
                  skIPSetStrerror(rv));
    return -1;
}


/*
 *  out_set = sampleSets(argc, argv);
 *
 *    Create a new IPset.  For each IPset specified on the command
 *    line---given by 'argc' and 'argv'---walk over the CIDR blocks in
 *    the set and add a sample of the IPs to the new IPset.  Return
 *    the new IPset, or return NULL on error.
 */
static skipset_t *
sampleSets(
    int                 argc,
    char              **argv)
{
    skipset_t *out_set;
    sample_state_t state;
    skipset_t *in_set = NULL;
    skstream_t *in_stream = NULL;
    sk_ipv6policy_t policy;
    int have_input;
    int rv;

    /* create the output set */
    rv = skIPSetCreate(&out_set, 0);
    if (rv) {
        skAppPrintErr("Cannot create IPset: %s", skIPSetStrerror(rv));
        return NULL;
    }
    skIPSetOptionsBind(out_set, &set_options);

    /* initialize the state structure */
    memset(&state, 0, sizeof(state));
    state.ipset = out_set;

    /* set the policy to be the type of IPs that out_set contains */
    policy = SK_IPV6POLICY_ASV4;

    if (OPT_SAMPLE_RATIO == sample_type) {
        /* the probability of choosing an IP is fixed. */
        state.frac = (long)((double)RAND_MAX * sample_ratio);
    }

    while (1 == (have_input = appNextInput(argc, argv, &in_stream))) {
        /* Read IPset */
        in_set = readSet(in_stream);
        if (NULL == in_set) {
            goto ERROR;
        }
        /* no longer need the input stream */
        skStreamDestroy(&in_stream);

        /* convert output set to IPv6 if required */
        if (skIPSetContainsV6(in_set) && !skIPSetIsV6(out_set)) {
            policy = SK_IPV6POLICY_FORCE;
            rv = skIPSetConvert(out_set, 6);
            if (rv) {
                goto ERROR;
            }
        }

        /* TODO: Try list-based sampling algorithm  */

        switch (sample_type) {
          case OPT_SAMPLE_RATIO:
            rv = skIPSetWalk(
                in_set, 1, policy, &sampleRatioCallback, (void*)&state);
            break;

          case OPT_SAMPLE_SIZE:
            /* update state counts for this IPset */
            state.set_remain = skIPSetCountIPs(in_set, NULL);
            if (state.set_remain <= sample_size) {
                rv = skIPSetUnion(out_set, in_set);
            } else {
                state.sample_remain = sample_size;
                rv = skIPSetWalk(
                    in_set, 1, policy, &sampleSizeCallback, (void*)&state);
            }
            break;

          default:
            skAbortBadCase(sample_type);
        }
        if (rv < 0) {
            goto ERROR;
        }

        skIPSetDestroy(&in_set);
    }
    if (0 != have_input) {
        goto ERROR;
    }

    skIPSetClean(out_set);

    return out_set;

  ERROR:
    skIPSetDestroy(&in_set);
    skStreamDestroy(&in_stream);
    skIPSetDestroy(&out_set);
    return NULL;
}


/*
 *  out_set = intersectSets(argc, argv);
 *
 *    Create a new IPset that is the intersection of all IPsets
 *    specified on the command line---given by 'argc' and 'argv'.
 *    Return the new IPset, or return NULL on error.
 */
static skipset_t *
intersectSets(
    int                 argc,
    char              **argv)
{
    skstream_t *in_stream = NULL;
    skipset_t *out_set = NULL;
    skipset_t *in_set = NULL;
    int have_input;
    int rv;

    while (1 == (have_input = appNextInput(argc, argv, &in_stream))) {
        in_set = readSet(in_stream);
        if (NULL == in_set) {
            goto ERROR;
        }
        skStreamDestroy(&in_stream);

        if (NULL == out_set) {
            /* this is the first set */
            out_set = in_set;
            in_set = NULL;
            skIPSetOptionsBind(out_set, &set_options);
        } else {
            rv = skIPSetIntersect(out_set, in_set);
            skIPSetDestroy(&in_set);
            in_set = NULL;
            if (rv) {
                skAppPrintErr("Error in %s operation: %s",
                              appOptions[operation].name, skIPSetStrerror(rv));
                goto ERROR;
            }
        }
    }
    if (0 != have_input) {
        goto ERROR;
    }
    return out_set;

  ERROR:
    skStreamDestroy(&in_stream);
    skIPSetDestroy(&in_set);
    skIPSetDestroy(&out_set);
    return NULL;
}


/*
 *  out_set = symmetricDiffSets(argc, argv);
 *
 *    Create a new IPset that is the symmetic difference of all IPsets
 *    specified on the command line---given by 'argc' and 'argv'.
 *    Return the new IPset, or return NULL on error.
 */
static skipset_t *
symmetricDiffSets(
    int                 argc,
    char              **argv)
{
    skstream_t *in_stream = NULL;
    skipset_t *out_set = NULL;
    skipset_t *set1 = NULL;
    skipset_t *set2 = NULL;
    int have_input;
    int rv;

    have_input = appNextInput(argc, argv, &in_stream);
    if (1 != have_input) {
        return NULL;
    }
    out_set = readSet(in_stream);
    if (NULL == out_set) {
        rv = 0;
        goto ERROR;
    }
    skStreamDestroy(&in_stream);

    /* create an IPset to use as a temporary copy */
    rv = skIPSetCreate(&set1, skIPSetContainsV6(out_set));
    if (rv) { goto ERROR; }

    while (1 == (have_input = appNextInput(argc, argv, &in_stream))) {
        set2 = readSet(in_stream);
        if (NULL == set2) {
            rv = 0;
            goto ERROR;
        }
        skStreamDestroy(&in_stream);

        /* compute set1 - set2, where out_set is the current set1, but
         * we need to keep a copy of set1 */
        assert(0 == skIPSetCountIPs(set1, NULL));
        rv = skIPSetUnion(set1, out_set);
        if (rv) { goto ERROR; }
        rv = skIPSetClean(set1);
        if (rv) { goto ERROR; }
        rv = skIPSetSubtract(out_set, set2);
        if (rv) { goto ERROR; }

        /* compute set2 - set1, use the copy of set1 and we may
         * overwrite set2 */
        rv = skIPSetSubtract(set2, set1);
        if (rv) { goto ERROR; }
        rv = skIPSetClean(set2);
        if (rv) { goto ERROR; }

        /* we may empty set1 */
        rv = skIPSetRemoveAll(set1);
        if (rv) { goto ERROR; }

        /* compute the union of the differences */
        rv = skIPSetUnion(out_set, set2);
        if (rv) { goto ERROR; }
        rv = skIPSetClean(out_set);
        if (rv) { goto ERROR; }

        /* done with set2 */
        skIPSetDestroy(&set2);
    }
    if (0 != have_input) {
        goto ERROR;
    }

    skIPSetDestroy(&set1);

    return out_set;

  ERROR:
    if (rv) {
        skAppPrintErr("Error during %s operation: %s",
                      appOptions[operation].name, skIPSetStrerror(rv));
    }
    skStreamDestroy(&in_stream);
    skIPSetDestroy(&out_set);
    skIPSetDestroy(&set1);
    skIPSetDestroy(&set2);
    return NULL;
}


#if SK_ENABLE_IPV6
/*
 *    Callback invoked after opening a stream to performing the union
 *    of IPsets.  Convert the output IPset to IPv6 when the input
 *    IPset is capable of containing IPv6 addresses.
 */
static int
unionConvert(
    const skipset_t            *stream_set,
    const sk_file_header_t     *hdr,
    void                       *v_out_set,
    skipset_procstream_parm_t  *proc_stream_settings)
{
    skipset_t *out_set = (skipset_t*)v_out_set;

    /* quiet "unsued parameter" warning */
    (void)hdr;

    /* convert output set to IPv6 if required */
    if (skIPSetIsV6(stream_set)) {
        proc_stream_settings->v6_policy = SK_IPV6POLICY_FORCE;
        if (!skIPSetIsV6(out_set)) {
            return skIPSetConvert(out_set, 6);
        }
    }
    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */

static int
differenceCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return skIPSetRemoveAddress((skipset_t*)v_ipset, ipaddr, prefix);
}

static int
unionCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return skIPSetInsertAddress((skipset_t*)v_ipset, ipaddr, prefix);
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
    skipset_procstream_parm_t param;
    skipset_procstream_init_t cb_init = NULL;
    skstream_t *in_stream;
    skipset_t *out_set = NULL;
    int have_input;
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    if (OPT_SAMPLE == operation) {
        out_set = sampleSets(argc, argv);
        if (NULL == out_set) {
            return EXIT_FAILURE;
        }

    } else if (OPT_INTERSECT == operation) {
        out_set = intersectSets(argc, argv);
        if (NULL == out_set) {
            return EXIT_FAILURE;
        }

    } else if (OPT_SYMMETRIC_DIFFERENCE == operation) {
        out_set = symmetricDiffSets(argc, argv);
        if (NULL == out_set) {
            return EXIT_FAILURE;
        }

    } else {
        /* load the first set; it is the basis for the output set */
        have_input = appNextInput(argc, argv, &in_stream);
        if (have_input != 1) {
            return EXIT_FAILURE;
        }
        out_set = readSet(in_stream);
        skStreamDestroy(&in_stream);
        if (NULL == out_set) {
            skIPSetDestroy(&out_set);
            return EXIT_FAILURE;
        }
        skIPSetOptionsBind(out_set, &set_options);

        memset(&param, 0, sizeof(param));
        param.cb_entry_func_ctx = out_set;
        param.visit_cidr = 1;
        param.v6_policy = SK_IPV6POLICY_MIX;

        switch (operation) {
          case OPT_UNION:
          case OPT_MASK:
          case OPT_FILL_BLOCKS:
            param.cb_entry_func = unionCallback;
#if SK_ENABLE_IPV6
            cb_init = unionConvert;
#endif
            break;

          case OPT_DIFFERENCE:
            param.cb_entry_func = differenceCallback;
            break;

          default:
            skAbortBadCase(operation);
        }

        /* read remaining sets */
        while (1 == (have_input = appNextInput(argc, argv, &in_stream))) {
            param.v6_policy = (skIPSetIsV6(out_set)
                               ? SK_IPV6POLICY_FORCE
                               : SK_IPV6POLICY_ASV4);
            rv = skIPSetProcessStream(in_stream, cb_init, out_set, &param);
            if (rv) {
                char errbuf[2 * PATH_MAX];

                if (SKIPSET_ERR_FILEIO == rv) {
                    skStreamLastErrMessage(
                        in_stream, skStreamGetLastReturnValue(in_stream),
                        errbuf, sizeof(errbuf));
                } else {
                    strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
                    errbuf[sizeof(errbuf) - 1] = '\0';
                }
                skAppPrintErr("Error in %s operation: %s",
                              appOptions[operation].name, errbuf);
                skStreamDestroy(&in_stream);
                skIPSetDestroy(&out_set);
                return EXIT_FAILURE;
            }
            skStreamDestroy(&in_stream);
        }
        if (0 != have_input) {
            skIPSetDestroy(&out_set);
            return EXIT_FAILURE;
        }
    }

    /* mask the IPs in the resulting set */
    if (mask != 0) {
        rv = 0;
        if (skIPSetIsV6(out_set)) {
            if (mask < 128) {
                if (fill_blocks) {
                    rv = skIPSetMaskAndFill(out_set, mask);
                } else {
                    rv = skIPSetMask(out_set, mask);
                }
            }
        } else if (mask > 32) {
            skAppPrintErr("Ignoring mask of %" PRIu32 " for an IPv4 IPset",
                          mask);
        } else if (mask != 32) {
            if (fill_blocks) {
                rv = skIPSetMaskAndFill(out_set, mask);
            } else {
                rv = skIPSetMask(out_set, mask);
            }
        }
        if (rv) {
            skAppPrintErr(("Error applying mask of '%" PRIu32 "' to IPset"),
                          mask);
        }
    }

#if SK_ENABLE_IPV6
    /* convert the set to IPv4 if possible */
    if (skIPSetIsV6(out_set) && !skIPSetContainsV6(out_set)) {
        skIPSetConvert(out_set, 4);
    }
#endif  /* SK_ENABLE_IPV6 */

    skIPSetClean(out_set);

    /* write the set */
    rv = skIPSetWrite(out_set, out_stream);
    if (rv) {
        if (rv == SKIPSET_ERR_FILEIO) {
            skStreamPrintLastErr(out_stream,
                                 skStreamGetLastReturnValue(out_stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing IPset to '%s': %s",
                          skStreamGetPathname(out_stream),skIPSetStrerror(rv));
        }
        skStreamDestroy(&out_stream);
        skIPSetDestroy(&out_set);
        return EXIT_FAILURE;
    }

    /* close the output stream */
    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&out_stream);
        skIPSetDestroy(&out_set);
        return EXIT_FAILURE;
    }

    if (modify_inplace) {
        rv = moveTempFileToOutputPath();
        if (rv) {
            skStreamDestroy(&out_stream);
            skIPSetDestroy(&out_set);
            return EXIT_FAILURE;
        }
    }

    skIPSetDestroy(&out_set);
    rv = skStreamDestroy(&out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        return EXIT_FAILURE;
    }

    /* done */
    return (0);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
