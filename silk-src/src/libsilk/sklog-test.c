/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  Code to test the sklog module.  Note that this C files #includes
**  the sklog.c source file.
**
*/

/* set a testing flag */
#define SKLOG_TESTING_LOG 1

/* NOTE: pull in the sklog source file */
#include "sklog.c"

RCSIDENTVAR(rcsID_sklog_c, "$SiLK: sklog-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLE DEFINITIONS */

/* the features to test; set by --test-features */
static int test_features = -1;

/* whether to print a message using EMERGMSG(); usually it is skipped */
static int test_emerg = 0;

/* whether to test threaded logging; default is no */
static int test_threaded = 0;

/* number of times to write a log message */
static uint32_t repeat_count = 5;

/* number of seconds to wait between writing to the log */
static uint32_t repeat_delay = 10;

/* number of times the logToAllLevels() function has been called */
static int global_count = 0;

/* mutex to protect the count */
static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;


/* OPTIONS SETUP */

typedef enum {
    OPT_TEST_FEATURES,
    OPT_TEST_EMERG,
    OPT_TEST_THREADED,
    OPT_REPEAT_COUNT,
    OPT_REPEAT_DELAY
} appOptionsEnum;

static struct option appOptions[] = {
    {"test-features",   REQUIRED_ARG, 0, OPT_TEST_FEATURES},
    {"test-emerg",      NO_ARG,       0, OPT_TEST_EMERG},
    {"test-threaded",   NO_ARG,       0, OPT_TEST_THREADED},
    {"repeat-count",    REQUIRED_ARG, 0, OPT_REPEAT_COUNT},
    {"repeat-delay",    REQUIRED_ARG, 0, OPT_REPEAT_DELAY},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("The features to test.  Passed to sklogSetup(). Sum of:\n"
     "\t1  Enable options for use of syslog\n"
     "\t2  Enable options that mimic SiLK legacy logging"),
    "Test EMERGMSG() as well (usually it is skipped)",
    "Test threaded logging. Def. no",
    "Number of times to write messages to the log. Def. 5",
    "Number of seconds between writes to the log. Def. 10",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);


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
#define USAGE_MSG                                                       \
    ("--test-features=FEATURES [SWITCHES]\n"                            \
     "\tSimple code to test the sklog module.\n"                        \
     "\tUse ``--test-features=FEATURES --help'' to see the options\n"   \
     "\tthat sklog will provide for various feature levels.\n"          \
     "\tNOTE: Attempting to use a \"Log switch\" before specifying\n"   \
     "\t--test-features results in an \"unrecognized option\" error.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);

    fprintf(fh, "\nLog switches:\n");
    sklogOptionsUsage(fh);
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

    sklogTeardown();
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

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    if (test_features < 0) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_TEST_FEATURES].name);
        skAppUsage();
    }

    if (test_threaded) {
        sklogEnableThreadedLogging();
    }

    /* verify logging */
    if (sklogOptionsVerify()) {
        exit(EXIT_FAILURE);
    }

    /* write command line */
    sklogCommandLine(argc, argv);

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
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
    uint32_t val;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_TEST_FEATURES:
        rv = skStringParseUint32(&val, opt_arg, SKLOG_FEATURE_SYSLOG,
                                 (SKLOG_FEATURE_LEGACY | SKLOG_FEATURE_SYSLOG));
        if (rv) {
            goto PARSE_ERROR;
        }
        test_features = (int)val;
        if (sklogSetup(test_features)) {
            skAppPrintErr("Unable to setup log");
            exit(EXIT_FAILURE);
        }
        break;

      case OPT_TEST_EMERG:
        test_emerg = 1;
        break;

      case OPT_TEST_THREADED:
        test_threaded = 1;
        break;

      case OPT_REPEAT_COUNT:
        rv = skStringParseUint32(&val, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        repeat_count = val;
        break;

      case OPT_REPEAT_DELAY:
        rv = skStringParseUint32(&val, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        repeat_delay = val;
        break;
    }

    return 0;  /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


static void
logToAllLevels(
    void               *v_name)
{
#define ST_ND_TH(c) \
    ((((c) % 10) == 1) ? "st" : ((((c) % 10) == 2) ? "nd" : "th"))

    int c;
    char *name = (char *)v_name;

    pthread_mutex_lock(&count_mutex);
    c = ++global_count;
    pthread_mutex_unlock(&count_mutex);

    if (test_emerg) {
        EMERGMSG("Writing a EMERGMSG for the %d%s time [%s]",
                 c, ST_ND_TH(c), name);
    }
    ALERTMSG("Writing a ALERTMSG for the %d%s time [%s]",
             c, ST_ND_TH(c), name);
    CRITMSG("Writing a CRITMSG for the %d%s time [%s]",
            c, ST_ND_TH(c), name);
    ERRMSG("Writing a ERRMSG for the %d%s time [%s]",
           c, ST_ND_TH(c), name);
    WARNINGMSG("Writing a WARNINGMSG for the %d%s time [%s]",
               c, ST_ND_TH(c), name);
    NOTICEMSG("Writing a NOTICEMSG for the %d%s time [%s]",
            c, ST_ND_TH(c), name);
    INFOMSG("Writing a INFOMSG for the %d%s time [%s]",
            c, ST_ND_TH(c), name);
    DEBUGMSG("Writing a DEBUGMSG for the %d%s time [%s]",
             c, ST_ND_TH(c), name);
}


/*
 *  THREAD ENTRY POINT
 */
static void *
write_msg_thread(
    void               *v_name)
{
    uint32_t i;

    for (i = 0; i < repeat_count; ++i) {
        if (i > 0) {
            sleep(repeat_delay);
        }
        logToAllLevels(v_name);
    }

    return v_name;
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);                       /* never returns on error */

    if (sklogOpen()) {
        skAppPrintErr("Unable to open log");
    }
    INFOMSG("Current log level is %s and log mask is %d",
            sklogGetLevel(), sklogGetMask());

    if (!test_threaded) {
        write_msg_thread((void*)"main");
    } else {
        pthread_t p1;
        pthread_t p2;

        pthread_create(&p1, NULL, &write_msg_thread, (void*)"p1");
        pthread_create(&p2, NULL, &write_msg_thread, (void*)"p2");
        logToAllLevels((void*)"main");
        pthread_join(p2, NULL);
        pthread_join(p1, NULL);
    }

    sklogClose();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
