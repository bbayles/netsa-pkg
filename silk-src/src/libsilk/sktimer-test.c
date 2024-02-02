/*
** Copyright (C) 2010-2023 by Carnegie Mellon University.
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
**  Test program for the sktimer module
**  Michael Welsh Duggan - 2010.07.21
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sktimer-test.c c3cb530920e1 2023-04-26 14:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/sktimer.h>
#include <silk/skthread.h>
#include <silk/sklog.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* maximum number of timers to start */
#define MAX_TIMERS  256


typedef struct timer_info_st {
    /* the timer object */
    skTimer_t           timer;

    /* manage access to this struct */
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;

    /* the id of this structure */
    uint32_t            id;

    /* number of times this timer has fired */
    uint32_t            callback_count;
} timer_info_t;


/* LOCAL VARIABLE DEFINITIONS */

/* whether the program is shutting down */
static int quit;

/* keep track of information for each timer */
static timer_info_t timer_info[MAX_TIMERS];

/* when to start the timers (--start).  default: now */
static sktime_t start_time;

/* how long to wait between timer firings (--interval) */
static uint32_t interval;

/* number of times to allow the timer to fire (--iteratations).
 * default: 0 == unlimited */
static uint32_t iterations;

/* time the process should take to complete.  this is a list of values. */
static uint32_t *proc_times;

/* length of 'proc_times'. */
static uint32_t num_proc_times;

/* number of timers to use (--num-timers). default: 1 */
static int num_timers;

/* number of valid timers */
static uint32_t valid_timer_count;

/* protect/signal access to valid_timer_count */
pthread_mutex_t valid_timer_mutex;
pthread_cond_t  valid_timer_cond;


/* OPTIONS SETUP */

typedef enum {
    OPT_INTERVAL,
    OPT_START,
    OPT_ITERATIONS,
    OPT_PROCESS_TIME,
    OPT_NUM_TIMERS
} appOptionsEnum;

static struct option appOptions[] = {
    {"interval",        REQUIRED_ARG, 0, OPT_INTERVAL},
    {"start",           REQUIRED_ARG, 0, OPT_START},
    {"iterations",      REQUIRED_ARG, 0, OPT_ITERATIONS},
    {"process-time",    REQUIRED_ARG, 0, OPT_PROCESS_TIME},
    {"num-timers",      REQUIRED_ARG, 0, OPT_NUM_TIMERS},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Interval between timer firings (in seconds)",
    ("Date/time when timer firing should commence. Def. now.\n"
     "\tFormat: YYYY/MM/DD:hh:mm:ss in UTC"),
    "Number of times to call the timer callback. Def. unlimited",
    ("Comma-separated list of seconds of processing time after\n"
     "\ttimer triggers. Def. 0"),
    "Number of timers to create. Def. 1. Range 1-256",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void timer_signal_handler(int signal_num);
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
#define USAGE_MSG                                                       \
    ("--interval <SECS> [SWITCHES]\n"                                   \
     "\tOutputs the time every SECS seconds\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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
    timer_info_t *ti;
    int i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;
    quit = 1;

    pthread_cond_broadcast(&valid_timer_cond);

    for (i = 0, ti = timer_info; i < num_timers; ++i, ++ti) {
        /* wait for each timer to end */
        pthread_mutex_lock(&ti->mutex);
        if (ti->timer) {
            skTimerDestroy(ti->timer);
            ti->timer = NULL;
        }
        pthread_mutex_unlock(&ti->mutex);
        pthread_mutex_destroy(&ti->mutex);
        pthread_cond_destroy(&ti->cond);
    }

    if (proc_times) {
        free(proc_times);
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
    timer_info_t *ti;
    int i;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    start_time = (sktime_t)(-1);
    interval = 0;
    iterations = 0;
    proc_times = NULL;
    num_proc_times = 0;
    quit = 0;
    num_timers = 1;
    valid_timer_count = 0;
    memset(timer_info, 0, sizeof(timer_info));

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)) {
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

    if (interval == 0) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_INTERVAL].name);
        skAppUsage();
    }

    rv = skAppSetSignalHandler(timer_signal_handler);
    if (rv != 0) {
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    for (i = 0, ti = timer_info; i < num_timers; ++i, ++ti) {
        pthread_mutex_init(&ti->mutex, NULL);
        pthread_cond_init(&ti->cond, NULL);
    }
    pthread_mutex_init(&valid_timer_mutex, NULL);
    pthread_cond_init(&valid_timer_cond, NULL);

    /* Must enable the logger */
    sklogSetup(0);
    sklogSetDestination("stdout");
    sklogSetLevel("debug");
    sklogSetStampFunction(&logprefix);
    sklogOpen();

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
    int rv;
    uint32_t value;

    switch ((appOptionsEnum)opt_index) {
      case OPT_INTERVAL:
        rv = skStringParseUint32(&value, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        interval = value;
        break;


      case OPT_ITERATIONS:
        rv = skStringParseUint32(&value, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        iterations = value;
        break;

      case OPT_START:
        rv = skStringParseDatetime(&start_time, opt_arg, NULL);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_PROCESS_TIME:
        rv = skStringParseNumberList(&proc_times, &num_proc_times, opt_arg,
                                     0, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_NUM_TIMERS:
        rv = skStringParseUint32(&value, opt_arg, 1, MAX_TIMERS);
        if (rv) {
            goto PARSE_ERROR;
        }
        num_timers = value;
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
timer_signal_handler(
    int                 signal_num)
{
    timer_info_t *ti;
    int i;

    if (quit) {
        skAppPrintErr("Already shutting down; ignoring SIG%s",
                      skSignalToName(signal_num));
    } else {
        skAppPrintErr("Stopping due to SIG%s", skSignalToName(signal_num));
        quit = 1;
        pthread_cond_broadcast(&valid_timer_cond);
        for (i = 0, ti = timer_info; i < num_timers; ++i, ++ti) {
            pthread_cond_broadcast(&ti->cond);
        }
    }
}


static skTimerRepeat_t
timer_callback(
    void               *v_ti)
{
    skTimerRepeat_t retval = SK_TIMER_REPEAT;
    timer_info_t *ti = (timer_info_t*)v_ti;

    INFOMSG(("Timer #%" PRIu32 " called %" PRIu32 " time%s"),
            ti->id, (1 + ti->callback_count),
            ((0 == ti->callback_count) ? "" : "s"));

    pthread_mutex_lock(&ti->mutex);

    if (proc_times) {
        struct timespec w;
        struct timeval now;
        int rv;

        gettimeofday(&now, NULL);
        w.tv_nsec = now.tv_usec * 1000;
        w.tv_sec = now.tv_sec + proc_times[ti->callback_count % num_proc_times];
        do {
            rv = pthread_cond_timedwait(&ti->cond, &ti->mutex, &w);
        } while (rv == EINTR);
    }

    ++ti->callback_count;
    if (quit || (iterations && iterations == ti->callback_count)) {
        retval = SK_TIMER_END;
    }
    pthread_mutex_unlock(&ti->mutex);

    if (SK_TIMER_END == retval && !quit) {
        pthread_mutex_lock(&valid_timer_mutex);
        if (valid_timer_count) {
            --valid_timer_count;
            pthread_cond_broadcast(&valid_timer_cond);
        }
        pthread_mutex_unlock(&valid_timer_mutex);
    }

    return retval;
}


/* thread entry point for a thread that spins */
static void *
do_nothing(
    void        UNUSED(*dummy))
{
    struct timespec w;
    struct timeval now;
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t c = PTHREAD_COND_INITIALIZER;
#if 0
    int j = 0;
#endif

    pthread_mutex_lock(&m);
    while (!quit) {
#if 0
        ++j;
#endif
        gettimeofday(&now, NULL);
        if (now.tv_usec < 500000) {
            w.tv_nsec = (now.tv_usec + 500000) * 1000;
            w.tv_sec = now.tv_sec;
        } else {
            w.tv_nsec = (now.tv_usec - 500000) * 1000;
            w.tv_sec = now.tv_sec + 1;
        }
        pthread_cond_timedwait(&c, &m, &w);
    }
    pthread_mutex_unlock(&m);

    return NULL;
}


/*
 *    Prefix any error messages from sktimer with the program name
 *    and an abbreviated time instead of the standard logging tag.
 */
static size_t
logprefix(
    char               *buffer,
    size_t              bufsize)
{
    struct timeval t;
    struct tm ts;

    gettimeofday(&t, NULL);
    localtime_r(&t.tv_sec, &ts);

    return (size_t)snprintf(buffer, bufsize, "%s %2d:%02d:%02d.%06ld: ",
                            skAppName(), ts.tm_hour, ts.tm_min, ts.tm_sec,
                            (long)t.tv_usec);
}


int main(int argc, char **argv)
{
    timer_info_t *ti;
    pthread_t t;
    int rv;
    int i;

    appSetup(argc, argv);                       /* never returns on error */

    /* create our "busy" threads */
    for (i = 0; i < 1 + num_timers/2; ++i) {
        rv = skthread_create_detached("timer-test-busy", &t, do_nothing, NULL);
        if (rv) {
            skAppPrintErr("Unable to spawn busy threads");
            return EXIT_FAILURE;
        }
    }

    pthread_mutex_lock(&valid_timer_mutex);

    for (i = 0, ti = timer_info; i < num_timers; ++i, ++ti) {
        ti->id = i;
        INFOMSG("Timer #%d being created...", i);
        if (start_time == (sktime_t)(-1)) {
            rv = skTimerCreate(&ti->timer, interval, timer_callback, ti);
            INFOMSG("Timer #%d started", i);
        } else {
            char buf[256];
            rv = skTimerCreateAtTime(&ti->timer, interval, start_time,
                                     timer_callback, ti);
            INFOMSG("Timer #%d scheduled to start at %s",
                    i, sktimestamp_r(buf, start_time, SKTIMESTAMP_LOCAL));
        }
        if (rv != 0) {
            skAppPrintErr("Timer #%d creation failed", i);
            pthread_mutex_unlock(&valid_timer_mutex);
            appTeardown();
            return EXIT_FAILURE;
        }
        ++valid_timer_count;
    }

    while (!quit && valid_timer_count > 0) {
        rv = pthread_cond_wait(&valid_timer_cond, &valid_timer_mutex);
    }
    pthread_mutex_unlock(&valid_timer_mutex);

    appTeardown();

    return EXIT_SUCCESS;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
