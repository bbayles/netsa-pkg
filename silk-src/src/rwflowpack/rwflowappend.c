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
**  Daemon that appends rw files to hourly files.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwflowappend.c d0634a5fb86d 2023-09-07 15:45:51Z mthomas $");

#include <silk/redblack.h>
#include <silk/rwrec.h>
#include <silk/skdaemon.h>
#include <silk/sklog.h>
#include <silk/skpolldir.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skthread.h>
#include <silk/utils.h>
#include "rwflow_utils.h"

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* default number of seconds between which to poll for new files */
#define DEFAULT_POLLING_INTERVAL 15

/* default number of appender threads to run */
#define DEFAULT_THREADS 1

/*
 *  The appender_status_t indicates an appender thread's status.
 */
enum appender_status_en {
    APPENDER_STOPPED = 0,
    APPENDER_STARTING,
    APPENDER_STARTED
};
typedef enum appender_status_en appender_status_t;

/*
 *  appender_disposal_t indicates how to dispose of an incremental
 *  file.
 */
enum appender_disposal_en {
    APPENDER_FILE_IGNORE = 0,
    APPENDER_FILE_ARCHIVE = 1,
    APPENDER_FILE_ERROR = 2
};
typedef enum appender_disposal_en appender_disposal_t;

/*
 *  The appender_state_t contains thread information for each appender
 *  thread.
 */
struct appender_state_st {
    /* the thread itself */
    pthread_t           thread;
    /* input stream it is currently reading */
    skstream_t         *in_stream;
    /* output stream it is currently writing */
    skstream_t         *out_stream;
    /* position in the 'out_stream' when the file was opened */
    int64_t             pos;
    /* the full path to the input file */
    char                in_path[PATH_MAX];
    /* the full path to the output file */
    char                out_path[PATH_MAX];
    /* the location in 'in_path' where the basename begins */
    char               *in_basename;
    /* the location in 'out_path' where the basename begins */
    char               *out_basename;
    /* the location in 'out_path' where the relative directory path
     * begins (just after the root_directory ends) */
    char               *relative_dir;
    /* the name of this thread, for log messages */
    char                name[16];
    /* current status of this thread */
    appender_status_t   status;
};
typedef struct appender_state_st appender_state_t;


/* LOCAL VARIABLES */

/* number of appender threads to run; may be modified by
 * --threads */
static uint32_t appender_count = DEFAULT_THREADS;

/* how often to poll the directory for new incremental files; may be
 * modified by --polling-interval */
static uint32_t polling_interval = DEFAULT_POLLING_INTERVAL;

/* directory to watch for new incremental files; must be set by
 * --incoming-directory */
static const char *incoming_directory = NULL;

/* directory in which to write hourly files; must be set by
 * --root-directory */
static const char *root_directory = NULL;

/* command, supplied by user, to run whenever a new hourly file is
 * created; may be set by --hour-file-command */
static const char *hour_file_command = NULL;

/* oldest file (in hours) that is considered acceptable.  incremental
 * files older than this will be put into the error directory.  May be
 * set by --reject-hours-past */
static int64_t reject_hours_past = INT64_MAX;

/* how far into the future are incremental files accepted.  May be set
 * by --reject-hours-future */
static int64_t reject_hours_future = INT64_MAX;

/* whether reject_hours_past and/or reject_hours_future differ from
 * their default values--meaning we need to run the tests */
static int check_time_window = 0;

/* byte order of the files we generate; default is to use the order of
 * the files we receive; may be modified by --byte-order */
static silk_endian_t byte_order = SILK_ENDIAN_ANY;

/* compression method of the files we generate; default is to use the
 * method of the files we receive; may be modified by
 * --compression-method */
static sk_compmethod_t comp_method;

/* non-zero when file locking is disabled; may be modified by
 * --no-file-locking */
static int no_file_locking = 0;

/* whether we are in shut-down mode */
static volatile int shuttingdown = 0;

/* Set to true once skdaemonized() has been called---regardless of
 * whether the --no-daemon switch was given. */
static int daemonized = 0;

/* object that handles polling of the 'incoming_directory' */
static skPollDir_t *polldir = NULL;

/* the states for each of the threads that handle incremental files */
static appender_state_t *appender_state = NULL;

/* mutex to guard access to the 'status' field of appender_state */
static pthread_mutex_t appender_state_mutex = PTHREAD_MUTEX_INITIALIZER;

/* red-black tree to ensure multiple threads do not attempt to modify
 * an hourly file simultaneously.  the tree stores appender_state_t
 * pointers, and the key is the basename of the hourly file. */
static struct rbtree *appender_tree;

/* mutex to guard access to appender_tree */
static pthread_mutex_t appender_tree_mutex = PTHREAD_MUTEX_INITIALIZER;

/* condition variable to awake blocked threads */
static pthread_cond_t appender_tree_cond = PTHREAD_COND_INITIALIZER;


/* OPTIONS SETUP */

typedef enum {
    OPT_INCOMING_DIRECTORY, OPT_ROOT_DIRECTORY, OPT_ERROR_DIRECTORY,
    OPT_ARCHIVE_DIRECTORY, OPT_FLAT_ARCHIVE,
    OPT_POST_COMMAND, OPT_HOUR_FILE_COMMAND,
    OPT_THREADS,
    OPT_REJECT_HOURS_PAST, OPT_REJECT_HOURS_FUTURE,
    OPT_NO_FILE_LOCKING,
    OPT_POLLING_INTERVAL,
    OPT_BYTE_ORDER, OPT_PAD_HEADER
} appOptionsEnum;

static struct option appOptions[] = {
    {"incoming-directory",      REQUIRED_ARG, 0, OPT_INCOMING_DIRECTORY},
    {"root-directory",          REQUIRED_ARG, 0, OPT_ROOT_DIRECTORY},
    {"error-directory",         REQUIRED_ARG, 0, OPT_ERROR_DIRECTORY},
    {"archive-directory",       REQUIRED_ARG, 0, OPT_ARCHIVE_DIRECTORY},
    {"flat-archive",            NO_ARG,       0, OPT_FLAT_ARCHIVE},
    {"post-command",            REQUIRED_ARG, 0, OPT_POST_COMMAND},
    {"hour-file-command",       REQUIRED_ARG, 0, OPT_HOUR_FILE_COMMAND},
    {"threads",                 REQUIRED_ARG, 0, OPT_THREADS},
    {"reject-hours-past",       REQUIRED_ARG, 0, OPT_REJECT_HOURS_PAST},
    {"reject-hours-future",     REQUIRED_ARG, 0, OPT_REJECT_HOURS_FUTURE},
    {"no-file-locking",         NO_ARG,       0, OPT_NO_FILE_LOCKING},
    {"polling-interval",        REQUIRED_ARG, 0, OPT_POLLING_INTERVAL},
    {"byte-order",              REQUIRED_ARG, 0, OPT_BYTE_ORDER},
    {"pad-header",              NO_ARG,       0, OPT_PAD_HEADER},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    ("Watch this directory for new incremental files to\n"
     "\tappend to hourly files"),
    ("Append to/Create hourly files in this directory tree"),
    ("Store in this directory incremental files that were\n"
     "\tNOT successfully appended to an hourly file"),
    ("Archive into this directory tree incremental files\n"
     "\tthat were successfully appended to an hourly file.  If not given,\n"
     "\tincremental files are deleted after appending. Def. No archive"),
    ("Store incremental files in the root of the archive\n"
     "\tdirectory.  When not given, incremental files are stored in\n"
     "\tsubdirectories of the archive-directory. Def. Use subdirectories"),
    ("Run this command on each incremental file after\n"
     "\tsuccessfully appending it and moving it to the archive-directory.\n"
     "\tDef. None.  Each \"%s\" in the command is replaced by the\n"
     "\tarchived file's complete path.  Requires use of --archive-directory"),
    ("Run this command on new hourly files upon their\n"
     "\tcreation.  Def. None.  Each \"%s\" in the command is replaced by\n"
     "\tthe full path to the hourly file"),
    ("Run this number of appending threads simultaneously"),
    ("Reject incremental files containing records whose\n"
     "\tstart times occur more than this number of hours in the past.  The\n"
     "\tfiles are moved into the error directory.  Def. Accept all files"),
    ("Reject incremental files containing records whose\n"
     "\tstart times occur more than this number of hours in the future.  The\n"
     "\tfiles are moved into the error directory.  Def. Accept all files"),
    ("Do not attempt to lock the files prior to writing\n"
     "\trecords to them. Def. Use locking"),
    ("Check the incoming-directory this often for new\n"
     "\tincremental files (in seconds)"),
    ("Create new hourly files in this byte order. Def. 'as-is'.\n"
     "\tChoices: 'as-is'=same as incremental file, 'native', 'little', 'big'"),
    ("Ignored.  For backward compatibility only"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  byteOrderParse(const char *endian_string);
static int  appender_tree_cmp(const void *a, const void *b, const void *c);


/* FUNCTION DEFINITONS */

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
    ("<SWITCHES>\n"                                                        \
     "\tWatches a directory for files containing small numbers of SiLK\n"  \
     "\tflow records (incremental files) and appends those records to\n"   \
     "\thourly files stored in a directory tree creating subdirectories\n" \
     "\tand new hourly files as required.\n")

    FILE *fh = USAGE_FH;
    int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_POLLING_INTERVAL:
            fprintf(fh, "%s. Def. %d", appHelp[i], DEFAULT_POLLING_INTERVAL);
            break;
          case OPT_THREADS:
            fprintf(fh, "%s. Def. %d", appHelp[i], DEFAULT_THREADS);
            break;
          default:
            fprintf(fh, "%s", appHelp[i]);
            break;
        }
        fprintf(fh, "\n");
    }
    skCompMethodOptionsUsage(fh);
    sksiteOptionsUsage(fh);

    fprintf(fh, "\nLogging and daemon switches:\n");
    skdaemonOptionsUsage(fh);
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
    appender_state_t *state;
    appender_status_t status;
    uint32_t i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;
    shuttingdown = 1;

    if (!daemonized) {
        if (appender_tree) {
            rbdestroy(appender_tree);
        }
        free(appender_state);
        skdaemonTeardown();
        skAppUnregister();
        return;
    }

    INFOMSG("Begin shutting down...");

    if (polldir) {
        skPollDirStop(polldir);
    }

    /* awake anyone blocked on red-black tree access */
    pthread_cond_broadcast(&appender_tree_cond);

    /* wait for threads to finish and join each thread */
    for (i = 0, state = appender_state; i < appender_count; ++i, ++state) {
        pthread_mutex_lock(&appender_state_mutex);
        status = state->status;
        pthread_mutex_unlock(&appender_state_mutex);
        if (APPENDER_STARTED == status) {
            DEBUGMSG("Waiting for incoming file thread %s to finish...",
                     state->name);
            pthread_join(state->thread, NULL);
            DEBUGMSG("Incoming file thread %s has finished.", state->name);
        }
        pthread_mutex_lock(&appender_state_mutex);
        state->status = APPENDER_STOPPED;
        pthread_mutex_unlock(&appender_state_mutex);
    }

    rbdestroy(appender_tree);
    free(appender_state);

    if (polldir) {
        skPollDirDestroy(polldir);
    }

    INFOMSG("Finished shutting down.");

    skdaemonTeardown();
    skthread_teardown();
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
    int error_count = 0;
    appender_state_t *state;
    uint32_t i;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* do not set the comp_method from the environment */
    skCompMethodOptionsNoEnviron();

    /* Add the --compression-method switch.  This call will cause us
     * to use the compression method set at compile time if the user
     * doesn't provide the switch.  Since we want to default to using
     * the compression on the incremental files, reset the comp_method
     * variable to "invalid". */
    if (skCompMethodOptionsRegister(&comp_method)) {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }
    comp_method = SK_INVALID_COMPMETHOD;

    /* rwflowappend runs as a daemon */
    if (skdaemonSetup((SKLOG_FEATURE_LEGACY | SKLOG_FEATURE_SYSLOG),
                      argc, argv))
    {
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

    /* Check directories */
    if (NULL == incoming_directory) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_INCOMING_DIRECTORY].name);
        ++error_count;
    }
    if (NULL == root_directory) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_ROOT_DIRECTORY].name);
        ++error_count;
    }
    if (!errorDirectoryIsSet()) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_ERROR_DIRECTORY].name);
        ++error_count;
    }

    /* When post-command is given, verify that archive_directory is set. */
    if (archiveDirectoryIsSet() == -1) {
        skAppPrintErr("The --%s switch is required when using --%s",
                      appOptions[OPT_ARCHIVE_DIRECTORY].name,
                      appOptions[OPT_POST_COMMAND].name);
        ++error_count;
    }

    /* verify the required options for logging */
    if (skdaemonOptionsVerify()) {
        ++error_count;
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        ++error_count;
    }

    /* set root directory */
    if (sksiteSetRootDir(root_directory)) {
        exit(EXIT_FAILURE);
    }

    /* Ensure the site config file is available */
    if (sksiteConfigure(1)) {
        ++error_count;
    }

    /* create structure for each thread */
    appender_state = ((appender_state_t*)
                      calloc(appender_count, sizeof(appender_state_t)));
    if (NULL == appender_state) {
        skAppPrintOutOfMemory("appender_state");
        appender_count = 0;
        exit(EXIT_FAILURE);
    }
    for (i = 0, state = appender_state; i < appender_count; ++i, ++state) {
        state->status = APPENDER_STOPPED;
        snprintf(state->name, sizeof(state->name), "#%" PRIu32, 1 + i);
    }

    /* create the red-black tree */
    appender_tree = rbinit(&appender_tree_cmp, NULL);
    if (NULL == appender_tree) {
        skAppPrintOutOfMemory("red-black tree");
        exit(EXIT_FAILURE);
    }

    if (error_count) {
        skAppUsage();             /* never returns */
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
    uint32_t tmp32;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_INCOMING_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        incoming_directory = opt_arg;
        break;

      case OPT_ROOT_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        root_directory = opt_arg;
        break;

      case OPT_ARCHIVE_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        archiveDirectorySetPath(opt_arg);
        break;

      case OPT_FLAT_ARCHIVE:
        archiveDirectorySetFlat();
        break;

      case OPT_ERROR_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        errorDirectorySetPath(opt_arg);
        break;

      case OPT_REJECT_HOURS_PAST:
        rv = skStringParseUint32(&tmp32, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        reject_hours_past = (int64_t)tmp32;
        check_time_window = 1;
        break;

      case OPT_REJECT_HOURS_FUTURE:
        rv = skStringParseUint32(&tmp32, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        reject_hours_future = (int64_t)tmp32;
        check_time_window = 1;
        break;

      case OPT_NO_FILE_LOCKING:
        no_file_locking = 1;
        break;

      case OPT_POLLING_INTERVAL:
        rv = skStringParseUint32(&polling_interval, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_THREADS:
        rv = skStringParseUint32(&appender_count, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_PAD_HEADER:
        break;

      case OPT_BYTE_ORDER:
        if (byteOrderParse(opt_arg)) {
            return 1;
        }
        break;

      case OPT_POST_COMMAND:
        if (verifyCommandString(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        archiveDirectorySetPostCommand(opt_arg, appOptions[opt_index].name);
        break;

      case OPT_HOUR_FILE_COMMAND:
        if (verifyCommandString(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        hour_file_command = opt_arg;
        break;
    }

    return 0;  /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  ok = byteOrderParse(argument)
 *
 *    parse the argument to the --byte-order switch
 */
static int
byteOrderParse(
    const char         *endian_string)
{
    static int option_seen = 0;
    int i;
    size_t len;
    /* Options for byte-order switch */
    struct {
        const char     *name;
        silk_endian_t   value;
    } byte_order_opts[] = {
        {"as-is",  SILK_ENDIAN_ANY},
        {"native", SILK_ENDIAN_NATIVE},
        {"little", SILK_ENDIAN_LITTLE},
        {"big",    SILK_ENDIAN_BIG},
        {NULL,     SILK_ENDIAN_ANY} /* sentinel */
    };

    /* only process option one time */
    if (option_seen != 0) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }
    option_seen = 1;

    len = strlen(endian_string);
    if (len == 0) {
        skAppPrintErr("Invalid %s: Empty string",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }

    /* parse user's input */
    for (i = 0; byte_order_opts[i].name; ++i) {
        if ((len <= strlen(byte_order_opts[i].name))
            && (0 == strncmp(byte_order_opts[i].name, endian_string, len)))
        {
            byte_order = byte_order_opts[i].value;
            option_seen = 2;
            break;
        }
    }

    if (option_seen != 2) {
        skAppPrintErr("Invalid %s '%s': Unrecognized value",
                      appOptions[OPT_BYTE_ORDER].name, endian_string);
        return 1;
    }

    if (byte_order == SILK_ENDIAN_NATIVE) {
#if SK_LITTLE_ENDIAN
        byte_order = SILK_ENDIAN_LITTLE;
#else
        byte_order = SILK_ENDIAN_BIG;
#endif
    }

    return 0;
}


/*
 *  cmp = appender_tree_cmp(a, b, ctx);
 *
 *    Comparison function for the red-black tree 'appender_tree'.  The
 *    first two parameters are pointers to appender_state_t.
 */
static int
appender_tree_cmp(
    const void         *state1,
    const void         *state2,
    const void  UNUSED(*ctx))
{
    return strcmp(((const appender_state_t*)state1)->out_basename,
                  ((const appender_state_t*)state2)->out_basename);
}


/*
 *  destroyOutputStream(state);
 *
 *    Destroy the output stream that 'state' is writing, and remove
 *    'state' from the red-black tree.
 *
 *    To handle or log errors when the output stream is closed, the
 *    caller must call skStreamClose() to close the stream before
 *    calling this function.
 */
static void
destroyOutputStream(
    appender_state_t   *state)
{
    skStreamDestroy(&state->out_stream);
    pthread_mutex_lock(&appender_tree_mutex);
    TRACEMSG(1, ("Thread %s has finished processing file '%s'",
                 state->name, state->out_basename));
    rbdelete(state, appender_tree);
    pthread_cond_broadcast(&appender_tree_cond);
    pthread_mutex_unlock(&appender_tree_mutex);
}


/*
 *  status = truncateOutputFile(state);
 *
 *    Handle an error after writing some data to the repository file
 *    in 'state->out_stream'.  This function assumes the stream is still
 *    open.
 *
 *    Truncate the repository file to its original size as specified
 *    by 'state->pos' and then close the file and destroy the stream.
 *
 *    If either of these actions result in an error, return -1.
 *    Otherwise, return 0.
 */
static int
truncateOutputFile(
    appender_state_t   *state)
{
    char errbuf[2 * PATH_MAX];
    int retval;
    int rv;

    retval = 0;

    NOTICEMSG("Truncating repository file size to %" PRId64 ": '%s'",
              state->pos, state->out_path);
    rv = skStreamTruncate(state->out_stream, (off_t)state->pos);
    if (rv) {
        skStreamLastErrMessage(state->out_stream, rv, errbuf, sizeof(errbuf));
        ERRMSG(("State of repository file is unknown due to error"
                " while truncating file: %s"), errbuf);
        retval = -1;
        rv = skStreamClose(state->out_stream);
        if (rv) {
            skStreamPrintLastErr(state->out_stream, rv, ERRMSG);
        }
    } else {
        rv = skStreamClose(state->out_stream);
        if (rv) {
            skStreamLastErrMessage(state->out_stream,rv,errbuf,sizeof(errbuf));
            NOTICEMSG(("State of repository file is unknown due to error"
                       " while closing the truncated file: %s"), errbuf);
            retval = -1;
        }
    }
    destroyOutputStream(state);

    return retval;
}


/*
 *  status = openOutputStream(state, in_hdr)
 *
 *    Given the SiLK Flow stream connected to an incremental file
 *    whose SiLK header is in 'in_hdr', either open an existing hourly
 *    file or create a new hourly file at the location specified by
 *    'state->out_path' of the same type and version (RWSPLIT, etc) to
 *    hold the data in the incremental file.  The handle to the opened
 *    stream is put into the value pointed at by 'state->out_stream'.
 *    'state->pos' is set to 0 if the file is newly created, or to the
 *    current size of the file.  This function obtains a write-lock on
 *    the opened file.
 *
 *    The endianness of the new file is determined by the global
 *    'byte_order' variable.  The compression method of the new file
 *    is determined by the 'comp_method' global if that value is set
 *    to a valid compression method.
 *
 *    Return 0 on success.  On error, print a message to the log and
 *    return -1.  When an error occurs, the value of 'out_pos' is
 *    indeterminate.  Return 1 if the 'shuttingdown' variable is set
 *    while waiting on another thread's write-lock.
 */
static int
openOutputStream(
    appender_state_t       *state,
    const sk_file_header_t *in_hdr)
{
    char errbuf[2 * PATH_MAX];
    sk_file_header_t *out_hdr = NULL;
    skstream_mode_t mode;
    const void *found;
    int rv = SKSTREAM_OK;

    assert(state);

    found = NULL;

    /* insert 'state' into the red-black tree to denote that this
     * thread is writing to state->out_basename.  If another thread is
     * already modifying that hourly file, the rbsearch() call will
     * return that thread's state, and this thread then waits on the
     * condition variable. */
    pthread_mutex_lock(&appender_tree_mutex);
    while (!shuttingdown
           && ((found = rbsearch(state, appender_tree)) != state))
    {
        if (NULL == found) {
            skAppPrintOutOfMemory("red-black insert");
            pthread_mutex_unlock(&appender_tree_mutex);
            exit(EXIT_FAILURE);
        }
        TRACEMSG(1, ("Thread %s waiting for thread %s to finish writing '%s'",
                     state->name, ((const appender_state_t*)found)->name,
                     state->out_basename));
        pthread_cond_wait(&appender_tree_cond, &appender_tree_mutex);
    }
    if (shuttingdown) {
        if (found == state) {
            rbdelete(found, appender_tree);
        }
        pthread_mutex_unlock(&appender_tree_mutex);
        return 1;
    }
    pthread_mutex_unlock(&appender_tree_mutex);

    TRACEMSG(1, ("Thread %s is writing '%s'",
                 state->name, state->out_basename));

    /* open the file */
    state->out_stream = openRepoStream(
        state->out_path, &mode, no_file_locking, &shuttingdown);
    if (NULL == state->out_stream) {
        destroyOutputStream(state);
        return -1;
    }

    if (SK_IO_APPEND == mode) {
        state->pos = (int64_t)skStreamTell(state->out_stream);
        return 0;
    }

    /* Create and write a new file header */
    state->pos = 0;

    /* Determine the byte order and compression-method for the new
     * file, using the input file's values unless the appropriate
     * command line options were given. */
    out_hdr = skStreamGetSilkHeader(state->out_stream);
    if (SK_INVALID_COMPMETHOD == comp_method) {
        if (SILK_ENDIAN_ANY == byte_order) {
            if ((rv = skHeaderCopy(out_hdr, in_hdr, SKHDR_CP_ALL))) {
                goto ERROR;
            }
            /* else successfully copied complete header */
        } else if ((rv = skHeaderCopy(out_hdr, in_hdr,
                                      (SKHDR_CP_ALL & ~SKHDR_CP_ENDIAN)))
                   || (rv = skHeaderSetByteOrder(out_hdr, byte_order)))
        {
            goto ERROR;
        }
        /* else successfully copied header, setting byte-order */
    } else if (SILK_ENDIAN_ANY == byte_order) {
        if ((rv = skHeaderCopy(out_hdr, in_hdr,
                               (SKHDR_CP_ALL & ~SKHDR_CP_COMPMETHOD)))
            || (rv = skHeaderSetCompressionMethod(out_hdr, comp_method)))
        {
            goto ERROR;
        }
        /* else successfully copied header, setting compression-method */
    } else if ((rv = skHeaderCopy(out_hdr, in_hdr,
                                  (SKHDR_CP_ALL & ~(SKHDR_CP_COMPMETHOD
                                                    | SKHDR_CP_ENDIAN))))
               || (rv = skHeaderSetCompressionMethod(out_hdr, comp_method))
               || (rv = skHeaderSetByteOrder(out_hdr, byte_order)))
    {
        goto ERROR;
    }
    /* else successfully copied header, setting byte-order and
     * compression-method */

    rv = skStreamWriteSilkHeader(state->out_stream);
    if (rv) {
        skStreamLastErrMessage(state->out_stream, rv, errbuf, sizeof(errbuf));
        ERRMSG("Error writing header to newly opened file: %s", errbuf);
        truncateOutputFile(state);
        return -1;
    }

    /* Success! */
    return 0;

  ERROR:
    if (state->out_stream) {
        if (rv) {
            skStreamPrintLastErr(state->out_stream, rv, &WARNINGMSG);
        }
    }
    destroyOutputStream(state);
    return -1;
}


/*
 *    Dispose of the incremental file in the 'in_path' member of
 *    'state' according to the value of 'disposal' and the
 *    command-line options.
 *
 *    This function may move the file to the error directory, delete
 *    the file, move the file to the archive directory, run a
 *    post-command on the file, or ignore it.
 *
 *    If a stream exists for that file, the stream is closed and
 *    destroyed.  The file is closed after the file has been moved or
 *    deleted to ensure no other process may access the file.
 */
static void
destroyInputStream(
    appender_state_t   *state,
    appender_disposal_t disposal)
{
    ssize_t rv;

    assert(state);
    switch (disposal) {
      case APPENDER_FILE_IGNORE:
        break;
      case APPENDER_FILE_ERROR:
        INFOMSG("Moving incremental file '%s' to the error directory",
                state->in_basename);
        errorDirectoryInsertFile(state->in_path);
        break;
      case APPENDER_FILE_ARCHIVE:
        assert(state->relative_dir);
        assert(state->out_basename);
        /* we need to pass the relative-directory to the archive
         * function.  Modify out_path so it terminates just before the
         * basename which is just after the relative directory. */
        *(state->out_basename - 1) = '\0';
        /* archive or remove the incremental file.  this also
         * invokes the post-command if that was specified. */
        archiveDirectoryInsertOrRemove(state->in_path, state->relative_dir);
        break;
    }

    /* close input */
    if (state->in_stream) {
        rv = skStreamClose(state->in_stream);
        if (rv) {
            skStreamPrintLastErr(state->in_stream, rv, &NOTICEMSG);
        }
        skStreamDestroy(&state->in_stream);
    }
}


/*
 *    Open the incremental file specified in the 'in_path' member of
 *    'state' and get an exclusive lock on the file.  Return the
 *    stream.  On error, move the file to the error directory and
 *    return NULL.
 *
 *    If the file is removed while before it can be opened or locked,
 *    return NULL.
 *
 *    The incremental file is not locked in 'no_file_locking' is true.
 */
static skstream_t *
openInputStream(
    appender_state_t   *state)
{
    char errbuf[2 * PATH_MAX];
    skstream_t *stream = NULL;
    ssize_t rv = SKSTREAM_OK;
    int fd;

    TRACEMSG(3, ("Opening incremental file '%s'", state->in_path));

    /* note: must open file for reading/writing to be able to get an
     * exclusive lock */
    fd = open(state->in_path, O_RDWR);
    if (-1 == fd) {
        TRACEMSG(3, ("Error opening incremental file '%s': %d",
                     state->in_basename, errno));
        if (ENOENT == errno) {
            DEBUGMSG(("Ignoring incremental file '%s': File was removed"
                      " before it could be opened"), state->in_basename);
        } else {
            WARNINGMSG("Error initializing initializing file '%s': %s",
                       state->in_path, strerror(errno));
            destroyInputStream(state, APPENDER_FILE_ERROR);
        }
        return NULL;
    }

    if (!no_file_locking) {
        TRACEMSG(3, ("Locking incremental file %d '%s'", fd, state->in_path));
        /* F_SETLK returns EAGAIN immediately if the lock cannot be
         * obtained; change to F_SETLKW if we want to wait. */
        while (skFileSetLock(fd, F_WRLCK, F_SETLK) != 0) {
            TRACEMSG(3, ("Error locking incremental file '%s': %d",
                         state->in_basename, errno));
            if (shuttingdown) {
                TRACEMSG(3,("Shutdown while locking '%s'",state->in_basename));
                goto ERROR;
            }
            if (EAGAIN == errno) {
                DEBUGMSG(("Ignoring incremental file '%s': File is locked"
                          " by another process"), state->in_basename);
                goto ERROR;
            }
            if (EINTR != errno) {
                INFOMSG(("Ignoring incremental file '%s': Error getting an"
                         " exclusive lock: %s"),
                        state->in_basename, strerror(errno));
                goto ERROR;
            }
        }

        /* check to see whether the file was removed while we were
         * waiting for the lock */
        if (!skFileExists(state->in_path)) {
            DEBUGMSG(("Ignoring incremental file '%s': File was removed"
                      " before it could be locked"), state->in_basename);
            goto ERROR;
        }
    }

    /* wrap the descriptor in a stream */
    TRACEMSG(3, ("Creating skstream for '%s'", state->in_path));
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(stream, state->in_path))
        || (rv = skStreamFDOpen(stream, fd)))
    {
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        WARNINGMSG("Error initializing initializing file: %s", errbuf);
        /* NOTE: it is possible for skStreamFDOpen() to have stored
         * the value of 'fd' but return an error. */
        if (stream && skStreamGetDescriptor(stream) == fd) {
            fd = -1;
        }
        destroyInputStream(state, APPENDER_FILE_ERROR);
        goto ERROR;
    }
    return stream;

  ERROR:
    skStreamDestroy(&stream);
    if (-1 != fd) {
        close(fd);
    }
    return NULL;
}


/*
 *  THREAD ENTRY POINT
 *
 *    This is the entry point for each of the appender_state[].thread.
 *
 *    This function waits for an incremental file to appear in the
 *    incoming_directory being monitored by polldir.  When a file
 *    appears, its corresponding hourly file is determined and the
 *    incremental file is appended to the hourly file.
 */
static void *
appender_main(
    void               *vstate)
{
    appender_state_t *state = (appender_state_t*)vstate;
    char errbuf[2 * PATH_MAX];
    const sk_header_entry_t *hentry;
    skPollDirErr_t pderr;
    int64_t close_pos;
    int rv;
    int out_rv;
    sk_file_header_t *in_hdr;
    rwRec rwrec;

    /* set this thread's state as started */
    pthread_mutex_lock(&appender_state_mutex);
    state->status = APPENDER_STARTED;
    if (shuttingdown) {
        pthread_mutex_unlock(&appender_state_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&appender_state_mutex);

    INFOMSG("Started appender thread %s.", state->name);

    while (!shuttingdown) {
        /* location in output file where records for this input file
         * begin */
        state->pos = 0;
        /* file handles */
        state->in_stream = NULL;
        state->out_stream = NULL;
        state->relative_dir = NULL;
        state->in_path[0] = '\0';

        /* Get the name of the next incremental file */
        pderr = skPollDirGetNextFile(polldir, state->in_path,
                                     &state->in_basename);
        if (pderr != PDERR_NONE) {
            if (pderr == PDERR_STOPPED) {
                assert(shuttingdown);
                continue;
            }
            ERRMSG("Fatal error polling directory: %s",
                   ((pderr == PDERR_SYSTEM)
                    ? strerror(errno)
                    : skPollDirStrError(pderr)));
            exit(EXIT_FAILURE);
        }

        /* Open the incremental file and read its header */
        DEBUGMSG("Processing incremental file '%s'...", state->in_basename);
        state->in_stream = openInputStream(state);
        if (NULL == state->in_stream) {
            continue;
        }
        rv = skStreamReadSilkHeader(state->in_stream, &in_hdr);
        if (SKSTREAM_OK != rv) {
            skStreamLastErrMessage(state->in_stream,rv,errbuf,sizeof(errbuf));
            WARNINGMSG(("Error reading header from incremental file: %s."
                        " Repository unchanged"), errbuf);
            destroyInputStream(state, APPENDER_FILE_ERROR);
            continue;
        }

        /* Determine the pathname of the hourly file to which the
         * incremental file will be appended.  If the file has a
         * packed-file header, attempt to use it.  If that fails,
         * attempt to parse the name assuming it uses the file
         * naming convention.  If that also fails, print a warning
         * and give up on this file.  The 'relative_dir' that is set
         * here is used when archiving the file. */
        hentry = skHeaderGetFirstMatch(in_hdr, SK_HENTRY_PACKEDFILE_ID);
        if (((hentry == NULL)
             || (sksiteGeneratePathname(
                     state->out_path, sizeof(state->out_path),
                     skHentryPackedfileGetFlowtypeID(hentry),
                     skHentryPackedfileGetSensorID(hentry),
                     skHentryPackedfileGetStartTime(hentry),
                     "", /* no suffix */
                     &state->relative_dir, &state->out_basename) == NULL))
            && (sksiteParseGeneratePath(
                    state->out_path, sizeof(state->out_path),
                    state->in_basename, "", /* no suffix */
                    &state->relative_dir, &state->out_basename) == NULL))
        {
            /* Failed. Set part of warning based on header presence */
            const char *pfh_error;
            if (hentry) {
                pfh_error = ("File's packed-file header contains an unknown"
                             " sensor or flowtype");
            } else {
                pfh_error = "File does not have a packed-file header";
            }
            WARNINGMSG(("Error initializing incremental file '%s':"
                        " %s, file name does not match SiLK convention or"
                        " names an unknown sensor or flowtype, or resulting"
                        " pathname is too long. Repository unchanged"),
                       state->in_basename, pfh_error);
            destroyInputStream(state, APPENDER_FILE_ERROR);
            continue;
        }

        /* Read the first record from the incremental file */
        rv = skStreamReadRecord(state->in_stream, &rwrec);
        if (SKSTREAM_OK != rv) {
            if (SKSTREAM_ERR_EOF == rv) {
                INFOMSG(("No records found in incremental file '%s'."
                         " Repository unchanged"), state->in_basename);
                /* the next message is here for consistency, but it is
                 * misleading since the output file was never opened
                 * and may not even exist */
                INFOMSG(("APPEND OK '%s' to '%s' @ %" PRId64),
                        state->in_basename, state->out_path, state->pos);
                destroyInputStream(state, APPENDER_FILE_ARCHIVE);
            } else {
                skStreamLastErrMessage(state->in_stream, rv, errbuf,
                                       sizeof(errbuf));
                WARNINGMSG(("Error reading first record from incremental"
                            " file: %s. Repository unchanged"), errbuf);
                destroyInputStream(state, APPENDER_FILE_ERROR);
            }
            continue;
        }

        /* Check for incremental files outside of the time window */
        if (check_time_window) {
            int64_t diff;
            time_t t = time(NULL);

            diff = ((int64_t)t / 3600) - (rwRecGetStartSeconds(&rwrec) / 3600);
            if (diff > reject_hours_past) {
                NOTICEMSG(("Skipping incremental file: First record's"
                           " timestamp occurs %" PRId64 " hours in the"
                           " past: '%s'. Repository unchanged"),
                           diff, state->in_path);
                destroyInputStream(state, APPENDER_FILE_ERROR);
                continue;
            }
            if (-diff > reject_hours_future) {
                NOTICEMSG(("Skipping incremental file: First record's"
                           " timestamp occurs %" PRId64 " hours in the"
                           " future: '%s'. Repository unchanged"),
                          -diff, state->in_path);
                destroyInputStream(state, APPENDER_FILE_ERROR);
                continue;
            }
        }

        /* Open the hourly file as the output */
        rv = openOutputStream(state, in_hdr);
        if (1 == rv) {
            /* shutting down */
            destroyInputStream(state, APPENDER_FILE_IGNORE);
            continue;
        }
        if (rv) {
            /* Error opening output file. */
            ERRMSG("APPEND FAILED '%s' to '%s' -- nothing written",
                   state->in_basename, state->out_path);
            destroyInputStream(state, APPENDER_FILE_IGNORE);
            CRITMSG("Aborting due to append error");
            exit(EXIT_FAILURE);
        }

        /* initialize close_pos */
        close_pos = 0;

        /* Write record to output and read next record from input */
        do {
            out_rv = skStreamWriteRecord(state->out_stream, &rwrec);
            if (out_rv != SKSTREAM_OK) {
                if (SKSTREAM_ERROR_IS_FATAL(out_rv)) {
                    goto APPEND_ERROR;
                }
                skStreamPrintLastErr(state->out_stream, out_rv, &WARNINGMSG);
            }
        } while ((rv = skStreamReadRecord(state->in_stream, &rwrec))
                 == SKSTREAM_OK);

        /* Flush and close the output file.  If flush fails, truncate
         * the file before closing. */
        out_rv = skStreamFlush(state->out_stream);
        if (out_rv) {
            goto APPEND_ERROR;
        }
        close_pos = (int64_t)skStreamTell(state->out_stream);
        out_rv = skStreamClose(state->out_stream);
        if (out_rv) {
            /* Assuming the flush above was successful (and assuming
             * the stream is still open), the close() call should not
             * fail except for EINTR (interrupt).  However, go ahead
             * and exit anyway. */
            goto APPEND_ERROR;
        }

        DEBUGMSG(("Read %" PRIu64 " recs from '%s';"
                  " wrote %" PRIu64 " recs to '%s';"
                  " old size %" PRId64 "; new size %" PRId64),
                 skStreamGetRecordCount(state->in_stream), state->in_basename,
                 skStreamGetRecordCount(state->out_stream),state->out_basename,
                 state->pos, close_pos);

        destroyOutputStream(state);

        if (SKSTREAM_ERR_EOF != rv) {
            /* Success; though unexpected error on read.  Currently
             * treat this as successful, but should we move to the
             * error_directory instead? */
            skStreamLastErrMessage(state->in_stream,rv,errbuf,sizeof(errbuf));
            NOTICEMSG(("Unexpected error reading incremental file but"
                       " treating file as successful: %s"), errbuf);
        }

        INFOMSG(("APPEND OK '%s' to '%s' @ %" PRId64),
                state->in_basename, state->out_path, state->pos);

        /* Run command if this is a new hourly file */
        if (state->pos == 0 && hour_file_command) {
            runCommand(appOptions[OPT_HOUR_FILE_COMMAND].name,
                       hour_file_command, state->out_path);
        }

        destroyInputStream(state, APPENDER_FILE_ARCHIVE);

    } /* while (!shuttingdown) */

    INFOMSG("Finishing appender thread %s...", state->name);

    return NULL;

  APPEND_ERROR:
    /* Error writing. If repository file is still open, truncate it to
     * its original size.  Move incremental file to the error
     * directory if repository file cannot be truncated. */
    skStreamLastErrMessage(state->out_stream, out_rv, errbuf, sizeof(errbuf));
    ERRMSG("Fatal error writing to hourly file: %s", errbuf);
    ERRMSG(("APPEND FAILED '%s' to '%s' @ %" PRId64),
           state->in_basename, state->out_path, state->pos);
    if (close_pos) {
        /* flush was okay but close failed. */
        ERRMSG(("Repository file '%s' in unknown state since flush"
                " succeeded but close failed"), state->out_path);
        destroyOutputStream(state);
    } else if (truncateOutputFile(state)) {
        /* error truncating file */
        close_pos = -1;
    }
    destroyInputStream(state, ((close_pos)
                               ? APPENDER_FILE_ERROR
                               : APPENDER_FILE_IGNORE));
    CRITMSG("Aborting due to append error");
    exit(EXIT_FAILURE);
}


int main(int argc, char **argv)
{
    appender_state_t *state;
    uint32_t i;
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    /* start the logger and become a daemon */
    if (skdaemonize(&shuttingdown, NULL) == -1
        || sklogEnableThreadedLogging() == -1)
    {
        exit(EXIT_FAILURE);
    }
    daemonized = 1;

    skthread_init("main");

    /* Set up directory polling */
    polldir = skPollDirCreate(incoming_directory, polling_interval);
    if (NULL == polldir) {
        ERRMSG("Could not initiate polling on '%s'", incoming_directory);
        exit(EXIT_FAILURE);
    }

    /* Start the appender threads. */
    NOTICEMSG("Starting %" PRIu32 " appender thread%s...",
              appender_count, ((appender_count > 1) ? "s" : ""));
    pthread_mutex_lock(&appender_state_mutex);
    for (i = 0, state = appender_state; i < appender_count; ++i, ++state) {
        DEBUGMSG("Starting appender thread %s...", state->name);
        state->status = APPENDER_STARTING;
        rv=skthread_create(state->name, &state->thread, appender_main, state);
        if (rv) {
            ERRMSG("Failed to start appender thread %s: %s",
                   state->name, strerror(rv));
            state->status = APPENDER_STOPPED;
            pthread_mutex_unlock(&appender_state_mutex);
            exit(EXIT_FAILURE);
        }
    }
    pthread_mutex_unlock(&appender_state_mutex);
    NOTICEMSG("Started all appender threads.");

    while (!shuttingdown) {
        pause();
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
