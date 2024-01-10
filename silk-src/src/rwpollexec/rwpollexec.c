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
**  Daemon to run commands on files placed in a directory.
**  Michael Duggan  (Aug 2010)
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwpollexec.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skthread.h>
#include <silk/skdaemon.h>
#include <silk/sklog.h>
#include <silk/skpolldir.h>
#include <silk/skvector.h>
#include <silk/skdllist.h>
#include <silk/redblack.h>

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>

/* LOCAL DEFINES AND TYPEDEFS */

/* The environment variable for a shell to use, if set */
#define SHELL_ENV "SILK_RWPOLLEXEC_SHELL"

/* If this environment variable is set, the program is being run in
 * shell testing mode. */
#define CHECK_SHELL_ENV "SILK_RWPOLLEXEC_SHELL_TEST"

#define EXIT_PPID_DID_NOT_MATCH (EXIT_FAILURE + 1)
#define EXIT_EXEC_FAILED        (EXIT_FAILURE + 2)

/* where to write --help output */
#define USAGE_FH stdout

/* Number of seconds to wait between polling the incoming directory */
#define DEFAULT_POLL_INTERVAL 15
#define DEFAULT_POLL_INTERVAL_STRING "15"

/* The maximum number of simultaneous commands we allow users to
 * select */
#define MAX_SIMULTANEOUS 50
#define MAX_SIMULTANEOUS_STRING "50"

/* Signal/delay pairs */
typedef struct signal_list_st {
    uint32_t delay;
    int      signal;
} signal_list_t;

/* Per-command data */
typedef struct command_data_st {
    char *path;
    pid_t pid;
    pthread_t timing_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned complete : 1;
    unsigned timer_complete : 1;
} command_data_t;


/* LOCAL VARIABLE DEFINITIONS */

/* Shells to attempt to use */
static const char *possible_shells[] = {
    "/bin/sh",
    "/bin/bash",
    "/bin/ksh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/ksh",
    NULL                        /* sentinel */
};

/* Incoming directory */
static const char *incoming_dir = NULL;

/* Error directory */
static const char *error_dir = NULL;

/* Archive directory */
static const char *archive_dir  = NULL;
static int   archive_flat = 0;

/* Command to run */
static const char *command = NULL;

/* Shell to use */
static const char *shell = NULL;

/* Whether that shell exec()s its command.  This variable is only used
 * to print an appropriate message to the log. */
static int shell_uses_exec = 1;

/* The list of command data structures */
static sk_dllist_t    *cmd_list = NULL;
static command_data_t *cmd_block = NULL;
static struct rbtree  *cmd_running = NULL;

/* Number of simultaneous commands to run */
static uint32_t        simultaneous = 1;
static pthread_mutex_t sim_mutex    = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  sim_cond     = PTHREAD_COND_INITIALIZER;
static uint32_t        sim_left; /* Number of commands that can still be run */
static uint32_t        sim_running  = 0;

/* Main thread */
static pthread_t main_thread;

/* Set to true once skdaemonized() has been called---regardless of
 * whether the --no-daemon switch was given. */
static int daemonized = 0;

/* Processing directory thread */
static pthread_t incoming_dir_thread;
static int       incoming_thread_valid = 0;

/* Process reaper thread */
static pthread_t reaper_thread;
static int       reaper_thread_valid = 0;

/* Directory polling information */
static skPollDir_t *polldir          = NULL;
static uint32_t     polling_interval = DEFAULT_POLL_INTERVAL;

/* Signal list */
static sk_vector_t   *signal_vec  = NULL;
static signal_list_t *signal_list = NULL;
static size_t         num_signals;

/* Set to non-zero when shutting down. */
static volatile int shuttingdown = 0;

/* Return value for program */
static int main_retval = EXIT_SUCCESS;

/* OPTIONS SETUP */

typedef enum {
    OPT_COMMAND,
    OPT_INCOMING_DIR,
    OPT_ERROR_DIR,
    OPT_ARCHIVE_DIR,
    OPT_FLAT_ARCHIVE,
    OPT_SIMULTANEOUS,
    OPT_TIMEOUT,
    OPT_POLLING_INTERVAL
} appOptionsEnum;

static struct option appOptions[] = {
    {"command",            REQUIRED_ARG, 0, OPT_COMMAND},
    {"incoming-directory", REQUIRED_ARG, 0, OPT_INCOMING_DIR},
    {"error-directory",    REQUIRED_ARG, 0, OPT_ERROR_DIR},
    {"archive-directory",  REQUIRED_ARG, 0, OPT_ARCHIVE_DIR},
    {"flat-archive",       NO_ARG,       0, OPT_FLAT_ARCHIVE},
    {"simultaneous",       REQUIRED_ARG, 0, OPT_SIMULTANEOUS},
    {"timeout",            REQUIRED_ARG, 0, OPT_TIMEOUT},
    {"polling-interval",   REQUIRED_ARG, 0, OPT_POLLING_INTERVAL},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Run this command on each file found in the incoming\n"
     "\tdirectory. Each \"%s\" in the argument is replaced by the complete\n"
     "\tpath to the file"),
    ("Monitor this directory for files to process"),
    ("If the exit status of running the command on a file\n"
     "\tis non-zero, move the file into this directory"),
    ("If the exit status of running the command on a\n"
     "\tfile is zero, move the file into this directory tree. If the archive\n"
     "\tdirectory is not given, delete the file. Def. No archive"),
    ("Store files in the root of the archive directory.\n"
     "\tWhen not given, files are stored in subdirectories of the archive\n"
     "\tdirectory based on the current time. Def. Use subdirectories"),
    ("Run at most this many simultaneous invocations of the\n"
     "\tcommand when multiple incoming files are present."
     " Range 1-" MAX_SIMULTANEOUS_STRING ". Def. 1"),
    ("Given an argument in the form SIGNAL,SECONDS, send the\n"
     "\tspecified signal to the command if it has not completed within this\n"
     "\tnumber of seconds. SIGNAL may be a signal name or a number. Repeat\n"
     "\tthe switch to send signals at multiple timeouts"),
    ("Check the incoming-directory for new files this\n"
     "\toften (in seconds). Def. "
     DEFAULT_POLL_INTERVAL_STRING),
    (char*)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  signal_compare(const void *a, const void *b);
static int  command_compare(const void *a, const void *b, const void *ctx);
static int  verify_command_string(const char *command);
static int  parse_timeout_option(const char *opt_arg);
static int  test_shell(const char *shell);
static void use_shell(const char *sh);


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
    ("<SWITCHES>\n"                                                     \
     "\tMonitors a directory for incoming files, and runs an\n"          \
     "\tarbitrary command on them.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (!daemonized) {
        if (signal_vec) {
            skVectorDestroy(signal_vec);
        }
        skdaemonTeardown();
        skAppUnregister();
        return;
    }

    NOTICEMSG("Begin shutting down...");

    shuttingdown = 1;

    /* End the file thread. */
    if (polldir) {
        skPollDirStop(polldir);
    }

    /* Wait for reaper thread here */
    if (reaper_thread_valid) {
        INFOMSG("Waiting for running commands to terminate...");
        MUTEX_LOCK(&sim_mutex);
        MUTEX_BROADCAST(&sim_cond);
        MUTEX_UNLOCK(&sim_mutex);
        pthread_join(reaper_thread, NULL);
        INFOMSG("Running commands have ended.");
    }

    /* Wait for file thread here */
    if (incoming_thread_valid) {
        DEBUGMSG("Waiting for incoming file thread to end...");
        pthread_join(incoming_dir_thread, NULL);
        DEBUGMSG("Incoming file thread has ended.");
    }

    if (polldir) {
        skPollDirDestroy(polldir);
    }

    if (signal_vec) {
        skVectorDestroy(signal_vec);
    }
    if (signal_list) {
        free(signal_list);
    }

    if (cmd_list) {
        skDLListDestroy(cmd_list);
    }
    if (cmd_block) {
        free(cmd_block);
    }
    if (cmd_running) {
        rbdestroy(cmd_running);
    }

    NOTICEMSG("Finished shutting down.");

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
    uint32_t i;
    const char *check_pid;
    int arg_index;
    int err = 0;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char*)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* If we are checking for shell functionality, check to see if the
     * PID in the environment variable is equal to our parent's
     * PID. */
    check_pid = getenv(CHECK_SHELL_ENV);
    if (check_pid) {
        pid_t pid = getppid();
        long check = strtol(check_pid, NULL, 10);
        if ((long)pid != check) {
            exit(EXIT_PPID_DID_NOT_MATCH);
        }
        exit(EXIT_SUCCESS);
    }

    /* Set global variables */
    signal_vec = skVectorNew(sizeof(signal_list_t));
    if (signal_vec == NULL) {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)) {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* rwpollexec runs as a daemon */
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

    if (incoming_dir == NULL) {
        err = 1;
        skAppPrintErr("The --%s option is required",
                      appOptions[OPT_INCOMING_DIR].name);
    }
    if (command == NULL) {
        err = 1;
        skAppPrintErr("The --%s option is required",
                      appOptions[OPT_COMMAND].name);
    }
    if (error_dir == NULL) {
        err = 1;
        skAppPrintErr("The --%s option is required",
                      appOptions[OPT_ERROR_DIR].name);
    }
    if (err) {
        skAppUsage();           /* never returns */
    }

    /* verify the required options for logging */
    if (skdaemonOptionsVerify()) {
        skAppUsage();           /* never returns */
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    cmd_running = rbinit(command_compare, NULL);
    if (cmd_running == NULL) {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }

    /* Create a set of command data structures */
    cmd_block = (command_data_t*)calloc(simultaneous, sizeof(*cmd_block));
    if (cmd_block == NULL) {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }
    cmd_list = skDLListCreate(NULL);
    if (cmd_list == NULL) {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < simultaneous; i++) {
        rv = skDLListPushTail(cmd_list, &cmd_block[i]);
        if (rv != 0) {
            skAppPrintOutOfMemory(NULL);
            exit(EXIT_FAILURE);
        }
    }

    /* Set up the signal list */
    num_signals = skVectorGetCount(signal_vec);
    if (num_signals) {
        signal_list = (signal_list_t*)skVectorToArrayAlloc(signal_vec);
        if (signal_list == NULL) {
            skAppPrintOutOfMemory(NULL);
            exit(EXIT_FAILURE);
        }
        skQSort(signal_list, num_signals, sizeof(signal_list_t),
                signal_compare);
    }
    skVectorDestroy(signal_vec);
    signal_vec = NULL;

    /* Set up the command semaphore */
    sim_left = simultaneous;

    /* Determine the shell */
    shell = getenv(SHELL_ENV);
    if (shell != NULL) {
        use_shell(shell);
    } else {
        const char **test;
        /* Look for a good shell */
        for (test = possible_shells; *test; test++) {
            rv = test_shell(*test);
            if (rv == -2) {
                exit(EXIT_FAILURE);
            }
            if (rv == 0) {
                shell = *test;
                break;
            }
        }
        if (NULL == *test) {
            /* If no shells are good, default to the first possible
             * shell */
            use_shell(possible_shells[0]);
        }
    }

    /* Identify the main thread */
    skthread_init("main");
    main_thread = pthread_self();

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

    switch ((appOptionsEnum)opt_index) {

      case OPT_INCOMING_DIR:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        incoming_dir = opt_arg;
        break;

      case OPT_COMMAND:
        if (verify_command_string(opt_arg)) {
            return 1;
        }
        command = opt_arg;
        break;

      case OPT_ERROR_DIR:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        error_dir = opt_arg;
        break;

      case OPT_ARCHIVE_DIR:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        archive_dir = opt_arg;
        break;

      case OPT_FLAT_ARCHIVE:
        archive_flat = 1;
        break;

      case OPT_SIMULTANEOUS:
        rv = skStringParseUint32(&simultaneous, opt_arg, 1, MAX_SIMULTANEOUS);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_TIMEOUT:
        rv = parse_timeout_option(opt_arg);
        if (rv != 0) {
            return 1;
        }
        break;

      case OPT_POLLING_INTERVAL:
        rv = skStringParseUint32(&polling_interval, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
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
 *  use_shell(shell);
 *
 *    Use a particular shell, whether of not it is a "good" shell.
 */
static void
use_shell(
    const char         *sh)
{
    int rv = test_shell(sh);
    if (rv < 0) {
        if (rv == -1) {
            skAppPrintErr("The shell %s cannot be executed", sh);
        }
        exit(EXIT_FAILURE);
    }
    if (rv > 0) {
        skAppPrintErr(("The shell %s does not exec its last command; "
                       "using it anyway"), sh);
        shell_uses_exec = 0;
    }
    shell = sh;
}


/*
 *  ok = test_test(shell);
 *
 *    Test a shell for usability.  A shell is usable if after "<sh> -c
 *    cmd", cmd is exec()-ed by the shell, having the same PID as the
 *    shell.  If the shell instead fork()s, execs cmd, and waits on
 *    it, then the shell fails this test.
 *
 *    To test the shell, the application invokes itself with the
 *    application's PID in the CHECK_SHELL_ENV environment variable.
 *
 *    Returns 0 if the shell is good, 1 if the shell works, but does
 *    not exec, -1 if the shell does not execute, and -2 on internal
 *    failures.
 *
 *    FIXME: Note that on OS X, when running from within the build
 *    directory and System Integrity Protection (SIP) is enabled, this
 *    check fails because the DYLD_LIBRARY_PATH variables required to
 *    invoke rwpollexec initially are not passed through /bin/sh, and
 *    the self-invocations of rwpollexec fail.
 *
 *    One work-around for this problem is to set the environment
 *    variable named by SHELL_ENV to a shell that is not in /bin or
 *    /usr/bin.
 */
static int
test_shell(
    const char         *sh)
{
    int rv;
    pid_t child_pid;
    pid_t pid;

    pid = getpid();
    child_pid = fork();
    if (child_pid == -1) {
        skAppPrintSyserror("Could not fork");
        return -2;
    }

    if (child_pid == 0) {
        /* Child */
        char buf[64];
        const char *app = skAppFullPathname();

        rv = snprintf(buf, sizeof(buf), "%s=%ld", CHECK_SHELL_ENV, (long)pid);
        if ((size_t)rv >= sizeof(buf)) {
            skAppPrintErr("Buffer size too small for %s=%ld",
                          CHECK_SHELL_ENV, (long)pid);
            exit(EXIT_FAILURE);
        }
        putenv(buf);
        execl(sh, sh, "-c", app, NULL);
        exit(EXIT_EXEC_FAILED);
    }

    /* Parent */
    pid = waitpid(child_pid, &rv, 0);
    if (child_pid != pid) {
        skAppPrintSyserror("waitpid failure");
        return -2;
    }
    if (WIFEXITED(rv)) {
        switch (WEXITSTATUS(rv)) {
          case EXIT_SUCCESS:
            return 0;
          case EXIT_PPID_DID_NOT_MATCH:
            return 1;
          case EXIT_EXEC_FAILED:
            return -1;
          case EXIT_FAILURE:
          default:
            return -2;
        }
    }

    return -1;
}


/*
 *  status = verify_command_string(command);
 *
 *    Verify that the command string specified in 'command' does not
 *    contain unknown conversions.  If 'command' is valid, return 0.
 *
 *    If 'command' is not valid, print an error and return -1.
 */
static int
verify_command_string(
    const char         *cmd)
{
    const char *cp = cmd;

    if (!*cmd) {
        skAppPrintErr("Invalid %s: Empty string",
                      appOptions[OPT_COMMAND].name);
        return -1;
    }

    while (NULL != (cp = strchr(cp, '%'))) {
        ++cp;
        switch (*cp) {
          case '%':
          case 's':
            ++cp;
            break;
          case '\0':
            skAppPrintErr(("Invalid %s '%s':"
                           " '%%' appears at end of string"),
                          appOptions[OPT_COMMAND].name, cmd);
            return -1;
          default:
            skAppPrintErr("Invalid %s '%s': Unknown conversion '%%%c'",
                          appOptions[OPT_COMMAND].name, cmd, *cp);
            return -1;
        }
    }
    return 0;
}


/*
 *  status = parse_timeout_option(timeout);
 *
 *    Verify that 'timeout' contains a "SIGNAL,DELAY" pair, where
 *    SIGNAL is a signal name or number and DELAY is a number of
 *    seconds.  If 'timeout' is valid, return 0.
 *
 *    If 'timeout' is not valid, print an error and return -1.
 */
static int
parse_timeout_option(
    const char         *opt_arg)
{
    signal_list_t sig_element;
    const char *c;
    int rv;

    rv = skStringParseSignal(&sig_element.signal, opt_arg);
    if (rv < 0) {
        skAppPrintErr("Invalid %s '%s': Error parsing signal: %s",
                      appOptions[OPT_TIMEOUT].name, opt_arg,
                      skStringParseStrerror(rv));
        return -1;
    }
    if (rv == 0) {
        skAppPrintErr("Invalid %s '%s': Timeout delay did not follow signal",
                      appOptions[OPT_TIMEOUT].name, opt_arg);
        return -1;
    }
    c = &opt_arg[rv];
    if (*c != ',') {
        skAppPrintErr("Invalid %s '%s': Expected a comma after the signal, "
                      "found a '%c' instead",
                      appOptions[OPT_TIMEOUT].name, opt_arg, *c);
        return -1;
    }
    ++c;

    rv = skStringParseUint32(&sig_element.delay, c, 1, 0);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': Error parsing delay: %s",
                      appOptions[OPT_TIMEOUT].name, opt_arg,
                      skStringParseStrerror(rv));
        return -1;
    }

    rv = skVectorAppendValue(signal_vec, &sig_element);
    if (rv != 0) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }

    return 0;
}


/* Called by threads to exit program */
static void
threadExit(
    int                 status,
    void               *retval)
{
    SKTHREAD_DEBUG_PRINT1("threadExit called");
    main_retval = status;
    pthread_kill(main_thread, SIGQUIT);
    pthread_exit(retval);
}


/* Compare function for signal_list_t (by delay) */
static int
signal_compare(
    const void         *va,
    const void         *vb)
{
    signal_list_t *a = (signal_list_t*)va;
    signal_list_t *b = (signal_list_t*)vb;

    if (a->delay < b->delay) {
        return -1;
    }
    return a->delay > b->delay;
}


/* Compare function for command_data_t (by pid) */
static int
command_compare(
    const void         *va,
    const void         *vb,
    const void  UNUSED(*ctx))
{
    command_data_t *a = (command_data_t*)va;
    command_data_t *b = (command_data_t*)vb;

    if (a->pid < b->pid) {
        return -1;
    }
    return a->pid > b->pid;
}


/*
 *    signal_timing_thread(command_data)
 *
 *    THREAD ENTRY POINT from handle_new_file
 *
 *    This thread handles sending signals to forked-off commands.
 */
static void *
signal_timing_thread(
    void               *ctx)
{
    size_t current_signal;
    uint32_t last_offset = 0;
    command_data_t *data = (command_data_t*)ctx;

    TRACEMSG(2, ("signal_timing_thread has started"));

    MUTEX_LOCK(&data->mutex);

    for (current_signal = 0;
         !shuttingdown && !data->complete && (current_signal < num_signals);
         ++current_signal)
    {
        int rv;
        struct timeval tv;
        struct timespec ts;
        signal_list_t *sig = &signal_list[current_signal];

        gettimeofday(&tv, NULL);
        ts.tv_nsec = tv.tv_usec * 1000;
        ts.tv_sec = tv.tv_sec + sig->delay - last_offset;
        last_offset = sig->delay;

        do {
            rv = pthread_cond_timedwait(&data->cond, &data->mutex, &ts);
        } while (rv == EINTR);

        if (rv == ETIMEDOUT) {
            WARNINGMSG("Sending SIG%s to process [%d]",
                       skSignalToName(sig->signal), (int)data->pid);
            kill(data->pid, sig->signal);
        }
    }

    data->timer_complete = 1;

    /* Notify the fact that we are exiting */
    MUTEX_BROADCAST(&data->cond);

    MUTEX_UNLOCK(&data->mutex);

    TRACEMSG(2, ("signal_timing_thread has ended"));

    return NULL;
}


static int
archive_file(
    const char         *file)
{
    char        buf[PATH_MAX];
    const char *path;
    int         rv;

    if (archive_dir == NULL) {
        DEBUGMSG("Removing %s", file);
        rv = unlink(file);
        if (rv != 0 && errno != ENOENT) {
            WARNINGMSG("Could not remove %s: %s", file, strerror(errno));
            return -1;
        }
        return 0;
    }

    if (archive_flat) {
        /* file goes directly into the archive_directory */
        path = archive_dir;
    } else {
        time_t      curtime;
        struct tm   ctm;

        /* create archive path based on current local time:
         * ARCHIVE/YEAR/MONTH/DAY/HOUR/FILE */
        curtime = time(NULL);
        localtime_r(&curtime, &ctm);
        rv = snprintf(buf, sizeof(buf), "%s/%04d/%02d/%02d/%02d",
                      archive_dir, (ctm.tm_year + 1900),
                      (ctm.tm_mon + 1), ctm.tm_mday, ctm.tm_hour);
        if (sizeof(buf) <= (size_t)rv) {
            WARNINGMSG("Archive directory path too long");
            return -1;
        }
        path = buf;

        DEBUGMSG("Creating directory %s", path);
        rv = skMakeDir(path);
        if (rv != 0) {
            ERRMSG("Could not create directory '%s': %s",
                   path, strerror(errno));
            return -1;
        }
    }

    DEBUGMSG("Moving %s to %s", file, path);
    rv = skMoveFile(file, path);
    if (rv != 0) {
        ERRMSG("Could not archive %s to %s: %s",
               file, path, strerror(rv));
        return -1;
    }

    return 0;
}


/* Handle deletion or archival of a file */
static void
cleanupFile(
    const char         *file,
    pid_t               pid,
    int                 status)
{
    int rv;

    /* Delete or move file to archive on standard exit (success) */
    if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_SUCCESS)) {
        INFOMSG("Command [%d] on %s has completed successfully", (int)pid,
                file);
        archive_file(file);
        return;
    }

    if (WIFEXITED(status)) {
        WARNINGMSG(("Command [%d] on %s has completed with a nonzero return "
                    "status (%d)"), (int)pid, file, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        WARNINGMSG("Command [%d] on %s was terminated by SIG%s",
                   (int)pid, file, skSignalToName(WTERMSIG(status)));
    } else {
        WARNINGMSG(("Command [%d] on %s was terminated due to "
                    "an unknown reason (%d)"), (int)pid, file, status);
    }

    /* Move file to error otherwise */
    DEBUGMSG("Moving %s to %s", file, error_dir);
    rv = skMoveFile(file, error_dir);
    if (rv != 0) {
        ERRMSG("Could not move %s to %s: %s",
               file, error_dir, strerror(rv));
    }

    return;
}


/* Asynchronously starts a command on file, and returns its pid. */
static pid_t
executeCommand(
    const char         *cmd,
    const char         *file)
{
    size_t len;
    sigset_t sigs;
    pid_t pid;
    size_t file_len;
    const char *cp;
    const char *sp;
    char *expanded_cmd;
    char *exp_cp;

    /* Determine length of buffer needed to hold the expanded command
     * string and allocate it. */
    len = strlen(cmd);
    file_len = strlen(file);
    cp = cmd;
    while (NULL != (cp = strchr(cp, '%'))) {
        ++cp;
        switch (*cp) {
          case '%':
            --len;
            break;
          case 's':
            len += file_len - 2;
            break;
          default:
            skAbortBadCase((int)(*cp));
        }
        ++cp;
    }
    expanded_cmd = (char*)malloc(len + 1);
    if (expanded_cmd == NULL) {
        WARNINGMSG("Unable to allocate memory to create command string");
        threadExit(EXIT_FAILURE, NULL);
    }

    /* Copy command into buffer, handling %-expansions */
    cp = cmd;
    exp_cp = expanded_cmd;
    while (NULL != (sp = strchr(cp, '%'))) {
        /* copy text we just jumped over */
        strncpy(exp_cp, cp, sp - cp);
        exp_cp += (sp - cp);
        /* handle conversion */
        switch (*(sp+1)) {
          case '%':
            *exp_cp = '%';
            ++exp_cp;
            break;
          case 's':
            strcpy(exp_cp, file);
            exp_cp += file_len;
            break;
          default:
            skAbortBadCase((int)(*(sp+1)));
        }
        cp = sp + 2;
        assert(len >= (size_t)(exp_cp - expanded_cmd));
    }
    strcpy(exp_cp, cp);
    expanded_cmd[len] = '\0';

    DEBUGMSG("Invoking command: %s", expanded_cmd);

    /* Fork for exec */
    pid = fork();
    if (-1 == pid) {
        ERRMSG("Could not fork to run command: %s", strerror(errno));
        free(expanded_cmd);
        return -1;
    }

    /* Parent returns pid */
    if (pid != 0) {
        NOTICEMSG("Running [%d]: %s", (int)pid, expanded_cmd);
        free(expanded_cmd);
        return pid;
    }

    /* Disable/Ignore locking of the log file; disable log rotation */
    sklogSetLocking(NULL, NULL, NULL, NULL);
    sklogDisableRotation();

    /* Unmask signals */
    sigemptyset(&sigs);
    sigprocmask(SIG_SETMASK, &sigs, NULL);

    /* Execute the command */
    if (execl(shell, shell, "-c", expanded_cmd, (char*)NULL)
        == -1)
    {
        ERRMSG("Error invoking '%s': %s", shell, strerror(errno));
        _exit(EXIT_FAILURE);
    }

    /* Should never get here. */
    skAbort();
}


/*
 *    reap_commands(unused)
 *
 *    THREAD ENTRY POINT FOR main.
 *
 *    Waits for command processes to exit, and then calls cleanup on
 *    the files.
 */
static void *
reap_commands(
    void        UNUSED(*ctx))
{
    TRACEMSG(1, ("reap_commands thread has started"));

    for (;;) {
        int rv;
        int status;
        command_data_t target;
        command_data_t *cmd_data;

        /* Wait for a child to exist */
        MUTEX_LOCK(&sim_mutex);
        while (sim_running == 0) {
            if (shuttingdown) {
                MUTEX_UNLOCK(&sim_mutex);
                goto end;
            }
            MUTEX_WAIT(&sim_cond, &sim_mutex);
        }
        MUTEX_UNLOCK(&sim_mutex);

        /* Wait for a child to exit */
        /* We use 0 as the first argument for waitpid() in order to
         * wait for any child from our process group.  Anything else
         * in libsilk that might fork and wait in another thread
         * during execution (such as log rotation in the logging code)
         * should have those children place themselves in a separate
         * process group. */
        target.pid = waitpid(0, &status, 0);
        if (target.pid == -1) {
            if (errno == EINTR) {
                continue;
            }
            CRITMSG("waitpid() failed: %s", strerror(errno));
            threadExit(EXIT_FAILURE, NULL);
        }

        /* Remove the child from the running tree */
        MUTEX_LOCK(&sim_mutex);
        cmd_data = (command_data_t*)rbdelete(&target, cmd_running);
        MUTEX_UNLOCK(&sim_mutex);

        if (cmd_data == NULL) {
            continue;
        }

        /* Clean up the child */
        MUTEX_LOCK(&cmd_data->mutex);
        cmd_data->complete = 1;
        cleanupFile(cmd_data->path, cmd_data->pid, status);

        /* Signal timing thread to end */
        if (signal_list) {
            MUTEX_BROADCAST(&cmd_data->cond);

            /* Wait for timing thread to end */
            while (!cmd_data->timer_complete) {
                MUTEX_WAIT(&cmd_data->cond, &cmd_data->mutex);
            }

            /* Join timing thread */
            pthread_join(cmd_data->timing_thread, NULL);
        }

        /* Free command data */
        pthread_cond_destroy(&cmd_data->cond);
        free(cmd_data->path);
        MUTEX_UNLOCK(&cmd_data->mutex);
        MUTEX_DESTROY(&cmd_data->mutex);
        memset(cmd_data, 0, sizeof(*cmd_data));

        /* Release the command slot */
        MUTEX_LOCK(&sim_mutex);
        rv = skDLListPushTail(cmd_list, cmd_data);
        if (rv != 0) {
            skAppPrintOutOfMemory(NULL);
            MUTEX_UNLOCK(&sim_mutex);
            threadExit(EXIT_FAILURE, NULL);
        }
        if (sim_left == 0) {
            /* Wake up waiters */
            MUTEX_BROADCAST(&sim_cond);
        }
        sim_running--;
        sim_left++;
        if (sim_left > simultaneous) {
            sim_left = simultaneous;
        }
        MUTEX_UNLOCK(&sim_mutex);
    }

  end:
    TRACEMSG(1, ("reap_commands thread has ended"));

    return NULL;
}


/* Deal with a new file. */
static void
handle_new_file(
    const char         *path,
    const char         *name)
{
    int rv;
    command_data_t *cmd_data;
    command_data_t *inserted;

    MUTEX_LOCK(&sim_mutex);

    /* Wait until a command slot opens */
    while (sim_left == 0 && !shuttingdown) {
        MUTEX_WAIT(&sim_cond, &sim_mutex);
    }
    if (shuttingdown) {
        MUTEX_UNLOCK(&sim_mutex);
        return;
    }
    if (sim_left == simultaneous) {
        /* Wake up reaper */
        MUTEX_BROADCAST(&sim_cond);
    }
    sim_left--;

    rv = skDLListPopHead(cmd_list, (void **)&cmd_data);
    assert(rv == 0);

    cmd_data->path = strdup(path);
    if (cmd_data->path == NULL) {
        skAppPrintOutOfMemory(NULL);
        MUTEX_UNLOCK(&sim_mutex);
        threadExit(EXIT_FAILURE, NULL);
    }
    cmd_data->pid = executeCommand(command, cmd_data->path);
    if (cmd_data->pid == -1) {
        skPollDirErr_t err;

        free(cmd_data->path);

        --simultaneous;
        if (simultaneous < 1) {
            CRITMSG("Cannot fork at all");
            MUTEX_UNLOCK(&sim_mutex);
            threadExit(EXIT_FAILURE, NULL);
        }
        ERRMSG("Failed to fork().  Reducing simultaneous calls to %d",
               simultaneous);
        err = skPollDirPutBackFile(polldir, name);
        if (err != PDERR_NONE) {
            skAppPrintOutOfMemory(NULL);
            MUTEX_UNLOCK(&sim_mutex);
            threadExit(EXIT_FAILURE, NULL);
        }

        /* We do not put back the cmd_data structure, as it is no
         * longer needed (simultaneous was decremented). */
        return;
    }
    MUTEX_INIT(&cmd_data->mutex);
    pthread_cond_init(&cmd_data->cond, NULL);

    if (signal_list) {
        rv = skthread_create("signal_timer", &cmd_data->timing_thread,
                             signal_timing_thread, cmd_data);
        if (rv != 0) {
            CRITMSG("Could not create signal timing thread");
            MUTEX_UNLOCK(&sim_mutex);
            threadExit(EXIT_FAILURE, NULL);
        }
    }

    /* Add this one to the running list */
    inserted = (command_data_t*)rbsearch(cmd_data, cmd_running);
    if (inserted != cmd_data) {
        CRITMSG("Failed to add command to pid list");
        MUTEX_UNLOCK(&sim_mutex);
        threadExit(EXIT_FAILURE, NULL);
    }
    sim_running++;

    MUTEX_UNLOCK(&sim_mutex);
}


/*
 *  handle_incoming_directory(ignored);
 *
 *    THREAD ENTRY POINT FOR main.
 *
 *    As long as we are not shutting down, poll for new files in the
 *    incoming directory and pass the filenames to handleNewFile().
 */
static void *
handle_incoming_directory(
    void        UNUSED(*dummy))
{
    char *filename;
    char path[PATH_MAX];
    skPollDirErr_t pderr;

    TRACEMSG(1, ("handle_incoming_directory thread has started"));

    while (!shuttingdown) {
        pderr = skPollDirGetNextFile(polldir, path, &filename);
        if (pderr != PDERR_NONE) {
            if (pderr == PDERR_STOPPED || shuttingdown) {
                continue;
            }
            CRITMSG("Polldir error ocurred: %s",
                    ((pderr == PDERR_SYSTEM)
                     ? strerror(errno)
                     : skPollDirStrError(pderr)));
            threadExit(EXIT_FAILURE, NULL);
        }
        assert(filename);

        handle_new_file(path, filename);
    }

    TRACEMSG(1, ("handle_incoming_directory thread has ended"));

    return NULL;
}


int main(int argc, char **argv)
{
    int rv;

    appSetup(argc, argv);                       /* never returns on error */

    /* Start the logger and become a daemon */
    if (skdaemonize(&shuttingdown, NULL) == -1
        || sklogEnableThreadedLogging() == -1)
    {
        exit(EXIT_FAILURE);
    }
    daemonized = 1;

    DEBUGMSG("Shell is '%s'", shell);
    if (!shell_uses_exec) {
        WARNINGMSG(("The shell %s does not exec its last command; "
                    "continuing anyway"), shell);
    }

    /* Set up directory polling */
    polldir = skPollDirCreate(incoming_dir, polling_interval);
    if (NULL == polldir) {
        CRITMSG("Could not initiate polling for %s", incoming_dir);
        exit(EXIT_FAILURE);
    }

    /* Start incoming files thread */
    rv = skthread_create("incoming", &incoming_dir_thread,
                         handle_incoming_directory, NULL);
    if (rv != 0) {
        CRITMSG("Failed to create incoming file handling thread: %s",
                strerror(rv));
        exit(EXIT_FAILURE);
    }
    incoming_thread_valid = 1;

    /* Start process reaper thread */
    rv = skthread_create("reaper", &reaper_thread,
                         reap_commands, NULL);
    if (rv != 0) {
        CRITMSG("Failed to create process reaping thread: %s",
                strerror(rv));
        exit(EXIT_FAILURE);
    }
    reaper_thread_valid = 1;

    /* We now run forever, accepting signals */
    while (!shuttingdown) {
        pause();
    }

    /* done */
    appTeardown();
    return main_retval;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
