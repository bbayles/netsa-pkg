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
**  Provide functions to daemonize an application
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skdaemon.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skdaemon.h>
#include <silk/sklog.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* daemon context */
typedef struct skdaemon_ctx_st {
    /* location of pid file */
    char           *pidfile;
    /* variable to set to '1' once the signal handler is called */
    volatile int   *shutdown_flag;
    /* whether to chdir to the root directory (0 = yes, 1 = no) */
    unsigned        no_chdir :1;
    /* whether to run as a daemon (0 = yes, 1 = no) */
    unsigned        no_daemon :1;
    /* whether the legacy logging was provided as an option */
    unsigned        legacy_log:1;
} skdaemon_ctx_t;


/* map a signal number to its name */
typedef struct sk_siglist_st {
    int         signal;
    const char *name;
} sk_siglist_t;


/* Use this macro to print an error message to the log stream and to
 * the standard error. Use double parens around arguments to this
 * macro: PRINT_AND_LOG(("%s is bad", "foo")); */
#ifdef TEST_PRINTF_FORMATS
#  define PRINT_AND_LOG(args) printf args
#else
#  define PRINT_AND_LOG(args) \
    do {                      \
        skAppPrintErr args;   \
        ERRMSG args;          \
    } while(0)
#endif


/* LOCAL VARIABLE DEFINITIONS */


/* there is a single context */
static skdaemon_ctx_t daemon_ctx;
static skdaemon_ctx_t *skdaemon = NULL;

/* Signals to ignore or to catch */
static sk_siglist_t ignored_signals[] = {
    /* {SIGCHLD, "CHLD"},  leave at default (which is ignore) */
    {SIGPIPE, "PIPE"},
    {0,NULL}  /* sentinel */
};

static sk_siglist_t caught_signals[] = {
    {SIGHUP,  "HUP"},
    {SIGINT,  "INT"},
#ifdef SIGPWR
    {SIGPWR,  "PWR"},
#endif
    {SIGQUIT, "QUIT"},
    {SIGTERM, "TERM"},
    {0,NULL}  /* sentinel */
};


/* OPTIONS SETUP */
typedef enum {
    OPT_PIDFILE,
    OPT_NO_CHDIR,
    OPT_NO_DAEMON
} daemonOptionsEnum;

static struct option daemonOptions[] = {
    {"pidfile",               REQUIRED_ARG, 0, OPT_PIDFILE},
    {"no-chdir",              NO_ARG,       0, OPT_NO_CHDIR},
    {"no-daemon",             NO_ARG,       0, OPT_NO_DAEMON},
    {0,0,0,0}                 /* sentinel */
};


/* LOCAL FUNCTION PROTOTYPES */

static void daemonHandleSignal(int sigNum);
static int daemonInstallSignalHandler(void);
static int
daemonOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);
static int daemonWritePid(void);


/* FUNCTION DEFINITIONS */

/*
 *  daemonHandleSignal(sig_num);
 *
 *    Trap all signals and shutdown when told to.
 */
static void
daemonHandleSignal(
    int                 sig_num)
{
    /* determine name of our signal */
    sk_siglist_t *s;

    for (s = caught_signals; s->name && s->signal != sig_num; s++)
        ; /* empty */

    /* don't allow the writing of the log message to cause the entire
     * program to deadlock.  */
    if (s->name) {
        sklogNonBlock(LOG_NOTICE, "Shutting down due to SIG%s signal",s->name);
    } else {
        sklogNonBlock(LOG_NOTICE, "Shutting down due to unknown signal");
    }

    /* set the global shutdown variable */
    if (skdaemon && skdaemon->shutdown_flag) {
        *(skdaemon->shutdown_flag) = 1;
    }
}


/*
 *  ok = daemonInstallSignalHandler();
 *
 *    Trap all signals we can here with our own handler.
 *    Exception: SIGPIPE.  Set this to SIGIGN.
 *
 *    Returns 0 if OK. -1 else.
 */
static int
daemonInstallSignalHandler(
    void)
{
    sk_siglist_t *s;
    struct sigaction action;
    int rv;

    memset(&action, 0, sizeof(action));

    /* mask any further signals while we're inside the handler */
    sigfillset(&action.sa_mask);

    /* ignored signals */
    action.sa_handler = SIG_IGN;
    for (s = ignored_signals; s->name; ++s) {
        if (sigaction(s->signal, &action, NULL) == -1) {
            rv = errno;
            PRINT_AND_LOG(("Cannot ignore SIG%s: %s",
                           s->name, strerror(rv)));
            return -1;
        }
    }

    /* signals to catch */
    action.sa_handler = &daemonHandleSignal;
    for (s = caught_signals; s->name; ++s) {
        if (sigaction(s->signal, &action, NULL) == -1) {
            rv = errno;
            PRINT_AND_LOG(("Cannot handle SIG%s: %s",
                           s->name, strerror(rv)));
            return -1;
        }
    }

    return 0;
}


/*
 *  status = daemonOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Handle the options that we registered in skdaemonSetup().
 */
static int
daemonOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    switch ((daemonOptionsEnum)opt_index) {
      case OPT_PIDFILE:
        if (skdaemon->pidfile) {
            skAppPrintErr("The --%s switch is given multiple times",
                          daemonOptions[opt_index].name);
            return -1;
        }
        if (opt_arg[0] != '/') {
            skAppPrintErr(("Must use full path to %s\n"
                           "\t('%s' does not begin with a slash)"),
                          daemonOptions[opt_index].name, opt_arg);
            return -1;
        }
        skdaemon->pidfile = strdup(opt_arg);
        break;

      case OPT_NO_CHDIR:
        skdaemon->no_chdir = 1;
        break;

      case OPT_NO_DAEMON:
        skdaemon->no_daemon = 1;
        break;
    }

    return 0;
}


/*
 *  status = daemonWritePid();
 *
 *    Write the process ID (PID) to the pidfile the user specified.
 *    If no pidfile was specified but a log directory was specified,
 *    write it to that directory.  Otherwise, do not write the PID to
 *    disk.  Store the location of the pidfile on the global context.
 *
 *    Return 0 on success, or errno on failure.
 */
static int
daemonWritePid(
    void)
{
    char pidfile[PATH_MAX+1];
    char pidstr[24];
    int fd;
    ssize_t len;
    ssize_t len2;
    const char *log_directory;
    int saveerr;

    if (!skdaemon->pidfile) {
        /* No pidfile on command line. */
        log_directory = sklogGetDirectory(pidfile, sizeof(pidfile));
        if (!log_directory) {
            return 0;
        }
        /* We do have a log-directory; store the PID there using the
         * application name as the file's base name */
        len = strlen(pidfile);
        len2 = snprintf(&pidfile[len], sizeof(pidfile)-len, "/%s.pid",
                        skAppName());
        if ((size_t)(len + len2) >= sizeof(pidfile)) {
            /* make up an errno */
            return ENAMETOOLONG;
        }
        skdaemon->pidfile = strdup(pidfile);
        if (!skdaemon->pidfile) {
            return errno;
        }
    }

    /* Filesystem Hierarchy Standard says the pid file contains
     * the PID in ASCII-encoded decimal followed by a newline. */
    len = snprintf(pidstr, sizeof(pidstr), "%ld\n", (long)getpid());
    if ((size_t)len >= sizeof(pidstr)) {
        return ENAMETOOLONG;
    }
    fd = open(skdaemon->pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        return errno;
    }
    if (skwriten(fd, pidstr, len) == -1) {
        saveerr = errno;
        close(fd);
        unlink(skdaemon->pidfile);
        return saveerr;
    }
    if (close(fd) == -1) {
        saveerr = errno;
        unlink(skdaemon->pidfile);
        return saveerr;
    }

    return 0;
}


/* force the application not to fork */
void
skdaemonDontFork(
    void)
{
    if (skdaemon) {
        skdaemon->no_daemon = 1;
    }
}


/* print the usage of the options defined by this library */
void
skdaemonOptionsUsage(
    FILE               *fh)
{
    int i;

    sklogOptionsUsage(fh);
    for (i = 0; daemonOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", daemonOptions[i].name,
                SK_OPTION_HAS_ARG(daemonOptions[i]));
        switch ((daemonOptionsEnum)i) {
          case OPT_PIDFILE:
            if (skdaemon && skdaemon->legacy_log) {
                fprintf(fh, ("Complete path to the process ID file."
                             "  Overrides the path\n"
                             "\tbased on the --log-directory argument."));
            } else {
                fprintf(fh, ("Complete path to the process ID file."
                             "  Def. None"));
            }
            break;
          case OPT_NO_CHDIR:
            fprintf(fh, ("Do not change directory to the root directory.\n"
                         "\tDef. Change directory unless --%s is specified"),
                    daemonOptions[OPT_NO_DAEMON].name);
            break;
          case OPT_NO_DAEMON:
            fprintf(fh, ("Do not fork off as a daemon (for debugging)."
                         " Def. Fork"));
            break;
        }
        fprintf(fh, "\n");
    }
}


/* verify that the options are valid and that all required options
 * were provided. */
int
skdaemonOptionsVerify(
    void)
{
    /* skdaemon doesn't have any options that it requires, but the
     * logging library does. */
    return sklogOptionsVerify();
}


/* register our options and the options for logging */
int
skdaemonSetup(
    int                 log_features,
    int                 argc,
    char   * const     *argv)
{
    if (skdaemon) {
        /* called mulitple times */
        return -1;
    }

    skdaemon = &daemon_ctx;
    memset(skdaemon, 0, sizeof(skdaemon_ctx_t));

    /* setup the log. have it write the invocation when we open it */
    if (sklogSetup(log_features)) {
        return -1;
    }
    sklogCommandLine(argc, argv);

    /* note whether legacy logging was requested so we know how to
     * print the help for the --pidfile switch */
    if (log_features & SKLOG_FEATURE_LEGACY) {
        skdaemon->legacy_log = 1;
    }

    return skOptionsRegister(daemonOptions, &daemonOptionsHandler, NULL);
}


/* remove the PID file and shutdown the logger */
void
skdaemonTeardown(
    void)
{
    if (skdaemon == NULL) {
        return;
    }

    sklogTeardown();

    if (skdaemon->pidfile != NULL) {
        (void)unlink(skdaemon->pidfile);
        free(skdaemon->pidfile);
        skdaemon->pidfile = NULL;
    }

    skdaemon = NULL;
}


/* start logging, install the signal handler, fork off the daemon, and
 * write the PID file */
int
skdaemonize(
    volatile int       *shutdown_flag,
    void                (*exit_handler)(void))
{
    char errbuf[512];
    pid_t pid;
    int rv;
    int fd_devnull;

    /* Must call setup before daemonize; make certain we have a
     * shutdown variable */
    assert(skdaemon);
    assert(shutdown_flag);

    /* Store the shutdown flag */
    skdaemon->shutdown_flag = shutdown_flag;

    /* Start the logger */
    if (sklogOpen()) {
        return -1;
    }

    /* Install the signal handler */
    rv = daemonInstallSignalHandler();
    if (rv) {
        goto ERROR;
    }

    /* Fork a child and exit the parent. */
    if ( !skdaemon->no_daemon) {
        if ( !skdaemon->no_chdir) {
            if (chdir("/") == -1) {
                rv = errno;
                PRINT_AND_LOG(("Cannot change directory: %s", strerror(rv)));
                goto ERROR;
            }
        }
        if ((pid = fork()) == -1) {
            rv = errno;
            PRINT_AND_LOG(("Cannot fork for daemon: %s", strerror(rv)));
            goto ERROR;
        } else if (pid != 0) {
            NOTICEMSG("Forked child %ld.  Parent exiting", (long)pid);
            _exit(EXIT_SUCCESS);
        }

        setsid();
    }

    /* Set umask */
    umask(0022);

    /* Install the exit handler; do this after the fork() so the
     * parent does not execute it. */
    if (exit_handler) {
        rv = atexit(exit_handler);
        if (rv == -1) {
            PRINT_AND_LOG(("Unable to register function with atexit(): %s",
                           strerror(rv)));
            goto ERROR;
        }
    }

    /* Write the pidfile when running as a daemon */
    if ( !skdaemon->no_daemon) {
        rv = daemonWritePid();
        if (rv) {
            if (skdaemon->pidfile) {
                PRINT_AND_LOG(("Error creating pid file '%s': %s",
                               skdaemon->pidfile, strerror(rv)));
            } else {
                PRINT_AND_LOG(("Unable to create pid file path: %s",
                               strerror(rv)));
            }
            goto ERROR;
        }

        /* redirect stdin to /dev/null */
        fd_devnull = open("/dev/null", O_RDWR);
        if (fd_devnull == -1) {
            rv = errno;
            PRINT_AND_LOG(("Error opening /dev/null: %s", strerror(rv)));
            goto ERROR;
        }
        if (dup2(fd_devnull, STDIN_FILENO) == -1) {
            rv = errno;
            PRINT_AND_LOG(("Cannot dup(stdin): %s", strerror(rv)));
            goto ERROR;
        }
        close(fd_devnull);

        /* handle redirection of stdout and stderr to the log */
        if (sklogRedirectStandardStreams(errbuf, sizeof(errbuf))) {
            PRINT_AND_LOG(("%s", errbuf));
            goto ERROR;
        }
    }

    /* Send all error messages to the log */
    skAppSetFuncPrintErr(&WARNINGMSG_v);
    skAppSetFuncPrintSyserror(&WARNINGMSG_v);
    skAppSetFuncPrintFatalErr(&CRITMSG);

    /* Success! */
    if (skdaemon->no_daemon) {
        return 1;
    } else {
        return 0;
    }

  ERROR:
    skdaemonTeardown();
    return -1;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
