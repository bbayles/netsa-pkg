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
**  log.c
**
**  Library to support file-based logging.  Cobbled together based on
**  the report.c code written by M. Duggan.
**
**  Suresh Konda
**  4/23/2003
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sklog.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/sklog.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>
#include <syslog.h>
#include <sys/utsname.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* size of buffer to use when using a syslog facility that does not
 * provide vsyslog() */
#define MSGBUF_SIZE  (4 * PATH_MAX)

/* size of our hostname field; not all systems seem to define
 * HOST_NAME_MAX, so we'll use 255+1 from POSIX. */
#define SKLOG_HOST_NAME_MAX 256

/* size of date buffer */
#define SKLOG_DATE_BUFSIZ 32

/* hour at which to rotate the logs */
#define SKLOG_ROTATE_HOUR 0

/* when using log rotation, the suffix to add to file names */
#define SKLOG_SUFFIX ".log"

/* default log level */
#define SKLOG_DEFAULT_LEVEL    LOG_INFO

/* default syslog facility */
#define SKLOG_SYSFACILITY  LOG_USER

/* default syslog options */
#define SKLOG_SYSOPTIONS   LOG_PID

/* number of command-line/config-file options; must agree with
 * logOptions[] and other logOptions* constants. */
#define NUM_OPTIONS        7

/* invoke the proper logging function if the log has been setup and
 * the log is open */
#define SKLOG_CALL_LOGGER(pri, fmt, args)                               \
    if ( !(logctx && logctx->l_open && logctx->l_func)) { /*no-op*/ }   \
    else { logctx->l_func((pri), (fmt), (args)); }

/* a wrapper around SKLOG_CALL_LOGGER() that sets up and tears down
 * the va_list. */
#define SKLOG_VARARG_CALL_LOGGER(pri, fmt)      \
    {                                           \
        va_list _args;                          \
        va_start(_args, fmt);                   \
        SKLOG_CALL_LOGGER((pri), (fmt), _args); \
        va_end(_args);                          \
    }

/* return non-zero if messages at level 'pri' are being logged */
#define SKLOG_INCLUDES_PRI(pri)                 \
    logctx->l_priority & LOG_MASK(pri)

/* invoke the lock and unlock functions if they are defined */
#define SKLOG_LOCK()                                    \
    if ( !logctx->l_lock_fn) { /*no-op*/ }              \
    else { logctx->l_lock_fn(logctx->l_lock_data); }
#define SKLOG_UNLOCK()                                  \
    if ( !logctx->l_unlock_fn) { /*no-op*/ }            \
    else { logctx->l_unlock_fn(logctx->l_lock_data); }



/* possible logging destinations */
typedef enum {
    /* no destination has been set */
    SKLOG_DEST_NOT_SET = 0,
    /* no logs will be written */
    SKLOG_DEST_NONE,
    /* write to a single log file */
    SKLOG_DEST_PATH,
    /* for legacy support, write to multiple files in a
     * directory---support rotation and compression */
    SKLOG_DEST_DIRECTORY,
    /* write to stdout; same as DEST_PATH with FILE* of stdout */
    SKLOG_DEST_STDOUT,
    /* write to stderr; same as DEST_PATH with FILE* of stderr */
    SKLOG_DEST_STDERR,
    /* write using syslog() */
    SKLOG_DEST_SYSLOG,
    /* write to syslog() and to stderr.  Adds LOG_PERROR to syslog */
    SKLOG_DEST_BOTH
} sklog_dest_t;


/* internal log function */
typedef void (*sklog_fn_t)(int priority, const char *fmt, va_list args);

/* structure to support logging with syslog(3) */
typedef struct sklog_system_st {
    int             options;
    int             facility;
} sklog_system_t;

/* structure needed to hold everything to support logging outside of
 * syslog */
typedef struct sklog_simple_st {
    /* function to call to prepend the time/machine stamp to the message */
    sklog_stamp_fn_t    stamp_fn;
    char                machine_name[SKLOG_HOST_NAME_MAX];
    char                path[2 * (PATH_MAX + SKLOG_DATE_BUFSIZ)];
    const char         *app_name;
    FILE               *fp;
} sklog_simple_t;

/* structure used in conjuction with sklog_simple_t when log rotation
 * is desired */
typedef struct sklog_rotated_st {
    /* time of next scheduled log rotation */
    time_t          rolltime;
    /* user command to run on the closed log file; if NULL, compress
     * the file using SK_LOG_COMPRESSOR */
    const char     *post_rotate;
    /* the directory in which to write all log files */
    char            dir[PATH_MAX];
    /* basename of the log files; the date and SKLOG_SUFFIX will be
     * appended. */
    char            basename[PATH_MAX];
} sklog_rotated_t;

/* the actual logging context */
typedef struct sklog_context_st {
    /* holds the argument that the user provided to each option.
     * Index is a value from logOptionsEnum */
    const char     *l_opt_values[NUM_OPTIONS];
    /* holds all the syslog-specific info */
    sklog_system_t  l_sys;
    /* holds the info when logging to a single file */
    sklog_simple_t  l_sim;
    /* holds info required in addition to l_sim when using log rotatation */
    sklog_rotated_t l_rot;
    /* function to call to write a message to the log; varies
     * depending on type of log being used */
    sklog_fn_t      l_func;
    /* functions to call to lock and unlock the log. */
    sklog_lock_fn_t l_lock_fn;
    sklog_lock_fn_t l_unlock_fn;
    sklog_lock_fn_t l_trylock_fn;
    /* data passed to the l_lock_fn() and l_unlock_fn(). */
    void           *l_lock_data;
    /* the command line invocation of the application */
    char           *l_cmd;
    /* which levels of messages to log */
    int             l_priority;
    /* what features users requested in sklogSetup() */
    int             l_features;
    /* whether the log is open */
    unsigned        l_open :1;
    /* whether stdout/stderr go to the log */
    unsigned        l_dup_stdout :1;
    /* which log destination is being used */
    sklog_dest_t    l_dest;
} sklog_context_t;


/* LOCAL VARIABLE DEFINITIONS */

/* we have a static log structure, and a static pointer that we will
 * point at it once the logger has been initialized. */
static sklog_context_t logger;
static sklog_context_t *logctx = NULL;

/* available destinations */
static const sk_stringmap_entry_t log_dest[] = {
    {"none",    SKLOG_DEST_NONE,    NULL, NULL},
    {"stdout",  SKLOG_DEST_STDOUT,  NULL, NULL},
    {"stderr",  SKLOG_DEST_STDERR,  NULL, NULL},
    {"syslog",  SKLOG_DEST_SYSLOG,  NULL, NULL},
#ifdef LOG_PERROR
    {"both",    SKLOG_DEST_BOTH,    NULL, NULL},
#endif
    SK_STRINGMAP_SENTINEL
};

/* available levels */
static const sk_stringmap_entry_t log_level[] = {
    {"emerg",   LOG_EMERG,      NULL, NULL},
    {"alert",   LOG_ALERT,      NULL, NULL},
    {"crit",    LOG_CRIT,       NULL, NULL},
    {"err",     LOG_ERR,        NULL, NULL},
    {"warning", LOG_WARNING,    NULL, NULL},
    {"notice",  LOG_NOTICE,     NULL, NULL},
    {"info",    LOG_INFO,       NULL, NULL},
    {"debug",   LOG_DEBUG,      NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* available facilities */
static const sk_stringmap_entry_t log_facility[] = {
    {"user",    LOG_USER,   NULL, NULL},
    {"local0",  LOG_LOCAL0, NULL, NULL},
    {"local1",  LOG_LOCAL1, NULL, NULL},
    {"local2",  LOG_LOCAL2, NULL, NULL},
    {"local3",  LOG_LOCAL3, NULL, NULL},
    {"local4",  LOG_LOCAL4, NULL, NULL},
    {"local5",  LOG_LOCAL5, NULL, NULL},
    {"local6",  LOG_LOCAL6, NULL, NULL},
    {"local7",  LOG_LOCAL7, NULL, NULL},
    {"daemon",  LOG_DAEMON, NULL, NULL},
    SK_STRINGMAP_SENTINEL
};


/* OPTIONS SETUP */

/*
 *    Identifiers for each option.
 */
typedef enum {
    OPT_LOG_DIRECTORY,
    OPT_LOG_BASENAME,
    OPT_LOG_POST_ROTATE,
    OPT_LOG_PATHNAME,
    OPT_LOG_DESTINATION,
    OPT_LOG_LEVEL,
    OPT_LOG_SYSFACILITY
} logOptionsEnum;

/*
 *    Whether the option is used/required by the file-based (legacy)
 *    logging or syslog logging.  Order must be kept in sync with
 *    logOptionsEnum.
 */
static const int logOptionsIsUsed[] = {
    SKLOG_FEATURE_LEGACY,
    SKLOG_FEATURE_LEGACY,
    SKLOG_FEATURE_LEGACY,
    SKLOG_FEATURE_LEGACY,
    SKLOG_FEATURE_SYSLOG,
    SKLOG_FEATURE_SYSLOG | SKLOG_FEATURE_LEGACY,
    SKLOG_FEATURE_SYSLOG
};

/*
 *    Array of options for command-line switches.  Must keep in sync
 *    with logOptionsEnum and logOptionsIsUsed above.
 */
static struct option logOptions[] = {
    {"log-directory",   REQUIRED_ARG, 0, OPT_LOG_DIRECTORY},
    {"log-basename",    REQUIRED_ARG, 0, OPT_LOG_BASENAME},
    {"log-post-rotate", REQUIRED_ARG, 0, OPT_LOG_POST_ROTATE},
    {"log-pathname",    REQUIRED_ARG, 0, OPT_LOG_PATHNAME},
    {"log-destination", REQUIRED_ARG, 0, OPT_LOG_DESTINATION},
    {"log-level",       REQUIRED_ARG, 0, OPT_LOG_LEVEL},
    {"log-sysfacility", REQUIRED_ARG, 0, OPT_LOG_SYSFACILITY},
    {0,0,0,0}           /* sentinel entry */
};



/* LOCAL FUNCTION PROTOTYPES */

static void logCompress(char *file);
static size_t logMakeStamp(char *buf, size_t buflen);
static int logOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void logRotatedLog(int priority, const char *fmt, va_list args);
static int logRotatedOpen(void);
static void logSimpleClose(void);
static void logSimpleLog(int priority, const char *fmt, va_list args);
static int logSimpleOpen(void);
static int logStringifyCommand(int argc, char * const *argv);
static void logSimpleVPrintf(int priority, const char *fmt, va_list args);
static void logVSyslog(int priority, const char *fmt, va_list args);
static void logWriteCommandLine(void);


/* FUNCTION DEFINITIONS */

/*
 *    Only compile these functions when they have not been defined as
 *    macros.
 */
#if !defined(EMERGMSG)
int
EMERGMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_EMERG, fmt);
    return 0;
}
#endif


#if !defined(ALERTMSG)
int
ALERTMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_ALERT, fmt);
    return 0;
}
#endif


#if !defined(CRITMSG)
int
CRITMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_CRIT, fmt);
    return 0;
}
#endif


#if !defined(ERRMSG)
int
ERRMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_ERR, fmt);
    return 0;
}
#endif


#if !defined(WARNINGMSG)
int
WARNINGMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_WARNING, fmt);
    return 0;
}
#endif


#if !defined(NOTICEMSG)
int
NOTICEMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_NOTICE, fmt);
    return 0;
}
#endif


#if !defined(INFOMSG)
int
INFOMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_INFO, fmt);
    return 0;
}
#endif


#if !defined(DEBUGMSG)
int
DEBUGMSG(
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(LOG_DEBUG, fmt);
    return 0;
}
#endif


/*
 *  logCompress(file);
 *
 *    Run the user's post-rotate command or the SK_LOG_COMPRESSOR
 *    command to compress the log file 'file'.  Will call free() on
 *    the 'file' parameter.
 */
static void
logCompress(
    char               *file)
{
    long pid;

    if (file == NULL) {
        INFOMSG("logCompress passed NULL pointer");
        return;
    }

    if (NULL == logctx->l_rot.post_rotate) {
#ifndef SK_LOG_COMPRESSOR
        free(file);
        return;
#else
        char *command[4];
        command[0] = (char *)SK_LOG_COMPRESSOR;
        command[1] = (char *)"-f";
        command[2] = file;
        command[3] = (char *)NULL;
        pid = skSubcommandExecute(command);
        free(file);
#endif  /* SK_LOG_COMPRESSOR */

    } else if ('\0' == *logctx->l_rot.post_rotate) {
        /* do nothing when post-rotate command is empty string */
        free(file);
        return;

    } else {
        char *expanded_cmd;

        expanded_cmd = skSubcommandStringFill(logctx->l_rot.post_rotate,
                                              "s", file);
        free(file);
        if (NULL == expanded_cmd) {
            WARNINGMSG("Unable to allocate memory to create command string");
            return;
        }
        DEBUGMSG("Running %s: %s",
                 logOptions[OPT_LOG_POST_ROTATE].name,  expanded_cmd);
        pid = skSubcommandExecuteShell(expanded_cmd);
        free(expanded_cmd);
    }

    switch (pid) {
      case -1:
        ERRMSG("Unable to fork to run command: %s", strerror(errno));
        break;
      case -2:
        NOTICEMSG("Error waiting for child: %s", strerror(errno));
        break;
      default:
        assert(pid > 0);
        break;
    }
}


/*
 *  size = logMakeStamp(buf, buflen)
 *
 *    Add a time, machine, application, and PID stamp on the front of
 *    the character array 'buf', whose length is 'buflen'.  Return the
 *    number of characters written to the buffer.
 */
static size_t
logMakeStamp(
    char               *buf,
    size_t              buflen)
{
    time_t t;
    struct tm ts;
    size_t len;

    t = time(NULL);
    localtime_r(&t, &ts);
    /* Format time as "May  4 01:02:03" */
    len = strftime(buf, buflen, "%b %e %H:%M:%S", &ts);
    assert(len < buflen);
    len += snprintf(buf+len, buflen-len, " %s %s[%ld]: ",
                    logctx->l_sim.machine_name,
                    logctx->l_sim.app_name,
                    (long)getpid());
    return len;
}


/*
 *    A simple options handler that stores the string 'opt_arg' in the
 *    array pointed to by cData.
 */
static int
logOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    sklog_context_t *ctx = (sklog_context_t*)cData;

    assert(ctx);
    assert(opt_index < (int)(sizeof(ctx->l_opt_values)/sizeof(char*)));

    ctx->l_opt_values[opt_index] = opt_arg;
    return 0;
}


/*
 *    Register the command-line switches depending on the type of log
 *    feature requested.
 */
static int
logOptionsSetup(
    int                 feature_flags)
{
    static struct option options_used[NUM_OPTIONS+1];
    unsigned int opt_count = 0;
    unsigned int i;

    assert(NUM_OPTIONS == (sizeof(logOptions)/sizeof(struct option) - 1));
    assert(NUM_OPTIONS == (sizeof(logOptionsIsUsed)/sizeof(int)));

    /* loop through the options, copying those that the caller needs
     * into 'options_used'.  'opt_count' is the number of 'struct
     * option' entries we have */
    for (i = 0; logOptions[i].name; ++i) {
        if (feature_flags & logOptionsIsUsed[i]) {
            /* use this option */
            memcpy(&(options_used[opt_count]), &(logOptions[i]),
                   sizeof(struct option));
            ++opt_count;
        }
    }

    /* set sentinel */
    memset(&(options_used[opt_count]), 0, sizeof(struct option));

    /* register the options */
    if (opt_count > 0) {
        if (skOptionsRegister(options_used, &logOptionsHandler,
                              (clientData)logctx))
        {
            return -1;
        }
    }

    return 0;
}


/*
 *  logRotatedLog(priority, fmt, args);
 *
 *    Write a log message to a file that may need to be rotated.
 *
 *    The logctx->l_func is set to this function when log rotation is
 *    enabled.
 *
 *    Lock the mutex for the log.  If the rollover-time for the log
 *    has passed call logRotatedOpen() to open a new log file.  Use
 *    logSimpleVPrintf() to print the message to the log.
 */
static void
logRotatedLog(
    int                 priority,
    const char         *fmt,
    va_list             args)
{
    char msgbuf[MSGBUF_SIZE];
    char timebuf[SKTIMESTAMP_STRLEN];
    uint32_t timeflags = SKTIMESTAMP_NOMSEC|SKTIMESTAMP_UTC|SKTIMESTAMP_ISO;
    FILE *rotated_fp = NULL;
    char *rotated_path = NULL;
    int rv;

    if (logctx && logctx->l_open && SKLOG_INCLUDES_PRI(priority)) {
        SKLOG_LOCK();
        if (logctx->l_rot.rolltime < time(NULL)) {
            /* Must rotate logs.  First, grab current log file. */
            assert(logctx->l_sim.fp);
            rotated_fp = logctx->l_sim.fp;
            rotated_path = strdup(logctx->l_sim.path);
            if (!rotated_path) {
                (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
                fprintf(rotated_fp,
                        "%sLog not rotated--Unable to allocate pathname\n",
                        msgbuf);
                SKLOG_UNLOCK();
                return;
            }

            /* Log a message about rotating the log. */
            (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
            fprintf(rotated_fp, "%sLog rollover\n", msgbuf);

            /* Open the new log file */
            rv = logRotatedOpen();
            if (0 == rv) {
                (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
                fprintf(logctx->l_sim.fp, "%sRotated log file at %s",
                        msgbuf, sktimestamp_r(timebuf, sktimeNow(), timeflags));
            } else {
                /* Could not open new file.  Continue to use existing
                 * log file. */
                (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
                fprintf(rotated_fp,
                        ("%sLog not rotated--"
                         "error opening log new log '%s': %s\n"),
                        msgbuf, logctx->l_sim.path, strerror(rv));
                /* restore the old settings */
                logctx->l_sim.fp = rotated_fp;
                strncpy(logctx->l_sim.path, rotated_path,
                        sizeof(logctx->l_sim.path) - 1);
                logctx->l_sim.path[sizeof(logctx->l_sim.path) - 1] = '\0';
                rotated_fp = NULL;
                free(rotated_path);
                rotated_path = NULL;
            }
        }

        /* Print the original message to the log */
        logSimpleVPrintf(priority, fmt, args);

        SKLOG_UNLOCK();
    }

    /* if we rotated the log; redirect stdout and stderr into the new
     * log file, close the existing log file, and compress it. */
    if (rotated_fp) {
        if (logctx->l_dup_stdout) {
            int fd_log;

            SKLOG_LOCK();
            fd_log = fileno(logctx->l_sim.fp);
            if (dup2(fd_log, STDOUT_FILENO) == -1) {
                (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
                fprintf(logctx->l_sim.fp, "Cannot dup(stdout): %s",
                         strerror(errno));
            }
            if (dup2(fd_log, STDERR_FILENO) == -1) {
                (void)logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
                fprintf(logctx->l_sim.fp, "Cannot dup(stderr): %s",
                         strerror(errno));
            }
            SKLOG_UNLOCK();
        }

        fclose(rotated_fp);
        logCompress(rotated_path);
    }
}


/*
 *  errno = logRotatedOpen();
 *
 *    Open a new log file when the caller has requested log rotation,
 *    and set the time when the next rotation will occur.
 *
 *    This function will overwrite the current log path and log FILE
 *    pointer; this function does not close the current log file.
 *
 *    Returns 0 on success.  On failure, the errno of the system call
 *    that failed is returned.  The rollover time will be advanced
 *    regardless if the function succeeds or fails.
 */
static int
logRotatedOpen(
    void)
{
    char date[SKLOG_DATE_BUFSIZ];
    time_t t;
    struct tm ts;
    int rv;

    /* get current time */
    t = time(NULL);
    localtime_r(&t, &ts);
    strftime(date, sizeof(date), "%Y%m%d", &ts);

    /* compute the roll-over time by setting hour to last second of
     * today, adding a second to get to midnight, then adding the
     * rollover hour.  Do this before we rotate, so that if rotation
     * fails we don't try again until the next rotation time. */
#ifndef SKLOG_TESTING_LOG
    ts.tm_hour = 23;
    ts.tm_min = 59;
    ts.tm_sec = 59;
    logctx->l_rot.rolltime = mktime(&ts) + 1 + (SKLOG_ROTATE_HOUR * 3600);
#else
    /* rotate each minute */
    strftime(date, sizeof(date), "%Y%m%d:%H:%M", &ts);

    if (ts.tm_sec > 55) {
        ++ts.tm_min;
    }
    ts.tm_sec = 0;
    ++ts.tm_min;
    logctx->l_rot.rolltime = mktime(&ts);
#endif /* SKLOG_TESTING_LOG */

    /* fill in the simple path with the new name */
    snprintf(logctx->l_sim.path, sizeof(logctx->l_sim.path), "%s/%s-%s%s",
             logctx->l_rot.dir, logctx->l_rot.basename, date,
             SKLOG_SUFFIX);

    /* if this is the initial open, use logOpenSimple() to set the
     * application and machine names.  otherwise, just fopen() the
     * new location */
    if (logctx->l_sim.fp == NULL) {
        rv = logSimpleOpen();
        if (rv) {
            return rv;
        }
    } else {
        logctx->l_sim.fp = fopen(logctx->l_sim.path, "a");
        if (NULL == logctx->l_sim.fp) {
            return errno;
        }
    }

    return 0;
}


/*
 *  logSimpleClose();
 *
 *    Close the "simple" logger that writes to a file or to stdout/stderr.
 */
static void
logSimpleClose(
    void)
{
    if (logctx->l_sim.fp) {
        SKLOG_LOCK();

        if ((logctx->l_sim.fp != stdout) && (logctx->l_sim.fp != stderr)) {
            fclose(logctx->l_sim.fp);
        }
        logctx->l_sim.fp = NULL;

        SKLOG_UNLOCK();
    }
}


/*
 *  logSimpleLog(priority, fmt, args);
 *
 *    Write a log message to a file that does not get rotated.
 *
 *    The logctx->l_func is set to this function when log messages are
 *    written to a single file, to standard output, or to standard
 *    error.
 *
 *    Lock the mutex for the log and call logSimpleVPrintf() to print
 *    a message to the log.
 */
static void
logSimpleLog(
    int                 priority,
    const char         *fmt,
    va_list             args)
{
    if (logctx && logctx->l_open && SKLOG_INCLUDES_PRI(priority)) {
        SKLOG_LOCK();

        logSimpleVPrintf(priority, fmt, args);

        SKLOG_UNLOCK();
    }
}


/*
 *  errno = logSimpleOpen();
 *
 *    Open a "simple" logger that writes to a file or to stdout or
 *    stderr.  Will also fill the logctx with the names of the
 *    application and machine.  Return 0 on success; on failure,
 *    return the errno of the system call that failed.
 */
static int
logSimpleOpen(
    void)
{
    sklog_simple_t *simplog = &logctx->l_sim;
    struct utsname u;
    char *cp;

    simplog->app_name = skAppName();

    if (NULL == simplog->stamp_fn) {
        simplog->stamp_fn = &logMakeStamp;
    }

    /* set the machine name; use only host part of a FQDN */
    if (uname(&u) == -1) {
        return errno;
    }
    cp = strchr(u.nodename, '.');
    if (cp) {
        *cp = '\0';
    }
    strncpy(simplog->machine_name, u.nodename, sizeof(simplog->machine_name));
    simplog->machine_name[sizeof(simplog->machine_name)-1] = '\0';

    if (0 == strcmp("stdout", simplog->path)) {
        simplog->fp = stdout;
    } else if (0 == strcmp("stderr", simplog->path)) {
        simplog->fp = stderr;
    } else {
        simplog->fp = fopen(simplog->path, "a");
        if (NULL == simplog->fp) {
            return errno;
        }
    }

    return 0;
}


SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
/*
 *  logSimpleVPrintf(priority, fmt, args);
 *
 *    Create a message using the format 'fmt' and variable list 'args'
 *    and write that message with the specified 'priority' to the
 *    current FILE pointer given in the simple-log.  The message will
 *    be prepended by the result of calling the 'stamp_fn' member of
 *    the log.  The caller must lock the mutex of the log before
 *    calling this function.
 */
static void
logSimpleVPrintf(
    int                 priority,
    const char         *fmt,
    va_list             args)
{
    char msgbuf[MSGBUF_SIZE];
    size_t len;

    SK_UNUSED_PARAM(priority);
    assert(LOG_MASK(priority) & logctx->l_priority);

    len = logctx->l_sim.stamp_fn(msgbuf, sizeof(msgbuf));
    vsnprintf(msgbuf+len, (sizeof(msgbuf)-len), fmt, args);
    fprintf(logctx->l_sim.fp, "%s\n", msgbuf);
    fflush(logctx->l_sim.fp);
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP


/*
 *  status = logStringifyCommand(argc, argv);
 *
 *    Create a string holding the comamnd line paramters and store it
 *    on the global context.  Return 0 on success, or errno on
 *    failure.
 */
static int
logStringifyCommand(
    int                 argc,
    char * const       *argv)
{
    size_t cmd_len;
    size_t rem_len;
    char *cp;
    int i;

    /* free an existing string */
    if (logctx->l_cmd) {
        free(logctx->l_cmd);
    }

    /* compute length of command string.  use 3*argc since each arg is
     * surrounded with quotes and has a space after it */
    cmd_len = 1 + 3 * argc;
    for (i = 0; i < argc; ++i) {
        cmd_len += strlen(argv[i]);
    }
    logctx->l_cmd = (char*)malloc(cmd_len * sizeof(char));
    if (!logctx->l_cmd) {
        return errno;
    }

    cp = logctx->l_cmd;
    rem_len = cmd_len;
    *cp++ = '\'';
    --rem_len;
    for (i = 0; i < argc; ++i) {
        if (i > 0) {
            *cp++ = '\'';
            *cp++ = ' ';
            *cp++ = '\'';
            rem_len -= 3;
        }
        strncpy(cp, argv[i], rem_len);
        cp += strlen(argv[i]);
        assert((cp - logctx->l_cmd) < (int)cmd_len);
        rem_len = cmd_len - (cp - logctx->l_cmd);
    }
    *cp++ = '\'';
    *cp = '\0';

    return 0;
}


SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
/*
 *  logVSyslog(priority, fmt, args);
 *
 *    Write a log message to syslog.
 *
 *    The logctx->l_func is set to this function when writing to
 *    syslog and the OS does not provide vsyslog().
 *
 *    Create a message using the format 'fmt' and variable list
 *    'args', then write that message to syslog() with the specified
 *    'priority'.
 */
static void
logVSyslog(
    int                 priority,
    const char         *fmt,
    va_list             args)
{
    char msgbuf[MSGBUF_SIZE];

    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    msgbuf[sizeof(msgbuf)-1] = '\0';
    syslog(priority, "%s", msgbuf);
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP


/*
 *  logWriteCommandLine();
 *
 *    Write the command line string stored on the global context to
 *    the log, free the string, and reset it to NULL.  Assumes the log
 *    is open and the command line string is non NULL.
 */
static void
logWriteCommandLine(
    void)
{
    assert(logctx && logctx->l_open && logctx->l_cmd);
    NOTICEMSG("%s", logctx->l_cmd);
    free(logctx->l_cmd);
    logctx->l_cmd = NULL;
}


/* write the message to the log */
#if !defined(sklog)
void
sklog(
    int                 priority,
    const char         *fmt,
    ...)
{
    SKLOG_VARARG_CALL_LOGGER(priority, fmt);
}
#endif


void
sklogNonBlock(
    int                 priority,
    const char         *fmt,
    ...)
{
    va_list args;
    va_start(args, fmt);

    if (logctx && logctx->l_open && logctx->l_func) {
        switch (logctx->l_dest) {
          case SKLOG_DEST_NOT_SET:
          case SKLOG_DEST_NONE:
            break;

          case SKLOG_DEST_PATH:
          case SKLOG_DEST_STDOUT:
          case SKLOG_DEST_STDERR:
          case SKLOG_DEST_DIRECTORY:
            if (SKLOG_INCLUDES_PRI(priority)) {
                if (logctx->l_trylock_fn) {
                    if (0 != logctx->l_trylock_fn(logctx->l_lock_data)) {
                        /* cannot get lock */
                        break;
                    }
                }
                logSimpleVPrintf(priority, fmt, args);
                if (logctx->l_unlock_fn) {
                    logctx->l_unlock_fn(logctx->l_lock_data);
                }
            }
            break;

          case SKLOG_DEST_BOTH:
          case SKLOG_DEST_SYSLOG:
            logctx->l_func(priority, fmt, args);
            break;
        }
    }

    va_end(args);
}


int
sklogCheckLevel(
    int                 level)
{
    if (logctx) {
        return (SKLOG_INCLUDES_PRI(level) ? 1 : 0);
    }
    return 0;
}


/* close a log if open. */
void
sklogClose(
    void)
{
    if (logctx && logctx->l_open) {
        NOTICEMSG("Stopped logging.");
        logctx->l_open = 0;
        switch (logctx->l_dest) {
          case SKLOG_DEST_NOT_SET:
          case SKLOG_DEST_NONE:
            break;

          case SKLOG_DEST_PATH:
          case SKLOG_DEST_STDOUT:
          case SKLOG_DEST_STDERR:
          case SKLOG_DEST_DIRECTORY:
            logSimpleClose();
            break;

          case SKLOG_DEST_BOTH:
          case SKLOG_DEST_SYSLOG:
            closelog();
            break;
        }
        logctx->l_func = NULL;

        skAppSetFuncPrintFatalErr(NULL);
    }
}


/* create command line string; write it to the log if open */
void
sklogCommandLine(
    int                 argc,
    char * const       *argv)
{
    int rv;

    if ( !logctx) {
        return;
    }

    rv = logStringifyCommand(argc, argv);
    if (rv != 0) {
        return;
    }

    if (logctx->l_open) {
        logWriteCommandLine();
    }

    return;
}


void
sklogDisableRotation(
    void)
{
    if (logctx) {
        SKLOG_LOCK();
        logctx->l_rot.rolltime = (time_t)INT32_MAX;
        SKLOG_UNLOCK();
    }
}


/* get the destination file handle */
FILE *
sklogGetDestination(
    void)
{
    if (logctx) {
        switch (logctx->l_dest) {
          case SKLOG_DEST_DIRECTORY:
          case SKLOG_DEST_STDOUT:
          case SKLOG_DEST_STDERR:
          case SKLOG_DEST_PATH:
            return logctx->l_sim.fp;

          case SKLOG_DEST_BOTH:
            return stderr;

          default:
            return NULL;
        }
    }

    return NULL;
}


/* get the log directory */
char *
sklogGetDirectory(
    char               *buf,
    size_t              bufsize)
{
    if ( !(logctx && logctx->l_rot.dir[0])) {
        return NULL;
    }

    strncpy(buf, logctx->l_rot.dir, bufsize);
    if ('\0' != buf[bufsize-1]) {
        /* buffer too short */
        buf[bufsize-1] = '\0';
        return NULL;
    }

    return buf;
}


/* get the log level */
const char *
sklogGetLevel(
    void)
{
    const sk_stringmap_entry_t *e;

    if (logctx) {
        for (e = log_level; e->name != NULL; ++e) {
            if (LOG_UPTO(e->id) == logctx->l_priority) {
                return e->name;
            }
        }
        skAbort();
    }
    return NULL;
}


int
sklogGetMask(
    void)
{
    if (logctx) {
        return logctx->l_priority;
    }
    return 0;
}


/* open a log that has been Setup() and had its destination set */
int
sklogOpen(
    void)
{
    char timebuf[SKTIMESTAMP_STRLEN];
    uint32_t timeflags = SKTIMESTAMP_NOMSEC|SKTIMESTAMP_UTC|SKTIMESTAMP_ISO;
    int rv;

    if (!logctx) {
        skAppPrintErr("Must setup the log before opening it");
        return -1;
    }

    if (logctx->l_open) {
        /* called multiple times */
        return 0;
    }

    switch (logctx->l_dest) {
      case SKLOG_DEST_NOT_SET:
        skAppPrintErr("Must set log destination prior to opening log");
        return -1;

      case SKLOG_DEST_NONE:
        break;

      case SKLOG_DEST_DIRECTORY:
        rv = logRotatedOpen();
        if (rv) {
            skAppPrintErr("Unable to open log file '%s': %s",
                          logctx->l_sim.path, strerror(rv));
            return -1;
        }
        logctx->l_func = &logRotatedLog;
        break;

      case SKLOG_DEST_STDOUT:
      case SKLOG_DEST_STDERR:
      case SKLOG_DEST_PATH:
        rv = logSimpleOpen();
        if (rv) {
            skAppPrintErr("Unable to open log file '%s': %s",
                          logctx->l_sim.path, strerror(rv));
            return -1;
        }
        logctx->l_func = &logSimpleLog;
        break;

      case SKLOG_DEST_BOTH:
#ifdef LOG_PERROR
        logctx->l_sys.options |= LOG_PERROR;
#endif
        /* FALLTHROUGH */
      case SKLOG_DEST_SYSLOG:
        openlog(skAppName(), logctx->l_sys.options,
                logctx->l_sys.facility);
#ifdef SK_HAVE_VSYSLOG
        logctx->l_func = &vsyslog;
#else
        logctx->l_func = &logVSyslog;
#endif
        break;
    }

    logctx->l_open = 1;

    NOTICEMSG("Started logging at %sZ",
              sktimestamp_r(timebuf, sktimeNow(), timeflags));

    if (logctx->l_cmd) {
        logWriteCommandLine();
    }

    skAppSetFuncPrintFatalErr(CRITMSG);

    return 0;
}


/* print the usage of the options defined by this library */
void
sklogOptionsUsage(
    FILE               *fp)
{
#ifdef SK_LOG_COMPRESSOR
    const char *post_rotate = SK_LOG_COMPRESSOR " -f %s";
#else
    const char *post_rotate = "";
#endif
    int i, j;
    int features = INT32_MAX;

    if (logctx) {
        features = logctx->l_features;
    }

    for (i = 0; logOptions[i].name; ++i) {
        /* skip options that are not part of our feature set */
        if ( !(logOptionsIsUsed[i] & features)) {
            continue;
        }

        fprintf(fp, "--%s %s. ",
                logOptions[i].name, SK_OPTION_HAS_ARG(logOptions[i]));
        switch ((logOptionsEnum)i) {
          case OPT_LOG_DIRECTORY:
            fprintf(fp,
                    ("Write log files to this directory and enable log\n"
                     "\trotatation; must be the complete path to an existing"
                     " directory"));
            break;

          case OPT_LOG_BASENAME:
            fprintf(fp, ("Use this name as the basename for files in the\n"
                         "\t%s. Def. '%s'"),
                    logOptions[OPT_LOG_DIRECTORY].name, skAppName());
            break;

          case OPT_LOG_POST_ROTATE:
            fprintf(fp,
                    ("Run this command on the previous day's log file\n"
                     "\tafter log rotatation."
                     " Each \"%%s\" in the command is replaced by the\n"
                     "\tfile's complete path."
                     " When set to the empty string, no action is\n"
                     "\ttaken. Def. '%s'"),
                    post_rotate);
            break;

          case OPT_LOG_PATHNAME:
            fprintf(fp,
                    ("Write log messages to this single file and disable\n"
                     "\tlog rotation; must be a complete pathname"));
            break;

          case OPT_LOG_DESTINATION:
            fprintf(fp, ("Specify the log destination.  Acceptable values:\n"
                         "\t"));
            for (j = 0; log_dest[j].name; ++j) {
                fprintf(fp, "'%s', ", log_dest[j].name);
            }
            fprintf(fp, "or\n\tcomplete path to a log file");
            break;

          case OPT_LOG_LEVEL:
            fprintf(fp, ("Enable logging of messages of this severity."
                         " Def. "));
            for (j = 0; log_level[j].name; ++j) {
                if (SKLOG_DEFAULT_LEVEL == log_level[j].id) {
                    fprintf(fp, "%s\n", log_level[j].name);
                    break;
                }
            }
            fprintf(fp, "\tChoices: %s", log_level[0].name);
            for (j = 1; log_level[j].name; ++j) {
                fprintf(fp, ", %s", log_level[j].name);
            }
            break;

          case OPT_LOG_SYSFACILITY:
            fprintf(fp, ("Set the facility to use for syslog() messages.\n"
                         "\tDef. "));
            for (j = 0; log_facility[j].name; ++j) {
                if (SKLOG_SYSFACILITY == log_facility[j].id) {
                    fprintf(fp, ("%s (%" PRIu32 ").  "),
                            log_facility[j].name, log_facility[j].id);
                    break;
                }
            }
            fprintf(fp,
                    ("Specify as an integer or one of the following names:\n"
                     "\t%s"),
                    log_facility[0].name);
            for (j = 1; log_facility[j].name; ++j) {
                fprintf(fp, ",%s", log_facility[j].name);
            }
            fprintf(fp, ".\n\tSee syslog(3) and"
                         " /usr/include/sys/syslog.h for integer values");
            break;
        }
        fprintf(fp, "\n");
    }
}


/* verify we got all the options we needed. */
int
sklogOptionsVerify(
    void)
{
    int dest_count = 0;
    int err_count = 0;

    if (!logctx) {
        skAppPrintErr("Must setup the log before verifying");
        return -1;
    }

    /* only one of directory, pathname, or destination may be given,
     * and one must be given */
    if (logctx->l_opt_values[OPT_LOG_DIRECTORY] != NULL) {
        ++dest_count;
    }
    if (logctx->l_opt_values[OPT_LOG_PATHNAME] != NULL) {
        ++dest_count;
    }
    if (logctx->l_opt_values[OPT_LOG_DESTINATION] != NULL) {
        ++dest_count;
    }

    if (dest_count == 0) {
        ++err_count;
        if ((logctx->l_features & (SKLOG_FEATURE_LEGACY|SKLOG_FEATURE_SYSLOG))
            == (SKLOG_FEATURE_LEGACY|SKLOG_FEATURE_SYSLOG))
        {
            skAppPrintErr("One of --%s, --%s, or --%s is required",
                          logOptions[OPT_LOG_DIRECTORY].name,
                          logOptions[OPT_LOG_PATHNAME].name,
                          logOptions[OPT_LOG_DESTINATION].name);
        } else if (logctx->l_features & SKLOG_FEATURE_LEGACY) {
            skAppPrintErr("Either --%s or --%s is required",
                          logOptions[OPT_LOG_DIRECTORY].name,
                          logOptions[OPT_LOG_PATHNAME].name);
        } else if (logctx->l_features & SKLOG_FEATURE_SYSLOG) {
            skAppPrintErr("The --%s switch is required",
                          logOptions[OPT_LOG_DESTINATION].name);
        }
    } else if (dest_count > 1) {
        ++err_count;
        if ((logctx->l_features & (SKLOG_FEATURE_LEGACY|SKLOG_FEATURE_SYSLOG))
            == (SKLOG_FEATURE_LEGACY|SKLOG_FEATURE_SYSLOG))
        {
            skAppPrintErr("Only one of --%s, --%s, or --%s may be specified",
                          logOptions[OPT_LOG_DIRECTORY].name,
                          logOptions[OPT_LOG_PATHNAME].name,
                          logOptions[OPT_LOG_DESTINATION].name);
        } else if (logctx->l_features & SKLOG_FEATURE_LEGACY) {
            skAppPrintErr("Only one of --%s or --%s may be specified",
                          logOptions[OPT_LOG_DIRECTORY].name,
                          logOptions[OPT_LOG_PATHNAME].name);
        } else {
            skAbort();
        }
    }

    if (logctx->l_opt_values[OPT_LOG_BASENAME]
        && !logctx->l_opt_values[OPT_LOG_DIRECTORY])
    {
        ++err_count;
        skAppPrintErr("May only use --%s when --%s is specified",
                      logOptions[OPT_LOG_BASENAME].name,
                      logOptions[OPT_LOG_DIRECTORY].name);
    }
    if (logctx->l_opt_values[OPT_LOG_POST_ROTATE]
        && !logctx->l_opt_values[OPT_LOG_DIRECTORY])
    {
        ++err_count;
        skAppPrintErr("May only use --%s when --%s is specified",
                      logOptions[OPT_LOG_POST_ROTATE].name,
                      logOptions[OPT_LOG_DIRECTORY].name);
    }

    if (logctx->l_opt_values[OPT_LOG_DIRECTORY]) {
        if (sklogSetDirectory(logctx->l_opt_values[OPT_LOG_DIRECTORY],
                              logctx->l_opt_values[OPT_LOG_BASENAME]))
        {
            ++err_count;
        }
        if (logctx->l_opt_values[OPT_LOG_POST_ROTATE]) {
            if (sklogSetPostRotateCommand(
                    logctx->l_opt_values[OPT_LOG_POST_ROTATE]))
            {
                ++err_count;
            }
        }
    }
    if (logctx->l_opt_values[OPT_LOG_PATHNAME]) {
        if (logctx->l_opt_values[OPT_LOG_PATHNAME][0] != '/') {
            ++err_count;
            skAppPrintErr(("Invalid %s '%s': A complete path is required"
                           " and value does not begin with a slash"),
                          logOptions[OPT_LOG_PATHNAME].name,
                          logctx->l_opt_values[OPT_LOG_PATHNAME]);
        } else if (sklogSetDestination(logctx->l_opt_values[OPT_LOG_PATHNAME]))
        {
            ++err_count;
        }
    }
    if (logctx->l_opt_values[OPT_LOG_DESTINATION]) {
        if (sklogSetDestination(logctx->l_opt_values[OPT_LOG_DESTINATION])) {
            ++err_count;
        }
    }

    if (logctx->l_opt_values[OPT_LOG_LEVEL]) {
        if (sklogSetLevel(logctx->l_opt_values[OPT_LOG_LEVEL])) {
            ++err_count;
        }
    }

    if (logctx->l_opt_values[OPT_LOG_SYSFACILITY]) {
        if (sklogSetFacilityByName(logctx->l_opt_values[OPT_LOG_SYSFACILITY])){
            ++err_count;
        }
    }

    if (err_count) {
        return -1;
    }
    return 0;
}


/* redirect stdout and stderr to the log or to /dev/null */
int
sklogRedirectStandardStreams(
    char               *buf,
    size_t              bufsize)
{
    int fd_log = -1;
    int rv = 0;

    if (!logctx) {
        skAppPrintErr("Must setup the log before redirecting stdout");
        return -1;
    }
    if (!logctx->l_open) {
        if (buf) {
            snprintf(buf, bufsize,
                     "May not redirect stdout prior to opening log");
        }
        return -1;
    }

    SKLOG_LOCK();
    switch (logctx->l_dest) {
      case SKLOG_DEST_NOT_SET:
        SKLOG_UNLOCK();
        skAbortBadCase(logctx->l_dest);

      case SKLOG_DEST_STDOUT:
      case SKLOG_DEST_STDERR:
      case SKLOG_DEST_BOTH:
        /* Do not redirect anything */
        goto END;

      case SKLOG_DEST_NONE:
      case SKLOG_DEST_SYSLOG:
        /* redirect stdout and stderr to /dev/null */
        fd_log = open("/dev/null", O_RDWR);
        if (-1 == fd_log) {
            if (buf) {
                snprintf(buf, bufsize, "Cannot open /dev/null: %s",
                         strerror(errno));
            }
            rv = -1;
            goto END;
        }
        break;

      case SKLOG_DEST_PATH:
      case SKLOG_DEST_DIRECTORY:
        /* redirect stdout and stderr to the log */
        logctx->l_dup_stdout = 1;
        fd_log = fileno(logctx->l_sim.fp);
        break;
    }

    if (-1 != fd_log) {
        if (dup2(fd_log, STDOUT_FILENO) == -1) {
            if (buf) {
                snprintf(buf, bufsize, "Cannot dup(stdout): %s",
                         strerror(errno));
            }
            rv = -1;
            goto END;
        }
        if (dup2(fd_log, STDERR_FILENO) == -1) {
            if (buf) {
                snprintf(buf, bufsize, "Cannot dup(stderr): %s",
                         strerror(errno));
            }
            rv = -1;
            goto END;
        }
    }

  END:
    SKLOG_UNLOCK();
    return rv;
}

/* set the destination */
int
sklogSetDestination(
    const char         *destination)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *map_entry;
    int rv = -1;

    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the destination");
        return -1;
    }
    if (logctx->l_open) {
        skAppPrintErr("Cannot set destination after opening log");
        return -1;
    }

    if (destination[0] == '/') {
        /* treat it as a pathname */
        logctx->l_dest = SKLOG_DEST_PATH;
        if (skDirExists(destination)) {
            skAppPrintErr(("Invalid %s '%s':"
                           " Value must name a file, not a directory"),
                          logOptions[OPT_LOG_DESTINATION].name, destination);
            return -1;
        }
        if (strlen(destination) >= sizeof(logctx->l_sim.path)) {
            skAppPrintErr("Invalid %s: The path is too long",
                          logOptions[OPT_LOG_DESTINATION].name);
            return -1;
        }
        strncpy(logctx->l_sim.path, destination, sizeof(logctx->l_sim.path));
        return 0;
    }
    /* else, see which of the possible destinations it matches */

    /* create a stringmap of the available entries */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, log_dest) != SKSTRINGMAP_OK) {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, destination, &map_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        logctx->l_dest = (sklog_dest_t)map_entry->id;
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s '%s': Value is ambiguous",
                      logOptions[OPT_LOG_DESTINATION].name, destination);
        goto END;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr(("Invalid %s '%s': Value is not a complete path and"
                       " does not match known keys"),
                      logOptions[OPT_LOG_DESTINATION].name, destination);
        goto END;

      default:
        skAppPrintErr(("Invalid %s '%s':"
                       "Unexpected return value from string-map parser (%d)"),
                      logOptions[OPT_LOG_DESTINATION].name, destination,
                      rv_map);
        goto END;
    }

    if (logctx->l_dest == SKLOG_DEST_STDOUT) {
        strncpy(logctx->l_sim.path, "stdout", sizeof(logctx->l_sim.path));
    } else if (logctx->l_dest == SKLOG_DEST_STDERR) {
        strncpy(logctx->l_sim.path, "stderr", sizeof(logctx->l_sim.path));
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/* set the logger to use a directory with log rotation */
int
sklogSetDirectory(
    const char         *dir_name,
    const char         *base_name)
{
    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the directory");
        return -1;
    }
    if (logctx->l_open) {
        skAppPrintErr("Cannot set directory after opening log.");
        return -1;
    }

    /* verify basename, or use skAppName if basename was not given */
    if (base_name == NULL || base_name[0] == '\0') {
        base_name = skAppName();
    } else if (strchr(base_name, '/')) {
        skAppPrintErr("Invalid %s '%s': Value may not contain '/'",
                      logOptions[OPT_LOG_BASENAME].name, base_name);
        return -1;
    }

    /* verify directory name */
    if (skOptionsCheckDirectory(dir_name, logOptions[OPT_LOG_DIRECTORY].name)){
        return -1;
    }

    /* copy directory name */
    if (strlen(dir_name) >= sizeof(logctx->l_rot.dir)) {
        skAppPrintErr("Invalid %s '%s': Value is too long",
                      logOptions[OPT_LOG_DIRECTORY].name, dir_name);
        return -1;
    }
    strncpy(logctx->l_rot.dir, dir_name, sizeof(logctx->l_rot.dir));

    /* copy base name */
    if (strlen(base_name) >= sizeof(logctx->l_rot.basename)) {
        skAppPrintErr("Invalid %s '%s': Value is too long",
                      logOptions[OPT_LOG_BASENAME].name, base_name);
        return -1;
    }
    strncpy(logctx->l_rot.basename, base_name, sizeof(logctx->l_rot.basename));

    logctx->l_dest = SKLOG_DEST_DIRECTORY;
    return 0;
}


/* set the facility for syslog() */
int
sklogSetFacility(
    int                 facility)
{
    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the facility");
        return -1;
    }
    if (logctx->l_open) {
        skAppPrintErr("Cannot set facility after opening log.");
        return -1;
    }

    if (logctx->l_dest == SKLOG_DEST_BOTH
        || logctx->l_dest == SKLOG_DEST_SYSLOG)
    {
        logctx->l_sys.facility = facility;
        return 0;
    }

    skAppPrintErr("Cannot set facility unless %s is 'syslog' or 'both'",
                  logOptions[OPT_LOG_DESTINATION].name);
    return -1;
}


/* set the facility for syslog() by name; can be a name or an integer */
int
sklogSetFacilityByName(
    const char         *name_or_number)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *found_entry;
    uint32_t facility;
    int rv;

    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the facility");
        return -1;
    }

    /* try to parse the facility as a number */
    rv = skStringParseUint32(&facility, name_or_number, 0, INT32_MAX);
    if (rv == 0) {
        /* was parsable as a number */
        return sklogSetFacility(facility);
    }

    /* a return value of SKUTILS_ERR_BAD_CHAR means the value was
     * unparsable--we will try to treat it as a name.  any other value
     * indicates an error */
    if (rv != SKUTILS_ERR_BAD_CHAR) {
        skAppPrintErr("Invalid %s '%s': %s",
                      logOptions[OPT_LOG_SYSFACILITY].name, name_or_number,
                      skStringParseStrerror(rv));
        return -1;
    }

    /* reset rv */
    rv = -1;

    /* create a stringmap of the available levels */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, log_facility) != SKSTRINGMAP_OK) {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, name_or_number, &found_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        rv = sklogSetFacility(found_entry->id);
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s '%s': Value is ambiguous",
                      logOptions[OPT_LOG_SYSFACILITY].name, name_or_number);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s '%s': Value is not recognized",
                      logOptions[OPT_LOG_SYSFACILITY].name, name_or_number);
        break;

      default:
        skAppPrintErr(("Invalid %s '%s':"
                       " Unexpected return value from string-map parser (%d)"),
                      logOptions[OPT_LOG_SYSFACILITY].name, name_or_number,
                      rv_map);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/* set logging level to all levels through 'level', a string. */
int
sklogSetLevel(
    const char         *level)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *found_entry;
    int rv = -1;

    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the level");
        return -1;
    }

    /* create a stringmap of the available levels */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, log_level) != SKSTRINGMAP_OK) {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, level, &found_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        sklogSetMask(LOG_UPTO(found_entry->id));
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s '%s': Value is ambiguous",
                      logOptions[OPT_LOG_LEVEL].name, level);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s '%s': Value is not recognized",
                      logOptions[OPT_LOG_LEVEL].name, level);
        break;

      default:
        skAppPrintErr(("Invalid %s '%s':"
                       " Unexpected return value from string-map parser (%d)"),
                      logOptions[OPT_LOG_LEVEL].name, level, rv_map);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/* set lock and unlock functions */
int
sklogSetLocking(
    sklog_lock_fn_t     locker,
    sklog_lock_fn_t     unlocker,
    sklog_lock_fn_t     try_locker,
    void               *data)
{
    if (!logctx) {
        skAppPrintErr("Must setup the log before setting lock functions");
        return -1;
    }
    logctx->l_lock_fn = locker;
    logctx->l_unlock_fn = unlocker;
    logctx->l_trylock_fn = try_locker;
    logctx->l_lock_data = data;
    return 0;
}


/* set the mask for the logger */
int
sklogSetMask(
    int                 new_mask)
{
    int old_mask;

    if (!logctx) {
        skAppPrintErr("Must setup the log before setting the mask");
        return -1;
    }
    old_mask = logctx->l_priority;
    logctx->l_priority = new_mask;

    switch (logctx->l_dest) {
      case SKLOG_DEST_NOT_SET:
      case SKLOG_DEST_NONE:
      case SKLOG_DEST_PATH:
      case SKLOG_DEST_DIRECTORY:
      case SKLOG_DEST_STDOUT:
      case SKLOG_DEST_STDERR:
        break;

      case SKLOG_DEST_BOTH:
      case SKLOG_DEST_SYSLOG:
        old_mask = setlogmask(new_mask);
        break;
    }

    return old_mask;
}


int
sklogSetPostRotateCommand(
    const char         *command)
{
    size_t rv;

    if (!logctx) {
        skAppPrintErr("Must setup the log before setting post-rotate command");
        return -1;
    }
    if (logctx->l_dest != SKLOG_DEST_DIRECTORY) {
        skAppPrintErr("Post-rotate command is ignored unless"
                      " log-rotation is used");
        return 0;
    }

    if (NULL == command) {
        if (logctx->l_rot.post_rotate) {
            free((char*)logctx->l_rot.post_rotate);
            logctx->l_rot.post_rotate = NULL;
        }
        return 0;
    }

    rv = skSubcommandStringCheck(command, "s");
    if (rv) {
        switch (command[rv]) {
          case '\0':
            skAppPrintErr(("Invalid %s command '%s':"
                           " '%%' appears at end of string"),
                          logOptions[OPT_LOG_POST_ROTATE].name, command);
            return -1;
          default:
            skAppPrintErr(("Invalid %s command '%s':"
                           " Unknown conversion '%%%c'"),
                          logOptions[OPT_LOG_POST_ROTATE].name, command,
                          command[rv]);
            return -1;
        }
    }

    logctx->l_rot.post_rotate = strdup(command);
    if (NULL == logctx->l_rot.post_rotate) {
        skAppPrintErr("Unable to allocate space for %s command",
                      logOptions[OPT_LOG_POST_ROTATE].name);
        return -1;
    }

    return 0;
}


/* set the function to make that timestamp.  will be used instead of
 * logMakeStamp(). */
int
sklogSetStampFunction(
    sklog_stamp_fn_t    makestamp)
{
    if (!logctx) {
        skAppPrintErr("Must setup the log before setting lock functions");
        return -1;
    }
    if (logctx->l_dest == SKLOG_DEST_BOTH
        || logctx->l_dest == SKLOG_DEST_SYSLOG)
    {
        skAppPrintErr("Stamp function is ignored when syslog() is used");
        return 0;
    }
    if (makestamp == NULL) {
        skAppPrintErr("Stamp function cannot be NULL");
        return -1;
    }
    logctx->l_sim.stamp_fn = makestamp;
    return 0;
}


/* initialize all variables for logging */
int
sklogSetup(
    int                 feature_flags)
{
    if (logctx) {
        skAppPrintErr("Ignoring multiple calls to sklogSetup()");
        return 0;
    }

    /* initialize the logging context */
    logctx = &logger;
    memset(logctx, 0, sizeof(sklog_context_t));
    logctx->l_dest = SKLOG_DEST_NOT_SET;
    logctx->l_priority = LOG_UPTO(SKLOG_DEFAULT_LEVEL);
    logctx->l_sys.options = SKLOG_SYSOPTIONS;
    logctx->l_sys.facility = SKLOG_SYSFACILITY;
    logctx->l_features = feature_flags;

    if (logOptionsSetup(feature_flags)) {
        return -1;
    }

    return 0;
}


/* close the logger */
void
sklogTeardown(
    void)
{
    if (logctx == NULL) {
        /* either never set up or already shut down */
        return;
    }

    sklogClose();

    if (logctx->l_cmd) {
        free(logctx->l_cmd);
    }
    if (logctx->l_rot.post_rotate) {
        free((char*)logctx->l_rot.post_rotate);
    }
    memset(logctx, 0, sizeof(sklog_context_t));
    logctx = NULL;
}


int
EMERGMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_EMERG, fmt, args);
    return 0;
}


int
ALERTMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_ALERT, fmt, args);
    return 0;
}


int
CRITMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_CRIT, fmt, args);
    return 0;
}


int
ERRMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_ERR, fmt, args);
    return 0;
}


int
WARNINGMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_WARNING, fmt, args);
    return 0;
}


int
NOTICEMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_NOTICE, fmt, args);
    return 0;
}


int
INFOMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_INFO, fmt, args);
    return 0;
}


int
DEBUGMSG_v(
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(LOG_DEBUG, fmt, args);
    return 0;
}


/* write the log message */
void
sklogv(
    int                 priority,
    const char         *fmt,
    va_list             args)
{
    SKLOG_CALL_LOGGER(priority, fmt, args);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
