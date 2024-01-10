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
**  sklog.h
**
**    Function prototypes for writing messages to log files.
**
*/
#ifndef _LOG_H
#define _LOG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_LOG_H, "$SiLK: sklog.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <syslog.h>

/**
 *  @file
 *
 *    Functions to write messages to log files or to the system log
 *    (syslog).
 *
 *    This file is part of libsilk.
 */


/*
 *    These wrapper functions invoke syslog() or fprintf().  The
 *    syslog level is implied by the function's name (see syslog(3))
 *    and are listed here from most severe to least.  This functions
 *    have the same caveats as sklog().
 *
 *    These functions always return 0; they return a value to be
 *    consistent with printf and sk_msg_fn_t.
 */
#ifdef TEST_PRINTF_FORMATS
#  define EMERGMSG printf
#  define ALERTMSG printf
#  define CRITMSG printf
#  define ERRMSG printf
#  define WARNINGMSG printf
#  define NOTICEMSG printf
#  define INFOMSG printf
#  define DEBUGMSG printf
#else
int
EMERGMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
ALERTMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
CRITMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
ERRMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
WARNINGMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
NOTICEMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
INFOMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
int
DEBUGMSG(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif


/*
 *   Available features; pass to sklogSetup().
 */
/** Enable options for use of syslog() */
#define SKLOG_FEATURE_SYSLOG  1
/** Enable options that mimic the legacy logging */
#define SKLOG_FEATURE_LEGACY  2


/*
 *    TRACEMSG() messages should use DEBUGMSG.  See sktracemsg.h.
 */
#ifndef TRACEMSG_FUNCTION
#  define TRACEMSG_FUNCTION DEBUGMSG
#endif


/**
 *    Signature of function callbacked that will be invoked to lock
 *    and unlock the log.  These functions are set by
 *    sklogSetLocking().
 */
typedef int (*sklog_lock_fn_t)(
    void       *caller_data);


/**
 *    Signature of function that will produce a time/machine stamp on
 *    each log message.  Function should write the stamp into the
 *    beginning of the buffer and return the strlen() of the text it
 *    added.  The text should probably include a trailing ": ".
 */
typedef size_t (*sklog_stamp_fn_t)(
    char        *buffer,
    size_t       buffer_size);


/**
 *    Writes a message with the specified 'priority' to the log.
 *    Requires that sklogSetup() has created the log, that
 *    sklogSetDestination() has been called, and that sklogOpen() has
 *    opened the log.  Writing to an unopend log produces no error and
 *    no message.
 */
#ifdef TEST_PRINTF_FORMATS
#define sklog(priority, ...) printf(__VA_ARGS__)
#else
void
sklog(
    int                 priority,
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);
#endif


/**
 *    Return a non-zero value if the current logging level includes
 *    'level', where 'level' is one of the syslog macros LOG_EMERG,
 *    LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
 *    or LOG_DEBUG.
 *
 *    Return 0 if messages at 'level' are not being written to the log.
 *
 *    Since SiLK 3.17.0.
 */
int
sklogCheckLevel(
    int                 level);


/**
 *    Closes the log.  The log can be re-opened by calling
 *    sklogOpen().
 */
void
sklogClose(
    void);


/**
 *    Creates an internal buffer holding the command line used to
 *    invoke the application from the specified 'argc' and 'argv' and
 *    writes it to the log.  If the log is not yet opened, the buffer
 *    will be written once sklogOpen() is called.
 */
void
sklogCommandLine(
    int                 argc,
    char * const       *argv);


/**
 *    Disable log rotation once the log has been opened.  Once this
 *    function has been called, there is no way to re-enable log
 *    rotation.
 *
 *    This function should be called in the child process after a call
 *    to fork() to avoid having multiple processes attempt to rotate
 *    the log file.
 */
void
sklogDisableRotation(
    void);


/**
 *    This function is only available when using libsilk-thrd.
 *
 *    Configure the log for use in a multithreaded environemnt.  This
 *    function creates a mutex and calls the sklogSetLocking()
 *    function with the necessary function pointers.  This function
 *    returns the value returned by sklogSetLocking(); i.e., it
 *    returns 0 unless sklogSetup() has not yet been called.
 *
 *    If the multithreaded program calls fork(), the child process
 *    should first call sklogSetLocking() using NULL for all
 *    parameters.  This ensures that the (single-threaded) child
 *    process ignores the log-file lock that the parent may have held
 *    when fork() was called.  Next the child should call
 *    sklogDisableRotation() to ensure it does not attempt to rotate
 *    the log-file.
 */
int
sklogEnableThreadedLogging(
    void);


/**
 *    Return the file handle to the log file or rotated log file.
 *    Return NULL if syslog or no logging is being used, or if the log
 *    has not yet been opened.
 */
FILE *
sklogGetDestination(
    void);


/**
 *    Fill the character array 'buf' with the name of the logging
 *    directory as set by sklogSetDirectory() and return a pointer to
 *    'buf'.  Returns NULL if a log-directory has not been specified,
 *    or if the logging directory is longer than 'bufsize' characters.
 */
char *
sklogGetDirectory(
    char               *buf,
    size_t              bufsize);


/**
 *    Return the current level for log messages.  Return NULL before
 *    sklogSetup() is called and after sklogTeardown() is called.
 *
 *    Since SiLK 3.11.0.
 */
const char *
sklogGetLevel(
    void);


/**
 *    Return the current mask for log messages.  Return 0 before
 *    sklogSetup() is called and after sklogTeardown() is called.
 *
 *    Since SiLK 3.11.0.
 */
int
sklogGetMask(
    void);


/**
 *    Similar to sklog(), but returns without logging the message if
 *    the log is already locked.
 */
void
sklogNonBlock(
    int                 priority,
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);


/**
 *    Opens the log.  This function requires that sklogSetup() and
 *    sklogSetDestination() be called beforehand.  Return 0 on
 *    success, or -1 if the log cannot be opened.
 */
int
sklogOpen(
    void);


/**
 *    Verifies that all the required options have been specified and
 *    that valid values were given.  When an invalid option is found,
 *    an error message will be printed.  Returns -1 if there is an
 *    issue with an option; returns 0 on success.
 */
int
sklogOptionsVerify(
    void);


/**
 *    Print the usage of the options defined by this library to the
 *    specified file handle.
 */
void
sklogOptionsUsage(
    FILE               *fp);


/**
 *    Redirect the standard output and standard error as follows:
 *
 *    If log messages are going to a local file, redirect stdout and
 *    stderr to write to that file.
 *
 *    If log messages are going to either stdout or stderr, do not
 *    redirect anything.  This also includes the case where messages
 *    are going to both syslog and stderr.
 *
 *    If logging is disabled or if the messages are going to syslog
 *    exclusively, redirect stdout and stderr to /dev/null.
 *
 *    This function may only be called after the log has been opened.
 *
 *    Return 0 on success.  On failure, write an error message into
 *    'buf' (when provided) and return -1.
 */
int
sklogRedirectStandardStreams(
    char               *buf,
    size_t              bufsize);


/**
 *    Set the destination for the log messages.  This should be the
 *    full path to the log file, or the strings 'none' for no logging,
 *    'stdout' to log to the standard output, 'stderr' to log to the
 *    standard error, 'syslog' to log with syslog(3), or 'both' to log
 *    to both syslog and the standard error.  Note that 'both' is only
 *    available on systems where LOG_PERROR is defiend.
 *
 *    This function must be called after sklogSetup() and prior to
 *    sklogOpen()ing the log.
 *
 *    Returns 0 on success, or -1 on error (not a full path).
 *
 *    See also sklogSetDirectory().
 */
int
sklogSetDestination(
    const char         *destination);


/**
 *    This function is provided for backward compatibility.  We
 *    recommend the use of syslog(3) instead.
 *
 *    Set the destination for log messages to multiple files in the
 *    directory 'dir_name', using 'base_name' as part of the basename
 *    for the files, and the current date as the remainder of the
 *    name.  The format of the files will be
 *
 *        <dir_name>/<base_name>-YYYYMMDD.log
 *
 *    The files will be rotated when they receive the first message
 *    after midnight local time.  The previous day's log file will be
 *    compressed.
 *
 *    If 'base_name' is NULL, the string returned by skAppName() is
 *    used.
 *
 *    This function must be called after sklogSetup() and prior to
 *    sklogOpen()ing the log.
 *
 *    Return 0 on success, or -1 if 'dir_name' does not exist,
 *    'base_name' contains a '/', or the combined path is too long.
 */
int
sklogSetDirectory(
    const char         *dir_name,
    const char         *base_name);


/**
 *    When using syslog(3) for logging, this determines the facility
 *    to use.  This can only be called prior to sklogOpen().  The
 *    facility is ignored unless syslog(3) is used.
 */
int
sklogSetFacility(
    int                 facility);


/**
 *    Set the facility for syslog(3) by name or by a C-string that is
 *    parsable as a number or a recognized name.  Recognized names are
 *    the values 'user', 'daemon', and 'local0'..'local7'.  Other
 *    facilities must be set by value.
 */
int
sklogSetFacilityByName(
    const char         *name_or_number);


/**
 *    Sets the log level to all levels up to and including the level
 *    named by 'level'.  This may be called at any time after
 *    sklogSetup().  Returns 0 on success, or -1 if 'level' is not a
 *    valid level.
 *
 *    The valid levels are: "emerg", "alert", "crit", "err",
 *    "warning", "notice", "info", "debug".
 */
int
sklogSetLevel(
    const char         *level);


/**
 *    Set functions that lock and unlock the log when a logging
 *    mechanism other than syslog(3) is used.  These functions should
 *    be set in a multi-threaded application so that messages from
 *    different threads are kept distinct.  The 'locker' function will
 *    be called to lock the log; the 'unlocker' function to unlock it.
 *    The value in 'data' will be passed to these functions.
 *
 *    The function in 'try_locker' is used when sklogNonBlock() is
 *    called.  The function should lock the log and return 0 if it is
 *    currently unlocked, or immediately return a non-zero value.
 *
 *    This function must be called after sklogSetup().  The function
 *    returns 0 unless sklogSetup() has not yet been called, in which
 *    case -1 is returned.
 *
 *    This function can be called multiple times to modify the locking
 *    mechanism, and it can be called with all arguments set to NULL
 *    to disable log file locking.  Changing or disabling the locking
 *    in a multi-threaded environment or when the log file is locked
 *    is undefined.
 *
 *    See also the sklogEnableThreadedLogging() function.
 */
int
sklogSetLocking(
    sklog_lock_fn_t     locker,
    sklog_lock_fn_t     unlocker,
    sklog_lock_fn_t     try_locker,
    void               *data);


/**
 *    Set the mask for log messages.  This may be set at any time
 *    after calling setup.  Returns the old log mask.  Use the syslog
 *    macro LOG_UPTO() to specify the mask for this function.
 */
int
sklogSetMask(
    int                 mask);


/**
 *    Specify that 'command' is to run on the newly closed log file
 *    after log roation.  If 'command' is the empty string, no action
 *    is taken.  If 'command' is NULL, the default action of
 *    compressing the log file is taken.
 *
 *    Return 0 on success.  If log-rotation is not active, print a
 *    message and return 0.  On failure, print an error message and
 *    return -1.
 *
 *    The following %-conversions are supported: %s is the full path
 *    to the closed file, and %% is the character '%'.
 */
int
sklogSetPostRotateCommand(
    const char         *command);


/**
 *    Sets the function that will be used to prefix each log message
 *    when a logging mechanism other than syslog(3) is used.  If this
 *    function is not called, a default stamping function is used.
 *    This function must be called after sklogSetup() and before
 *    sklogOpen().
 */
int
sklogSetStampFunction(
    sklog_stamp_fn_t    makestamp);


/**
 *    Sets up the sklog module by initializing all memory.  The module
 *    will register the options appropriate for the 'feature_list'
 *    requested.  The available features are macros defined above as
 *    SKLOG_FEATURE_*.  Returns 0 unless there was a problem
 *    registering the options.
 */
int
sklogSetup(
    int                 feature_list);


/**
 *    Frees and clears all memory associated with the log.  If the log
 *    is opened it will be closed.
 */
void
sklogTeardown(
    void);


/**
 *    Prototypes that match sk_msg_vargs_fn_t
 */
int
EMERGMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
ALERTMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
CRITMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
ERRMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
WARNINGMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
NOTICEMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
INFOMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);
int
DEBUGMSG_v(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);


/**
 *    Writes a message with the specified 'priority' to the log.
 *    Requires that sklogSetup() has created the log, that
 *    sklogSetDestination() has been called, and that sklogOpen() has
 *    opened the log.
 */
void
sklogv(
    int                 priority,
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(2, 0);

#ifdef __cplusplus
}
#endif
#endif /*  _LOG_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
