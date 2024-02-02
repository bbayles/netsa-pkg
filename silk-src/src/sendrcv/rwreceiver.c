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
**  SiLK file transfer program (receiver)
**
**  Michael Welsh Duggan
**  December 2006
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwreceiver.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skdaemon.h>
#include <silk/skdllist.h>
#include <silk/sklog.h>
#include <silk/utils.h>
#ifdef SK_HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#include "rwtransfer.h"

/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

#define RWRECEIVER_PASSWORD_ENV ("RWRECEIVER" PASSWORD_ENV_POSTFIX)

/* Implement certain error conditions differently depending on the
 * version of the protocol */
#define SEND_CONN_REJECT(sndr)                  \
    (((sndr)->remote_version > 1)               \
     ? CONN_REJECT_FILE                         \
     : CONN_DISCONNECT)
#define SEND_CONN_DUPLICATE(sndr)               \
    (((sndr)->remote_version > 1)               \
     ? CONN_DUPLICATE_FILE                      \
     : CONN_DISCONNECT)
#define FILE_INFO_ERROR_STATE(sndr)                     \
    (sndr->remote_version > 1 ? File_info : Error)
#define FILESYSTEM_FULL_ERROR_STATE(sndr) Error


#ifndef SK_HAVE_STATVFS
#define CHECK_DISK_SPACE(cds_size)  (0)
#define GOT_DISK_SPACE(gds_size)
#else
/* minimum number of bytes to leave free on the data disk.  File
 * distribution will stop when the freespace on the disk reaches or
 * falls below this mark.  This value is parsed by
 * skStringParseHumanUint64(). */
#define DEFAULT_FREESPACE_MINIMUM   "0"

/* maximum percentage of disk space to take */
#define DEFAULT_SPACE_MAXIMUM_PERCENT  ((double)100.00)
#define DEFAULT_SPACE_MAXIMUM_PERCENT_STR  "100"

/* check and reserve disk space by adding to pre_alloc_size */
#define CHECK_DISK_SPACE(cds_size)                              \
    ((freespace_minimum > 0 || space_maximum_percent < 100.0)   \
     ? checkDiskSpace(cds_size)                                 \
     : 0)

/* file is written; remove space from pre_alloc_size */
#define GOT_DISK_SPACE(gds_size)                                        \
    if (freespace_minimum > 0 || space_maximum_percent < 100.0) {       \
        pthread_mutex_lock(&pre_alloc_size_mutex);                      \
        pre_alloc_size -= gds_size;                                     \
        pthread_mutex_unlock(&pre_alloc_size_mutex);                    \
    }
#endif  /* SK_HAVE_STATVFS */


/* EXPORTED VARIABLE DEFINITIONS */

/* Set to non-zero when shutting down. */
volatile int shuttingdown;

/* Per-sender data */
struct rbtree *transfers;

/* Local-side and remote-side version type identifiers */
connection_msg_t local_version_check = CONN_RECEIVER_VERSION;
connection_msg_t remote_version_check = CONN_SENDER_VERSION;

/* Password environment variable name */
const char *password_env = RWRECEIVER_PASSWORD_ENV;


/* LOCAL VARIABLE DEFINITIONS */

/* Primary destination directory (--destination-directory) */
static char *destination_dir;

/* Duplicate destination directories (--duplicate-destination) */
static sk_dllist_t *duplicate_dirs;

/* When non-zero, do not use hard links when creating the duplicate
 * copies (--unique-duplicates) */
static int unique_duplicates = 0;

/* List of inodes for open files; used to check for multiple rwsenders
 * sending the same file */
static sk_dllist_t *open_file_list;

/* Conversion characters supported in post_command */
static const char *post_command_conversions = "sI";

/* Command, supplied by user, to run whenever a file is received */
static const char *post_command = NULL;

/* Set to true once skdaemonized() has been called---regardless of
 * whether the --no-daemon switch was given. */
static int daemonized = 0;

#ifdef SK_HAVE_STATVFS
/* Amount of space pre-allocated for files.  This gets added to by
 * checkDiskSpace(), and then decremented once the space is actually
 * allocated.  */
static uint64_t pre_alloc_size;

/* Mutex for pre_alloc_size */
static pthread_mutex_t pre_alloc_size_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Amount of free space (in bytes) to leave on the disk; specified by
 * --freespace-minimum.  Gets set to DEFAULT_FREESPACE_MINIMUM */
static int64_t freespace_minimum = -1;

/* Percentage of the disk to use; specified by
 * --space-maximum-percent */
static double space_maximum_percent = DEFAULT_SPACE_MAXIMUM_PERCENT;
#endif /* SK_HAVE_STATVFS */


/* OPTIONS SETUP */

typedef enum {
    /* App specific options */
    OPT_DESTINATION_DIR,
    OPT_DUPLICATE_DEST,
    OPT_UNIQUE_DUPLICATES,
#ifdef SK_HAVE_STATVFS
    OPT_FREESPACE_MINIMUM, OPT_SPACE_MAXIMUM_PERCENT,
#endif
    OPT_POST_COMMAND
} appOptionsEnum;

static struct option appOptions[] = {
    {"destination-directory", REQUIRED_ARG, 0, OPT_DESTINATION_DIR},
    {"duplicate-destination", REQUIRED_ARG, 0, OPT_DUPLICATE_DEST},
    {"unique-duplicates",     NO_ARG,       0, OPT_UNIQUE_DUPLICATES},
#ifdef SK_HAVE_STATVFS
    {"freespace-minimum",     REQUIRED_ARG, 0, OPT_FREESPACE_MINIMUM},
    {"space-maximum-percent", REQUIRED_ARG, 0, OPT_SPACE_MAXIMUM_PERCENT},
#endif
    {"post-command",          REQUIRED_ARG, 0, OPT_POST_COMMAND},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Write incoming files to this directory"),
    ("Create a duplicate of each incoming file in\n"
     "\tthis directory. Repeat to create multiple duplicates"),
    ("Create a unique copy of the incoming file in each\n"
     "\tduplicate-destination directory. When not specified, files in each\n"
     "\tduplicate-destination are a reference (hard link) to each other and\n"
     "\tto the file in the destination-directory"),
#ifdef SK_HAVE_STATVFS
    ("Set the minimum free space (in bytes) to maintain\n"
     "\ton the filesystem. Use 0 for no limit. Accepts k,m,g,t suffix. Def. "
     DEFAULT_FREESPACE_MINIMUM),
    ("Set the maximum percentage of the disk to\n"
     "\tuse. Def. " DEFAULT_SPACE_MAXIMUM_PERCENT_STR "%"),
#endif /* SK_HAVE_STATVFS */
    ("Run this command on each file after it is successfully\n"
     "\treceived. Def. None. Each \"%s\" in the command is replaced by the\n"
     "\tfile's complete path, and each \"%I\" is replaced by the identifier\n"
     "\tof the rwsender that sent the file"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  rwreceiverVerifyOptions(void);
#ifdef SK_HAVE_STATVFS
static int checkDiskSpace(uint64_t size);
#endif


/* FUNCTION DEFINITIONS */

/*
 *  appUsageLong();
 *
 *    Print complete usage information to USAGE_FH.  This function is
 *    passed to optionsSetup(); skOptionsParse() will call this funciton
 *    and then exit the program when the --help option is given.
 */
static void
appUsageLong(
    void)
{
#define USAGE_MSG                                                       \
    ("<SWITCHES>\n"                                                     \
     "\tAccepts files from one or more sender daemons (rwsender)\n"     \
     "\tand places them in a given directory.\n")

    transferUsageLong(USAGE_FH, USAGE_MSG, appOptions, appHelp);
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
    RBLIST *iter;
    transfer_t *sndr;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (!daemonized) {
        rbdestroy(transfers);
        skDLListDestroy(duplicate_dirs);
        skDLListDestroy(open_file_list);
        skdaemonTeardown();
        skAppUnregister();
        return;
    }

    NOTICEMSG("Begin shutting down...");

    shuttingdown = 1;

    transferShutdown();
    transferTeardown();

    /* Destroy stuff */
    iter = rbopenlist(transfers);
    CHECK_ALLOC(iter);
    while ((sndr = (transfer_t *)rbreadlist(iter)) != NULL) {
        if (sndr->ident != NULL) {
            free(sndr->ident);
        }
        if (sndr->addr) {
            skSockaddrArrayDestroy(sndr->addr);
        }
        free(sndr);
    }
    rbcloselist(iter);
    rbdestroy(transfers);

    skDLListDestroy(duplicate_dirs);
    skDLListDestroy(open_file_list);

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
    int arg_index;
    int rv;

    /* check that we have the same number of options entries and help*/
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    shuttingdown    = 0;
    destination_dir = NULL;
    duplicate_dirs  = skDLListCreate(NULL);
    if (duplicate_dirs == NULL) {
        skAppPrintOutOfMemory("duplicate directory list");
        exit(EXIT_FAILURE);
    }
    open_file_list  = skDLListCreate(NULL);
    if (open_file_list == NULL) {
        skAppPrintOutOfMemory("open file list");
        exit(EXIT_FAILURE);
    }

    transfers = transferIdentTreeCreate();
    if (transfers == NULL) {
        skAppPrintOutOfMemory("receiver data structure");
        exit(EXIT_FAILURE);
    }
#ifdef SK_HAVE_STATVFS
    {
        uint64_t tmp_64;
        rv = skStringParseHumanUint64(&tmp_64, DEFAULT_FREESPACE_MINIMUM,
                                     SK_HUMAN_NORMAL);
        if (rv) {
            skAppPrintErr("Bad default value for freespace_minimum: '%s': %s",
                          DEFAULT_FREESPACE_MINIMUM,skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
        freespace_minimum = (int64_t)tmp_64;
    }
#endif /* SK_HAVE_STATVFS */

    /* register the options and handler */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register application options");
        exit(EXIT_FAILURE);
    }

    /* Register the other transfer options */
    if (transferSetup()) {
        exit(EXIT_FAILURE);
    }

    /* rwreceiver runs as a daemon */
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

    /* Verify the options */
    rv = rwreceiverVerifyOptions();

    /* verify the required options for logging */
    if (skdaemonOptionsVerify()) {
        rv = -1;
    }

    if (rv) {
        skAppUsage();           /* never returns */
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch --%s",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    /* Identify the main thread */
    skthread_init("main");

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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    int rv;

    SK_UNUSED_PARAM(cData);

    switch ((appOptionsEnum)opt_index) {
      case OPT_DESTINATION_DIR:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        destination_dir = opt_arg;
        break;

      case OPT_DUPLICATE_DEST:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        rv = skDLListPushTail(duplicate_dirs, opt_arg);
        if (rv != 0) {
            skAppPrintOutOfMemory("directory name");
            return 1;
        }
        break;

      case OPT_UNIQUE_DUPLICATES:
        unique_duplicates = 1;
        break;

      case OPT_POST_COMMAND:
        if (!*opt_arg) {
            skAppPrintErr("Invalid %s: Empty string",
                          appOptions[opt_index].name);
            return 1;
        }
        rv = skSubcommandStringCheck(opt_arg, post_command_conversions);
        if (rv) {
            if ('\0' == opt_arg[rv]) {
                skAppPrintErr(("Invalid %s '%s':"
                               " '%%' appears at end of string"),
                              appOptions[opt_index].name, opt_arg);
            } else {
                skAppPrintErr("Invalid %s '%s': Unknown conversion '%%%c'",
                              appOptions[opt_index].name, opt_arg,opt_arg[rv]);
            }
            return 1;
        }
        post_command = opt_arg;
        break;

#ifdef SK_HAVE_STATVFS
      case OPT_FREESPACE_MINIMUM:
        {
            uint64_t tmp_64;
            rv = skStringParseHumanUint64(&tmp_64, opt_arg, SK_HUMAN_NORMAL);
            if (rv) {
                goto PARSE_ERROR;
            }
            freespace_minimum = (int64_t)tmp_64;
        }
        break;

      case OPT_SPACE_MAXIMUM_PERCENT:
        rv = skStringParseDouble(&space_maximum_percent, opt_arg, 0.0, 100.0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;
#endif /* SK_HAVE_STATVFS */
    }

    return 0;  /* OK */

#ifdef SK_HAVE_STATVFS
  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
#endif
}


static int
rwreceiverVerifyOptions(
    void)
{
    int rv;

    /* Verify the transfer options */
    rv = transferVerifyOptions();

    /* Check for the existance of destination_dir */
    if (destination_dir == NULL) {
        skAppPrintErr("A destination directory is required");
        rv = -1;
    }

    return rv;
}


int
transferUnblock(
    transfer_t         *item)
{
    SK_UNUSED_PARAM(item);
    return 0;
}


#ifdef SK_HAVE_STATVFS
/*
 *  checkDiskSpace(size);
 *
 *    Verify that we haven't reached the limits of the file system
 *    usage specified by the command line parameters after the
 *    creation of a file of given size (in bytes).
 *
 *    If we're out of space, return -1.  Else, add 'size' to the
 *    'pre_alloc_size' global variable and return 0.
 */
static int
checkDiskSpace(
    uint64_t            size)
{
    struct statvfs vfs;
    int64_t free_space, total, newfree;
    int rv;
    double percent_used;

    DEBUGMSG(("Checking for %" PRIu64 " bytes of free space"),
             size);

    rv = statvfs(destination_dir, &vfs);
    if (rv != 0) {
        CRITMSG("Could not statvfs '%s'", destination_dir);
        return -1;
    }

    /* free bytes is fundamental block size multiplied by the
     * available (non-privileged) blocks. */
    free_space = ((int64_t)vfs.f_frsize * (int64_t)vfs.f_bavail);
    /* to compute the total (non-privileged) blocks, subtract the
     * available blocks from the free (privileged) blocks to get
     * the count of privileged-only blocks, subtract that from the
     * total blocks, and multiply the result by the block size. */
    total = ((int64_t)vfs.f_frsize
             * ((int64_t)vfs.f_blocks
                - ((int64_t)vfs.f_bfree - (int64_t)vfs.f_bavail)));

    pthread_mutex_lock(&pre_alloc_size_mutex);
    newfree = free_space - pre_alloc_size - size;;
    percent_used = ((double)(total - newfree) /
                    ((double)total / 100.0));

    /* SENDRCV_DEBUG is defined in libsendrcv.h */
#if (SENDRCV_DEBUG) & DEBUG_RWRECEIVER_DISKFREE
    DEBUGMSG(("frsize: %" PRIu32 "; blocks: %" PRIu64
              "; bfree: %" PRIu64 "; bavail: %" PRIu64
              "; total: %" PRId64 "; free_space: %" PRId64
              "; pre-alloc: %" PRIu64 "; newfree: %" PRId64),
             (uint32_t)vfs.f_frsize, (uint64_t)vfs.f_blocks,
             (uint64_t)vfs.f_bfree, (uint64_t)vfs.f_bavail,
             total, free_space, pre_alloc_size, newfree);
#endif

    if (newfree < freespace_minimum) {
        CRITMSG(("Free disk space limit overrun: "
                 "free=%" PRId64 " < min=%" PRId64 " (used %.4f%%)"),
                newfree, freespace_minimum, percent_used);
        pthread_mutex_unlock(&pre_alloc_size_mutex);
        return -1;
    }
    if (percent_used > space_maximum_percent) {
        CRITMSG(("Free disk space limit overrun: "
                 "used=%.4f%% > max=%.4f%% (free %" PRId64 " bytes)"),
                percent_used, space_maximum_percent, newfree);
        pthread_mutex_unlock(&pre_alloc_size_mutex);
        return -1;
    }

    DEBUGMSG(("Free space available after file of size %" PRIu64
              " would be %" PRId64 " bytes (%.4f%%)"),
             size, newfree, percent_used);

    pre_alloc_size += size;

    pthread_mutex_unlock(&pre_alloc_size_mutex);
    return 0;
}
#endif /* SK_HAVE_STATVFS */


/*
 *  runPostCommand(filename, ident);
 *
 *    Spawn a new subprocess to run 'post_command'.  Formatting
 *    directives in 'post_command' may be expanded to hold to the
 *    'filename' that has just been received and the 'ident' of the
 *    rwsender that sent the file.
 */
static void
runPostCommand(
    const char         *file,
    const char         *ident)
{
    char *expanded_cmd;
    long rv;

    /* order of arguments is file, ident */
    assert('s' == post_command_conversions[0]
           && 'I' == post_command_conversions[1]);

    expanded_cmd = (skSubcommandStringFill(
                        post_command, post_command_conversions, file, ident));
    if (NULL == expanded_cmd) {
        WARNINGMSG("Unable to allocate memory to create command string");
        return;
    }

    DEBUGMSG("Invoking %s: %s",
             appOptions[OPT_POST_COMMAND].name, expanded_cmd);
    rv = skSubcommandExecuteShell(expanded_cmd);
    switch (rv) {
      case -1:
        ERRMSG("Unable to fork to run command: %s", strerror(errno));
        break;
      case -2:
        NOTICEMSG("Error waiting for child: %s", strerror(errno));
        break;
      default:
        assert(rv > 0);
        break;
    }
    free(expanded_cmd);
}


/*
 *    This function is called by the handleConnection() function in
 *    rwtransfer.c once the connection has been established.  This
 *    function returns -1 on error, 0 if no files were transferred, or
 *    1 if one or more files were successfully received.
 */
int
transferFiles(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    transfer_t         *sndr)
{
    static pthread_mutex_t open_file_mutex = PTHREAD_MUTEX_INITIALIZER;
    int fd = -1;
    uint64_t size = 0;
    uint64_t pa_size = 0;
    uint8_t *map = NULL;
    char *name = NULL;
    char *dotname = NULL;
    char dotpath[PATH_MAX];
    char destpath[sizeof(dotpath)-1];
    struct stat st;
    ino_t *inode;
    int proto_err;
    int rv;
    sk_dll_iter_t iter;
    const char *duplicate_dir;
    enum transfer_state {File_info, File_info_ack,
                         Send_file, Complete_ack, Error} state;
    int thread_exit;
    int transferred_file = 0;

    state = File_info;
    proto_err = 0;
    thread_exit = 0;
    destpath[0] = '\0';
    dotpath[0] = '\0';
    memset(&st, 0, sizeof(st));

    while (!shuttingdown && !proto_err && !thread_exit && !sndr->disconnect
           && (state != Error))
    {
        sk_msg_t *msg;

        /* Handle reads */
        switch (state) {
          case File_info:
          case Send_file:
            rv = skMsgQueueGetMessage(q, &msg);
            if (rv == -1) {
                ASSERT_ABORT(shuttingdown);
                continue;
            }
            if (handleDisconnect(msg, sndr->ident)) {
                state = Error;
            }
            break;
          case Error:
            ASSERT_ABORT(0);
            break;
          default:
            msg = NULL;
        }

        /* Handle all states */
        switch (state) {
          case File_info:
            /* Create the placeholder and dot files and mmap() the
             * space. */
            {
                file_info_t *finfo;
                uint32_t len;
                mode_t mode;
                off_t offrv;

                if ((proto_err = checkMsg(msg, q, CONN_NEW_FILE))) {
                    break;
                }
                DEBUG_PRINT1("Received CONN_NEW_FILE");
                finfo = (file_info_t *)skMsgMessage(msg);
                size = (uint64_t)ntohl(finfo->high_filesize) << 32 |
                       ntohl(finfo->low_filesize);
                pa_size = size;
                /* blocksize = ntohl(finfo->block_size); --- UNUSED */
                mode = ntohl(finfo->mode) & 0777;
                len = skMsgLength(msg) - offsetof(file_info_t, filename);
                dotname = (char *)calloc(1, len + 1);
                CHECK_ALLOC(dotname);
                name = dotname + 1;
                dotname[0] = '.';
                memcpy(name, finfo->filename, len);
                if (!memchr(name, '\0', len)) {
                    sendString(q, channel, EXTERNAL, SEND_CONN_REJECT(sndr),
                               LOG_WARNING, "Illegal filename (from %s)",
                               sndr->ident);
                    state = FILE_INFO_ERROR_STATE(sndr);
                    break;
                }

                INFOMSG("Receiving from %s: '%s' (%" PRIu64 " bytes)",
                        sndr->ident, name, size);

                /* Check filesystem for enough space for file */
                if (CHECK_DISK_SPACE(pa_size)) {
                    WARNINGMSG(("Not enough space on filesystem for %" PRIu64
                                " byte file '%s'"),
                               pa_size, name);
                    pa_size = 0;
                    state = FILESYSTEM_FULL_ERROR_STATE(sndr);
                    break;
                }

                /* Create the placeholder file */
                rv = snprintf(destpath, sizeof(destpath), "%s/%s",
                              destination_dir, name);
                if ((size_t)rv >= sizeof(destpath)) {
                    sendString(q, channel, EXTERNAL,
                               SEND_CONN_REJECT(sndr),
                               LOG_WARNING, "Filename too long (from %s)",
                               sndr->ident);
                    state = FILE_INFO_ERROR_STATE(sndr);
                    destpath[0] = '\0';
                    break;
                }

                assert((size_t)rv < sizeof(destpath));

                pthread_mutex_lock(&open_file_mutex);
              reopen:
                fd = open(destpath, O_CREAT | O_EXCL | O_WRONLY, 0);
                if (fd == -1) {
                    if (errno != EEXIST) {
                        CRITMSG("Could not create '%s': %s",
                                destpath, strerror(errno));
                        thread_exit = 1;
                        pthread_mutex_unlock(&open_file_mutex);
                        break;
                    }

                    if (stat(destpath, &st) == -1) {
                        WARNINGMSG("Unable to stat '%s': %s",
                                   destpath, strerror(errno));
                    } else if (S_ISREG(st.st_mode)
                               && ((st.st_mode & 0777) == 0)
                               && ((st.st_size == 0)))
                    {
                        /* looks like a placeholder file.  are we
                         * receiving a file with the same name from a
                         * different rwsender? */
                        int found = 0;
                        skDLLAssignIter(&iter, open_file_list);
                        while (skDLLIterForward(&iter, (void **)&inode) == 0) {
                            if (st.st_ino == *inode) {
                                WARNINGMSG(("Multiple rwsenders attempting"
                                            " to send file '%s'"),
                                           name);
                                found = 1;
                                break;
                            }
                        }
                        if (!found) {
                            WARNINGMSG(("Filename already exists (from a"
                                        " previous run?). Removing '%s'"),
                                       destpath);
                            if (unlink(destpath) == 0) {
                                goto reopen;
                            }
                            WARNINGMSG("Failed to unlink '%s': %s",
                                       destpath, strerror(errno));
                            /* treat file as a duplicate */
                        }
                    }
                    /* else file is a duplicate */
                    st.st_ino = 0;
                    destpath[0] = dotpath[0] = '\0';
                    sendString(q, channel, EXTERNAL,
                               SEND_CONN_DUPLICATE(sndr),
                               LOG_WARNING,
                               "Filename already exists (from %s)",
                               sndr->ident);
                    state = FILE_INFO_ERROR_STATE(sndr);
                    pthread_mutex_unlock(&open_file_mutex);
                    break;
                }
                /* else, successfully opened placeholder file */
                if (fstat(fd, &st) == -1) {
                    CRITMSG("Could not fstat newly created file '%s': %s",
                            destpath, strerror(errno));
                    st.st_ino = 0;
                    thread_exit = 1;
                    pthread_mutex_unlock(&open_file_mutex);
                    break;
                }
                if (skDLListPushTail(open_file_list, &st.st_ino)) {
                    CRITMSG("Unable to grow open file list");
                    st.st_ino = 0;
                    thread_exit = 1;
                    pthread_mutex_unlock(&open_file_mutex);
                    break;
                }
                pthread_mutex_unlock(&open_file_mutex);

                DEBUGMSG("Created '%s'", destpath);

                rv = close(fd);
                fd = -1;
                if (rv == -1) {
                    CRITMSG("Could not close file '%s': %s",
                            destpath, strerror(errno));
                    thread_exit = 1;
                    break;
                }

                /* Create the dotfile */
                rv = snprintf(dotpath, sizeof(dotpath), "%s/%s",
                              destination_dir, dotname);
              reopen2:
                fd = open(dotpath, O_RDWR | O_CREAT | O_EXCL, mode);
                if (fd == -1) {
                    int saveerrno = errno;
                    if (errno == EEXIST) {
                        WARNINGMSG("Filename already exists. Removing '%s'",
                                   dotpath);
                        if (unlink(dotpath) == 0) {
                            goto reopen2;
                        }
                        WARNINGMSG("Failed to unlink '%s': %s",
                                   dotpath, strerror(errno));
                    }
                    CRITMSG("Could not create '%s': %s",
                            dotpath, strerror(saveerrno));
                    thread_exit = 1;
                    dotpath[0] = '\0';
                    break;
                }
                DEBUGMSG("Created '%s'", dotpath);

                /* Allocate space on disk */
                offrv = lseek(fd, size - 1, SEEK_SET);
                if (offrv == -1) {
                    CRITMSG("Could not allocate disk space for '%s': %s",
                            dotpath, strerror(errno));
                    thread_exit = 1;
                    break;
                }
                rv = write(fd, "", 1);
                if (rv == -1) {
                    CRITMSG("Could not allocate disk space for '%s': %s",
                            dotpath, strerror(errno));
                    thread_exit = 1;
                    break;
                }

                /* Map space */
                map = (uint8_t *)mmap(0, size, PROT_READ | PROT_WRITE,
                                      MAP_SHARED, fd, 0);
                if ((void *)map == MAP_FAILED) {
                    CRITMSG("Could not map '%s': %s",
                            dotpath, strerror(errno));
                    thread_exit = 1;
                    break;
                }
                rv = close(fd);
                fd = -1;
                if (rv == -1) {
                    CRITMSG("Could not close file '%s': %s",
                            dotpath, strerror(errno));
                    thread_exit = 1;
                    break;
                }
                GOT_DISK_SPACE(pa_size);
                pa_size = 0;
                state = File_info_ack;
            }
            break;

          case File_info_ack:
            DEBUG_PRINT1("Sending CONN_NEW_FILE_READY");
            proto_err = skMsgQueueSendMessage(q, channel,
                                              CONN_NEW_FILE_READY, NULL, 0);
            state = Send_file;
            break;

          case Send_file:
            /* Get the content of the file and write into the dot file */
            {
                block_info_t *block;
                uint64_t offset;
                uint32_t len;

                if (skMsgType(msg) != CONN_FILE_BLOCK) {
                    /* have the error reflect that CONN_FILE_BLOCK was
                     * expected unless msg is CONN_FILE_COMPLETE */
                    if (skMsgType(msg) == CONN_FILE_COMPLETE) {
                        DEBUG_PRINT1("Received CONN_FILE_COMPLETE");
                        state = Complete_ack;
                    } else {
                        proto_err = checkMsg(msg, q, CONN_FILE_BLOCK);
                    }
                    break;
                }
#if !((SENDRCV_DEBUG) & DEBUG_RWTRANSFER_CONTENT)
                /* no need to report when also reporting content */
                DEBUG_PRINT1("Received CONN_FILE_BLOCK");
#endif

                block = (block_info_t *)skMsgMessage(msg);
                len = skMsgLength(msg) - offsetof(block_info_t, block);
                offset = (uint64_t)ntohl(block->high_offset) << 32 |
                         ntohl(block->low_offset);
                DEBUG_CONTENT_PRINT("Received CONN_FILE_BLOCK"
                                    "  offset=%" PRIu64 " len=%" PRIu32,
                                    offset, len);
                if (offset + len > size) {
                    sendString(q, channel, EXTERNAL, CONN_DISCONNECT,
                               LOG_WARNING,
                               ("Illegal block (offset/size %" PRIu64
                                "/%" PRIu32 ")"), offset, len);
                    state = Error;
                    break;
                }
                memcpy(map + offset, block->block, len);
            }
            break;

          case Complete_ack:
            /* Un-mmap() the file, create any duplicate files, and
             * move the dotfile over the placeholder file */
            rv = munmap(map, size);
            map = NULL;
            if (rv == -1) {
                CRITMSG("Could not unmap file '%s': %s",
                        dotpath, strerror(errno));
                thread_exit = 1;
                break;
            }

            /* Handle duplicate-destinations. Any errors here are
             * simply logged and processing continues. */
            skDLLAssignIter(&iter, duplicate_dirs);
            while (skDLLIterForward(&iter, (void **)&duplicate_dir) == 0) {
                char path[sizeof(destpath)];

                snprintf(path, sizeof(path), "%s/%s", duplicate_dir, name);
                if (unique_duplicates) {
                    rv = skCopyFile(dotpath, path);
                    if (rv != 0) {
                        WARNINGMSG("Could not copy '%s' to '%s': %s",
                                   dotpath, path, strerror(rv));
                    }
                } else {
                    DEBUGMSG("Linking '%s' as '%s'", dotpath, path);
                    rv = link(dotpath, path);
                    if (EXDEV == errno) {
                        DEBUGMSG("Link failed EXDEV; copying '%s' to '%s'",
                                 dotpath, path);
                        rv = skCopyFile(dotpath, path);
                        if (rv != 0) {
                            WARNINGMSG("Could not copy '%s' to '%s': %s",
                                       dotpath, path, strerror(rv));
                        }
                    } else if (rv != 0) {
                        WARNINGMSG("Could not link '%s' as '%s': %s",
                                   dotpath, path, strerror(errno));
                    }
                }
            }

            DEBUGMSG("Renaming '%s' to '%s'", dotpath, destpath);
            rv = rename(dotpath, destpath);
            if (rv != 0) {
                CRITMSG("Failed rename of '%s' to '%s': %s",
                        dotpath, destpath, strerror(errno));
                thread_exit = 1;
                break;
            }

            /* remove the file from the open_file_list */
            pthread_mutex_lock(&open_file_mutex);
            skDLLAssignIter(&iter, open_file_list);
            while (skDLLIterForward(&iter, (void **)&inode) == 0) {
                if (st.st_ino == *inode) {
                    skDLLIterDel(&iter);
                    break;
                }
            }
            st.st_ino = 0;
            pthread_mutex_unlock(&open_file_mutex);

            DEBUG_PRINT1("Sending CONN_FILE_COMPLETE");
            proto_err = skMsgQueueSendMessage(q, channel,
                                              CONN_FILE_COMPLETE, NULL, 0);
            if (proto_err == 0) {
                /* Run the post command on the file */
                if (post_command) {
                    runPostCommand(destpath, sndr->ident);
                }
                destpath[0] = '\0';
                INFOMSG("Finished receiving from %s: '%s'", sndr->ident, name);
                free(dotname);
                dotname = NULL;
            }

            destpath[0] = dotpath[0] = '\0';
            transferred_file = 1;

            state = File_info;
            break;

          case Error:
            break;
        }

        if (msg != NULL) {
            skMsgDestroy(msg);
        }
    }

    if (fd != -1) {
        close(fd);
    }
    if (map != NULL) {
        munmap(map, size);
    }
    if (dotname != NULL) {
        free(dotname);
    }
    if (dotpath[0] != '\0') {
        DEBUGMSG("Removing '%s'", dotpath);
        unlink(dotpath);
    }
    if (destpath[0] != '\0') {
        DEBUGMSG("Removing '%s'", destpath);
        unlink(destpath);
    }
    if (st.st_ino != 0) {
        skDLLAssignIter(&iter, open_file_list);
        while (skDLLIterForward(&iter, (void **)&inode) == 0) {
            if (st.st_ino == *inode) {
                skDLLIterDel(&iter);
                break;
            }
        }
    }
    if (pa_size) {
        GOT_DISK_SPACE(pa_size);
    }
    if (thread_exit) {
        return -1;
    }

    return transferred_file;
}


int main(int argc, char **argv)
{
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    /* start the logger and become a daemon */
    if (skdaemonize(&shuttingdown, NULL) == -1
        || sklogEnableThreadedLogging() == -1)
    {
        exit(EXIT_FAILURE);
    }
    daemonized = 1;

    /* Run in client or server mode */
    rv = startTransferDaemon();
    if (rv != 0) {
        exit(EXIT_FAILURE);
    }

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
