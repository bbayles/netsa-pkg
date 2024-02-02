/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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
**  rwflowpack.c
**
**    rwflowpack is a daemon that runs as part of the SiLK flow
**    collection and packing tool-chain.  The primary job of
**    rwflowpack is to convert each incoming flow record to the SiLK
**    Flow format, categorize each incoming flow record (e.g., as
**    incoming or outgoing), set the sensor value for the record, and
**    determine which hourly file will ultimately store the record.
**
**    Assuming the required support libraries are present, rwflowpack
**    can process:
**
**        PDU records (NetFlow v5).  These can be read from a network
**        socket (UDP), from an individual file, or from a directory
**        where PDU files are continuously deposited.
**
**        IPFIX records.  These can be read from a network socket (TCP
**        or UDP) or from a directory where the files are continuously
**        deposited.  IPFIX support requires libfixbuf.
**
**        NetFlow v9 records.  These can be read from a network socket
**        (UDP).  NetFlow v9 support requires libfixbuf.
**
**        sFlow v5 records.  These can be read from a network socket
**        (UDP).  sFlow support requires libfixbuf.
**
**        Existing SiLK Flow files.  These can be read from a
**        directory where the files are continuosly deposited.
**        rwflowpack will modify the flowtype and sensor information
**        on the records.
**
**        SiLK Flow files can be processed in such a way that the
**        flowtype and sensor information on the records is not
**        modified.  The incoming records are simply "respooled" into
**        the data repository.
**
**        SiLK Flow files packaged by the flowcap daemon.  In this
**        case, rwflowpack does not do data collection; it simply
**        processes the records that flowcap collected.
**
**    Some of the input_mode_types alter the way rwflowpack operates.  For
**    example, when reading a single file of PDU records, the
**    input_mode_type will disable the daemonization of rwflowpack, so
**    that rwflowpack will process a single PDU file and exit.  These
**    changes to rwflowpack's operation are reflected in the
**    --input-mode switch.
**
**    For the output from rwflowpack, rwflowpack can create the hourly
**    files locally, or it can create "incremental files", which are
**    small files that the rwflowappend daemon can combine into hourly
**    files.  Using these incremental files allows rwflowpack to run
**    on a different machine than where the repository is located.
**
**    There are two concepts in rwflowpack that are easy to confuse.
**
**    The first concept is the "input_mode_type".  In general, a
**    input_mode_type contains the knowledge necessary to process one of
**    the types of inputs that rwflowpack supports.  (The IPFIX and
**    NetFlow v9 records are handled by the same input_mode_type.  The
**    input_mode_type to process PDU records from the network is different
**    from the input_mode_type to process PDU records from a file.  The
**    information for each input_mode_type is located in a separate file,
**    and file pointers are used to access the functions that each
**    input_mode_type provides.
**
**    The second concept is the "flow_processor".  The flow_processor
**    can be thought of as an "instance" of the input_mode_type.  A
**    flow_processor is associated with a specific collection point
**    for incoming flow records.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwflowpack.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <dlfcn.h>

#include <silk/redblack.h>
#include <silk/skdaemon.h>
#include <silk/skplugin.h>
#include <silk/skpolldir.h>
#include <silk/sksite.h>
#include <silk/sktimer.h>
#include <silk/skvector.h>
#include "rwflowpack_priv.h"
#include "stream-cache.h"

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/*
 *    MAX FILE HANDLE NOTES
 *
 *    In response to attempts to use 100+ probes that polled
 *    directories which caused us to run out of file handles, we tried
 *    to make some of the code smarter about the number of files
 *    handles we use.
 *
 *    However, currently we only look at polldir numbers, and we do
 *    not consider the number of file handles that we have open to
 *    read from the network.  One issue is we don't know how many that
 *    is until after we start.
 *
 *    We could be smarter and set the number of poll dir handles after
 *    we see how many polldirs we are actually using.
 *
 *    We could use sysconf(_SC_OPEN_MAX) to get the max number of file
 *    handles available and set our values based on that.
 */


/* MACROS AND DATA TYPES */

/* Where to write usage (--help) information */
#define USAGE_FH stdout

/* The maximum number of open output files to support, which is the
 * size of the stream_cache.  This default may be changed with the
 * --file-cache-size switch.  Also specify the minimum size of stream
 * cache. */
#define STREAM_CACHE_SIZE 128
#define STREAM_CACHE_MIN  4

/* These next two values are used when rwflowpack is using probes that
 * poll directories, and they specify fractions of the
 * stream_cache_size.
 *
 * The first is the maximum number of input files to read from
 * simultaneously.  The second is the maximum number of simultaneous
 * directory polls to perform.
 *
 * In addition, specify the absolute minimum for those values. */
#define INPUT_FILEHANDLES_FRACTION   (1.0/8.0)
#define POLLDIR_FILEHANDLES_FRACTION (1.0/16.0)

#define INPUT_FILEHANDLES_MIN      2
#define POLLDIR_FILEHANDLES_MIN    1

/* How often, in seconds, to flush the files in the stream_cache.
 * This default may be changed with the --flush-timeout switch. */
#define FLUSH_TIMEOUT  120

/* Number of seconds to wait between polling the incoming directory or
 * the poll-directory's specified in the sensor.conf file.  This
 * default may be changed with the --polling-interval switch. */
#define POLLING_INTERVAL 15

/* Helper macro for messages */
#define CHECK_PLURAL(cp_x) ((1 == (cp_x)) ? "" : "s")

/* The number of input modes supported.  Used to set array sizes. */
#define MAX_INPUT_MODE_TYPE_COUNT 9

/* The signal the reader thread (the manageProcessor() function) sends
 * to main thread to indicate that the reader thread is done.
 * Normally SIGUSR2, but you may need to use a different value when
 * running under a debugger, valgrind, etc. */
#ifndef READER_DONE_SIGNAL
#  define READER_DONE_SIGNAL  SIGUSR2
#endif

/* Must be greater than the number of switches defined */
#define MAX_OPTION_COUNT 32

/* In each of the above mode, an option can be required, optional,
 * illegal, or non-sensical.  This enumerates those values; the
 * mode_options[][] array holds the values for each option for each
 * mode. */
typedef enum {
    MODOPT_ILLEGAL = 0, MODOPT_REQUIRED, MODOPT_OPTIONAL, MODOPT_NONSENSE
} mode_option_t;

typedef void (*cleanupHandler)(void *);

/* signal list */
struct siglist_st {
    int signal;
    char *name;
};

/* Create an array of these to cache the options we get from the
 * user */
typedef struct opt_cache_st {
    int     seen;
    char   *value;
} opt_cache_t;

/* IDs for the input modes.  Keep in sync with imt_init_fn_list[]. */
typedef enum {
    INPUT_MODE_TYPE_FLOWCAP_FILES,
#if SK_ENABLE_IPFIX
    INPUT_MODE_TYPE_IPFIX,
#endif
    INPUT_MODE_TYPE_PDU,
    INPUT_MODE_TYPE_PDU_FILE,
    INPUT_MODE_TYPE_DIRECTORY,
    INPUT_MODE_TYPE_RESPOOL,
    _INPUT_MODE_TYPE_MAX_
} input_mode_type_id_t;


/* LOCAL VARIABLES */

/*
 *    Define an array of function pointers, where the function takes a
 *    input_mode_type and fills in the name and the function pointers
 *    for that input_mode_type.  Keep this list in sync with
 *    input_mode_type_id_t.
 */
static int (*imt_init_fn_list[])(input_mode_type_t*) = {
    &fcFilesReaderInitialize,
#if SK_ENABLE_IPFIX
    &ipfixReaderInitialize,
#endif
    &pduReaderInitialize,
    &pduFileReaderInitialize,
    &dirReaderInitialize,
    &respoolReaderInitialize
};

/* The possible input mode types */
static input_mode_type_t input_mode_types[MAX_INPUT_MODE_TYPE_COUNT];

/* Get a total count of the input mode types actually implemented. */
static const size_t num_input_mode_types = (sizeof(imt_init_fn_list)
                                            / sizeof(imt_init_fn_list[0]));

/* The flow processors; one per probe */
static flow_proc_t *flow_processors = NULL;

/* The number of flow_processors */
static size_t num_flow_processors = 0;

/* The number of flow_processor threads currently running */
static int fproc_thread_count = 0;

/* Mutex controlling access to 'fproc_thread_count' */
static pthread_mutex_t fproc_thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The packing logic to use to categorize flow records */
static packlogic_plugin_t packlogic;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* When running in stream mode, rwflowpack normally collects data from
 * all probes.  This is the value of the --sensor-name command line
 * switch which limits which probes are activated.  It is also used
 * when running in PDU single-file mode. */
static const char *sensor_name = NULL;

/* set to 1 when the --pack-interfaces switch is given. */
static int pack_interfaces = 0;

/* True as long as we are reading. */
static uint8_t reading = 0;

/* non-zero when rwflowpack is shutting down */
static volatile int shuttingDown = 0;

/* Set to true once skdaemonized() has been called---regardless of
 * whether the --no-daemon switch was given. */
static int daemonized = 0;

/* non-zero when file locking is disabled */
static int no_file_locking = 0;

/* suffix used for mkstemp().  Note: we use sizeof() on this */
static const char temp_suffix[] = ".XXXXXX";

/* control thread */
static pthread_t main_thread;

/* Timer that flushes files every so often */
static skTimer_t timing_thread = NULL;

/* Number of seconds between cache flushes */
static uint32_t flush_timeout = FLUSH_TIMEOUT;

/* All open files to which we are writing */
static stream_cache_t *stream_cache;

/* Size of the cache for writing output files.  Can be modified by
 * --file-cache-size switch. */
static uint32_t stream_cache_size = STREAM_CACHE_SIZE;

/* Maximum number of input file handles and the number remaining.
 * They are computed as a fraction of the stream_cache_size.  */
static int input_filehandles_max;
static int input_filehandles_left;

/* Mutex controlling access to the 'input_filehandles' variables */
static pthread_mutex_t input_filehandles_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  input_filehandles_cond  = PTHREAD_COND_INITIALIZER;

/* Byte order for newly packed files.  When appending to existing
 * files, use the files' existing byte order. */
static silk_endian_t byte_order = SILK_ENDIAN_NATIVE;

/* When the output_mode is "local-storage" (which is the default),
 * rwflowpack writes the flows to the hourly files located under the
 * root directory (sksiteGetRootDir()). */

/* In the "sending" and "incremental-files" output modes, rwflowpack
 * uses this working directory to create the incremental files while
 * it is processing the incoming records.  This is set by the
 * --incremental-dir switch. */
static const char *incremental_directory = NULL;

/* As of SiLK-3.6.0, incremental files are created as a pair of files,
 * a placeholder file and a working file (aka a dot file).  In the
 * incremental-files mode (new as of SiLK-3.6.0), every flush_timeout
 * seconds the working file replaces the placeholder file, and the
 * incremental-directory is the only directory required.
 */

/* In the "sending" output_mode, every flush_timeout seconds
 * rwflowpack closes the incremental working files, copies them to
 * this destination directory, and removes the placeholder files.
 * This is set by the --sender-dir switch. */
static const char *sender_directory = NULL;

/* This structure holds the user's options related to the type of
 * flow-reader being used. */
static reader_options_t reader_opts;

/* options from the user's command line */
static opt_cache_t *opt_cache = NULL;

/* How to run: Input and Output Modes. Must be kept in sync with the
 * available_modes[] array */
typedef enum {
    INPUT_STREAM,
    INPUT_PDUFILE,
    INPUT_FLOWCAP_FILES,
    INPUT_RESPOOL,
    OUTPUT_LOCAL_STORAGE, OUTPUT_INCREMENTAL_FILES, OUTPUT_SENDING
} io_mode_t;

/* The number of modes */
#define NUM_MODES 7

/* default input and output modes */
static io_mode_t input_mode = INPUT_STREAM;
static io_mode_t output_mode = OUTPUT_LOCAL_STORAGE;

/* The index of the first Output Mode */
static const io_mode_t first_output_mode = OUTPUT_LOCAL_STORAGE;

/* Keep in sync with values in io_mode_t enumeration */
static const struct available_modes_st {
    const io_mode_t iomode;
    const char     *name;
    const char     *title;
    const char     *description;
} available_modes[NUM_MODES] = {
    {INPUT_STREAM, "stream", "Stream Input",
     ("\tRead flow data from the network and/or poll directories for files\n"
      "\tcontaining NetFlow v5 PDUs.  The --polling-interval switch applies\n"
      "\tonly when polling directories.\n")},
    {INPUT_PDUFILE, "pdufile", "PDU-File Input",
     ("\tProcess a single file containing NetFlow v5 PDUs and exit.  The\n"
      "\t--sensor-name switch is required unless the sensor configuration\n"
      "\tfile contains a single sensor.\n")},
    {INPUT_FLOWCAP_FILES, "fcfiles", "Flowcap Files Input",
     ("\tContinually poll a directory for files created by flowcap and\n"
      "\tprocess the data those files contain.\n")},
    {INPUT_RESPOOL, "respool", "Respool SiLK Files Input",
     ("\tContinually poll a directory for SiLK Flow files.  Store the SiLK\n"
      "\tFlow records in each file in the repository, keeping the existing\n"
      "\tsensor ID and flowtype values on each record unchanged.\n")},
    {OUTPUT_LOCAL_STORAGE, "local-storage", "Local-Storage Output",
     ("\tWrite the SiLK Flow records to their final location.\n")},
    {OUTPUT_INCREMENTAL_FILES, "incremental-files", "Incremental-Files Output",
     ("\tWrite the SiLK Flow records to temporary files (called incremental\n"
      "\tfiles) and allow another daemon (such as rwsender or rwflowappend)\n"
      "\tto process the files for final storage.  Files are created and\n"
      "\tstored in the same directory.\n")},
    {OUTPUT_SENDING, "sending", "Sending Output",
     ("\tWrite the SiLK Flow records to temporary files (called incremental\n"
      "\tfiles) and allow another daemon (such as rwsender or rwflowappend)\n"
      "\tto process the files for final storage.  Files are stored in a\n"
      "\tseparate directory from where they are created.\n")},
};

/* which options are valid in which modes. */
static mode_option_t mode_options[NUM_MODES][MAX_OPTION_COUNT];

/* Options for byte-order switch */
static struct {
    const char     *name;
    silk_endian_t   value;
} byte_order_opts[] = {
    {"native", SILK_ENDIAN_NATIVE},
    {"little", SILK_ENDIAN_LITTLE},
    {"big",    SILK_ENDIAN_BIG},
    {NULL,     SILK_ENDIAN_ANY} /* sentinel */
};


/* OPTIONS SETUP */

typedef enum {
    OPT_INPUT_MODE, OPT_OUTPUT_MODE,
    OPT_NO_FILE_LOCKING,
    OPT_FLUSH_TIMEOUT,
    OPT_STREAM_CACHE_SIZE,
    OPT_PACK_INTERFACES, OPT_BYTE_ORDER,
    OPT_ERROR_DIRECTORY,
    OPT_ARCHIVE_DIRECTORY, OPT_FLAT_ARCHIVE, OPT_POST_ARCHIVE_COMMAND,
    OPT_SENSOR_CONFIG, OPT_VERIFY_SENSOR_CONFIG,
#ifndef SK_PACKING_LOGIC_PATH
    OPT_PACKING_LOGIC,
#endif
    OPT_SENSOR_NAME,
    OPT_INCOMING_DIRECTORY, OPT_POLLING_INTERVAL,
    OPT_NETFLOW_FILE,
    OPT_ROOT_DIRECTORY,
    OPT_INCREMENTAL_DIRECTORY, OPT_SENDER_DIRECTORY
} appOptionsEnum;

static struct option appOptions[] = {
    {"input-mode",              REQUIRED_ARG, 0, OPT_INPUT_MODE},
    {"output-mode",             REQUIRED_ARG, 0, OPT_OUTPUT_MODE},

    {"no-file-locking",         NO_ARG,       0, OPT_NO_FILE_LOCKING},
    {"flush-timeout",           REQUIRED_ARG, 0, OPT_FLUSH_TIMEOUT},
    {"file-cache-size",         REQUIRED_ARG, 0, OPT_STREAM_CACHE_SIZE},
    {"pack-interfaces",         NO_ARG,       0, OPT_PACK_INTERFACES},
    {"byte-order",              REQUIRED_ARG, 0, OPT_BYTE_ORDER},

    {"error-directory",         REQUIRED_ARG, 0, OPT_ERROR_DIRECTORY},
    {"archive-directory",       REQUIRED_ARG, 0, OPT_ARCHIVE_DIRECTORY},
    {"flat-archive",            NO_ARG,       0, OPT_FLAT_ARCHIVE},
    {"post-archive-command",    REQUIRED_ARG, 0, OPT_POST_ARCHIVE_COMMAND},

    {"sensor-configuration",    REQUIRED_ARG, 0, OPT_SENSOR_CONFIG},
    {"verify-sensor-config",    OPTIONAL_ARG, 0, OPT_VERIFY_SENSOR_CONFIG},
#ifndef SK_PACKING_LOGIC_PATH
    {"packing-logic",           REQUIRED_ARG, 0, OPT_PACKING_LOGIC},
#endif

    {"sensor-name",             REQUIRED_ARG, 0, OPT_SENSOR_NAME},

    {"incoming-directory",      REQUIRED_ARG, 0, OPT_INCOMING_DIRECTORY},
    {"polling-interval",        REQUIRED_ARG, 0, OPT_POLLING_INTERVAL},

    {"netflow-file",            REQUIRED_ARG, 0, OPT_NETFLOW_FILE},

    {"root-directory",          REQUIRED_ARG, 0, OPT_ROOT_DIRECTORY},

    {"incremental-directory",   REQUIRED_ARG, 0, OPT_INCREMENTAL_DIRECTORY},
    {"sender-directory",        REQUIRED_ARG, 0, OPT_SENDER_DIRECTORY},

    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    ("Select the source of flow records"),
    ("Select the destination for SiLK flow records"),
    ("Do not attempt to lock the files prior to writing\n"
     "\trecords to them. Def. Use locking"),
    ("Time (in seconds) between periodic flushes of open\n"
     "\tSiLK Flow files to disk"),
    ("Maximum number of SiLK Flow files to have open for\n"
     "\twriting simultaneously"),
    ("Include SNMP interface indexes in packed records\n"
     "\t(useful for debugging the router configuration). Def. No"),
    ("Byte order to use for newly packed files:\n"
     "\tChoices: 'native', 'little', or 'big'. Def. native"),

    ("Move input files that are NOT successfully processed\n"
     "\tinto this directory.  If not specified, rwflowpack exits when it\n"
     "\tencounters one of these problem files. Def. None"),
    ("Move input files into this directory after\n"
     "\tprocessing successfully.  When not specified, input files are\n"
     "\tdeleted unless the input mode is 'pdufile'.  In 'stream' input mode,\n"
     "\tthis switch affects 'poll-directory' probes.  Def. None"),
    ("Store files in the root of the archive-directory.\n"
     "\tWhen not given, incremental files are stored in subdirectories of\n"
     "\tthe archive-directory. Def. Use subdirectories"),
    ("Run this command on each input file once it has\n"
     "\tbeen successfully processed and moved to the archive-directory.\n"
     "\tDef. None.  Each \"%s\" in the command is replaced by the full\n"
     "\tpath to the archived file.  Requires use of --archive-directory."),

    ("Read sensor configuration from named file"),
    ("Verify that the sensor configuration file is\n"
     "\tcorrect and immediately exit.  If argument provided, print the names\n"
     "\tof the probes and sensors defined in the file. Def. no"),
#ifndef SK_PACKING_LOGIC_PATH
    ("Specify path to the plug-in that provides functions\n"
     "\tto determine into which class and type each flow record will be\n"
     "\tcategorized and the format of the output files"),
#endif

    ("Ignore all sensors in the sensor-configuration file\n"
     "\texcept this sensor"),

    ("Directory to monitor for input files to process"),
    ("Interval (in seconds) between checks of\n"
     "\tdirectories for new input files to process"),

    ("Read NetFlow v5 flow records from the named file,\n"
     "\tpack the flows, and exit rwflowpack"),
    ("Store the packed files locally under the directory\n"
     "\ttree tree rooted at this location"),

    (char*)NULL,  /* varies by output-mode */
    ("Move the incremental files to this destination\n"
     "\tdirectory to await processing by rwflowappend, rwsender, or another\n"
     "\tprocess"),

    (char *)NULL  /* sentinel entry */
};

/* First option that is mode-specific, i.e., not common to all modes */
static const appOptionsEnum first_mode_option = OPT_SENSOR_CONFIG;


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  appOptionsProcessOpt(int opt_index, char *opt_arg);
static int  byteOrderParse(const char *endian_string);
static int  validateOptions(opt_cache_t *ocache, size_t arg_count);
static int  flowpackSetMaximumFileHandles(int new_max_fh);
static int  startAllProcessors(void);
static void stopAllProcessors(void);
static void printReaderStats(void);
static int  getProbes(sk_vector_t *probe_vec);
static int  createFlowProcessorsFlowcap(void);
static int  createFlowProcessorsRespool(void);
static int  createFlowProcessorsPduFile(void);
static int  createFlowProcessorsStream(void);
static void nullSigHandler(int sig);
static void flushAndMoveFiles(void);
static void moveFiles(cache_file_iter_t *file_list);
static int  defineRunModeOptions(void);
static int  verifySensorConfig(const char *sensor_conf, int verbose);
static int  initPackingLogic(const char *user_path);
#ifndef SK_PACKING_LOGIC_PATH
static int  initPackingLogicFromPlugin(const char *user_path);
#endif


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
    ("<SWITCHES>\n"                                                        \
     "\tRead flow records generated by NetFlow(v5), IPFIX, or flowcap\n"   \
     "\tfrom a socket or from a file and pack the flow records into\n"     \
     "\thourly flat-files organized in a time-based directory structure.\n")

    /* Help strings for --incremental-directory vary by mode */
#define INCREMENTAL_DIR_INCREMENTAL_FILES               \
    ("Directory where incremental files are created\n"  \
     "\tand stored")

#define INCREMENTAL_DIR_SENDING                                         \
    ("Temporary working directory to use while\n"                       \
     "\tbuilding the incremental files prior to moving them to the\n"   \
     "\tsender-directory. Files are moved every flush-timeout seconds")


    FILE *fh = USAGE_FH;
    unsigned int i, j;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);

    fprintf(fh, "\nGeneral switches:\n");
    skOptionsDefaultUsage(fh);

    /* print the "common" (non-mode-specific) options */
    for (i = 0; i <= OPT_BYTE_ORDER; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_FLUSH_TIMEOUT:
            fprintf(fh, "%s. Def. %d", appHelp[i], FLUSH_TIMEOUT);
            break;

          case OPT_STREAM_CACHE_SIZE:
            fprintf(fh, "%s. Range %d-%d. Def. %d",
                    appHelp[i], STREAM_CACHE_MIN,
                    UINT16_MAX, STREAM_CACHE_SIZE);
            break;

          case OPT_INPUT_MODE:
            fprintf(fh, "%s\n\tChoices: %s",
                    appHelp[i], available_modes[0].name);
            for (j = 1; j < first_output_mode; ++j) {
                fprintf(fh, ", %s", available_modes[j].name);
            }
            for (j = 0; j < first_output_mode; ++j) {
                if (j == (unsigned int)input_mode) {
                    fprintf(fh, ". Def. %s", available_modes[j].name);
                    break;
                }
            }
            break;

          case OPT_OUTPUT_MODE:
            fprintf(fh, "%s\n\tChoices: %s",
                    appHelp[i], available_modes[first_output_mode].name);
            for (j = 1+first_output_mode; j < NUM_MODES; ++j) {
                fprintf(fh, ", %s", available_modes[j].name);
            }
            for (j = first_output_mode; j < NUM_MODES; ++j) {
                if (j == (unsigned int)output_mode) {
                    fprintf(fh, ". Def. %s", available_modes[j].name);
                    break;
                }
            }
            break;

          default:
            fprintf(fh, "%s", appHelp[i]);
            break;
        }
        fprintf(fh, "\n");
    }

    skCompMethodOptionsUsage(fh);
    sksiteOptionsUsage(fh);

    fprintf(fh, "\nSwitches for disposal of input flow files:\n");
    for ( ; i < first_mode_option; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    fprintf(fh, "\nLogging and daemon switches:\n");
    skdaemonOptionsUsage(fh);

    /* print options that are used by each input/output mode */
    for (j = 0; j < NUM_MODES; ++j) {
        assert(j == (unsigned int)available_modes[j].iomode);
        fprintf(fh, "\n%s Mode (--%s=%s)",
                available_modes[j].title,
                ((j < first_output_mode)
                 ? appOptions[OPT_INPUT_MODE].name
                 : appOptions[OPT_OUTPUT_MODE].name),
                available_modes[j].name);
        if ((j == (unsigned int)input_mode)||(j == (unsigned int)output_mode))
        {
            fprintf(fh, " [default]");
        }
        fprintf(fh, "\n%s", available_modes[j].description);

        for (i = first_mode_option; appOptions[i].name; ++i) {
            switch (mode_options[j][appOptions[i].val]) {
              case MODOPT_REQUIRED:
              case MODOPT_OPTIONAL:
                fprintf(fh, "--%s %s. ", appOptions[i].name,
                        SK_OPTION_HAS_ARG(appOptions[i]));

                switch (appOptions[i].val) {
                  case OPT_POLLING_INTERVAL:
                    fprintf(fh, "%s. Def. %d", appHelp[i], POLLING_INTERVAL);
                    break;

                  case OPT_INCREMENTAL_DIRECTORY:
                    fprintf(fh, "%s",
                            ((OUTPUT_INCREMENTAL_FILES == j)
                             ? INCREMENTAL_DIR_INCREMENTAL_FILES
                             : INCREMENTAL_DIR_SENDING));
                    break;

                  default:
                    fprintf(fh, "%s", appHelp[i]);
                    break;
                }
                fprintf(fh, "\n");
                break;

              case MODOPT_ILLEGAL:
              case MODOPT_NONSENSE:
                break;
            }
        }
    }
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
    size_t i;
    input_mode_type_t *imt;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (!daemonized) {
        free(opt_cache);
        if (packlogic.teardown_fn != NULL) {
            packlogic.teardown_fn();
        }
        if (packlogic.handle) {
            dlclose(packlogic.handle);
        }
        if (packlogic.path) {
            free(packlogic.path);
        }
        skpcTeardown();
        skdaemonTeardown();
        skAppUnregister();
        return;
    }

    if (input_mode == INPUT_PDUFILE) {
       INFOMSG("Finishing rwflowpack...");
    } else {
       INFOMSG("Begin shutting down...");
    }
    shuttingDown = 1;

    /* broadcast so any poll-dir probes that are waiting for a file
     * handle will wake up and begin shutting down. */
    pthread_cond_broadcast(&input_filehandles_cond);

    printReaderStats();
    stopAllProcessors();

    if (stream_cache) {
        cache_file_iter_t *iter;
        const char *path;
        uint64_t count;

        /* Destroy the cache, flushing, closing and freeing all the
         * open streams.  We're in shutdown, so ignore the return
         * code. */
        INFOMSG("Closing all files...");
        skCacheCloseAll(stream_cache, &iter);
        skCacheDestroy(stream_cache);
        stream_cache = NULL;

        if (OUTPUT_INCREMENTAL_FILES == output_mode) {
            /* In incremental-files mode, go ahead and move the files
             * since it should be a quick operation. */
            moveFiles(iter);
        } else {
            /* Report the files that were closed.  We do not move the
             * files in sending mode since the move may be slow if it
             * crosses file systems. */
            while (skCacheFileIterNext(iter, &path, &count) == SK_ITERATOR_OK){
                INFOMSG(("%s: %" PRIu64 " recs"), path, count);
            }
            skCacheFileIterDestroy(iter);
        }
    }

    if (flow_processors) {
        DEBUGMSG("Destroying the flow processors.");
        for (i = 0; i < num_flow_processors; i++) {
            flow_proc_t *fproc = &flow_processors[i];
            if (fproc->input_mode_type->free_fn != NULL) {
                fproc->input_mode_type->free_fn(fproc);
            }
        }
    }

    DEBUGMSG("Destroying the readers.");
    for (i = 0; i < num_input_mode_types; ++i) {
        imt = &input_mode_types[i];
        if (imt->cleanup_fn != NULL) {
            imt->cleanup_fn();
            imt->cleanup_fn = NULL;
        }
        if (imt->probes != NULL) {
            skVectorDestroy(imt->probes);
            imt->probes = NULL;
        }
    }

    if (flow_processors) {
        free(flow_processors);
        flow_processors = NULL;
    }
    free(opt_cache);

    /* clean up any site-specific memory */
    DEBUGMSG("Unloading the packing logic");
    if (packlogic.teardown_fn != NULL) {
        packlogic.teardown_fn();
    }
    if (packlogic.handle) {
        dlclose(packlogic.handle);
    }
    if (packlogic.path) {
        free(packlogic.path);
    }

    /* teardown the probe configuration */
    skpcTeardown();

    if (input_mode == INPUT_PDUFILE) {
       INFOMSG("Finished processing PDU file.");
    } else {
       INFOMSG("Finished shutting down.");
    }
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
    size_t i;
    int max_fh;
    input_mode_type_t *imt;
    size_t arg_count = sizeof(appOptions)/sizeof(struct option);
    struct sigaction action;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) == arg_count);
    assert(arg_count < MAX_OPTION_COUNT);

    /* verify input_mode_types array is big enough */
    assert(num_input_mode_types <= MAX_INPUT_MODE_TYPE_COUNT);
    assert(_INPUT_MODE_TYPE_MAX_ <= MAX_INPUT_MODE_TYPE_COUNT);

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(input_mode_types, 0, sizeof(input_mode_types));
    memset(&reader_opts, 0, sizeof(reader_opts));
    memset(&packlogic,   0, sizeof(packlogic));

    /* create an array to hold the user's command line options */
    opt_cache = (opt_cache_t*)calloc(arg_count, sizeof(opt_cache_t));
    if (NULL == opt_cache) {
        skAppPrintOutOfMemory(NULL);
        exit(EXIT_FAILURE);
    }

    /* Set which switches are valid for which modes */
    if (defineRunModeOptions()) {
        skAppPrintErr("Unable to initialize modes");
        exit(EXIT_FAILURE);
    }

    /* do not set the comp_method from the environment */
    skCompMethodOptionsNoEnviron();

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler,(clientData)opt_cache)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* rwflowpack runs as a daemon */
    if (skdaemonSetup((SKLOG_FEATURE_LEGACY | SKLOG_FEATURE_SYSLOG),
                      argc, argv))
    {
        exit(EXIT_FAILURE);
    }

    /* Allow each reader to do its initial setup and register its options */
    for (i = 0; i < num_input_mode_types; ++i) {
        imt = &input_mode_types[i];
        if (0 != ((*imt_init_fn_list[i])(imt))) {
            /* initialize failed.  print error and exit. */
            if (imt->reader_name) {
                skAppPrintErr("Unable to setup the %s flow reader",
                              input_mode_types[i].reader_name);
            } else {
                skAppPrintErr("Unable to setup the flow reader number %u",
                              (unsigned int)i);
            }
            exit(EXIT_FAILURE);
        }
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse the options.  This first pass does very little parsing; it
     * primarily fills the 'opt_cache[]' array with the arguments.  The
     * appOptionsProcessOpt() function called by validateOptions() is
     * where most of the parsing actually occurs. */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options handler has printed error */
        skAppUsage();
    }

    /* check for additional arguments */
    if (argc != arg_index) {
        skAppPrintErr("Too many or unrecognized argument specified '%s'",
                      argv[arg_index]);
        skAppUsage();
    }

    /* validate the options */
    if (validateOptions(opt_cache, arg_count)) {
        skAppUsage();  /* never returns */
    }

    /* set input file handles based on stream_cache_size */
    max_fh = (int)((double)stream_cache_size * INPUT_FILEHANDLES_FRACTION);
    if (max_fh < INPUT_FILEHANDLES_MIN) {
        max_fh = INPUT_FILEHANDLES_MIN;
    }
    if (flowpackSetMaximumFileHandles(max_fh)) {
        skAppPrintErr("Cannot set maximum input files to %d", max_fh);
        exit(EXIT_FAILURE);
    }

    /* set polldir file handles based on stream_cache_size */
    max_fh = (int)((double)stream_cache_size * POLLDIR_FILEHANDLES_FRACTION);
    if (max_fh < POLLDIR_FILEHANDLES_MIN) {
        max_fh = POLLDIR_FILEHANDLES_MIN;
    }
    if (skPollDirSetMaximumFileHandles(max_fh)) {
        skAppPrintErr("Cannot set maximum polldirs to %d", max_fh);
        exit(EXIT_FAILURE);
    }

    /* set the mask so that the mode is 0644 */
    (void)umask((mode_t)0022);

    /* Have the main thread handle the signal sent by readers to
     * indicate the reader (i.e., the manageProcessor() function) is
     * exiting.  Normally this is SIGUSR2.  */
    memset(&action, 0, sizeof(action));
    /* mask any further signals while we're inside the handler */
    sigfillset(&action.sa_mask);
    action.sa_handler = &nullSigHandler;
    if (sigaction(READER_DONE_SIGNAL, &action, NULL) == -1) {
        skAppPrintErr("Could not handle SIG%s: %s",
                      skSignalToName(READER_DONE_SIGNAL), strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* who am I? */
    main_thread = pthread_self();
    skthread_init("main");

    return;                       /* OK */
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    This function is passed to skOptionsRegister(); it will be
 *    called by skOptionsParse() for each user-specified switch that
 *    the application has registered; it should handle the switch as
 *    required---typically by setting global variables---and return 1
 *    if the switch processing failed or 0 if it succeeded.  Returning
 *    a non-zero from from the handler causes skOptionsParse() to
 *    return a negative value.
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
    static int arg_count = 0;
    opt_cache_t *ocache = (opt_cache_t*)cData;
    unsigned int i;
    int found_mode;

    switch ((appOptionsEnum)opt_index) {
      case OPT_INPUT_MODE:
        found_mode = 0;
        for (i = 0; i < first_output_mode; ++i) {
            if (0 == strcmp(opt_arg, available_modes[i].name)) {
                found_mode = 1;
                input_mode = (io_mode_t)i;
                break;
            }
        }
        if (!found_mode) {
            skAppPrintErr("Invalid %s '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_OUTPUT_MODE:
        found_mode = 0;
        for (i = first_output_mode; i < NUM_MODES; ++i) {
            if (0 == strcmp(opt_arg, available_modes[i].name)) {
                found_mode = 1;
                output_mode = (io_mode_t)i;
                break;
            }
        }
        if (!found_mode) {
            skAppPrintErr("Invalid %s '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      default:
        if (ocache[opt_index].seen) {
            skAppPrintErr("Switch %s already seen",
                          appOptions[opt_index].name);
            return 1;
        }
        ++arg_count;
        ocache[opt_index].seen = arg_count;
        ocache[opt_index].value = opt_arg;
        break;
    }

    return 0;
}


static int
appOptionsProcessOpt(
    int                 opt_index,
    char               *opt_arg)
{
    uint32_t opt_val;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_ROOT_DIRECTORY:
#ifndef SK_PACKING_LOGIC_PATH
      case OPT_PACKING_LOGIC:
#endif
        /* ignore; it was handled in validateOptions() */
        break;

      case OPT_ERROR_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        errorDirectorySetPath(opt_arg);
        break;

      case OPT_ARCHIVE_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        archiveDirectorySetPath(opt_arg);
        break;

      case OPT_POST_ARCHIVE_COMMAND:
        if (verifyCommandString(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        archiveDirectorySetPostCommand(opt_arg, appOptions[opt_index].name);
        break;

      case OPT_FLAT_ARCHIVE:
        archiveDirectorySetFlat();
        break;

      case OPT_INCREMENTAL_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        incremental_directory = opt_arg;
        break;

      case OPT_SENDER_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        sender_directory = opt_arg;
        break;

      case OPT_BYTE_ORDER:
        return byteOrderParse(opt_arg);

      case OPT_PACK_INTERFACES:
        pack_interfaces = 1;
        break;

      case OPT_NO_FILE_LOCKING:
        no_file_locking = 1;
        break;

      case OPT_SENSOR_CONFIG:
        if (verifySensorConfig(opt_arg, 0)) {
            exit(EXIT_FAILURE);
        }
        break;

      case OPT_SENSOR_NAME:
        sensor_name = opt_arg;
        break;

      case OPT_INCOMING_DIRECTORY:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        switch (input_mode) {
          case INPUT_FLOWCAP_FILES:
            reader_opts.fcfiles.incoming_directory = opt_arg;
            break;
          case INPUT_RESPOOL:
            reader_opts.respool.incoming_directory = opt_arg;
            break;
          default:
            skAbortBadCase(input_mode);
        }
        break;

      case OPT_POLLING_INTERVAL:
        rv = skStringParseUint32(&opt_val, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        switch (input_mode) {
          case INPUT_FLOWCAP_FILES:
            reader_opts.fcfiles.polling_interval = opt_val;
            break;
          case INPUT_STREAM:
            reader_opts.stream_polldir.polling_interval = opt_val;
            break;
          case INPUT_RESPOOL:
            reader_opts.respool.polling_interval = opt_val;
            break;
          default:
            skAbortBadCase(input_mode);
        }
        break;

      case OPT_FLUSH_TIMEOUT:
        rv = skStringParseUint32(&opt_val, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        flush_timeout = opt_val;
        break;

      case OPT_STREAM_CACHE_SIZE:
        rv = skStringParseUint32(&opt_val, opt_arg,
                                 STREAM_CACHE_MIN, INT16_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        stream_cache_size = (int)opt_val;
        break;

      case OPT_NETFLOW_FILE:
        if (opt_arg[0] == '\0') {
            skAppPrintErr("Empty %s supplied", appOptions[opt_index].name);
            return 1;
        }
        reader_opts.pdu_file.netflow_file = opt_arg;
        break;

      case OPT_INPUT_MODE:
      case OPT_OUTPUT_MODE:
      case OPT_VERIFY_SENSOR_CONFIG:
        /* ain't supposed to happen */
        skAbortBadCase(opt_index);
    }

    return 0;                     /* OK */

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

    /* only process option one time */
    if (option_seen != 0) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }
    option_seen = 1;

    len = strlen(endian_string);
    if (len == 0) {
        skAppPrintErr("Invalid %s: Empty string given as argument",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }

    /* initialize byte order */
    byte_order = SILK_ENDIAN_ANY;

    /* parse user's input */
    for (i = 0; byte_order_opts[i].name != NULL; ++i) {
        if ((len <= strlen(byte_order_opts[i].name))
            && (0 == strncmp(byte_order_opts[i].name, endian_string, len)))
        {
            if (byte_order != SILK_ENDIAN_ANY) {
                skAppPrintErr("Ambiguous %s value '%s'",
                              byte_order_opts[i].name, endian_string);
                return 1;
            }
            byte_order = byte_order_opts[i].value;
        }
    }

    if (byte_order == SILK_ENDIAN_ANY) {
        skAppPrintErr("Cannot parse %s value '%s'",
                      appOptions[OPT_BYTE_ORDER].name, endian_string);
        return 1;
    }

    return 0;
}


/*
 *  ok = validateOptions(argc, argv);
 *
 *    Call the options parser.  If options parsing succeeds, validate
 *    that all the required arguments are present, and that the user
 *    didn't give inconsistent arguments.  Returns 0 on success, or -1
 *    otherwise.
 */
static int
validateOptions(
    opt_cache_t        *ocache,
    size_t              arg_count)
{
    fp_daemon_mode_t old_deamon_mode = FP_DAEMON_OFF;
    fp_daemon_mode_t deamon_mode = FP_DAEMON_OFF;
    int daemon_seen;
    input_mode_type_t *imt;
    int options_error = 0;
    size_t i;

    /* Process the root directory first */
    if (ocache[OPT_ROOT_DIRECTORY].seen) {
        if (skOptionsCheckDirectory(ocache[OPT_ROOT_DIRECTORY].value,
                                    appOptions[OPT_ROOT_DIRECTORY].name))
        {
            return -1;
        }
        sksiteSetRootDir(ocache[OPT_ROOT_DIRECTORY].value);
    }

    /* ensure the site config is available; do this after setting the
     * root directory */
    if (sksiteConfigure(1)) {
        exit(EXIT_FAILURE);
    }

    /* setup the probe configuration parser */
    if (skpcSetup()) {
        skAppPrintErr("Unable to setup probe config file parser");
        exit(EXIT_FAILURE);
    }

    /* set the packlogic.* function pointers */
#ifndef SK_PACKING_LOGIC_PATH
    if (ocache[OPT_PACKING_LOGIC].seen) {
        if (initPackingLogic(ocache[OPT_PACKING_LOGIC].value)) {
            exit(EXIT_FAILURE);
        }
    } else
#endif  /* SK_PACKING_LOGIC_PATH */
    {
        if (initPackingLogic(NULL)) {
            exit(EXIT_FAILURE);
        }
    }

    /* setup the site packing logic */
    if ((packlogic.setup_fn != NULL) && (packlogic.setup_fn() != 0)) {
        skAppPrintErr("Unable to setup packing logic plugin");
        exit(EXIT_FAILURE);
    }

    /* if we're only checking the syntax of the sensor.conf file, do
     * that and exit. */
    if (ocache[OPT_VERIFY_SENSOR_CONFIG].seen) {
        int verbose = 0;

        /* any value except empty string and "0" turns on verbose */
        if ((ocache[OPT_VERIFY_SENSOR_CONFIG].value)
            && (ocache[OPT_VERIFY_SENSOR_CONFIG].value[0] != '\0')
            && (0 != strcmp(ocache[OPT_VERIFY_SENSOR_CONFIG].value, "0")))
        {
            verbose = 1;
        }

        /* make certain we have the sensor-config */
        if (!ocache[OPT_SENSOR_CONFIG].seen) {
            skAppPrintErr("The --%s switch is required",
                          appOptions[OPT_SENSOR_CONFIG].name);
            exit(EXIT_FAILURE);
        }
        if (verifySensorConfig(ocache[OPT_SENSOR_CONFIG].value, verbose)) {
            exit(EXIT_FAILURE);
        }
        appTeardown();
        exit(EXIT_SUCCESS);
    }

    /*
     * Do the real options parsing.
     *
     * Given the input and output modes, check for or missing
     * inconsistent switches: Make sure the required options were
     * provided, and that no illegal options were given.  If the
     * option is given and we were supposed to see it, call the "real"
     * options handler to process it.
     */
    for (i = 0; i < arg_count; ++i) {
        if (ocache[i].seen == 0) {
            /* option 'i' not given; see if it is required */
            if (mode_options[input_mode][i] == MODOPT_REQUIRED) {
                skAppPrintErr("The --%s switch is required in %s Mode",
                              appOptions[i].name,
                              available_modes[input_mode].title);
                options_error = 1;
            } else if (mode_options[output_mode][i] == MODOPT_REQUIRED) {
                skAppPrintErr("The --%s switch is required in %s Mode",
                              appOptions[i].name,
                              available_modes[output_mode].title);
                options_error = 1;
            }
        } else {
            /* option 'i' was given; see if it is illegal */
            if (mode_options[input_mode][i] == MODOPT_ILLEGAL) {
                skAppPrintErr("The --%s switch is illegal in %s Mode",
                              appOptions[i].name,
                              available_modes[input_mode].title);
                options_error = 1;
            } else if (mode_options[output_mode][i] == MODOPT_ILLEGAL) {
                skAppPrintErr("The --%s switch is illegal in %s Mode",
                              appOptions[i].name,
                              available_modes[output_mode].title);
                options_error = 1;
            }  else if (appOptionsProcessOpt(i, ocache[i].value)) {
                options_error = 1;
            }
        }
    }

    /* verify the required options for logging */
    if (skdaemonOptionsVerify()) {
        options_error = 1;
    }

    /* --post-archive-command requires --archive-dir */
    if (archiveDirectoryIsSet() == -1) {
        skAppPrintErr("The --%s switch is required when using --%s",
                      appOptions[OPT_ARCHIVE_DIRECTORY].name,
                      appOptions[OPT_POST_ARCHIVE_COMMAND].name);
        options_error = -1;
    }

    /* return if we have options problems */
    if (options_error) {
        return -1;
    }

    /* in pdufile mode, the archiveDirectoryInsertOrRemove() function
     * should not remove the input file when --archive-dir was not
     * given */
    if (INPUT_PDUFILE == input_mode) {
        archiveDirectorySetNoRemove();
    }

    /* Set the polling-interval default value */
    if (ocache[OPT_POLLING_INTERVAL].seen == 0) {
        switch (input_mode) {
          case INPUT_FLOWCAP_FILES:
            reader_opts.fcfiles.polling_interval = POLLING_INTERVAL;
            break;
          case INPUT_STREAM:
            reader_opts.stream_polldir.polling_interval = POLLING_INTERVAL;
            break;
          case INPUT_RESPOOL:
            reader_opts.respool.polling_interval = POLLING_INTERVAL;
            break;
          default:
            break;
        }
    }

    /* make certain we have at least one sensor from the configuration
     * file. */
    if ((mode_options[input_mode][OPT_SENSOR_CONFIG] == MODOPT_REQUIRED)
        && (skpcCountSensors() == 0))
    {
        skAppPrintErr("No sensors were read from the configuration file.");
        return -1;
    }

    /* how we create the flow_processors depends on the input mode. */
    switch (input_mode) {
      case INPUT_FLOWCAP_FILES:
        if (createFlowProcessorsFlowcap()) {
            return -1;
        }
        break;

      case INPUT_PDUFILE:
        if (createFlowProcessorsPduFile()) {
            return -1;
        }
        break;

      case INPUT_STREAM:
        if (createFlowProcessorsStream()) {
            return -1;
        }
        break;

      case INPUT_RESPOOL:
        if (createFlowProcessorsRespool()) {
            return -1;
        }
        break;

      case OUTPUT_LOCAL_STORAGE:
      case OUTPUT_INCREMENTAL_FILES:
      case OUTPUT_SENDING:
        skAbortBadCase(input_mode);
    }

    /* Call the setup function for each active reader; ignore readers
     * that have no probes. */
    daemon_seen = 0;
    for (i = 0; i < num_input_mode_types; ++i) {
        imt = &input_mode_types[i];
        if (NULL == imt->probes) {
            /* Call the cleanup_fn for this reader now? */
            continue;
        }

        if (imt->setup_fn(&deamon_mode, imt->probes, &reader_opts)) {
            return -1;
        }

        /* All the active input_mode_types must have same "daemon-ness" */
        if (daemon_seen == 0) {
            daemon_seen = 1;
            old_deamon_mode = deamon_mode;
        } else if (old_deamon_mode != deamon_mode) {
            skAppPrintErr("Cannot mix probes that work as daemons with\n"
                          "\tprobes that do not.");
            return -1;
        }
    }

    assert(daemon_seen);
    if (deamon_mode == FP_DAEMON_OFF) {
        skdaemonDontFork();
    }

    return 0;
}


/*
 *  status = verifySensorConfig(sensor_conf, verbose);
 *
 *    Verify that the 'sensor_conf' file is valid.  If verbose is
 *    non-zero, print the probes and sensors that were found in the
 *    file.
 *
 *    Return 0 if the file is valid, -1 otherwise.
 */
static int
verifySensorConfig(
    const char         *sensor_conf,
    int                 verbose)
{
    skpc_probe_iter_t probe_iter;
    const skpc_probe_t *probe;
    skpc_sensor_iter_t sensor_iter;
    const skpc_sensor_t *sensor;
    uint32_t count;
    int first;

    /* parse it */
    if (skpcParse(sensor_conf, packlogic.verify_sensor_fn)) {
        skAppPrintErr("Errors while parsing %s file '%s'",
                      appOptions[OPT_SENSOR_CONFIG].name, sensor_conf);
        return -1;
    }

    /* make certain we have at least one sensor from the configuration
     * file. */
    if (skpcCountSensors() == 0) {
        skAppPrintErr("No sensor definitions exist in '%s'", sensor_conf);
        return -1;
    }

    /* if a value was provided to the --verify-sensor switch, be verbose */
    if (verbose) {
        /* print the probes */
        count = skpcCountProbes();
        printf("%s: Successfully parsed %" PRIu32 " probe%s:\n",
               skAppName(), count, CHECK_PLURAL(count));
        if (count) {
            skpcProbeIteratorBind(&probe_iter);
            first = 1;
            while (skpcProbeIteratorNext(&probe_iter, &probe)) {
                if (first) {
                    first = 0;
                    printf("\t%s", skpcProbeGetName(probe));
                } else {
                    printf(", %s", skpcProbeGetName(probe));
                }
            }
            printf("\n");
        }

        /* print the sensors */
        count = skpcCountSensors();
        printf("%s: Successfully parsed %" PRIu32 " sensor%s:\n",
               skAppName(), count, CHECK_PLURAL(count));
        skpcSensorIteratorBind(&sensor_iter);
        first = 1;
        while (skpcSensorIteratorNext(&sensor_iter, &sensor)) {
            if (first) {
                first = 0;
                printf("\t%s", skpcSensorGetName(sensor));
            } else {
                printf(", %s", skpcSensorGetName(sensor));
            }
        }
        printf("\n");
    }

    return 0;
}


/*
 *  status = initPackingLogic(packlogic_path);
 *
 *    Find and call the appropriate initialization function to set the
 *    packlogic.* function pointers.
 *
 *    If the 'input_mode' is RESPOOL, use the respooling-functions.
 *
 *    Else, if the packing logic is compiled in, use that init
 *    function.
 *
 *    Else, call initPackingLogicFromPlugin() to load the packing
 *    logic from a plug-in.
 *
 *    Call the initalize function on the packing-logic "plug-in", and
 *    verify that the required function pointers are set.  Return an
 *    error code if they are not.
 *
 *    If all is well, return 0.
 */
static int
initPackingLogic(
    const char         *packlogic_path)
{
    /* call the appropriate initialization function */
    if (INPUT_RESPOOL == input_mode) {
        /* user is respooling */
        if (packLogicRespoolInitialize(&packlogic)) {
            skAppPrintErr("Unable to initialize respooling function table");
            goto ERROR;
        }
        /* set path to something for error messages */
        packlogic.path = strdup("respool");
        if (NULL == packlogic.path) {
            skAppPrintOutOfMemory(NULL);
            goto ERROR;
        }
    } else
#ifndef SK_PACKING_LOGIC_PATH
    {
        /* packing logic must be loaded from a plug-in */
        if (initPackingLogicFromPlugin(packlogic_path)) {
            goto ERROR;
        }
    }
#else  /* SK_PACKING_LOGIC_PATH */
    {
        /* packing logic is linked-in at compile time */
        const char *plp;

        packlogic_path = SK_PACKING_LOGIC_PATH;

        /* invoke the compiled-in initialization function */
        if (packLogicInitialize(&packlogic)) {
            skAppPrintErr("Unable to initialize packing-logic '%s'",
                          packlogic_path);
            goto ERROR;
        }
        plp = strrchr(packlogic_path, '/');
        if (plp) {
            ++plp;
        } else {
            plp = packlogic_path;
        }
        packlogic.path = strdup(plp);
        if (NULL == packlogic.path) {
            skAppPrintOutOfMemory(NULL);
            goto ERROR;
        }
    }
#endif  /* SK_PACKING_LOGIC_PATH */

    /* make certain required functions were provided */
    if (NULL == packlogic.determine_flowtype_fn) {
        skAppPrintErr(("Cannot find function to determine flowtype in the\n"
                       "\npacking logic plugin %s"),
                      (packlogic.path ? packlogic.path : ""));
        goto ERROR;
    }
    if (NULL == packlogic.verify_sensor_fn) {
        skAppPrintErr(("Cannot find function to verify sensor in the\n"
                       "\npacking logic plugin %s"),
                      (packlogic.path ? packlogic.path : ""));
        goto ERROR;
    }

    /* all OK */
    return 0;

  ERROR:
    if (packlogic.handle) {
        dlclose(packlogic.handle);
        packlogic.handle = NULL;
    }
    if (packlogic.path) {
        free(packlogic.path);
        packlogic.path = NULL;
    }
    return -1;
}


#ifndef SK_PACKING_LOGIC_PATH
/*
 *  status = initPackingLogicFromPlugin(packlogic_path);
 *
 *    If 'packlogic_path' is not NULL, treat it as the name of a
 *    plug-in to load.  If 'packlogic_path' is NULL, attempt to find
 *    the name of the packing packing-logic from the silk.conf file.
 *    If that fails, return -1.
 *
 *    If a name of a plug-in can be determined, attempt to load it,
 *    find the initialization in it, and invoke it to set the function
 *    pointers.  Return -1 on failure.
 *
 *    Return 0 on success.
 */
static int
initPackingLogicFromPlugin(
    const char         *packlogic_path)
{
    int (*init_fn)(packlogic_plugin_t *) = NULL;
    char pack_path[PATH_MAX];
    char dl_path[PATH_MAX];
    char *env_value;
    void *dl_handle = NULL;
    const char *debug = NULL;

    /* check if debug is enabled */
    env_value = getenv(SKPLUGIN_DEBUG_ENVAR);
    if ((NULL != env_value) && ('\0' != env_value[0])) {
        debug = (SKPLUGIN_DEBUG_ENVAR ": ");
    }

    if (NULL == packlogic_path) {
        /* no --packing-logic switch was given on the command line;
         * use the value from the silk.conf file. */
        if (sksiteGetPackingLogicPath(pack_path, sizeof(pack_path))) {
            packlogic_path = pack_path;
        } else {
            /* error if no site-specific packing logic */
            sksiteGetConfigPath(pack_path, sizeof(pack_path));
            skAppPrintErr(("The --%s switch is required since no"
                           " packing-logic statement was found in '%s'"),
                          appOptions[OPT_PACKING_LOGIC].name, pack_path);
            goto ERROR;
        }
    }

    /* Attempt to find the full path to the plug-in, and set 'dl_path'
     * to its path; if we cannot find the path, copy the plug-in's
     * name to 'dl_path' and we'll let dlopen() handle finding the
     * plug-in. */
    if ( !skFindPluginPath(packlogic_path, dl_path, sizeof(dl_path), debug)) {
        strncpy(dl_path, packlogic_path, sizeof(dl_path));
        dl_path[sizeof(dl_path)-1] = '\0';
    }

    /* try to dlopen() the plug-in  */
    if (debug) {
        skAppPrintErr("%sdlopen'ing '%s'", debug, dl_path);
    }
    dl_handle = dlopen(dl_path, RTLD_NOW | RTLD_GLOBAL);
    if (NULL == dl_handle) {
        if (debug) {
            skAppPrintErr("%sdlopen warning: %s",
                          debug, dlerror());
        }
        skAppPrintErr("Unable to open packing-logic '%s'",
                      packlogic_path);
        goto ERROR;
    }
    if (debug) {
        skAppPrintErr("%sdlopen() successful", debug);
    }

    /* get pointer to the initialization function */
    *(void**)&(init_fn) = dlsym(dl_handle, SK_PACKLOGIC_INIT);
    if (NULL == init_fn) {
        if (debug) {
            skAppPrintErr("%sfunction %s not found",
                          debug, SK_PACKLOGIC_INIT);
        }
        skAppPrintErr("Unable to initialize packing-logic '%s'",
                      packlogic_path);
        goto ERROR;
    }

    /* invoke the initialization function */
    if (init_fn(&packlogic)) {
        if (debug) {
            skAppPrintErr("%sfunction %s returned error",
                          debug, SK_PACKLOGIC_INIT);
        }
        skAppPrintErr("Unable to initialize packing-logic '%s'",
                      packlogic_path);
        goto ERROR;
    }

    /* stash the pathname */
    packlogic.path = strdup(dl_path);
    if (NULL == packlogic.path) {
        skAppPrintOutOfMemory(NULL);
        goto ERROR;
    }

    /* fill out the remaining variables on the packlogic object */
    packlogic.handle = dl_handle;

    return 0;

  ERROR:
    if (dl_handle) {
        dlclose(dl_handle);
    }
    return -1;
}
#endif  /* SK_PACKING_LOGIC_PATH */


/*
 *  status = defineRunModeOptions();
 *
 *    Set the values mode_options[][] array.
 */
static int
defineRunModeOptions(
    void)
{
    unsigned int i, j;

    memset(mode_options, MODOPT_ILLEGAL, sizeof(mode_options));

    /* common options; all are optional */
    for (i = 0; i < NUM_MODES; ++i) {
        for (j = 0; j < first_mode_option; ++j) {
            mode_options[i][j] = MODOPT_OPTIONAL;
        }
    }

    /* for the input modes, we don't care whether the output options
     * were specified. */
    for (i = 0; i < first_output_mode; ++i) {
        mode_options[i][OPT_INCREMENTAL_DIRECTORY] = MODOPT_NONSENSE;
        mode_options[i][OPT_SENDER_DIRECTORY] = MODOPT_NONSENSE;
        mode_options[i][OPT_ROOT_DIRECTORY] = MODOPT_NONSENSE;
    }

    /* for the output modes, we don't care about input-only options */
    for (i = first_output_mode; i < NUM_MODES; ++i) {
        mode_options[i][OPT_SENSOR_CONFIG] = MODOPT_NONSENSE;
        mode_options[i][OPT_VERIFY_SENSOR_CONFIG] = MODOPT_NONSENSE;
        mode_options[i][OPT_INCOMING_DIRECTORY] = MODOPT_NONSENSE;
        mode_options[i][OPT_POLLING_INTERVAL] = MODOPT_NONSENSE;
        mode_options[i][OPT_NETFLOW_FILE] = MODOPT_NONSENSE;
        mode_options[i][OPT_SENSOR_NAME] = MODOPT_NONSENSE;
#ifndef SK_PACKING_LOGIC_PATH
        mode_options[i][OPT_PACKING_LOGIC] = MODOPT_NONSENSE;
#endif
    }

    /* for all input modes except respool, set --sensor-conf as
     * required, and make --verify-sensor and --packing-logic
     * optional  */
    for (i = 0; i < first_output_mode; ++i) {
        if (INPUT_RESPOOL == i) {
            continue;
        }
        mode_options[i][OPT_SENSOR_CONFIG] = MODOPT_REQUIRED;
        mode_options[i][OPT_VERIFY_SENSOR_CONFIG] = MODOPT_OPTIONAL;
#ifndef SK_PACKING_LOGIC_PATH
        mode_options[i][OPT_PACKING_LOGIC] = MODOPT_OPTIONAL;
#endif
    }

    /* handle other mode-specific fields. */
    mode_options[INPUT_FLOWCAP_FILES][OPT_INCOMING_DIRECTORY]= MODOPT_REQUIRED;
    mode_options[INPUT_FLOWCAP_FILES][OPT_POLLING_INTERVAL] = MODOPT_OPTIONAL;

    mode_options[INPUT_PDUFILE][OPT_NETFLOW_FILE] = MODOPT_REQUIRED;
    mode_options[INPUT_PDUFILE][OPT_SENSOR_NAME] = MODOPT_OPTIONAL;

    mode_options[INPUT_STREAM][OPT_SENSOR_NAME] = MODOPT_OPTIONAL;
    mode_options[INPUT_STREAM][OPT_POLLING_INTERVAL] = MODOPT_OPTIONAL;

    mode_options[INPUT_RESPOOL][OPT_INCOMING_DIRECTORY]= MODOPT_REQUIRED;
    mode_options[INPUT_RESPOOL][OPT_POLLING_INTERVAL] = MODOPT_OPTIONAL;

    mode_options[OUTPUT_INCREMENTAL_FILES][OPT_INCREMENTAL_DIRECTORY]
        = MODOPT_REQUIRED;

    mode_options[OUTPUT_SENDING][OPT_SENDER_DIRECTORY] = MODOPT_REQUIRED;
    mode_options[OUTPUT_SENDING][OPT_INCREMENTAL_DIRECTORY] = MODOPT_REQUIRED;

    mode_options[OUTPUT_LOCAL_STORAGE][OPT_ROOT_DIRECTORY] = MODOPT_REQUIRED;

    return 0;
}


/*
 *  nullSigHandler(signal);
 *
 *    Do nothing.  Called when the reader thread---that is, the
 *    manageProcessor() function---sends a signal (normally SIGUSR2)
 *    indicating the reader is done.
 */
void
nullSigHandler(
    int                 s)
{
    SK_UNUSED_PARAM(s);
    return;
}


/* Acquire a file handle.  Return 0 on success, or -1 if we have
 * started shutting down.  */
int
flowpackAcquireFileHandle(
    void)
{
    int rv = -1;

    pthread_mutex_lock(&input_filehandles_mutex);
    while (input_filehandles_left <= 0 && !shuttingDown) {
        pthread_cond_wait(&input_filehandles_cond, &input_filehandles_mutex);
    }
    if (!shuttingDown) {
        --input_filehandles_left;
        rv = 0;
    }
    pthread_mutex_unlock(&input_filehandles_mutex);
    return rv;
}


/* Release the file handle. */
void
flowpackReleaseFileHandle(
    void)
{
    pthread_mutex_lock(&input_filehandles_mutex);
    ++input_filehandles_left;
    pthread_cond_signal(&input_filehandles_cond);
    pthread_mutex_unlock(&input_filehandles_mutex);
}


/* Change the maximum number of input filehandles we can use. */
static int
flowpackSetMaximumFileHandles(
    int                 new_max_fh)
{
    if (new_max_fh < 1) {
        return -1;
    }

    pthread_mutex_lock(&input_filehandles_mutex);
    input_filehandles_left += new_max_fh - input_filehandles_max;
    input_filehandles_max = new_max_fh;
    pthread_mutex_unlock(&input_filehandles_mutex);

    return 0;
}


/*
 *  printReaderStats();
 *
 *    Calls the print_stats_fn for each reader, assuming it supports
 *    that functionality.
 */
static void
printReaderStats(
    void)
{
    unsigned i;

    /* Call stats functions for each flow processor */
    for (i = 0; i < num_flow_processors; i++) {
        flow_proc_t *fproc = &flow_processors[i];
        if (fproc->input_mode_type->print_stats_fn) {
            fproc->input_mode_type->print_stats_fn(fproc);
        }
    }
}


/*
 *  timedFlush(NULL);
 *
 *  THREAD ENTRY POINT
 *
 *    This function is invoked by the skTimer_t, and it is used when
 *    the output_mode is OUTPUT_LOCAL_STORAGE.
 *
 *    Flushes all the files in global stream cache stream_cache.
 *
 *    Called every 'flush_timeout' seconds by the timing_thread.
 */
static skTimerRepeat_t
timedFlush(
    void               *dummy)
{
    cache_file_iter_t *iter;
    const char *path;
    uint64_t count;

    SK_UNUSED_PARAM(dummy);

    /* Flush the stream cache */
    NOTICEMSG("Flushing files after %" PRIu32 " seconds.", flush_timeout);
    printReaderStats();
    if (skCacheFlush(stream_cache, &iter)) {
        CRITMSG("Error flushing files -- shutting down");
        exit(EXIT_FAILURE);
    }
    while (skCacheFileIterNext(iter, &path, &count) == SK_ITERATOR_OK) {
        INFOMSG(("%s: %" PRIu64 " recs"), path, count);
    }
    skCacheFileIterDestroy(iter);

    return SK_TIMER_REPEAT;
}


/*
 *  timedFlushAndMove(NULL);
 *
 *  THREAD ENTRY POINT
 *
 *    This function is invoked by the skTimer_t, and it is used when
 *    the output_mode is OUTPUT_INCREMENTAL_FILES or OUTPUT_SENDING.
 *
 *    Closes all the open incremental files in the stream cache and
 *    moves all the working files to their final location, which is
 *    the incremental-directory in OUTPUT_INCREMENTAL_FILES mode and
 *    the sender-directory in OUTPUT_SENDING mode.
 *
 *    Called every 'flush_timeout' seconds by the timing_thread.
 */
static skTimerRepeat_t
timedFlushAndMove(
    void               *dummy)
{
    SK_UNUSED_PARAM(dummy);
    flushAndMoveFiles();
    printReaderStats();

    return SK_TIMER_REPEAT;
}


/*
 *  status = createFlowProcessorsFlowcap()
 *
 *    When processing flowcap files (in fcfiles mode), the
 *    input_mode_type handles all probes, and there is a single
 *    flow_processor.
 */
static int
createFlowProcessorsFlowcap(
    void)
{
    input_mode_type_t *imt;

    /* get the correct reader */
    assert(INPUT_FLOWCAP_FILES == input_mode);
    imt = &input_mode_types[INPUT_MODE_TYPE_FLOWCAP_FILES];

    /* only one flow_processor is required. */
    num_flow_processors = 1;
    flow_processors = (flow_proc_t*)calloc(num_flow_processors,
                                           sizeof(flow_proc_t));
    if (!flow_processors) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }
    flow_processors[0].probe = NULL;
    flow_processors[0].input_mode_type = imt;

    /* need to set the 'probes' field on the input_mode_type to a non-NULL
     * value, so we know the flowcap input_mode_type is in use.  Create an
     * empty vector; no need to fill it. */
    imt->probes = skVectorNew(sizeof(skpc_probe_t*));
    if (imt->probes == NULL) {
        skAppPrintOutOfMemory(NULL);
        free(flow_processors);
        return -1;
    }

    return 0;
}


/*
 *  status = createFlowProcessorsRespool()
 *
 *    When processing SiLK flow files for respooling, there are no
 *    probes, and there is a single flow_processor.
 */
static int
createFlowProcessorsRespool(
    void)
{
    input_mode_type_t *imt;
    skpc_probe_t *probe;

    /* get the correct reader */
    assert(INPUT_RESPOOL == input_mode);
    imt = &input_mode_types[INPUT_MODE_TYPE_RESPOOL];

    /* create a dummy probe that is used when reporting errors */
    if (skpcProbeCreate(&probe, PROBE_ENUM_SILK)) {
        exit(EXIT_FAILURE);
    }
    skpcProbeSetName(probe, "RESPOOL");
    skpcProbeSetPollDirectory(probe, reader_opts.respool.incoming_directory);
    if (skpcProbeVerify(probe, 0)) {
        exit(EXIT_FAILURE);
    }

    /* only one flow_processor is required. */
    num_flow_processors = 1;
    flow_processors = (flow_proc_t*)calloc(num_flow_processors,
                                           sizeof(flow_proc_t));
    if (!flow_processors) {
        skAppPrintOutOfMemory(NULL);
        return -1;
    }
    flow_processors[0].probe = probe;
    flow_processors[0].input_mode_type = imt;

    /* need to set the 'probes' field on the input_mode_type to a non-NULL
     * value, so we know the respool input_mode_type is in use.  Create an
     * empty vector; no need to fill it. */
    imt->probes = skVectorNew(sizeof(skpc_probe_t*));
    if (imt->probes == NULL) {
        skAppPrintOutOfMemory(NULL);
        free(flow_processors);
        return -1;
    }

    return 0;
}


/*
 *  status = createFlowProcessorsPduFile()
 *
 *    Search through the sensors to find the probe that will handle
 *    the PDU files.  It is an error if there is more than one.
 *    Create the single flow processor that will handle this probe.
 *
 *    Return 0 if everything is correct, or non-zero otherwise.
 */
static int
createFlowProcessorsPduFile(
    void)
{
    sk_vector_t *probe_vec;
    skpc_probe_t *have_probe = NULL;
    skpc_probe_t **p;
    input_mode_type_t *imt;
    size_t j;
    int rv = -1;

    assert(INPUT_PDUFILE == input_mode);

    /* get the reader, we know which reader we are using */
    imt = &input_mode_types[INPUT_MODE_TYPE_PDU_FILE];

    /* create vector to hold probes */
    probe_vec = skVectorNew(sizeof(skpc_probe_t*));
    if (NULL == probe_vec) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* get the probes; either all probes or those listed in the global
     * 'sensor_name' */
    if (getProbes(probe_vec)) {
        goto END;
    }
    if (0 == skVectorGetCount(probe_vec)) {
        skAbort();
    }

    /*
     *  There should only be a single probe that we want to process
     *  for this invocation.  In reality, we should support an
     *  unlimited number of probes as long as they all map to the same
     *  sensor.  Also, forcing the user to specify a probe when we
     *  know we are reading from the file system is kludgy; we should
     *  just be able to cons-up the proper probe on the fly....
     */

    for (j = 0;
         NULL != (p = (skpc_probe_t**)skVectorGetValuePointer(probe_vec, j));
         ++j)
    {
        if (imt->want_probe_fn(*p)) {
            if (NULL != have_probe) {
                /* ERROR: more than one probe */
                skAppPrintErr(("Multiple %s probes specified.  The %s input\n"
                               "\tmode requires a single probe"
                               " that reads from a file."),
                              skpcProbetypeEnumtoName(PROBE_ENUM_NETFLOW_V5),
                              available_modes[INPUT_PDUFILE].name);
                goto END;
            }
            have_probe = *p;
        }
    }

    if (NULL == have_probe) {
        /* ERROR: no valid probe */
        skAppPrintErr("Could not find any probes to use for %s input mode",
                      available_modes[INPUT_PDUFILE].name);
        goto END;
    }

    /* looks good.  create the flow processor */
    num_flow_processors = 1;
    flow_processors = (flow_proc_t*)calloc(num_flow_processors,
                                           sizeof(flow_proc_t));
    if (!flow_processors) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    flow_processors[0].probe = have_probe;
    flow_processors[0].input_mode_type = imt;

    /* re-use the existing probe vector and attach it to the
     * input-mode-type */
    if (skVectorGetCount(probe_vec) != 1) {
        /* need to clean it out */
        skVectorSetCapacity(probe_vec, 0);
        if (skVectorAppendValue(probe_vec, &have_probe)) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }
    imt->probes = probe_vec;

    /* success */
    rv = 0;

  END:
    if (rv != 0) {
        /* failure.  clean up the vectors and the flow_processors[] */
        free(flow_processors);
        flow_processors = NULL;
        skVectorDestroy(probe_vec);
    }
    return rv;
}


/*
 *  status = createFlowProcessorsStream()
 *
 *    Search through the sensors to find probes that the stream-based
 *    input-mode-types (PDU, IPFIX, etc) can use.  Create a flow
 *    processor for each probe, and add the probe to the
 *    input-mode-type's probe-list.
 *
 *    Return 0 if everything is correct, or non-zero otherwise.
 */
static int
createFlowProcessorsStream(
    void)
{
    sk_vector_t *probe_vec;
    size_t count;
    size_t i, j;
    input_mode_type_t *imt;
    input_mode_type_t *probe_imt;
    skpc_probe_t **p;
    int have_poll_dir = 0;
    int rv = -1;
#if SK_ENABLE_IPFIX
    int initialized_ipfix = 0;
#endif

    /* create vector to hold the probes */
    probe_vec = skVectorNew(sizeof(skpc_probe_t*));
    if (NULL == probe_vec) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* get the probes; either all probes or those specified in the
     * global 'sensor_name' */
    if (getProbes(probe_vec)) {
        goto END;
    }
    count = skVectorGetCount(probe_vec);
    if (0 == count) {
        skAbort();
    }

    /* as an upper limit, each probe will be used and will have its
     * own flow_processor. */
    num_flow_processors = 0;
    flow_processors = (flow_proc_t*)calloc(count, sizeof(flow_proc_t));
    if (!flow_processors) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* attempt to assign each probe to a input_mode_type */
    for (j = 0;
         NULL != (p = (skpc_probe_t**)skVectorGetValuePointer(probe_vec, j));
         ++j)
    {
        /* find the reader that will process the probe.  there can be
         * no more than one. */
        probe_imt = NULL;
        for (i = 0; i < num_input_mode_types; ++i) {
            /* ignore non-stream input modes */
            switch ((input_mode_type_id_t)i) {
              case INPUT_MODE_TYPE_FLOWCAP_FILES:
              case INPUT_MODE_TYPE_PDU_FILE:
                continue;
              default:
                break;
            }

            imt = &input_mode_types[i];
            if (imt->want_probe_fn != NULL && imt->want_probe_fn(*p)) {
                /* reader 'imt' can process probe 'p'.  If 'probe_imt'
                 * is not-NULL, multiple readers are attempting to
                 * claim the probe.  This shouldn't happen, and
                 * probably indicates a programming error. */
                if (NULL != probe_imt) {
                    skAppPrintErr("Multiple readers can process probe %s",
                                  skpcProbeGetName(*p));
                    goto END;
                }
                probe_imt = imt;
            }
        }
        if (probe_imt == NULL) {
            /* no reader wants to process this probe */
            skAppPrintErr("Warning: Ignoring probe '%s' in %s input mode",
                          skpcProbeGetName(*p),
                          available_modes[INPUT_STREAM].name);
            continue;
        }

        assert(num_flow_processors < count);
        flow_processors[num_flow_processors].probe = *p;
        flow_processors[num_flow_processors].input_mode_type = probe_imt;
        num_flow_processors++;

        /* if we haven't seen any probes with a poll-directory yet,
         * check if this probe has one. */
        if (!have_poll_dir) {
            if (skpcProbeGetPollDirectory(*p)) {
                have_poll_dir = 1;
            }
        }

        /* add the probe to the 'probes' vector on the input_mode_type,
         * creating the vector if it does not exist. */
        if (probe_imt->probes == NULL) {
            probe_imt->probes = skVectorNew(sizeof(skpc_probe_t*));
            if (probe_imt->probes == NULL) {
                skAppPrintOutOfMemory(NULL);
                goto END;
            }
        }
        if (skVectorAppendValue(probe_imt->probes, p)) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }

#if SK_ENABLE_IPFIX
        /* if we haven't initialized the IPFIX source, do that now */
        if (0 == initialized_ipfix
            && (PROBE_ENUM_IPFIX == skpcProbeGetType(*p)
                || PROBE_ENUM_SFLOW == skpcProbeGetType(*p)
                || PROBE_ENUM_NETFLOW_V9 == skpcProbeGetType(*p)))
        {
            if (skIPFIXSourcesSetup()) {
                skAppPrintErr(("Cannot use %s probes: "
                               "GLib2 does not support multiple threads"),
                              skpcProbetypeEnumtoName(skpcProbeGetType(*p)));
                goto END;
            }
        }
#endif /* SK_ENABLE_IPFIX */
    }

    if (0 == num_flow_processors) {
        skAppPrintErr("Found no probes to use for %s input mode",
                      available_modes[INPUT_STREAM].name);
        goto END;
    }

    /* sanity check that we processed every probe. */
    if (j != count) {
        skAppPrintErr("Error getting probe %u from vector",
                      (unsigned int)j);
        goto END;
    }

    /* if no probes are using a poll-directory, warn if --archive-dir,
     * --post-archive-command, --error-dir, or --polling-interval were
     * given. */
    if (!have_poll_dir) {
#define NUM_IGNORED_OPTS 4
        int ignored_opts[NUM_IGNORED_OPTS]
            = {OPT_ARCHIVE_DIRECTORY, OPT_POST_ARCHIVE_COMMAND,
               OPT_ERROR_DIRECTORY, OPT_POLLING_INTERVAL};
        for (i = 0; i < NUM_IGNORED_OPTS; ++i) {
            if (opt_cache[ignored_opts[i]].seen) {
                skAppPrintErr(("Ignoring --%s since no probes"
                               " use directory polling"),
                              appOptions[ignored_opts[i]].name);
            }
        }
    }

    /* we could realloc flow_processors[] here */

    /* success */
    rv = 0;

  END:
    if (rv != 0) {
        /* failure.  clean up the vectors and the flow_processors[] */
        for (i = 0; i < num_input_mode_types; ++i) {
            if (input_mode_types[i].probes != NULL) {
                skVectorDestroy(input_mode_types[i].probes);
                input_mode_types[i].probes = NULL;
            }
        }
        if (flow_processors) {
            free(flow_processors);
            flow_processors = NULL;
        }
    }
    if (probe_vec) {
        skVectorDestroy(probe_vec);
    }
    return rv;
}


/*
 *  status = getProbes(out_probe_vector);
 *
 *    If the global 'sensor_name' is NULL, then append each verified
 *    probe specified in the sensor.conf file to the
 *    'out_probe_vector' if the probe is associated with a sensor.
 *
 *    If 'sensor_name' is non-NULL, treat it as a C string containing
 *    a comma separated list of Sensor Names.  Append all the verified
 *    probes defined in the sensor-configuration file that appear in
 *    the sensor-list to the 'out_probe_vector'.
 *
 *    Note that if a probe is used by two sensors, the probe will be
 *    enabled if either of the sensor names is specified in the
 *    'sensor_name' global.
 *
 *    In either case, return 0 if probes were found and they were
 *    added to the vector.  Return -1 if no verified probes were
 *    found, if probes do not exist for a specified sensor, if there
 *    is an error parsing the 'sensor_list', or for a memory
 *    allocation error.
 */
static int
getProbes(
    sk_vector_t        *probe_vec)
{
    sk_vector_t *tmp_vec = NULL;
    skpc_probe_iter_t p_iter;
    const skpc_probe_t *p;
    const skpc_probe_t **p_ptr;
    const skpc_probe_t **p_ptr2;
    skpc_sensor_iter_t s_iter;
    const skpc_sensor_t *sensor;
    char *sensor_name_copy = NULL;
    char *sensor_name_tokens;
    char *sensor_token;
    int found_sensor;
    size_t i;
    size_t j;
    int seen;
    int rv = -1;

    /* If the global 'sensor-name' is NULL, return all verified probes
     * that are associated with a sensor. */
    if (NULL == sensor_name) {
        /* get each probe from probeconf and append to 'probe_vec' */
        skpcProbeIteratorBind(&p_iter);
        while (skpcProbeIteratorNext(&p_iter, &p)) {
            if (0 == skpcProbeGetSensorCount(p)) {
                continue;
            }
            if (0 == skpcProbeIsVerified(p)) {
                continue;
            }
            if (skVectorAppendValue(probe_vec, &p)) {
                skAppPrintOutOfMemory(NULL);
                return -1;
            }
        }

        if (0 == skVectorGetCount(probe_vec)) {
            skAppPrintErr("No probes are associated with the sensors");
            return -1;
        }
        return 0;
    }

    /* create a temporary vector to hold the probes */
    tmp_vec = skVectorNew(sizeof(skpc_probe_t*));
    if (NULL == probe_vec) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* create modifiable copy of the 'sensor_name' */
    sensor_name_copy = strdup(sensor_name);
    sensor_name_tokens = sensor_name_copy;
    if (NULL == sensor_name_copy) {
        goto END;
    }

    /* loop over list of sensor names; for each name find the
     * corresponding sensor object; for each object, find the probes
     * for that sensor. */
    while ((sensor_token = strsep(&sensor_name_tokens, ",")) != NULL) {
        /* check for empty token (e.g., double comma) */
        if ('\0' == *sensor_token) {
            continue;
        }

        /* loop over all sensors */
        found_sensor = 0;
        skpcSensorIteratorBind(&s_iter);
        while (skpcSensorIteratorNext(&s_iter, &sensor)) {
            /* find the named sensor */
            if (0 != strcmp(sensor_token, skpcSensorGetName(sensor))) {
                continue;
            }
            ++found_sensor;

            /* get the probes for the sensor and add to tmp_vec */
            skpcSensorGetProbes(sensor, tmp_vec);
        }

        if (0 == found_sensor) {
            skAppPrintErr("Sensor configuration does not define sensor '%s'",
                          sensor_token);
            goto END;
        }
    }

    /* filter any unverified probes out of tmp_vec, and ensure that
     * each probe only gets added to probe_vec one time. */
    for (i = 0;
         (p_ptr = (const skpc_probe_t**)skVectorGetValuePointer(tmp_vec, i))
             != NULL;
         ++i)
    {
        if (0 == skpcProbeIsVerified(*p_ptr)) {
            continue;
        }
        seen = 0;
        for (j = 0;
             (p_ptr2=(const skpc_probe_t**)skVectorGetValuePointer(probe_vec,j))
                 != NULL;
             ++j)
        {
            if (*p_ptr == *p_ptr2) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            if (skVectorAppendValue(probe_vec, p_ptr)) {
                skAppPrintOutOfMemory(NULL);
                goto END;
            }
        }
    }

    if (0 == skVectorGetCount(probe_vec)) {
        skAppPrintErr("No probes founds for sensor '%s'", sensor_name);
        goto END;
    }

    /* success */
    rv = 0;

  END:
    if (tmp_vec != NULL) {
        skVectorDestroy(tmp_vec);
    }
    if (sensor_name_copy != NULL) {
        free(sensor_name_copy);
    }
    return rv;
}


/*
 *    Determine the flow record format and version to use for a newly
 *    opened output file.
 *
 *    This function calls one of the functions defined in the-logic
 *    plug-in (typically probeconf-<SITE>.c) to get the format and
 *    version if the plug-in provdes such a function.
 *
 *    If the --pack-interfaces switch was given, the type returned by
 *    the plug-in is "rounded up" to a format that contains SNMP
 *    information.
 *
 *    If the plug-in does not define the needed function, return the
 *    most compact file format capable of holding all the infomation
 *    that this installation of SiLK supports.  All these file formats
 *    provide space for the next-hop IP address and SNMP interface
 *    information.
 */
static sk_file_format_t
determineFormatVersion(
    const skpc_probe_t *probe,
    sk_flowtype_id_t    ftype,
    sk_file_version_t  *version)
{
    sk_file_format_t file_format;

    *version = SK_RECORD_VERSION_ANY;
    if (packlogic.determine_formatversion_fn) {
        file_format = packlogic.determine_formatversion_fn(probe, ftype,
                                                           version);
    } else if (packlogic.determine_fileformat_fn) {
        file_format = packlogic.determine_fileformat_fn(probe, ftype);
    } else
#if   SK_ENABLE_IPV6
    {
        return FT_RWIPV6ROUTING;
    }
#else  /* SK_ENABLE_IPV6 */
    {
        if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
            /* Use a format that does not use bytes/packet ratio */
            *version = 5;
            return FT_RWAUGROUTING;
        }
        if (PROBE_ENUM_NETFLOW_V5 == skpcProbeGetType(probe)) {
            return FT_RWROUTED;
        }
        return FT_RWAUGROUTING;
    }
#endif  /* #else of #if SK_ENABLE_IPV6 */

    if (!pack_interfaces) {
        return file_format;
    }

    /* "round up" the format to one that includes SNMP interfaces */
    switch (file_format) {
      case FT_RWAUGROUTING:
      case FT_RWFILTER:
      case FT_RWGENERIC:
      case FT_RWIPV6ROUTING:
      case FT_RWROUTED:
        /* these all include interface information and the
         * next-hop IP. */
        return file_format;

      case FT_FLOWCAP:
        /* change the format and version */
        *version = SK_RECORD_VERSION_ANY;
        return FT_RWAUGROUTING;

      case FT_RWAUGMENTED:
      case FT_RWAUGWEB:
      case FT_RWAUGSNMPOUT:
        /* change the format; retain the version */
        return FT_RWAUGROUTING;

      case FT_RWIPV6:
        /* change the format and version */
        *version = SK_RECORD_VERSION_ANY;
        return FT_RWIPV6ROUTING;

      case FT_RWNOTROUTED:
      case FT_RWSPLIT:
      case FT_RWWWW:
        if (*version < 3) {
            /* V1 and V2 only use 8 bits for SNMP interfaces */
            *version = 3;
        }
        return FT_RWROUTED;

      default:
        skAbortBadCase(file_format);
    }
}


/*
 *  stream = openOutputStreamIncr(key, probe, pathname);
 *
 *    Create an open stream in the incremental-directory to store flow
 *    records for the 'flowtype', hourly 'timestamp', and 'sensor_id'
 *    contained in the structure 'key'.
 *
 *    If the {flowtype,sensor_id,timestamp} has been seen since the
 *    most recent call to flushAndMoveFiles(), the existing file is
 *    opened.  If not, a new incremental file is created, where the
 *    file's basename is determined by using the file location rules
 *    that are specified in the silk.conf file.
 *
 *    Returns the stream on success, or NULL on error.
 *
 *    This a callback function that will be invoked by the stream
 *    cache function, skCacheLookupOrOpenAdd() when the output-mode is
 *    OUTPUT_INCREMENTAL_FILES or OUTPUT_SENDING.
 */
static skstream_t *
openOutputStreamIncr(
    const cache_key_t  *key,
    void               *v_probe,
    const char         *pathname)
{
    const skpc_probe_t *probe = (skpc_probe_t*)v_probe;
    char dotpath[PATH_MAX];
    char placepath[PATH_MAX];
    char *fname;
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    sk_file_format_t file_format;
    sk_file_version_t file_version;
    size_t sz;
    int fd;
    int rv;

    assert(OUTPUT_INCREMENTAL_FILES == output_mode
           || OUTPUT_SENDING == output_mode);

    TRACEMSG(1, (("openOutputStreamIncr() called for"
                  " {flowtype = %u, sensor = %u, time = %" PRId64 "}"),
                 key->flowtype_id, key->sensor_id, (int64_t)key->time_stamp));

    if (pathname) {
        /* Open existing file for append, and read its header */
        DEBUGMSG("Opening existing incremental working file '%s'",
                 pathname);

        if ((rv = skStreamCreate(&stream, SK_IO_APPEND, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(stream, pathname))
            || (rv = skStreamOpen(stream))
            || (rv = skStreamReadSilkHeader(stream, NULL)))
        {
            skStreamPrintLastErr(stream, rv, &WARNINGMSG);
            skStreamDestroy(&stream);
            WARNINGMSG(("Failed to open existing incremental file '%s'."
                        " Creating new incremental file..."),
                       pathname);
            /* Drop into the code below. */
        } else {
            /* Successful */
            return stream;
        }
    }

    /* We must create a new placeholder file, create a dot file, and
     * store information about this file in the incr_path_map */

    /* initialize variables */
    placepath[0] = '\0';
    dotpath[0] = '\0';
    fd = -1;

    /* Call the function to get the file's record format and
     * version---HOW the records will be written to disk. */
    file_format = determineFormatVersion(probe,key->flowtype_id,&file_version);

    /* Build the file name--WHERE the records will be written onto
     * disk.  First get the filename, then make the path to the
     * placeholder file.  (NOTE: This is not the actual dotpath; we
     * are just using that buffer; 'fname' is what we want.) */
    if (!sksiteGeneratePathname(dotpath, sizeof(dotpath),
                                key->flowtype_id, key->sensor_id,
                                key->time_stamp, "", NULL, &fname))
    {
        CRITMSG(("Unable to generate pathname to file"
                 " {flowtype = %u, sensor = %u, time = %" PRId64 "}"),
                key->flowtype_id, key->sensor_id, (int64_t)key->time_stamp);
        dotpath[0] = '\0';
        goto ERROR;
    }
    dotpath[0] = '\0';

    TRACEMSG(2, ("Incremental file basename is '%s'", fname));

    sz = (size_t)snprintf(placepath, sizeof(placepath), "%s/%s%s",
                          incremental_directory, fname, temp_suffix);
    if (sz >= sizeof(placepath)) {
        CRITMSG("Placeholder pathname exceeds maximum size for '%s'", fname);
        placepath[0] = '\0';
        goto ERROR;
    }

    /* Open the file; making sure its name is unique */
    fd = mkstemp(placepath);
    if (-1 == fd) {
        CRITMSG("Unable to create and open file '%s': %s",
                placepath, strerror(errno));
        placepath[0] = '\0';
        goto ERROR;
    }
    fchmod(fd, 0644);
    rv = close(fd);
    fd = -1;
    if (-1 == rv) {
        CRITMSG("Unable to close file '%s': %s",
                placepath, strerror(errno));
        goto ERROR;
    }

    /* Set fname to point into placepath */
    fname = strrchr(placepath, '/');
    if (NULL == fname) {
        CRITMSG("Cannot find basename of '%s'", placepath);
        goto ERROR;
    }
    ++fname;

    INFOMSG("Opening new incremental file '%s'", fname);

    /* Create the path to the dotfile */
    sz = (size_t)snprintf(dotpath, sizeof(dotpath), "%s/.%s",
                          incremental_directory, fname);
    if (sz >= sizeof(dotpath)) {
        CRITMSG("Dot pathname exceeds buffer size");
        dotpath[0] = '\0';
        goto ERROR;
    }

    /* Open the dot file.  The while() will repeat only if the dot
     * file already exists and can be removed successfully. */
    while ((fd = open(dotpath, O_WRONLY | O_CREAT | O_EXCL, 0644))
           == -1)
    {
        /* Remove the dotfile if it exists and try again; otherwise
         * give up on this file. */
        int saveerrno = errno;
        if (errno == EEXIST) {
            WARNINGMSG("Working file already exists. Removing '%s'",
                       dotpath);
            if (unlink(dotpath) == 0) {
                continue;
            }
            WARNINGMSG("Failed to unlink existing working file '%s': %s",
                       dotpath, strerror(errno));
        }
        CRITMSG("Could not create '%s': %s",
                dotpath, strerror(saveerrno));
        dotpath[0] = '\0';
        goto ERROR;
    }

    TRACEMSG(1, ("Opened new working file '%s'", dotpath));

    /* Create an skstream_t from the 'fd' */
    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(stream, dotpath))
        || (rv = skStreamFDOpen(stream, fd)))
    {
        /* NOTE: it is possible for skStreamFDOpen() to have stored
         * the value of 'fd' but return an error. */
        if (stream && skStreamGetDescriptor(stream) == fd) {
            fd = -1;
        }
        skStreamPrintLastErr(stream, rv, &CRITMSG);
        goto ERROR;
    }
    /* The stream controls this now */
    fd = -1;

    TRACEMSG(2, ("Created stream for working file '.%s'", fname));

    /* Get file's header and fill it in */
    hdr = skStreamGetSilkHeader(stream);
    if ((rv = skHeaderSetFileFormat(hdr, file_format))
        || (rv = skHeaderSetRecordVersion(hdr, file_version))
        || (rv = skHeaderSetCompressionMethod(hdr, comp_method))
        || (rv = skHeaderSetByteOrder(hdr, byte_order))
        || (rv = skHeaderAddPackedfile(hdr, key->time_stamp,
                                       key->flowtype_id, key->sensor_id))
        || (rv = skStreamWriteSilkHeader(stream)))
    {
        skStreamPrintLastErr(stream, rv, &CRITMSG);
        goto ERROR;
    }

    TRACEMSG(2, ("Wrote header for working file '.%s'", fname));

    return stream;

  ERROR:
    if (stream) {
        TRACEMSG(2, ("Destroying stream"));
        skStreamDestroy(&stream);
    }
    if (-1 != fd) {
        TRACEMSG(2, ("Closing file"));
        close(fd);
    }
    if (dotpath[0]) {
        TRACEMSG(2, ("Unlinking working path '%s'", dotpath));
        unlink(dotpath);
    }
    if (placepath[0]) {
        TRACEMSG(2, ("Unlinking placeholder path '%s'", placepath));
        unlink(placepath);
    }
    return NULL;
}


/*
 *  stream = openOutputStreamRepo(key, probe, pathname);
 *
 *    Create an open stream in the local data repository to store
 *    flow records for the 'flowtype', hourly 'timestamp', and
 *    'sensor_id' contained in the structure 'key'.
 *
 *    The file's location is determined by using the file location
 *    rules that are specified in the silk.conf file.
 *
 *    The endianness of the new file is determined by the global
 *    'byte_order' variable.  The compression method of the new file
 *    is determined by the 'comp_method' global if that value is set
 *    to a valid compression method.
 *
 *    Gets a write lock on the file.
 *
 *    Returns the stream on success, or NULL on error.
 *
 *    This a callback function that will be invoked by the stream
 *    cache function, skCacheLookupOrOpenAdd() when the output-mode is
 *    OUTPUT_LOCAL_STORAGE.
 */
static skstream_t *
openOutputStreamRepo(
    const cache_key_t  *key,
    void               *v_probe,
    const char         *pathname)
{
    const skpc_probe_t *probe = (skpc_probe_t*)v_probe;
    char repo_file[PATH_MAX];
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    sk_file_format_t file_format;
    sk_file_version_t file_version;
    skstream_mode_t mode;
    int rv;

    assert(OUTPUT_LOCAL_STORAGE == output_mode);

    TRACEMSG(1, (("openOutputStreamRepo() called for"
                  " {flowtype = %u, sensor = %u, time = %" PRId64 "}"),
                 key->flowtype_id, key->sensor_id, (int64_t)key->time_stamp));

    if (NULL == pathname) {
        /* Build the file name--WHERE the records will be written onto
         * disk. */
        if (!sksiteGeneratePathname(repo_file, sizeof(repo_file),
                                    key->flowtype_id, key->sensor_id,
                                    key->time_stamp, "", NULL, NULL))
        {
            CRITMSG(("Unable to generate pathname to file"
                     " {flowtype = %u, sensor = %u, time = %" PRId64 "}"),
                    key->flowtype_id, key->sensor_id, (int64_t)key->time_stamp);
            return NULL;
        }
        pathname = repo_file;
    }

    stream = openRepoStream(pathname, &mode, no_file_locking, &shuttingDown);
    if (NULL == stream) {
        return NULL;
    }
    if (SK_IO_APPEND == mode) {
        return stream;
    }

    /* Call the function to get the file's record format and
     * version---HOW the records will be written to disk. */
    file_format = determineFormatVersion(probe,key->flowtype_id,&file_version);

    /* Get file's header and fill it in */
    hdr = skStreamGetSilkHeader(stream);
    if ((rv = skHeaderSetFileFormat(hdr, file_format))
        || (rv = skHeaderSetRecordVersion(hdr, file_version))
        || (rv = skHeaderSetCompressionMethod(hdr, comp_method))
        || (rv = skHeaderSetByteOrder(hdr, byte_order))
        || (rv = skHeaderAddPackedfile(hdr, key->time_stamp,
                                       key->flowtype_id, key->sensor_id)))
    {
        skStreamPrintLastErr(stream, rv, &WARNINGMSG);
        skStreamDestroy(&stream);
        return NULL;
    }

    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        skStreamPrintLastErr(stream, rv, &WARNINGMSG);
        NOTICEMSG("Error creating repository file; truncating size to 0: '%s'",
                  pathname);
        /* On error, truncate file to 0 bytes so it does not contain a
         * partially written header.  Do not unlink it, since another
         * rwflowpack process may have opened the file and be waiting
         * to obtain the write lock. */
        rv = skStreamTruncate(stream, 0);
        if (rv) {
            skStreamPrintLastErr(stream, rv, &WARNINGMSG);
        }
        skStreamDestroy(&stream);
    }

    return stream;
}


/*
 *  ok = packRecord(probe, rwrec);
 *
 *    Given a flow record, 'rwrec', that has been read from 'probe',
 *    determine the flowtype- and sensor-value(s) for that record and
 *    pack it into the correct file(s) using the appropriate file
 *    output format(s).
 *
 *    Return 0 on success.  Return -1 to indicate a fatal error.
 *    Return 1 to indicate a non-fatal write error or an error to
 *    determine the flowtype and sensor for the record.
 */
static int
packRecord(
    const skpc_probe_t *probe,
    rwRec              *rwrec)
{
    cache_entry_t *entry;
    cache_key_t key;
    sk_flowtype_id_t ftypes[MAX_SPLIT_FLOWTYPES];
    sk_sensor_id_t sensorids[MAX_SPLIT_FLOWTYPES];
    skstream_t *stream;
    int count;
    int rec_is_bad;
    int i;
    int rv;

    /* Get the record's sensor(s) and flow_type(s) by calling
     * the packLogicDetermineFlowtype() function */
    count = packlogic.determine_flowtype_fn(probe, rwrec, ftypes, sensorids);
    assert(count >= -1);
    assert(count < MAX_SPLIT_FLOWTYPES);
    if (count == -1) {
        NOTICEMSG(("Cannot determine flowtype of record from"
                   " probe %s: input %d; output %d"),
                  skpcProbeGetName(probe), rwRecGetInput(rwrec),
                  rwRecGetOutput(rwrec));
        return 1;
    }


    /* clear the memo field */
    rwRecSetMemo(rwrec, 0);

    /* have we logged this record as bad? */
    rec_is_bad = 0;

    /* Determine the hour this data is associated with.  This is a UTC
     * value expressed in milliseconds since the unix epoch, rounded
     * (down) to the hour. */
    key.time_stamp = rwRecGetStartTime(rwrec);
    key.time_stamp -= key.time_stamp % 3600000;

    /* Store the record in each flowtype/sensor file. */
    for (i = 0; i < count; ++i) {
        /* The flowtype (class/type) and sensor says where the flow
         * was collected and where to write the flow. */
        key.flowtype_id = ftypes[i];
        rwRecSetFlowType(rwrec, ftypes[i]);
        key.sensor_id = sensorids[i];
        rwRecSetSensor(rwrec, sensorids[i]);

        /* Get the file from the cache, which may use an open file,
         * open an existing file, or create a new file as required.
         * If the file is not already open, this function will invoke
         * openOutputStream() to open or create the file.  */
        rv = skCacheLookupOrOpenAdd(stream_cache, &key, (void*)probe, &entry);
        if (rv) {
            if (-1 == rv) {
                /* problem opening file or adding file to cache */
                CRITMSG(("Error opening file for probe '%s' -- "
                         " shutting down"),
                        skpcProbeGetName(probe));
            } else if (1 == rv) {
                /* problem closing existing cache entry */
                CRITMSG("Error closing file -- shutting down");
            } else {
                CRITMSG(("Unexpected error code from stream cache %d -- "
                         "shutting down"),
                        rv);
            }
            return -1;
        }

        /* Write record */
        stream = skCacheEntryGetStream(entry);
        rv = skStreamWriteRecord(stream, rwrec);
        if (SKSTREAM_OK != rv) {
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                skStreamPrintLastErr(stream, rv, &ERRMSG);
                CRITMSG(("Error writing record for probe '%s' -- "
                         " shutting down"),
                        skpcProbeGetName(probe));
                skCacheEntryRelease(entry);
                return -1;
            }
            skStreamPrintLastErr(stream, rv, &WARNINGMSG);
            rec_is_bad = 1;
        }

        /* unlock stream */
        skCacheEntryRelease(entry);
    }

    return rec_is_bad;
}


/*
 *  manageProcessor(fproc);
 *
 *  THREAD ENTRY POINT for the 'process_thread'.
 *
 *    Gets a flow record from the flowsource object and passes the
 *    record to writeRecord() for storage.  Runs until the flow
 *    source stream is exhausted (for file-based readers), until the
 *    global variable 'reading' is set to 0, or until an error occurs.
 */
static void *
manageProcessor(
    void               *vp_fproc)
{
    flow_proc_t *fproc = (flow_proc_t*)vp_fproc;
    input_mode_type_t *input_mode_type = fproc->input_mode_type;
    rwRec rec;
    const skpc_probe_t *probe;
    int rv;

    DEBUGMSG("Started manager thread for %s", input_mode_type->reader_name);

    for (;;) {
        /* get the next record that was read by the reader */
        switch (input_mode_type->get_record_fn(&rec, &probe, fproc)) {
          case FP_FILE_BREAK:
            /* We've processed one input file; there may be more input
             * files.  This is a safe place to quit, so if we are no
             * longer reading, break out of the while().  Otherwise we
             * try again to get a record---we didn't get a record this
             * time. */
            if (!reading) {
                goto END;
            }
            continue;

          case FP_END_STREAM:
            /* We've processed all the input; there is no more.  Tell
             * the sender to send the packed files we've created.
             * Set 'shuttingDown' to begin the shutdown process. */
            flushAndMoveFiles();
            shuttingDown = 1;
            goto END;

          case FP_GET_ERROR:
            /* An error occurred and we did not get a record.  Break
             * out of the while() if we are no longer reading,
             * otherwise try again to get a record. */
            if (!reading) {
                goto END;
            }
            continue;

          case FP_FATAL_ERROR:
            /* Exit the program.  The get_record_fn should have logged
             * an error. */
            shuttingDown = 1;
            goto END;

          case FP_BREAK_POINT:
            /* We got a record, and this is a safe place to quit if we
             * are no longer reading.  If not shutting down, process
             * the record. */
            if (!reading) {
                goto END;
            }
            /* FALLTHROUGH */

          case FP_RECORD:
            /* We got a record and we may NOT stop processing.
             * Process the record. */
            ++fproc->rec_count_total;
            rv = packRecord(probe, &rec);
            if (rv) {
                if (-1 == rv) {
                    shuttingDown = 1;
                    goto END;
                }
                ++fproc->rec_count_bad;
            }
            break;

        } /*switch*/
    } /*while*/

  END:
    DEBUGMSG("Stopping manager thread for %s", input_mode_type->reader_name);

    /* thread is ending, decrement the count */
    pthread_mutex_lock(&fproc_thread_count_mutex);
    --fproc_thread_count;
    pthread_mutex_unlock(&fproc_thread_count_mutex);

    /* send a signal (normally SIGUSR2) to the main thread to tell it
     * to check the thread count */
    pthread_kill(main_thread, READER_DONE_SIGNAL);
    return NULL;
}


/*
 *  status = startTimer();
 *
 *    Start the timer thread.  Return 0 on success, or -1 on failure.
 */
static int
startTimer(
    void)
{
    skTimerRepeat_t (*timer_func)(void*) = NULL;

    switch (output_mode) {
      case OUTPUT_LOCAL_STORAGE:
        timer_func = &timedFlush;
        break;

      case OUTPUT_INCREMENTAL_FILES:
      case OUTPUT_SENDING:
        if (input_mode == INPUT_PDUFILE) {
            /* disable timer */
            timer_func = NULL;
        } else {
            timer_func = &timedFlushAndMove;
        }
        break;

      default:
        skAbortBadCase(output_mode);
    }

    /* Start timer */
    if (timer_func) {
        INFOMSG("Starting flush timer");
        if (skTimerCreate(&timing_thread, flush_timeout, timer_func, NULL)
            == -1)
        {
            ERRMSG("Unable to start flush timer.");
            return -1;
        }
    }

    return 0;
}


/*
 *  status = startAllProcessors();
 *
 *    For each flow-processor, call its start function and spawn a
 *    thread to manage that processor.
 *
 *    Start the timing_thread to flush/send files when appropriate.
 *
 *    Return 1 if something fails, or 0 for success.
 */
static int
startAllProcessors(
    void)
{
    flow_proc_t *fproc;
    size_t i;

    assert(stream_cache);

    /* Start each flow_processor, but don't start reading records
     * until every processor is running */
    for (i = 0; i < num_flow_processors; ++i) {
        fproc = &flow_processors[i];

        DEBUGMSG("Starting flow processor #%" SK_PRIuZ " for %s",
                 (i + 1u), fproc->input_mode_type->reader_name);

        if (fproc->input_mode_type->start_fn(fproc) != 0) {
            ERRMSG(("Unable to start flow processor #%" SK_PRIuZ " for %s"),
                   (i + 1u), fproc->input_mode_type->reader_name);
            return 1;
        }
    }

    reading = 1;

    /* Spawn threads to read records from each processor */
    for (i = 0; i < num_flow_processors; ++i) {
        fproc = &flow_processors[i];

        pthread_mutex_lock(&fproc_thread_count_mutex);
        ++fproc_thread_count;
        pthread_mutex_unlock(&fproc_thread_count_mutex);

        if (skthread_create(fproc->input_mode_type->reader_name,
                            &fproc->thread, &manageProcessor, fproc))
        {
            ERRMSG(("Unable to create manager thread #%" SK_PRIuZ " for %s"),
                   (i + 1u), fproc->input_mode_type->reader_name);
            pthread_mutex_lock(&fproc_thread_count_mutex);
            --fproc_thread_count;
            pthread_mutex_unlock(&fproc_thread_count_mutex);
            reading = 0;
            return 1;
        }
    }

    /* Start timer */
    if (startTimer()) {
        return 1;
    }

    return 0;
}


static void
stopAllProcessors(
    void)
{
    flow_proc_t *fproc;
    size_t i;

    if (reading) {
        INFOMSG("Stopping processors...");
        reading = 0;

        /* Give the threads a chance to quit on their own---by their
         * checking the 'reading' variable. */
        sleep(2);

        if (timing_thread != NULL) {
            DEBUGMSG("Stopping timer");
            skTimerDestroy(timing_thread);
        }

        /* stop each flow processor and join its thread */
        INFOMSG("Waiting for record handlers...");
        for (i = 0; i < num_flow_processors; ++i) {
            fproc = &flow_processors[i];
            DEBUGMSG(("Stopping flow processor #%" SK_PRIuZ ": %s"),
                     (i + 1u), fproc->input_mode_type->reader_name);
            fproc->input_mode_type->stop_fn(fproc);
            pthread_join(fproc->thread, NULL); /* join */
        }

        INFOMSG("Stopped processors.");
    }
}


/*
 *  status = moveToSenderDir(base, dotpath, placepath);
 *
 *    Move the file whose basename is 'base' and whose full path is
 *    'dotpath' into the sender-directory.  Delete 'placepath' after
 *    moving 'dotfile'.  Return 0 on success, or -1 on failure.
 *
 *    The filename in 'base' is expected to have a mkstemp() type
 *    extension on the end.  This function attempts to move the file
 *    into the sender-directory without changing the extension.
 *    However, if a file with that name already exists, the existing
 *    entension is removed and a new one is generated in its place.
 */
static int
moveToSenderDir(
    const char         *filebase,
    const char         *dotpath,
    const char         *placepath)
{
    char senderpath[PATH_MAX];
    char *ep;
    int fd;
    int rv;

    assert(filebase);
    assert(dotpath);

    TRACEMSG(1, ("Moving to sender_dir file '%s'", filebase));

    /* Generate template for the new path in the final location */
    if ((size_t)snprintf(senderpath, sizeof(senderpath), "%s/%s",
                         sender_directory, filebase)
        >= sizeof(senderpath))
    {
        WARNINGMSG(("Not moving file:"
                    " Destination path exceeds maximum size for '%s'"),
                   filebase);
        return -1;
    }

    /* Attempt to exclusively create the destination */
    fd = open(senderpath, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (-1 != fd) {
        /* Opened the destination; we can simply copy the dotfile
         * here. */
        TRACEMSG(1, ("Opened destination file '%s'", senderpath));
        close(fd);
    } else {
        TRACEMSG(1, ("Failed to create file '%s': %s",
                     senderpath, strerror(errno)));

        /* Replace current temporary suffix with .XXXXXX */
        ep = strrchr(senderpath, '.');
        if ((NULL == ep) || (strlen(ep) + 1u != sizeof(temp_suffix))) {
            WARNINGMSG(("Not moving file:"
                        " Did not find temporary suffix in '%s'"),
                       filebase);
            return -1;
        }
        strncpy(ep, temp_suffix, sizeof(temp_suffix));

        /* Fill the template */
        fd = mkstemp(senderpath);
        if (-1 == fd) {
            ERRMSG("Could not create and open temporary file '%s': %s",
                   senderpath, strerror(errno));
            return -1;
        }
        TRACEMSG(1, ("Opened destination file (new suffix) '%s'", senderpath));
        close(fd);
    }

    /* Move the dotpath over the senderpath */
    rv = skMoveFile(dotpath, senderpath);
    if (rv != 0) {
        ERRMSG("Could not move file '%s' to '%s': %s",
               dotpath, senderpath, strerror(rv));
        return -1;
    }

    /* Remove the placeholder file */
    TRACEMSG(1, ("Removing placeholder file '%s'", placepath));
    if (unlink(placepath) == -1) {
        ERRMSG("Cannot remove file '%s': %s",
               placepath, strerror(errno));
        return -1;
    }

    INFOMSG("%s", senderpath);
    return 0;
}


/*
 *  flushAndMoveFiles();
 *
 *    When in incremental-files or sending output-mode, closes all the
 *    open files in the stream cache and calls moveFiles() with the
 *    list of closed incremental files.
 *
 *    Called repeatedly by the timedFlushAndMove() function every
 *    flush_timeout seconds.  (In the pdufile input-mode, called after
 *    the single file is procesed).
 */
static void
flushAndMoveFiles(
    void)
{
    cache_file_iter_t *incr_files;

    /* Return if incremental-files or sending mode not specified */
    if (OUTPUT_INCREMENTAL_FILES != output_mode
        && OUTPUT_SENDING != output_mode)
    {
        return;
    }

    NOTICEMSG("Closing and moving incremental files...");

    /* Close all the output files. */
    if (skCacheCloseAll(stream_cache, &incr_files)) {
        CRITMSG("Error closing incremental files -- shutting down");
        exit(EXIT_FAILURE);
    }

    moveFiles(incr_files);
}


/*
 *  moveFiles(incr_files);
 *
 *    Processes the files that were created since the previous flush
 *    timeout that are contained in 'incr_files'.
 *
 *    In incremental-files mode, copies the dot-file over the
 *    placeholder-file in the incremental-directory.
 *
 *    In sending mode, moves the dot-file in the incremental-directory
 *    to the sender-directory and removes the placeholder file in the
 *    incremental-directory.
 */
static void
moveFiles(
    cache_file_iter_t  *incr_files)
{
    char placepath[PATH_MAX];
    const char *dotpath;
    const char *dot_basename;
    size_t file_count;
    size_t moved_count;
    uint64_t count;

    file_count = skCacheFileIterCountEntries(incr_files);
    if (0 == file_count) {
        NOTICEMSG("No incremental files to move.");
        skCacheFileIterDestroy(incr_files);
        return;
    }

    INFOMSG("Moving %" SK_PRIuZ " incremental files...", file_count);
    moved_count = 0;

    /* Visit all files in incr_files */
    while (skCacheFileIterNext(incr_files, &dotpath, &count) == SK_ITERATOR_OK)
    {
        dot_basename = strrchr(dotpath, '/');
        if (!dot_basename) {
            dot_basename = dotpath;
        } else {
            ++dot_basename;
        }
        INFOMSG("%s: %" PRIu64 " recs", dotpath, count);
        assert(strlen(dot_basename) >= 2);
        assert('.' == *dot_basename);
        TRACEMSG(1, ("moveFiles(): Processing '%s'", dot_basename));
        if ((size_t)snprintf(placepath, sizeof(placepath), "%s/%s",
                             incremental_directory, dot_basename + 1)
            >= sizeof(placepath))
        {
            ERRMSG("Pathname exceeds maximum size for '%s'",
                   dot_basename);
            continue;
        }

        if (OUTPUT_SENDING == output_mode) {
            if (moveToSenderDir(dot_basename + 1, dotpath, placepath)
                == 0)
            {
                ++moved_count;
            }
        } else {
            /* Move the dot-file over the placeholder file. */
            if (-1 == rename(dotpath, placepath)) {
                ERRMSG("Could not move '%s' to '%s': %s",
                       dotpath, placepath, strerror(errno));
            } else {
                /* Moved the file. */
                ++moved_count;
                INFOMSG("%s", placepath);
            }
        }
    }
    skCacheFileIterDestroy(incr_files);

    /* Print status message */
    NOTICEMSG(("Successfully moved %" SK_PRIuZ "/%" SK_PRIuZ " file%s."),
              moved_count, file_count, CHECK_PLURAL(file_count));
}


/*
 *  checkIncrementalDir();
 *
 *    This function is used shortly after start-up when the
 *    output-mode is incremental-files or sending.
 *
 *    The function checks the files in the incremental-directory and
 *    "cleans up" any that appear to be left-over from a previous run
 *    of rwflowpack.
 *
 *    It checks for regular files that have a size of 0 and that do
 *    not begin with a dot.  (This is the placeholder file).  Then, it
 *    checks to see if a file exists whose name is "." followed by the
 *    same set of characters.  If so, that pair of files is assumed to
 *    be from a previous run.
 *
 *    If the current mode is incremental-files, the dot-file will
 *    replace the placeholder file.  If the current mode is sending,
 *    the dot-file is moved to the sender-directory and the
 *    placeholder file is removed.
 */
static void
checkIncrementalDir(
    void)
{
    char placepath[PATH_MAX];
    char dotpath[PATH_MAX];
    struct dirent *entry;
    DIR *dir;
    struct stat st;
    size_t file_count = 0;
    size_t moved_count = 0;
    int rv;

    if (OUTPUT_INCREMENTAL_FILES != output_mode
        && OUTPUT_SENDING != output_mode)
    {
        skAbortBadCase(output_mode);
    }

    NOTICEMSG("Checking incremental directory for old files...");

    /* Open the incremental directory and loop over the files in the
     * directory */
    dir = opendir(incremental_directory);
    if (NULL == dir) {
        CRITMSG("Fatal error: Unable to open incremental directory '%s': %s",
                incremental_directory, strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Ignore dot-files */
        if ('.' == entry->d_name[0]) {
            TRACEMSG(2, ("checkIncrDir(): Skipping '%s'", entry->d_name));
            continue;
        }

        /* Make complete path to file */
        if ((size_t)snprintf(placepath, sizeof(placepath), "%s/%s",
                             incremental_directory, entry->d_name)
            >= sizeof(placepath))
        {
            WARNINGMSG("Pathname exceeds maximum size for '%s'",
                       entry->d_name);
            continue;
        }

        /* Ignore files that are not regular files */
        rv = stat(placepath, &st);
        if (-1 == rv) {
            if (EEXIST != errno) {
                WARNINGMSG("Unable to stat '%s': %s",
                           placepath, strerror(errno));
            }
            continue;
        }
        if (!(st.st_mode & S_IFREG)) {
            DEBUGMSG("Ignoring non-file '%s'", entry->d_name);
            continue;
        }

        /* Ignore files that have non-zero size. NOTE: this means
         * SiLK-3.6.0 running in "sending" mode will ignore files left
         * by SiLK-3.5.x and older. */
        if (st.st_size > 0) {
            DEBUGMSG("Ignoring file with non-zero size '%s'", entry->d_name);
            continue;
        }

        /* Check for a corresponding dotfile from a previous run */
        if ((size_t)snprintf(dotpath, sizeof(dotpath), "%s/.%s",
                             incremental_directory, entry->d_name)
            >= sizeof(dotpath))
        {
            WARNINGMSG("Working path exceeds maximum size for '%s'",
                       entry->d_name);
            continue;
        }
        rv = stat(dotpath, &st);
        if (rv == -1 || !(st.st_mode & S_IFREG)) {
            DEBUGMSG("Ignoring file with no corresponding work file '%s'",
                     entry->d_name);
            continue;
        }
        if (st.st_size == 0) {
            DEBUGMSG("Ignoring file with empty work file '%s'",
                     entry->d_name);
            continue;
        }

        /* Move this file.  Ideally, we should open the file, get a
         * lock on the file, verify that it is a SiLK file, and then
         * move it.  Purpose of getting a lock is to avoid clashing
         * with a running rwflowpack. */

        if (OUTPUT_SENDING == output_mode) {
            if (moveToSenderDir(entry->d_name, dotpath, placepath) == 0) {
                ++moved_count;
            }
        } else {
            /* Move the dotfile over the placeholder file */
            if (-1 == rename(dotpath, placepath)) {
                WARNINGMSG("Failed to move '%s' to '%s': %s",
                           dotpath, placepath, strerror(errno));
            } else {
                /* Moved the file. */
                ++moved_count;
                INFOMSG("%s", placepath);
            }
        }
    }

    closedir(dir);

    /* Print status message */
    if (file_count == 0) {
        NOTICEMSG("No incremental files to move.");
    } else {
        NOTICEMSG("Successfully moved %" SK_PRIuZ "/%" SK_PRIuZ " file%s.",
                  moved_count, file_count, CHECK_PLURAL(file_count));
    }
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);                 /* never returns on error */

    /* start the logger and become a daemon */
    if (skdaemonize(&shuttingDown, NULL) == -1
        || sklogEnableThreadedLogging() == -1)
    {
        exit(EXIT_FAILURE);
    }
    daemonized = 1;

    /* Log a message about the packing logic we are using */
    INFOMSG("Using packing logic from %s", packlogic.path);

    /* Create a cache of streams (file handles) so we don't have to
     * incur the expense of reopening files */
    INFOMSG("Creating stream cache");
    if (output_mode == OUTPUT_LOCAL_STORAGE) {
        stream_cache = skCacheCreate(stream_cache_size, &openOutputStreamRepo);
        if (NULL == stream_cache) {
            CRITMSG("Unable to create stream cache.");
            exit(EXIT_FAILURE);
        }

    } else if (output_mode == OUTPUT_INCREMENTAL_FILES
               || output_mode == OUTPUT_SENDING)
    {
        stream_cache = skCacheCreate(stream_cache_size, &openOutputStreamIncr);
        if (NULL == stream_cache) {
            CRITMSG("Unable to create stream cache.");
            exit(EXIT_FAILURE);
        }

        /* Check for partial files in the incremental-directory from a
         * previous run. */
        checkIncrementalDir();

    } else {
        skAbortBadCase(output_mode);
    }

    /* Choose which processing thread to run based on user choice */
    if (startAllProcessors() != 0) {
        CRITMSG("Unable to start flow processor");
        exit(EXIT_FAILURE);
    }

    /* We now run forever, excepting signals, until the shuttingDown
     * flag is set or until all flow-processor threads exit. */
    while (!shuttingDown && fproc_thread_count > 0) {
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
