/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
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
**  rwrecgenerator
**
**    Mark Thomas
**    May 2011
**
**
**    Command to generate random SiLK Flow records.
**
**    Usage information is provided in the manual page.
**
**    The code uses lrand48() to generate random values, which will
**    provide consistent values across every platform where it is
**    available.
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwrecgenerator.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skbag.h>
#include <silk/skipaddr.h>
#include <silk/sklog.h>
#include <silk/skmempool.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>
#include "stream-cache.h"
#include "skheap-rwrec.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* whether to use the heap to sort records by their end-time */
#ifndef RECGEN_USE_HEAP
#  define RECGEN_USE_HEAP  0
#endif

#if !RECGEN_USE_HEAP
#  define skRwrecHeapInsert(rhi_heap, rhi_rec)  writeRecord(rhi_rec)
#endif

/* where to write --help output */
#define USAGE_FH stdout

/* where to write --version output */
#define VERS_FH stdout

/* number of SiLK flow records to use in initial allocations */
#define INITIAL_RWREC_COUNT  0x100000

/* mask to use when creating a new IP address (except when generating
 * a host scan).  this allows us to reduce the number of IPs used.
 * Make certain the mask has the bits 0 and bits 30 turned on */
/* #define IP_V4_MASK  0xc31e87a5 */
#define IP_V4_MASK  0xdbdddee7

/* default size of the stream cache when making incremenatal flows */
#define FILE_CACHE_SIZE  32

/* default value for how often, in milliseconds to flush the
 * incremental files */
#define RECGEN_FLUSH_TIMEOUT  30000

/* constants for referencing the flowtype[] array */
typedef enum rand_flowtype_en {
    FLOWTYPE_IN, FLOWTYPE_INWEB, FLOWTYPE_OUT, FLOWTYPE_OUTWEB
} rand_flowtype_t;

/* number of flowtypes */
#define NUM_FLOWTYPES  4

/* milliseconds per hour */
#define MILLISEC_PER_HOUR  3600000

/* how to adjust the seed of the subprocesses */
#define RECGEN_SUBPROC_SEED_ADJUST(rssa_seed, rssa_index) \
    ((rssa_seed) + ((rssa_index) * 0x00353535))

#ifndef _BITMASK64

/* In the following, 'x' is the value to get/set bits of; 's' is size
 * or number of bits; 'o' is the offset at which to start, where 0 is
 * the LSB; 'v' is the source value when setting bits. */
#define _BITMASK64(s)                                   \
    (((s) >= 64) ? UINT64_MAX : ~(UINT64_MAX << (s)))

#define GET_MASKED_BITS64(x, o, s) (((x) >> (o)) & _BITMASK64((s)))

#define SET_MASKED_BITS64(x, v, o, s)                   \
    do {                                                \
        (x) = (((x) & (~(_BITMASK64(s) << (o))))        \
               | (((v) & _BITMASK64(s)) << (o)));       \
    } while(0)

#endif  /* _BITMASK64 */

/* this structure holds a pointer to the genration functions, the
 * approximate percentage of time they will be invoked, how many flow
 * records they return.  The 'dispatch_value' is determined based on
 * the other numbers in this structure. */
typedef struct dispatch_table_st {
    int       (*generator)(const skipaddr_t *, const skipaddr_t *);
    uint32_t    target_percent;
    uint32_t    flows_per_func;
    uint32_t    dispatch_value;
} dispatch_table_t;


typedef struct recgen_subprocess_st {
    char        processing_dir[PATH_MAX];
    sktime_t    start_time;
    sktime_t    end_time;
    uint32_t    seed;
    pid_t       pid;
    unsigned    started  :1;
    unsigned    finished :1;
} recgen_subprocess_t;


/* LOCAL FUNCTION PROTOTYPES */

static void appUsageLong(void);
static void appTeardown(void);
static void appSetup(int argc, char **argv);
static void appExit(int exit_status) NORETURN;
static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseFlowtype(rand_flowtype_t which_ft, const char *string);
static void initDispatchTable(void);
static int  initSubprocStructure(void);
static void emptyProcessingDirectory(void);
static skstream_t *
openIncrementalFile(
    const cache_key_t  *key,
    void               *v_file_format);
static int generateDns(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateFtp(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateHttp(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateIcmp(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateImap(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateOtherProto(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generatePop3(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateSmtp(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateTcpHostScan(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateTcpPortScan(const skipaddr_t *ip1, const skipaddr_t *ip2);
static int generateTelnet(const skipaddr_t *ip1, const skipaddr_t *ip2);


/* LOCAL CONSTANTS */

/* output fields to produce for textual output */
static const uint32_t field_list[] = {
    RWREC_FIELD_SIP, RWREC_FIELD_DIP,
    RWREC_FIELD_SPORT, RWREC_FIELD_DPORT, RWREC_FIELD_PROTO,
    RWREC_FIELD_PKTS, RWREC_FIELD_BYTES,
    RWREC_FIELD_STIME, RWREC_FIELD_ELAPSED, RWREC_FIELD_ETIME,
    RWREC_FIELD_SID, RWREC_FIELD_FTYPE_CLASS, RWREC_FIELD_FTYPE_TYPE,
    RWREC_FIELD_INIT_FLAGS, RWREC_FIELD_REST_FLAGS,
    RWREC_FIELD_TCP_STATE, RWREC_FIELD_APPLICATION,
    RWREC_FIELD_ICMP_TYPE, RWREC_FIELD_ICMP_CODE
};

/* position of least significant bit, as in 1<<N */
static const uint8_t lowest_bit_in_val[] = {
    /*   0- 15 */  8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  16- 31 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  32- 47 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  48- 63 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  64- 79 */  6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  80- 95 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  96-111 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 112-127 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 128-143 */  7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 144-159 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 160-175 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 176-191 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 192-207 */  6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 208-223 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 224-239 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 240-255 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

/* position of most significant bit, as in 1<<N */
static const uint8_t highest_bit_in_val[] = {
    /*   0- 15 */  0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    /*  16- 31 */  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    /*  32- 47 */  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    /*  48- 63 */  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    /*  64- 79 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /*  80- 95 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /*  96-111 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /* 112-127 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /* 128-143 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 144-159 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 160-175 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 176-191 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 192-207 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 208-223 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 224-239 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    /* 240-255 */  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
};

/* number of high bits in each value */
static const uint8_t bits_in_value[] = {
    /*   0- 15 */  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    /*  16- 31 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  32- 47 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  48- 63 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  64- 79 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  80- 95 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  96-111 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 112-127 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 128-143 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /* 144-159 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 160-175 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 176-191 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 192-207 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 208-223 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 224-239 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 240-255 */  4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};


/* LOCAL VARIABLE DEFINITIONS */

static dispatch_table_t dispatch_table[] = {
    {generateHttp,          60,     2, 0},
    {generateDns,           10,     2, 0},
    {generateFtp,            4,     2, 0},
    {generateIcmp,           4,     1, 0},
    {generateImap,           4,     2, 0},
    {generateOtherProto,     4,     1, 0},
    {generatePop3,           4,     2, 0},
    {generateSmtp,           4,     2, 0},
    {generateTelnet,         4,     4, 0},
    {generateTcpHostScan,    1,   128, 0},
    {generateTcpPortScan,    1, 65536, 0}
};

static const size_t num_generators = (sizeof(dispatch_table)
                                      / sizeof(dispatch_table[0]));

/* the program's idea of the current time */
static sktime_t current_time;

/* time window at which flows begin.  is set by the --start-time
 * switch.  defaults to start of previous hour */
static sktime_t start_time;

/* time window at which flows end.  is set by the --end-time switch.
 * defaults to end of previous hour */
static sktime_t end_time;

/* how large of a time step to take.  is set by the --time-step switch
 * and defaults to the difference between start-time and end-time */
static sktime_t time_step;

/* how many events to produce at each time step.  is set by the
 * --events-per-step switch.  defaults to 1 */
static uint32_t events_per_step = 1;

/* when writing a single file of flow records, specifies the location
 * to write them.  set by the --silk-output-path switch. */
static skstream_t *silk_output_path = NULL;

/* when writing a file of textual output, specifies the ascii stream
 * and the file handle on which to write them.  set by the
 * --text-output-path switch. */
static rwAsciiStream_t *text_output_ascii;
static sk_fileptr_t text_output;

/* when writing textual output, how to print IP addresses.  set by the
 * --ip-format switch. */
static uint32_t ip_format = SKIPADDR_CANONICAL;

/* flags when registering --ip-format */
static const unsigned int ip_format_register_flags =
    (SK_OPTION_IP_FORMAT_INTEGER_IPS | SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);

/* when writing textual output, how to print timestamps.  set by the
 * --timestamp-format switch. */
static uint32_t time_flags = 0;

/* flags when registering --timestamp-format */
static const uint32_t time_register_flags = SK_OPTION_TIMESTAMP_OPTION_EPOCH;

/* when generating incremental files (like rwflowpack creates),
 * specifies the directory in which to copy them at the flush timeout.
 * set by the --output-directory switch. */
static const char *output_directory;

/* the working directory in which to create the incremental files.
 * set by the --processing-directory switch. */
static const char *processing_directory;

/* number of subprocesses to use when filling the output directory
 * with incremental files.  set by the --num-subprocesses switch.  */
static uint32_t num_subprocesses = 0;

/* sensor prefix map that maps from IPs to sensor.  specified by the
 * --sensor-prefix-map switch. */
static skPrefixMap_t *sensor_pmap = NULL;

/* default sensor to use when sensor_pmap is not specified */
static sk_sensor_id_t default_sensor;

/* seed to use for the rand48 family of functions.  set the by --seed
 * switch. */
static uint32_t seed = UINT32_MAX;

/* compression method to use for files */
static sk_compmethod_t comp_method;

/* map of flowtype values; set by the varous --flowtype-* switches. */
static sk_flowtype_id_t flowtype[NUM_FLOWTYPES];

/* file formats to use for those files */
static sk_file_format_t file_format[NUM_FLOWTYPES];

/* cache of open file handles when creating incremental files */
static stream_cache_t *cache = NULL;

/* time when the next flush of the incremental streams occurs */
static sktime_t incr_flush;

/* how often to flush the incremental files */
static int64_t flush_timeout = RECGEN_FLUSH_TIMEOUT;

/* how big to make the stream cache */
static int file_cache_size = FILE_CACHE_SIZE;

/* used to map an IP address to a high port */
static skBag_t *ip2port = NULL;

/* a memory pool of records */
static sk_mempool_t *mempool = NULL;

/* the heap of sorted records */
static skrwrecheap_t *heap = NULL;

/* array of subprocesses */
static recgen_subprocess_t *subproc = NULL;

/* whether this is a subprocess */
static int is_subprocess = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_SEED,
    OPT_START_TIME,
    OPT_END_TIME,
    OPT_TIME_STEP,
    OPT_EVENTS_PER_STEP,

    OPT_SILK_OUTPUT_PATH,

    OPT_OUTPUT_DIRECTORY,
    OPT_PROCESSING_DIRECTORY,
    OPT_NUM_SUBPROCESSES,
    OPT_FLUSH_TIMEOUT,
    OPT_FILE_CACHE_SIZE,

    OPT_TEXT_OUTPUT_PATH,
    OPT_INTEGER_SENSORS,
    OPT_INTEGER_TCP_FLAGS,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,

    OPT_SENSOR_PREFIX_MAP,
    OPT_FLOWTYPE_IN,
    OPT_FLOWTYPE_INWEB,
    OPT_FLOWTYPE_OUT,
    OPT_FLOWTYPE_OUTWEB
} appOptionsEnum;

static const struct option appOptions[] = {
    {"seed",                    REQUIRED_ARG, 0, OPT_SEED},
    {"start-time",              REQUIRED_ARG, 0, OPT_START_TIME},
    {"end-time",                REQUIRED_ARG, 0, OPT_END_TIME},
    {"time-step",               REQUIRED_ARG, 0, OPT_TIME_STEP},
    {"events-per-step",         REQUIRED_ARG, 0, OPT_EVENTS_PER_STEP},

    {"silk-output-path",        REQUIRED_ARG, 0, OPT_SILK_OUTPUT_PATH},

    {"output-directory",        REQUIRED_ARG, 0, OPT_OUTPUT_DIRECTORY},
    {"processing-directory",    REQUIRED_ARG, 0, OPT_PROCESSING_DIRECTORY},
    {"num-subprocesses",        REQUIRED_ARG, 0, OPT_NUM_SUBPROCESSES},
    {"flush-timeout",           REQUIRED_ARG, 0, OPT_FLUSH_TIMEOUT},
    {"file-cache-size",         REQUIRED_ARG, 0, OPT_FILE_CACHE_SIZE},

    {"text-output-path",        REQUIRED_ARG, 0, OPT_TEXT_OUTPUT_PATH},
    {"integer-sensors",         NO_ARG,       0, OPT_INTEGER_SENSORS},
    {"integer-tcp-flags",       NO_ARG,       0, OPT_INTEGER_TCP_FLAGS},
    {"no-titles",               NO_ARG,       0, OPT_NO_TITLES},
    {"no-columns",              NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",        REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",      NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",               OPTIONAL_ARG, 0, OPT_DELIMITED},

    {"sensor-prefix-map",       REQUIRED_ARG, 0, OPT_SENSOR_PREFIX_MAP},
    {"flowtype-in",             REQUIRED_ARG, 0, OPT_FLOWTYPE_IN},
    {"flowtype-inweb",          REQUIRED_ARG, 0, OPT_FLOWTYPE_INWEB},
    {"flowtype-out",            REQUIRED_ARG, 0, OPT_FLOWTYPE_OUT},
    {"flowtype-outweb",         REQUIRED_ARG, 0, OPT_FLOWTYPE_OUTWEB},

    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    "Specify seed to use for random number generator",
    ("Specify start of time window for creating events.\n"
     "\tDef. Start of previous hour. Format: YYYY/MM/DD[:HH[:MM[:SS[.sss]]]]\n"
     "\tor UNIX epoch seconds (with optional fractional seconds)"),
    ("Specify end of time window for creating events.\n"
     "\tDef. End of previous hour"),
    ("Move forward this number of milliseconds at each step.\n"
     "\tDef. Difference between start-time and end-time"),
    ("Create this many events at each time step. Def. 1"),

    ("Write binary SiLK flow records to the named file.\n"
     "\tUse '-' to write flow records to the standard output"),

    ("Write incremental files (like those produced by\n"
     "\trwflowpack) to this directory. Files only appear here once the\n"
     "\tflush timeout is reached. Requires use of --processing-directory"),
    ("Specify the working directory to use when\n"
     "\tcreating incremental files"),
    ("Use this number of subprocesses when creating\n"
     "\tincremental files. Def. 0"),
    ("Flush the incremental files after this number of\n"
     "\tmilliseconds. Def. 30,000"),
    ("Maximum number of SiLK Flow files to have open for\n"
     "\twriting simultaneously. Range 4-65535. Def. 32"),

    ("Write textual output in a columnar format to\n"
     "\tthe named file. Use '-' to write text to the standard output"),
    "Print sensor as an integer. Def. Sensor name",
    "Print TCP Flags as an integer. Def. No",
    "Do not print column titles. Def. Print titles",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",

    ("Specify a prefix map file that maps source IPs to\n"
     "\tsensor IDs.  If not provided, all flows belong to sensor 0"),
    ("Use this flowtype (class/type pair) for incoming flows\n"
     "\tthat are not web records.  Def. 'all/in'"),
    ("Use this flowtype for incoming web records.\n"
     "\tDef. 'all/inweb'"),
    ("Use this flowtype for outgoing web records.\n"
     "\tDef. 'all/out'"),
    ("Use this flowtype for outgoing web records.\n"
     "\tDef. 'all/outweb'"),

    (char *)NULL
};


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
    /* usage string is longer than allowed by C90 */
#define USAGE_MSG1                                                            \
    ("<SWITCHES>\n"                                                           \
     "\tUse pseudo-random numbers to generate events, where each event\n"     \
     "\tconsists of one or more flow records.  The time window for the\n"     \
     "\tstart of each event can be set on the command line, and the window\n" \
     "\tdefaults to the previous hour.  Switches exist for controlling the\n")
#define USAGE_MSG2                                                            \
    ("\tsize of each step taken in the window, and the number of events to\n" \
     "\tcreate at each time step.  The output may be text, a single file\n"   \
     "\tof flow records, or a directory full of incremental files (such as\n" \
     "\tthose produced by rwflowpack.  When creating incremental files,\n"    \
     "\tmultiple subprocesses can be specified.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s%s", skAppName(), USAGE_MSG1, USAGE_MSG2);
    fprintf(fh, "\nGeneral Switches:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_SILK_OUTPUT_PATH:
            sklogOptionsUsage(fh);
            fprintf(fh, "\nSingle SiLK Output File Switches:\n");
            break;

          case OPT_TEXT_OUTPUT_PATH:
            skCompMethodOptionsUsage(fh);
            fprintf(fh, "\nSingle Text Output File Switches:\n");
            break;

          case OPT_OUTPUT_DIRECTORY:
            fprintf(fh, "\nIncremental Files Output Switches:\n");
            break;

          case OPT_SENSOR_PREFIX_MAP:
            fprintf(fh, "\nSiLK Site Specific Switches:\n");
            sksiteOptionsUsage(fh);
            break;

          default:
            break;
        }

        fprintf(fh, "--%s %s. ",
                appOptions[i].name, SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_TEXT_OUTPUT_PATH:
            fprintf(fh, "%s\n", appHelp[i]);
            skOptionsTimestampFormatUsage(fh);
            skOptionsIPFormatUsage(fh);
            break;
          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
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
    uint32_t i;
    recgen_subprocess_t *sproc;
    int proc_status;
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (num_subprocesses && !is_subprocess) {
        /* signal any still-running subprocess */
        for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
            if (sproc->pid && sproc->started && !sproc->finished) {
                kill(sproc->pid, SIGTERM);
            }
        }
        /* collect any still-running subprocess */
        for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
            if (sproc->pid && sproc->started && !sproc->finished) {
                rv = waitpid(sproc->pid, &proc_status, 0);
                if (-1 == rv) {
                    WARNINGMSG("Error waiting for process #%u %d: %s",
                               i, (int)sproc->pid, strerror(errno));
                } else {
                    INFOMSG("Process #%u %d exited with status %d",
                            i, (int)sproc->pid, proc_status);
                }
                sproc->finished = 1;
            }
        }
        if (subproc) {
            free(subproc);
        }
    }

    if (cache) {
        skCacheDestroy(cache);
    }

    skStreamDestroy(&silk_output_path);

    if (text_output_ascii) {
        rwAsciiStreamDestroy(&text_output_ascii);
        text_output_ascii = NULL;
    }
    if (text_output.of_name) {
        skFileptrClose(&text_output, &WARNINGMSG);
    }

    if (ip2port) {
        skBagDestroy(&ip2port);
    }
    if (sensor_pmap) {
        skPrefixMapDelete(sensor_pmap);
    }
    if (heap) {
        skRwrecHeapDestroy(heap);
    }
    if (mempool) {
        skMemoryPoolDestroy(&mempool);
    }

    if (!is_subprocess) {
        sklogTeardown();
    }
    skAppUnregister();
}


static void
appExit(
    int                 exit_status)
{
    if (0 == is_subprocess) {
        exit(exit_status);
    }
    _exit(exit_status);
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
    sk_file_header_t *hdr;
    struct timeval tv;
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(flowtype, SK_INVALID_FLOWTYPE, sizeof(flowtype));
    initDispatchTable();

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE)
        || skOptionsTimestampFormatRegister(&time_flags, time_register_flags)
        || skOptionsIPFormatRegister(&ip_format, ip_format_register_flags))
    {
        skAppPrintErr("Unable to register options");
        appExit(EXIT_FAILURE);
    }

    /* setup the log and register options */
    if (sklogSetup(SKLOG_FEATURE_SYSLOG)) {
        skAppPrintErr("Unable to register options");
        appExit(EXIT_FAILURE);
    }

    /* create the ascii stream */
    if (rwAsciiStreamCreate(&text_output_ascii)) {
        skAppPrintErr("Unable to create ascii stream");
        appExit(EXIT_FAILURE);
    }
    rwAsciiAppendFields(text_output_ascii, field_list,
                        sizeof(field_list)/sizeof(field_list[0]));
    rwAsciiSetIPv6Policy(text_output_ascii, SK_IPV6POLICY_ASV4);

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        appExit(EXIT_FAILURE);
    }

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    if (sksiteConfigure(1)) {
        skAppUsage();
    }

    /* ensure num_subprocesses is zero when not creating incremental
     * files */
    if (num_subprocesses && !output_directory) {
        skAppPrintErr("Ignoring --%s since not creating incremental files",
                      appOptions[OPT_NUM_SUBPROCESSES].name);
        num_subprocesses = 0;
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    /* set default file formats */
    file_format[FLOWTYPE_IN]     = FT_RWAUGMENTED;
    file_format[FLOWTYPE_OUT]    = FT_RWAUGMENTED;
    file_format[FLOWTYPE_INWEB]  = FT_RWAUGWEB;
    file_format[FLOWTYPE_OUTWEB] = FT_RWAUGWEB;

    /* verify flow types */
    if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_IN]) {
        if (parseFlowtype(FLOWTYPE_IN, "all/in")) {
            appExit(EXIT_FAILURE);
        }
        if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_INWEB]) {
            if (parseFlowtype(FLOWTYPE_INWEB, "all/inweb")) {
                appExit(EXIT_FAILURE);
            }
        }
    }
    if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_OUT]) {
        if (parseFlowtype(FLOWTYPE_OUT, "all/out")) {
            appExit(EXIT_FAILURE);
        }
        if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_OUTWEB]) {
            if (parseFlowtype(FLOWTYPE_OUTWEB, "all/outweb")) {
                appExit(EXIT_FAILURE);
            }
        }
    }

    /* get default sensor is sensor prefix map is not specified */
    if (NULL == sensor_pmap) {
        char class_name[256];
        sk_sensor_iter_t iter;

        sksiteClassSensorIterator(
            sksiteFlowtypeGetClassID(flowtype[FLOWTYPE_IN]),
            &iter);
        if (sksiteSensorIteratorNext(&iter, &default_sensor) == 0) {
            sksiteFlowtypeGetClass(class_name, sizeof(class_name),
                                   flowtype[FLOWTYPE_IN]);
            skAppPrintErr("No sensors in the class %s", class_name);
            appExit(EXIT_FAILURE);
        }
    }

    /* check the time parameters */
    if (0 == start_time) {
        if (0 == end_time) {
            /* set end_time to start of the current hour; set
             * start_time an hour before that. */
            end_time = sktimeNow();
            end_time -= end_time % MILLISEC_PER_HOUR;
            start_time = end_time - MILLISEC_PER_HOUR;
        } else {
            skAppPrintErr("Cannot specify --%s without --%s",
                          appOptions[OPT_END_TIME].name,
                          appOptions[OPT_START_TIME].name);
            appExit(EXIT_FAILURE);
        }
    } else if (end_time < start_time) {
        char time_str[SKTIMESTAMP_STRLEN];
        skAppPrintErr("Invalid %s '%s': Occurs before %s '%s'",
                      appOptions[OPT_END_TIME].name,
                      sktimestamp_r(time_str, end_time, 0),
                      appOptions[OPT_START_TIME].name,
                      sktimestamp(start_time, 0));;
        appExit(EXIT_FAILURE);
    }
    if (0 == time_step) {
        time_step = end_time - start_time;
        if (0 == time_step) {
            time_step = 1;
        }
    }

    /* some sort of output is required */
    if (NULL == output_directory
        && NULL == silk_output_path
        && NULL == text_output.of_name)
    {
        skAppPrintErr("One of the output switches is required");
        skAppUsage();
    }
    if ((output_directory && (silk_output_path || text_output.of_name))
        || (silk_output_path && text_output.of_name))
    {
        skAppPrintErr("Only one output switch may be specified");
        skAppUsage();
    }

    /* need both or neither directory switches */
    if (output_directory) {
        if (NULL == processing_directory) {
            skAppPrintErr("Must specify --%s when --%s is specified",
                          appOptions[OPT_PROCESSING_DIRECTORY].name,
                          appOptions[OPT_OUTPUT_DIRECTORY].name);
            appExit(EXIT_FAILURE);
        }
    } else if (processing_directory) {
        skAppPrintErr("May only specify --%s when --%s is also specified",
                      appOptions[OPT_PROCESSING_DIRECTORY].name,
                      appOptions[OPT_OUTPUT_DIRECTORY].name);
        appExit(EXIT_FAILURE);
    }

    /* set header for a single silk output file */
    if (silk_output_path) {
        hdr = skStreamGetSilkHeader(silk_output_path);
        if ((rv = skHeaderSetFileFormat(hdr, FT_RWGENERIC))
            || (rv = skHeaderSetCompressionMethod(hdr, comp_method)))
        {
            skStreamPrintLastErr(silk_output_path, rv, &skAppPrintErr);
            skStreamDestroy(&silk_output_path);
            appExit(EXIT_FAILURE);
        }
    }

    /* bind the ascii stream if using it; otherwise destroy it */
    if (text_output.of_name) {
        rwAsciiSetOutputHandle(text_output_ascii, text_output.of_fp);
        rwAsciiSetIPFormatFlags(text_output_ascii, ip_format);
        rwAsciiSetTimestampFlags(text_output_ascii, time_flags);
    } else {
        rwAsciiStreamDestroy(&text_output_ascii);
        text_output_ascii = NULL;
    }

    /* verify logging options */
    if (sklogOptionsVerify()) {
        skAppUsage();
    }

    /* initialize pseudo-random number generator */
    if (UINT32_MAX == seed) {
        /* cons up a seed; constants are what perl uses */
        gettimeofday(&tv, NULL);
        seed = (((uint32_t)1000003 * tv.tv_sec + (uint32_t)3 * tv.tv_usec)
                & INT32_MAX);
    }

    /* get time window used by each subprocess; create required
     * processing subdirectories */
    if (num_subprocesses) {
        if (initSubprocStructure()) {
            appExit(EXIT_FAILURE);
        }
    }

    /* Set up and open the logger */
    sklogDisableRotation();
    sklogOpen();
    sklogCommandLine(argc, argv);

    NOTICEMSG(("Using seed of %" PRIu32), seed);

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
    skPrefixMapErr_t pmap_err;
    uint64_t tmp64;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_START_TIME:
        rv = skStringParseDatetime(&start_time, opt_arg, NULL);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_END_TIME:
        rv = skStringParseDatetime(&end_time, opt_arg, NULL);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_TIME_STEP:
        rv = skStringParseUint64(&tmp64, opt_arg, 0, INT64_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (0 == tmp64) {
            time_step = INT64_MAX;
        } else {
            time_step = (sktime_t)tmp64;
        }
        break;

      case OPT_EVENTS_PER_STEP:
        rv = skStringParseUint32(&events_per_step, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SENSOR_PREFIX_MAP:
        if (sensor_pmap) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        pmap_err = skPrefixMapLoad(&sensor_pmap, opt_arg);
        if (pmap_err != SKPREFIXMAP_OK) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[opt_index].name, opt_arg,
                          skPrefixMapStrerror(pmap_err));
            return -1;
        }
        if (SKPREFIXMAP_CONT_ADDR_V4 !=skPrefixMapGetContentType(sensor_pmap)){
            skAppPrintErr(("Invalid %s '%s':"
                           " Prefix Map must hold IPv4 addresses"),
                          appOptions[opt_index].name, opt_arg);
            skPrefixMapDelete(sensor_pmap);
            return -1;
        }
        break;

      case OPT_SILK_OUTPUT_PATH:
        if (silk_output_path) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        rv = skStreamOpenSilkFlow(&silk_output_path, opt_arg, SK_IO_WRITE);
        if (rv) {
            skStreamPrintLastErr(silk_output_path, rv, &skAppPrintErr);
            skStreamDestroy(&silk_output_path);
            return -1;
        }
        break;

      case OPT_TEXT_OUTPUT_PATH:
        if (text_output.of_name) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        text_output.of_name = opt_arg;
        rv = skFileptrOpen(&text_output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': Unable to open file, %s",
                          appOptions[opt_index].name, opt_arg,
                          skFileptrStrerror(rv));
            text_output.of_name = NULL;
            return -1;
        }
        break;

      case OPT_OUTPUT_DIRECTORY:
        if (output_directory) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        if (!skDirExists(opt_arg)) {
            skAppPrintErr("Invalid %s '%s': Not a directory",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        output_directory = opt_arg;
        break;

      case OPT_PROCESSING_DIRECTORY:
        if (processing_directory) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        if (!skDirExists(opt_arg)) {
            skAppPrintErr("Invalid %s '%s': Not a directory",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        processing_directory = opt_arg;
        break;

      case OPT_NUM_SUBPROCESSES:
        rv = skStringParseUint32(&num_subprocesses, opt_arg, 1, INT32_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_FLUSH_TIMEOUT:
        rv = skStringParseUint64(&tmp64, opt_arg, 1, INT64_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        flush_timeout = (int64_t)tmp64;
        break;

      case OPT_FILE_CACHE_SIZE:
        rv = skStringParseUint64(&tmp64, opt_arg, 4, UINT16_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        file_cache_size = (int)tmp64;
        break;

      case OPT_SEED:
        rv = skStringParseUint32(&seed, opt_arg, 0, INT32_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_FLOWTYPE_IN:
        if (parseFlowtype(FLOWTYPE_IN, opt_arg)) {
            return -1;
        }
        break;

      case OPT_FLOWTYPE_INWEB:
        if (parseFlowtype(FLOWTYPE_INWEB, opt_arg)) {
            return -1;
        }
        break;

      case OPT_FLOWTYPE_OUT:
        if (parseFlowtype(FLOWTYPE_OUT, opt_arg)) {
            return -1;
        }
        break;

      case OPT_FLOWTYPE_OUTWEB:
        if (parseFlowtype(FLOWTYPE_OUTWEB, opt_arg)) {
            return -1;
        }
        break;

      case OPT_INTEGER_SENSORS:
        rwAsciiSetIntegerSensors(text_output_ascii);
        break;

      case OPT_INTEGER_TCP_FLAGS:
        rwAsciiSetIntegerTcpFlags(text_output_ascii);
        break;

      case OPT_NO_TITLES:
        rwAsciiSetNoTitles(text_output_ascii);
        break;

      case OPT_NO_COLUMNS:
        rwAsciiSetNoColumns(text_output_ascii);
        break;

      case OPT_NO_FINAL_DELIMITER:
        rwAsciiSetNoFinalDelimiter(text_output_ascii);
        break;

      case OPT_COLUMN_SEPARATOR:
        rwAsciiSetDelimiter(text_output_ascii, opt_arg[0]);
        break;

      case OPT_DELIMITED:
        rwAsciiSetNoColumns(text_output_ascii);
        rwAsciiSetNoFinalDelimiter(text_output_ascii);
        if (opt_arg) {
            rwAsciiSetDelimiter(text_output_ascii, opt_arg[0]);
        }
        break;
    }

    return 0;  /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return -1;
}


/*
 *  ok = parseFlowtype(array_index, flowtype_string);
 *
 *    Parse the flowtype_string, which contains a 'class/type' pair,
 *    and set the value in the global flowtype[] array indexed by
 *    'array_index'.  Return 0 on success; nonzero otherwise.
 */
static int
parseFlowtype(
    rand_flowtype_t     which_ft,
    const char         *string)
{
    char class_name[256];
    char *type_name;
    sk_flowtype_id_t ft;

    if (strlen(string) >= sizeof(class_name)) {
        skAppPrintErr("Invalid %s '%s': Value too long",
                      appOptions[OPT_FLOWTYPE_IN + which_ft].name, string);
        return -1;
    }
    strncpy(class_name, string, sizeof(class_name));
    class_name[sizeof(class_name)-1] = '\0';

    /* break token into class and type separated by '/' */
    type_name = strchr(class_name, '/');
    if (NULL == type_name) {
        skAppPrintErr("Invalid %s '%s': Missing class-type separator '/'",
                      appOptions[OPT_FLOWTYPE_IN + which_ft].name, string);
        return -1;
    }
    *type_name = '\0';
    ++type_name;

    /* find class and type */
    ft = sksiteFlowtypeLookupByClassType(class_name, type_name);
    if (SK_INVALID_FLOWTYPE == ft) {
        skAppPrintErr("Invalid %s: Unknown class-type pair '%s/%s'",
                      appOptions[OPT_FLOWTYPE_IN + which_ft].name,
                      class_name, type_name);
        return -1;
    }

    flowtype[which_ft] = ft;
    return 0;
}


/*
 *  initDispatchTable();
 *
 *    Use the target_percent and flows_per_func members of the
 *    dispatch table to compute the dispatch_value member.
 */
static void
initDispatchTable(
    void)
{
    dispatch_table_t *disp;
    double sum1, sum2;
    size_t i;

    /* find the sum of the relative weight of each event */
    sum1 = 0.0;
    for (i = 0, disp = dispatch_table; i < num_generators; ++i, ++disp) {
        sum1 += (double)disp->target_percent / disp->flows_per_func;
    }

    /* figure out the dispatch_value for each entry in the table,
     * given that there are 1<<31 possible random values, and we want
     * the number of FLOW records produced to be near the
     * target_percent. */
    sum2 = 0.0;
    for (i = 0, disp = dispatch_table; i < num_generators; ++i, ++disp) {
        sum2 += ((double)disp->target_percent / disp->flows_per_func
                 * (double)(UINT32_C(1) << 31) / sum1);
        disp->dispatch_value = (uint32_t)sum2;
    }

#if 0
    /* print the values and exit. */
    for (i = 0, disp = dispatch_table; i < num_generators; ++i, ++disp) {
        fprintf(stderr, "%2u  %10u\n", (unsigned)i, disp->dispatch_value);
    }
    fprintf(stderr, "%f   %u   %f\n", sum2, (1 << 31),
            (((double)(UINT32_C(1) << 31)) - sum2));
    appExit(0);
#endif  /* 0 */
}


/*
 *  status = initSubprocStructure();
 *
 *    Initialize the information needed to run the subprocesses: find
 *    the time window each will use, create separate directories for
 *    their incremental files, adjust the seed.
 */
static int
initSubprocStructure(
    void)
{
    recgen_subprocess_t *sproc;
    uint32_t i;
    sktime_t t;
    imaxdiv_t steps_per_proc;
    intmax_t steps;
    int extra;
    int rv;

    steps = 1 + (end_time - start_time) / time_step;
    if (1 == steps) {
        /* do not use multiple processes when there is a single step */
        num_subprocesses = 0;
        return 0;
    }
    if (steps < num_subprocesses) {
        num_subprocesses = (uint32_t)steps;
    }

    subproc = ((recgen_subprocess_t*)
               calloc(num_subprocesses, sizeof(recgen_subprocess_t)));
    if (NULL == subproc) {
        skAppPrintErr("Unable to allocate memory for %u processes",
                      num_subprocesses);
        return -1;
    }

    for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
        rv = snprintf(sproc->processing_dir, sizeof(sproc->processing_dir),
                      "%s/subproc-%05u", processing_directory, i);
        if ((size_t)rv > sizeof(sproc->processing_dir)) {
            skAppPrintErr("Directory name too long");
            return -1;
        }
        rv = skMakeDir(sproc->processing_dir);
        if (rv) {
            skAppPrintErr(("Unable to create processing directory"
                           " for subprocess #%u: %s"),
                          i, strerror(errno));
            return -1;
        }
    }

    steps_per_proc = imaxdiv(steps, num_subprocesses);

    t = start_time;
    for (i = 0, sproc = subproc;
         i < num_subprocesses && t <= end_time;
         ++i, ++sproc)
    {
        if (steps_per_proc.rem) {
            extra = 1;
            --steps_per_proc.rem;
        } else {
            extra = 0;
        }
        sproc->start_time = t;
        t += time_step * (steps_per_proc.quot + extra - 1);
        sproc->end_time = t;
        t += time_step;
    }

    /* adjust the seed of each subprocess so they all do not create
     * the same flow records */
    for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
        sproc->seed = RECGEN_SUBPROC_SEED_ADJUST(seed, i);
    }

    return 0;
}


/*
 *  emptyProcessingDirectory();
 *
 *    Remove all files from the processing directory.
 */
static void
emptyProcessingDirectory(
    void)
{
    char path[2 * PATH_MAX];
    struct dirent *entry;
    DIR *dir;
    int file_count = 0;
    int rv;

    dir = opendir(processing_directory);
    if (NULL == dir) {
        CRITMSG("Fatal error: Unable to open directory '%s': %s",
                processing_directory, strerror(errno));
        appExit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        snprintf(path, sizeof(path), "%s/%s",
                 processing_directory, entry->d_name);
        if (skFileExists(path)) {
            if (0 == file_count) {
                DEBUGMSG("Removing files from '%s'", processing_directory);
            }
            ++file_count;
            rv = unlink(path);
            if (rv != 0) {
                ERRMSG("Could not remove file '%s': %s",
                       path, strerror(rv));
            }
        }
    }

    closedir(dir);
}


/*
 *  stream = openIncrementalFile(time_sensor_flowtype, format);
 *
 *    Callback invoked by the skCache code.
 *
 *    Open a new file in the processing directory to hold records
 *    having the time, sensor, and flowtype specified in the first
 *    argument to the function.  Create the file using the format
 *    specified in the second argument.  Return the new stream, or
 *    return NULL if the stream cannot be created.
 */
static skstream_t *
openIncrementalFile(
    const cache_key_t  *key,
    void               *v_file_format)
{
    char filename[PATH_MAX];
    char tmpbuf[PATH_MAX];
    char *fname;
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    sk_file_format_t format = *((sk_file_format_t*)v_file_format);
    int creating_file = 0;
    int rv;

    /* generate path to the file in the data repository, then replace
     * everything excpet the filename with the processing
     * directory */
    sksiteGeneratePathname(tmpbuf, sizeof(tmpbuf),
                           key->flowtype_id, key->sensor_id,
                           key->time_stamp, "", NULL, &fname);
    snprintf(filename, sizeof(filename), "%s/%s",
             processing_directory, fname);

    if (skFileExists(filename)) {
        /* Open existing file for append, lock it, and read its header */
        DEBUGMSG("Opening existing output file %s", filename);

        if ((rv = skStreamCreate(&stream, SK_IO_APPEND, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(stream, filename))
            || (rv = skStreamOpen(stream))
            || (rv = skStreamReadSilkHeader(stream, NULL)))
        {
            goto END;
        }
    } else {
        /* Open a new file, lock it, create and write its header */
        DEBUGMSG("Opening new output file %s", filename);
        creating_file = 1;

        if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(stream, filename))
            || (rv = skStreamOpen(stream)))
        {
            goto END;
        }

        /* Get file's header and fill it in */
        hdr = skStreamGetSilkHeader(stream);
        if ((rv = skHeaderSetFileFormat(hdr, format))
            || (rv = skHeaderSetCompressionMethod(hdr, comp_method))
            || (rv = skHeaderAddPackedfile(hdr, key->time_stamp,
                                           key->flowtype_id, key->sensor_id))
            || (rv = skStreamWriteSilkHeader(stream)))
        {
            goto END;
        }
    }

  END:
    if (rv) {
        skStreamPrintLastErr(stream, rv, &CRITMSG);
        skStreamDestroy(&stream);
        if (creating_file) {
            /* remove the file if we were creating it, so as to not
             * leave invalid files in the data store */
            unlink(filename);
        }
        stream = NULL;
    }

    return stream;
}


/*
 *  flushIncrementalFiles();
 *
 *    Close all the incremental files and move them from the
 *    processing_directory to the output_directory.
 */
static void
flushIncrementalFiles(
    void)
{
    int tmp_fd;
    char oldpath[2 * PATH_MAX];
    char newpath[2 * PATH_MAX];
    struct dirent *entry;
    DIR *dir;
    int file_count = 0;
    int moved = 0;
    int rv;

    if (skCacheLockAndCloseAll(cache)) {
        skCacheUnlock(cache);
        CRITMSG("Error closing incremental files -- shutting down");
        appExit(EXIT_FAILURE);
    }

    /* Open the processing directory and loop over the files in the
     * directory. */
    dir = opendir(processing_directory);
    if (NULL == dir) {
        CRITMSG("Fatal error: Unable to open directory '%s': %s",
                processing_directory, strerror(errno));
        skCacheUnlock(cache);
        appExit(EXIT_FAILURE);
    }

    DEBUGMSG("Moving files to %s...", output_directory);
    while ((entry = readdir(dir)) != NULL) {
        /* ignore dot-files */
        if ('.' == entry->d_name[0]) {
            continue;
        }

        /* generate full path to existing file */
        snprintf(oldpath, sizeof(oldpath), "%s/%s",
                 processing_directory, entry->d_name);
        /* ignore directories */
        if (skDirExists(oldpath)) {
            continue;
        }

        ++file_count;

        /* Copy each file to a unique name */
        snprintf(newpath, sizeof(newpath), "%s/%s.XXXXXX",
                 output_directory, entry->d_name);
        tmp_fd = mkstemp(newpath);
        if (tmp_fd == -1) {
            ERRMSG("Could not create and open temporary file '%s': %s",
                   newpath, strerror(errno));
            continue;
        }
        close(tmp_fd);
        rv = skMoveFile(oldpath, newpath);
        if (rv != 0) {
            ERRMSG("Could not move file '%s' to '%s': %s",
                   oldpath, newpath, strerror(rv));
            continue;
        }

        ++moved;
    }

    closedir(dir);

    /* Print status message */
    if (file_count == 0) {
        NOTICEMSG("No files to move.");
    } else {
        NOTICEMSG("Successfully moved %d/%d file%s.",
                  moved, file_count, ((file_count==1) ? "" : "s"));
    }

    skCacheUnlock(cache);
}


/*
 *  writeRecord(rec);
 *
 *    Sets the sensor and flowtype of the record, writes the record to
 *    the output, and destroys the record.
 */
static int
writeRecord(
    rwRec              *rec)
{
    sk_flowtype_id_t ft;
    sk_sensor_id_t sensor;
    sk_file_format_t format;
    skipaddr_t ip;
    int rv;

    /* set sensor and flowtype */

    if (rwRecGetSIPv4(rec) < rwRecGetDIPv4(rec)) {
        /* record is outgoing */
        if (sensor_pmap) {
            rwRecMemGetSIP(rec, &ip);
            sensor = skPrefixMapFindValue(sensor_pmap, &ip);
        } else {
            sensor = default_sensor;
        }
        if (rwRecIsWeb(rec)
            && (SK_INVALID_FLOWTYPE != flowtype[FLOWTYPE_OUTWEB]))
        {
            ft = flowtype[FLOWTYPE_OUTWEB];
            format = file_format[FLOWTYPE_OUTWEB];
        } else {
            ft = flowtype[FLOWTYPE_OUT];
            format = file_format[FLOWTYPE_OUT];
        }
    } else {
        /* record is incoming */
        if (sensor_pmap) {
            rwRecMemGetDIP(rec, &ip);
            sensor = skPrefixMapFindValue(sensor_pmap, &ip);
        } else {
            sensor = default_sensor;
        }
        if (rwRecIsWeb(rec)
            && (SK_INVALID_FLOWTYPE != flowtype[FLOWTYPE_INWEB]))
        {
            ft = flowtype[FLOWTYPE_INWEB];
            format = file_format[FLOWTYPE_INWEB];
        } else {
            ft = flowtype[FLOWTYPE_IN];
            format = file_format[FLOWTYPE_IN];
        }
    }

    rwRecSetFlowType(rec, ft);
    rwRecSetSensor(rec, sensor);

    if (output_directory) {
        cache_entry_t *entry;
        cache_key_t key;

        key.flowtype_id = ft;
        key.sensor_id = sensor;
        key.time_stamp = (rwRecGetStartTime(rec)
                          - (rwRecGetStartTime(rec) % MILLISEC_PER_HOUR));

        if (skCacheLookupOrOpenAdd(cache, &key, &format, &entry)) {
            WARNINGMSG("Unable to open file");
        } else {
            rv = skStreamWriteRecord(skCacheEntryGetStream(entry), rec);
            if (rv) {
                skStreamPrintLastErr(skCacheEntryGetStream(entry),
                                     rv, CRITMSG);
                abort();
            }
            skCacheEntryRelease(entry);
        }
    } else if (silk_output_path) {
        rv = skStreamWriteRecord(silk_output_path, rec);
        if (rv) {
            skStreamPrintLastErr(silk_output_path, rv, WARNINGMSG);
        }
    } else if (text_output_ascii) {
        rwAsciiPrintRec(text_output_ascii, rec);
    }

    skMemPoolElementFree(mempool, rec);

    return 0;
}


/*
 *  port = getHighPort(ip);
 *
 *    Given an IP address, generate a high port for it to use.
 *
 *    The idea here is to allow an IP to cycle through a series of
 *    high ports, with state maintained in a bag file.  This function
 *    assumes we will see a lot of repeated IP addresses.  If that it
 *    not the case, this function is not useful and the bag is wasting
 *    space.
 */
static uint16_t
getHighPort(
    const skipaddr_t   *ip)
{
    static const skBagTypedCounter_t incr = {SKBAG_COUNTER_U64, { 1 }};
    skBagTypedKey_t key;
    skBagTypedCounter_t new_counter;
    uint16_t cur_val;

    key.type = SKBAG_KEY_U32;
    new_counter.type = SKBAG_COUNTER_U64;

    if (skipaddrGetAsV4(ip, &key.val.u32)) {
        skAbort();
    }

    if (skBagCounterAdd(ip2port, &key, &incr, &new_counter)==SKBAG_ERR_MEMORY){
        NOTICEMSG("Bag out of memory; recreating...");
        skBagDestroy(&ip2port);
        if (skBagCreateTyped(
                &ip2port, SKBAG_FIELD_ANY_IPv4, SKBAG_FIELD_ANY_PORT,
                SKBAG_OCTETS_FIELD_DEFAULT, SKBAG_OCTETS_FIELD_DEFAULT))
        {
            CRITMSG("Unable to recreate bag");
            appExit(EXIT_FAILURE);
        }
    }

    cur_val = GET_MASKED_BITS64(new_counter.val.u64, 0, 16);
    if (cur_val == 1) {
        /* first time we have seen this value */
        uint16_t start_val;
        uint16_t max_val;
        uint32_t bits = (uint32_t)lrand48();

        start_val = 1024 + GET_MASKED_BITS64(bits, 0, 15);
        max_val = start_val + GET_MASKED_BITS64(bits, 16, 14);
        cur_val = start_val;

        SET_MASKED_BITS64(new_counter.val.u64, cur_val,    0, 16);
        SET_MASKED_BITS64(new_counter.val.u64, start_val, 16, 16);
        SET_MASKED_BITS64(new_counter.val.u64, max_val,   32, 16);

    } else if (cur_val < GET_MASKED_BITS64(new_counter.val.u64, 32, 16)) {
        /* value is below the max_val */
        return cur_val;

    } else {
        /* copy start_val to cur_val */
        cur_val = GET_MASKED_BITS64(new_counter.val.u64, 16, 16);
        SET_MASKED_BITS64(new_counter.val.u64, cur_val, 0, 16);
    }

    skBagCounterSet(ip2port, &key, &new_counter);
    return (uint16_t)cur_val;
}


/*
 *  rec = newRecord(template);
 *
 *    Get a new record from the memory pool.  If 'template' is
 *    specified; initialize the record with the contents of
 *    'template'.
 */
static rwRec *
newRecord(
    const rwRec        *template_rec)
{
    rwRec *r;

    r = (rwRec*)skMemPoolElementNew(mempool);
    if (r && template_rec) {
        RWREC_COPY(r, template_rec);
    }
    return r;
}


/*
 *  generateTcpPortScan(source, target);
 *
 *    Generate a scan of all ports on 'target' by 'source'.
 */
static int
generateTcpPortScan(
    const skipaddr_t   *source,
    const skipaddr_t   *target)
{
    rwRec first_rec;
    rwRec *r;
    uint16_t sport;
    uint16_t dport = 0;
    uint16_t j;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t stime_step;
    uint16_t sport_start;
    uint16_t sport_cycle;
    uint32_t bits;
    uint8_t flags;

    bits = (uint32_t)lrand48();
    sport_start = 2048 + GET_MASKED_BITS(bits, 0, 15);
    sport_cycle = 33 + GET_MASKED_BITS(bits, 15, 7);
    dur = 1 + GET_MASKED_BITS(bits, 22, 4);
    stime_step = 1 + dur + GET_MASKED_BITS(bits, 26, 5);
    flags = GET_MASKED_BITS(bits, 20, 8) ? GET_MASKED_BITS(bits, 20, 8) : 0xFF;

    RWREC_CLEAR(&first_rec);
    rwRecMemSetSIP(&first_rec, source);
    rwRecMemSetDIP(&first_rec, target);
    rwRecSetSPort(&first_rec, sport_start + sport_cycle);
    rwRecSetDPort(&first_rec, dport);
    rwRecSetProto(&first_rec, IPPROTO_TCP);
    rwRecSetPkts(&first_rec, 1);
    rwRecSetBytes(&first_rec, 40);
    rwRecSetStartTime(&first_rec, my_stime);
    rwRecSetElapsed(&first_rec, dur);
    rwRecSetInitFlags(&first_rec, flags);
    rwRecSetTcpState(&first_rec, SK_TCPSTATE_EXPANDED);

    r = newRecord(&first_rec);
    if (NULL == r) {
        return -1;
    }
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    do {
        if (UINT16_MAX - sport_cycle > dport) {
            /* no need to check dport */
            for (j = 0, sport = sport_start;
                 j < sport_cycle;
                 ++j, ++sport)
            {
                ++dport;
                r = newRecord(&first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecSetSPort(r, sport);
                rwRecSetDPort(r, dport);
                rwRecSetStartTime(r, my_stime);
                if (skRwrecHeapInsert(heap, r)) {
                    return -1;
                }
            }
        } else {
            /* make dport the stopping condition */
            for (j = 0, sport = sport_start;
                 dport < UINT16_MAX;
                 ++j, ++sport, my_stime += dur)
            {
                ++dport;
                r = newRecord(&first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecSetSPort(r, sport);
                rwRecSetDPort(r, dport);
                rwRecSetStartTime(r, my_stime);
                if (skRwrecHeapInsert(heap, r)) {
                    return -1;
                }
            }
        }
        my_stime += stime_step;
    } while (dport < UINT16_MAX);

    return 0;
}


/*
 *  generateTcpHostScan(source, target);
 *
 *    Generate a scan of a single port across hosts.  The scan
 *    originates at 'source'; the target IPs begin at 'target' and
 *    increase for a randomly chosen number of hosts.
 */
static int
generateTcpHostScan(
    const skipaddr_t   *source,
    const skipaddr_t   *first_target)
{
    const uint16_t dports[] = {139, 138, 1434, 9474, 6000, 22, 25, 80};
    skipaddr_t target;
    rwRec first_rec;
    rwRec *r;
    uint16_t sport;
    uint16_t dport;
    uint8_t flags;
    uint16_t j;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t stime_step;
    uint16_t sport_start;
    uint16_t sport_cycle;
    uint32_t num_hosts;
    uint32_t bits;

    bits = (uint32_t)lrand48();
    sport_start = 2048 + GET_MASKED_BITS(bits, 0, 15);
    sport_cycle = 11 + GET_MASKED_BITS(bits, 15, 7);
    dur = 1 + GET_MASKED_BITS(bits, 22, 4);
    stime_step = 1 + dur + GET_MASKED_BITS(bits, 26, 5);

    bits = (uint32_t)lrand48();
    dport = dports[GET_MASKED_BITS(bits, 0, 3)];
    flags = GET_MASKED_BITS(bits, 3, 5) ? GET_MASKED_BITS(bits, 3, 5) : 0xFF;
    num_hosts = 1 + GET_MASKED_BITS(bits, 16, 8);

    RWREC_CLEAR(&first_rec);
    rwRecMemSetSIP(&first_rec, source);
    rwRecMemSetDIP(&first_rec, first_target);
    rwRecSetSPort(&first_rec, sport_start + sport_cycle);
    rwRecSetDPort(&first_rec, dport);
    rwRecSetProto(&first_rec, IPPROTO_TCP);
    rwRecSetPkts(&first_rec, 1);
    rwRecSetBytes(&first_rec, 40);
    rwRecSetStartTime(&first_rec, my_stime);
    rwRecSetElapsed(&first_rec, dur);
    rwRecSetInitFlags(&first_rec, flags);
    rwRecSetTcpState(&first_rec, SK_TCPSTATE_EXPANDED);

    r = newRecord(&first_rec);
    if (NULL == r) {
        return -1;
    }
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    skipaddrCopy(&target, first_target);
    do {
        if (num_hosts > sport_cycle) {
            /* no need to check num_hosts */
            for (j = 0, sport = sport_start;
                 j < sport_cycle;
                 ++j, ++sport)
            {
                skipaddrIncrement(&target);
                --num_hosts;
                r = newRecord(&first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecMemSetDIP(r, &target);
                rwRecSetSPort(r, sport);
                rwRecSetStartTime(r, my_stime);
                if (skRwrecHeapInsert(heap, r)) {
                    return -1;
                }
            }
        } else {
            /* make num_hosts the stopping condition */
            for (j = 0, sport = sport_start;
                 num_hosts > 0;
                 ++j, ++sport, my_stime += dur)
            {
                skipaddrIncrement(&target);
                --num_hosts;
                r = newRecord(&first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecMemSetDIP(r, &target);
                rwRecSetSPort(r, sport);
                rwRecSetStartTime(r, my_stime);
                if (skRwrecHeapInsert(heap, r)) {
                    return -1;
                }
            }
        }
        my_stime += stime_step;
    } while (num_hosts);

    return 0;
}


/*
 *  generateDns(client, server);
 *
 *    Generate a DNS request and response from 'client' to 'server'.
 *    If 'new_stime' is not NULL, fill that variable with the time
 *    when the server finished its response.
 *
 */
static int
generateDns(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint32_t bpp[] = {54, 70, 56, 72, 61, 77, 121, 144, 127};
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();

    /* pull duration from the middle-upper 13 bits; gives a max of 8
     * seconds, even distribution */
    dur = GET_MASKED_BITS(bits, 13, 13);

    /* pkts will be a value between 1 and 17, weighted toward smaller
     * values */
    pkts = (1
            + lowest_bit_in_val[bits & 0xFF]
            + lowest_bit_in_val[(bits >> 8) & 0xFF]);
    bits >>= 16;

    /* bytes will be a value between 54 and 139, with spikes at values
     * in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = 54 + (bits & 0xFF) / 3;
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, 53);
    rwRecSetProto(r, IPPROTO_UDP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetApplication(r, 53);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    /* Repeat for the response */
    bits = (uint32_t)lrand48();

    dur = GET_MASKED_BITS(bits, 13, 13);

    /* adjust stime of the response */
    my_stime += GET_MASKED_BITS(bits, 26, 5);

    pkts = (1
            + lowest_bit_in_val[bits & 0xFF]
            + lowest_bit_in_val[(bits >> 8) & 0xFF]);
    bits >>= 16;

    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = 54 + (bits & 0xFF) / 3;
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, 53);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_UDP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetApplication(r, 53);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateFtp(client, server);
 *
 *    Generate a FTP request and response from 'client' to 'server'.
 */
static int
generateFtp(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint16_t server_port = 21;
    const uint32_t bpp[] = {40, 44, 46, 49, 68, 70, 0, 0, 0};
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t rest_flags;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* compute duration (in millisec) as product of three values from
     * 0 to 8 multiplied by a 10 bit value.  Two of the three 0-8
     * values are heavily weighted toward smaller numbers.  Max
     * duration is 524 seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 10)
            + GET_MASKED_BITS(bits, 10, 10))
           * (1 + (bits_in_value[bits & 0xFF]
                   * lowest_bit_in_val[(bits >> 8) & 0xFF]
                   * lowest_bit_in_val[(bits >> 16) & 0xFF])));

    rest_flags = GET_MASKED_BITS(bits, 24, 5);


    bits = (uint32_t)lrand48();

    /* pkts will be a value between 1 and 17, weighted toward 11 */
    pkts = (1
            + bits_in_value[bits & 0xFF]
            + bits_in_value[(bits >> 8) & 0xFF]);
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 127, with spikes at
     * values in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = pkts * (((bits & 0x7F) < 40) ? 40 : (bits & 0x7F));
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, server_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetInitFlags(r, SYN_FLAG);
    if (pkts > 1) {
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)lrand48();

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, server_port);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    if (pkts == 1) {
        rwRecSetInitFlags(r, RST_FLAG | (rest_flags & ACK_FLAG));
    } else {
        rwRecSetInitFlags(r, ACK_FLAG);
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateHttp(client, server);
 *
 *    Generate a HTTP/HTTPS request and response from 'client' to
 *    'server'.
 */
static int
generateHttp(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    uint16_t server_port = 80;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t rest_flags;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by a 13 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 524
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 13)
            + GET_MASKED_BITS(bits, 13, 13))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 2, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    bits = (uint32_t)lrand48();

    /* pkts will be a value between 1 and 25, weighted toward 6 */
    pkts = (1
            + (2 * lowest_bit_in_val[bits & 0xFF])
            + bits_in_value[(bits >> 8) & 0xFF]);
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 1500, fairly evenly
     * distributed */
    bytes = (GET_MASKED_BITS(bits, 0, 9)
             + (GET_MASKED_BITS(bits, 0, 9) << 1));
    if (bytes < 40) {
        bytes = 40 * pkts;
    } else if (bytes > 1500) {
        bytes = 1500 * pkts;
    } else {
        bytes *= pkts;
    }

    if (GET_MASKED_BITS(bits, 10, 1)) {
        server_port = 443;
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, server_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetInitFlags(r, SYN_FLAG);
    if (pkts > 1) {
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)lrand48();

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    /* limit bpp ratio to 1500 */
    if (pkts * 1500 < bytes) {
        bytes = 1500 * pkts;
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, server_port);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    if (pkts == 1) {
        rwRecSetInitFlags(r, RST_FLAG | (rest_flags & ACK_FLAG));
    } else {
        rwRecSetInitFlags(r, ACK_FLAG);
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateIcmp(client, server);
 *
 *    Generate an ICMP message
 */
static int
generateIcmp(
    const skipaddr_t   *sip,
    const skipaddr_t   *dip)
{
    uint16_t dport;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    uint32_t bits;

    bits = (uint32_t)lrand48();

    /* multiple ICMP packets can become a single flow */
    pkts = 1 + lowest_bit_in_val[GET_MASKED_BITS(bits, 0, 8)];

    dur = pkts * (GET_MASKED_BITS(bits, 8, 6) | 1);

    if (GET_MASKED_BITS(bits, 14, 6) < 13) {
        /* echo reply */
        bytes = 84 * pkts;
        dport = ((0 << 8) | 0);
    } else if (GET_MASKED_BITS(bits, 14, 6) < 26) {
        /* echo */
        bytes = 84 * pkts;
        dport = ((8 << 8) | 0);
    } else if (GET_MASKED_BITS(bits, 14, 6) < 39) {
        /* timeout */
        bytes = 56 * pkts;
        dport = ((11 << 8) | 0);
    } else if (GET_MASKED_BITS(bits, 14, 6) < 52) {
        /* host unreachable */
        bytes = 56 * pkts;
        dport = ((3 << 8) | 1);
    } else {
        /* port unreachable */
        bytes = 56 * pkts;
        dport = ((3 << 8) | 3);
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, sip);
    rwRecMemSetDIP(r, dip);
    rwRecSetDPort(r, dport);
    rwRecSetProto(r, IPPROTO_ICMP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, current_time);
    rwRecSetElapsed(r, dur);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateImap(client, server);
 *
 *    Generate a IMAP session between 'client' and 'server'.
 */
static int
generateImap(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint16_t server_port = 143;
    const uint32_t bpp[] = {91, 95, 93, 54, 0, 0, 0, 0, 0};
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t rest_flags;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by a 12 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 262
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 12)
            + GET_MASKED_BITS(bits, 12, 12))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)lrand48();

    /* pkts will be a value between 1 and 25, weighted toward 16 */
    pkts = (1
            + (2 * bits_in_value[bits & 0xFF])
            + bits_in_value[(bits >> 8) & 0xFF]);
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 255, with spikes at
     * values in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = pkts * (((bits & 0xFF) < 40) ? 40 : (bits & 0xFF));
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, server_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetInitFlags(r, SYN_FLAG);
    if (pkts > 1) {
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)lrand48();

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, server_port);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    if (pkts == 1) {
        rwRecSetInitFlags(r, RST_FLAG | (rest_flags & ACK_FLAG));
    } else {
        rwRecSetInitFlags(r, ACK_FLAG);
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateOtherProto(client, server);
 *
 *    Generate traffic on another IP protocol
 */
static int
generateOtherProto(
    const skipaddr_t   *sip,
    const skipaddr_t   *dip)
{
    const uint8_t protos[] = {50, 47, 58, 50, 47, 58, 50, 47, 58};
    uint8_t proto;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    uint32_t bits;

    bits = (uint32_t)lrand48();

    proto = protos[GET_MASKED_BITS(bits, 0, 3)];
    dur = 1 + GET_MASKED_BITS(bits, 3, 17);
    pkts = (1 + GET_MASKED_BITS(bits, 20, 3)) * (1 + (dur >> 15));
    bytes = pkts * (20 + GET_MASKED_BITS(bits, 23, 8));

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, sip);
    rwRecMemSetDIP(r, dip);
    rwRecSetProto(r, proto);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, current_time);
    rwRecSetElapsed(r, dur);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generatePop3(client, server);
 *
 *    Generate a POP3 session between 'client' and 'server'.
 */
static int
generatePop3(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint16_t server_port = 110;
    const uint32_t bpp[] = {47, 46, 419, 425, 0, 0, 0, 0, 0};
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t rest_flags;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by an 11 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 131
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 11)
            + GET_MASKED_BITS(bits, 11, 11))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)lrand48();

    /* pkts will be a value between 1 and 33, weighted toward 17 */
    pkts = (1
            + (2 * (bits_in_value[bits & 0xFF]
                    + bits_in_value[(bits >> 8) & 0xFF])));
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 1023, with spikes at
     * values in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = pkts * (((bits & 0x3FF) < 40) ? 40 : (bits & 0x3FF));
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, server_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetInitFlags(r, SYN_FLAG);
    if (pkts > 1) {
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)lrand48();

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, server_port);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    if (pkts == 1) {
        rwRecSetInitFlags(r, RST_FLAG | (rest_flags & ACK_FLAG));
    } else {
        rwRecSetInitFlags(r, ACK_FLAG);
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateSmtp(client, server);
 *
 *    Generate a SMTP request and response from 'client' to 'server'.
 */
static int
generateSmtp(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint16_t server_port = 25;
    const uint32_t bpp[] = {44, 55, 61, 90, 102, 131, 0, 0, 0};
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t rest_flags;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by an 11 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 131
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 11)
            + GET_MASKED_BITS(bits, 11, 11))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)lrand48();

    /* pkts will be a value between 1 and 16, weighted toward 13 */
    pkts = (1
            + bits_in_value[GET_MASKED_BITS(bits, 0, 8)]
            + highest_bit_in_val[GET_MASKED_BITS(bits, 8, 8)]);
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 511, with spikes at
     * values in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = pkts * (((bits & 0x1FF) < 40) ? 40 : (bits & 0x1FF));
    }

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, client);
    rwRecMemSetDIP(r, server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, server_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetInitFlags(r, SYN_FLAG);
    if (pkts > 1) {
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)lrand48();

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, server);
    rwRecMemSetDIP(r, client);
    rwRecSetSPort(r, server_port);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_TCP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    if (pkts == 1) {
        rwRecSetInitFlags(r, RST_FLAG | (rest_flags & ACK_FLAG));
    } else {
        rwRecSetInitFlags(r, ACK_FLAG);
        rwRecSetRestFlags(r, rest_flags);
    }
    rwRecSetTcpState(r, SK_TCPSTATE_EXPANDED);
    rwRecSetApplication(r, server_port);
    if (skRwrecHeapInsert(heap, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateTelnet(client, server);
 *
 *    Generate a TELNET session between 'client' and 'server'.
 */
static int
generateTelnet(
    const skipaddr_t   *client,
    const skipaddr_t   *server)
{
    const uint16_t server_port = 23;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t total_dur;
    uint32_t dur;
    sktime_t my_stime = current_time;
    uint32_t bits;
    uint8_t init_flags = SYN_FLAG;
    uint8_t rest_flags = SYN_FLAG | ACK_FLAG;
    uint8_t tcp_state = SK_TCPSTATE_EXPANDED;

    high_port = getHighPort(client);

    bits = (uint32_t)lrand48();
    /* total_dur is a 24 bit number, so we can generate long flow
     * records. */
    total_dur = 1 + GET_MASKED_BITS(bits, 0, 23);

    if (GET_MASKED_BITS(bits, 1, 25)) {
        rest_flags |= PSH_FLAG;
    }

    do {
        if (total_dur > MILLISEC_PER_HOUR/2) {
            /* this flow will continue */
            dur = MILLISEC_PER_HOUR/2;
            tcp_state |= SK_TCPSTATE_TIMEOUT_KILLED;
        } else {
            /* flow will not continue */
            dur = total_dur;
            tcp_state &= ~SK_TCPSTATE_TIMEOUT_KILLED;
            rest_flags |= FIN_FLAG;
        }

        bits = (uint32_t)lrand48();

        /* assume one packet approximately every 2 to 16 seconds */
        pkts = 1 + (dur >> (11 + GET_MASKED_BITS(bits, 0, 2)));

        /* use a bpp range of 40-48 */
        bytes = pkts * (40 + bits_in_value[GET_MASKED_BITS(bits, 2, 8)]);

        r = newRecord(NULL);
        if (NULL == r) {
            return -1;
        }
        rwRecMemSetSIP(r, client);
        rwRecMemSetDIP(r, server);
        rwRecSetSPort(r, high_port);
        rwRecSetDPort(r, server_port);
        rwRecSetProto(r, IPPROTO_TCP);
        rwRecSetPkts(r, pkts);
        rwRecSetBytes(r, bytes);
        rwRecSetStartTime(r, my_stime);
        rwRecSetElapsed(r, dur);
        rwRecSetInitFlags(r, init_flags);
        if (pkts > 1) {
            rwRecSetRestFlags(r, rest_flags);
        }
        rwRecSetTcpState(r, tcp_state);
        rwRecSetApplication(r, server_port);
        if (skRwrecHeapInsert(heap, r)) {
            return -1;
        }

        /* handle the response */

        /* adjust packets and bytes for the other side  */
        pkts += bits_in_value[GET_MASKED_BITS(bits, 10, 8)];
        bytes += 40 * bits_in_value[GET_MASKED_BITS(bits, 10, 8)];

        r = newRecord(NULL);
        if (NULL == r) {
            return -1;
        }
        rwRecMemSetSIP(r, server);
        rwRecMemSetDIP(r, client);
        rwRecSetSPort(r, server_port);
        rwRecSetDPort(r, high_port);
        rwRecSetProto(r, IPPROTO_TCP);
        rwRecSetPkts(r, pkts);
        rwRecSetBytes(r, bytes);
        rwRecSetStartTime(r, my_stime + GET_MASKED_BITS(bits, 18, 5));
        rwRecSetElapsed(r, dur);
        if (pkts == 1) {
            rwRecSetInitFlags(r, RST_FLAG);
        } else {
            rwRecSetInitFlags(r, init_flags);
            rwRecSetRestFlags(r, rest_flags);
        }
        rwRecSetTcpState(r, tcp_state);
        rwRecSetApplication(r, server_port);
        if (skRwrecHeapInsert(heap, r)) {
            return -1;
        }

        /* adjust values */
        my_stime += dur;
        total_dur -= dur;
        init_flags |= rest_flags;
        tcp_state |= SK_TCPSTATE_TIMEOUT_STARTED;

    } while (total_dur > 0);

    return 0;
}


/*
 *    Main loop to generate flow records.
 *
 *    Uses a random number to choose what sort of event to create and
 *    calls the function to create the flow records.  Repeats until
 *    the events_per_step has been reached.  Then it increments the
 *    time window by the time_step, prints the records whose end-times
 *    have been reached, and then generates a more events until the
 *    end_time is reached.
 */
static int
generateFlows(
    void)
{
    dispatch_table_t *disp;
    size_t i;
    uint32_t sip_v4;
    uint32_t dip_v4;
    skipaddr_t sip;
    skipaddr_t dip;
    uint32_t bits;
    uint32_t num_events;

    current_time = start_time;

    /* loop until the end_time is reached */
    while (current_time <= end_time) {
        for (num_events = 0; num_events < events_per_step; ++num_events) {
            /* use one random number to create both IPs. If LSB is
             * OFF, the number is the basis for the sip; otherwise the
             * dip.  Form other number by shifting random number.  If
             * MSB of neither IP is high, set the MSB of the IP that
             * is the unshifted random number.  */
            bits = IP_V4_MASK & (uint32_t)lrand48();
            if (0 == (bits & 0xFF000000)) {
                /* make certain first octet is non-zero */
                bits |= 0x01000000;
            }
            switch (bits & 0x40000001) {
              case 0x00000000:
                sip_v4 = 0x80000000 | bits;
                dip_v4 = (bits << 1) | 1;
                break;
              case 0x40000000:
                sip_v4 = bits;
                dip_v4 = (bits << 1) | 1;
                break;
              case 0x00000001:
                sip_v4 = bits << 1;
                dip_v4 = 0x80000000 | bits;
                break;
              case 0x40000001:
                sip_v4 = bits << 1;
                dip_v4 = bits;
                break;
              default:
                skAbort();
            }

            skipaddrSetV4(&sip, &sip_v4);
            skipaddrSetV4(&dip, &dip_v4);

            /* decide what to do.  put 59% of traffic as HTTP, 9% as
             * DNS, and 4% to each of ICMP, SMTP, FTP, IMAP, POP3,
             * TELNET, other-proto, scans. */

            bits = (uint32_t)lrand48();

            for (i=0, disp=dispatch_table; i < num_generators; ++i, ++disp) {
                if (bits < disp->dispatch_value) {
                    if (disp->generator(&sip, &dip)) {
                        /* out of memory; force break from outer for()
                         * loop */
                        NOTICEMSG("Out of memory condition in generator;"
                                  " flushing files");
                        goto TIME_STEP;
                    }
                    break;
                }
            }
        }

      TIME_STEP:
        /* move time forward */
        current_time += time_step;

        /* flush the incremental files if it is time */
        if (output_directory) {
            if (current_time >= incr_flush) {
                flushIncrementalFiles();
                do {
                    incr_flush += flush_timeout;
                } while (incr_flush <= current_time);
            }
        }

#if RECGEN_USE_HEAP
        /* write the records */
        while (((rwrec = skRwrecHeapPeek(heap)) != NULL)
               && (rwRecGetEndTime(rwrec) <= current_time))
        {
            writeRecord(skRwrecHeapPop(heap));
        }
#endif
    }

    if (output_directory) {
        flushIncrementalFiles();
    }

    return 0;
}


/*
 *  runSubprocess();
 *
 *    Complete initialization of required data structures and generate
 *    flow records.  This function never returns.
 */
static void
runSubprocess(
    void)
{
    /* initialize random number generator */
    srand48((long)seed);

    /* create the stream cache if necessary */
    if (output_directory) {
        cache = skCacheCreate(file_cache_size, openIncrementalFile);
        if (NULL == cache) {
            CRITMSG("Unable to create stream cache");
            appExit(EXIT_FAILURE);
        }
        /* set next flush time */
        incr_flush = start_time + flush_timeout;

        /* remove any files from the processing directory */
        emptyProcessingDirectory();
    }

    /* create the Bag to use for mapping IPs to high ports */
    if (skBagCreateTyped(&ip2port, SKBAG_FIELD_ANY_IPv4, SKBAG_FIELD_ANY_PORT,
                         SKBAG_OCTETS_FIELD_DEFAULT,
                         SKBAG_OCTETS_FIELD_DEFAULT))
    {
        CRITMSG("Unable to create bag");
        appExit(EXIT_FAILURE);
    }

    /* create memory pool */
    if (skMemoryPoolCreate(&mempool, sizeof(rwRec), INITIAL_RWREC_COUNT)) {
        CRITMSG("Unable to create memory pool");
        appExit(EXIT_FAILURE);
    }

#if RECGEN_USE_HEAP
    /* create the heap */
    heap = skRwrecHeapCreate(INITIAL_RWREC_COUNT);
    if (!heap) {
        CRITMSG("Unable to create heap");
        appExit(EXIT_FAILURE);
    }
#endif

    if (generateFlows()) {
        appExit(EXIT_FAILURE);
    }

    appExit(EXIT_SUCCESS);
}


int main(int argc, char **argv)
{
    char tbuf1[SKTIMESTAMP_STRLEN];
    char tbuf2[SKTIMESTAMP_STRLEN];
    recgen_subprocess_t *sproc;
    uint32_t i,j;
    int proc_status;
    int rv;

    appSetup(argc, argv);                       /* never returns on error */

    if (0 == num_subprocesses) {
        /* there is only one "subprocess", and it is us.  this
         * function never returns */
        runSubprocess();
    }

    /* if we get here, we must be creating incremental files */
    assert(processing_directory);
    assert(output_directory);

    /* spawn the subprocesses */
    for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
        sproc->pid = fork();
        if (-1 == sproc->pid) {
            CRITMSG("Failed to start process #%d: %s",
                    i, strerror(errno));
            appExit(EXIT_FAILURE);
        }
        if (sproc->pid > 0) {
            /* parent */
            sproc->started = 1;
            INFOMSG("Parent spawned subprocess #%u %d",
                    i, (int)sproc->pid);
        } else {
            /* child */
            is_subprocess = 1;
            processing_directory = sproc->processing_dir;
            start_time = sproc->start_time;
            end_time = sproc->end_time;
            seed = sproc->seed;
            /* in the array of subprocesses, clear the 'pid' value
             * for all previously spawned subprocesses */
            for (j = 0; j < i; ++j) {
                subproc[j].pid = 0;
            }

            DEBUGMSG(("Process #%u %d started using seed %" PRIu32
                      " to create flows dated %s to %s"),
                     i, (int)getpid(), sproc->seed,
                     sktimestamp_r(tbuf1, sproc->start_time, 0),
                     sktimestamp_r(tbuf2, sproc->end_time, 0));

            runSubprocess();    /* never returns */
        }
    }

    /* only the parent will make it here */
    assert(!is_subprocess);

    /* wait for the subprocess to end */
    for (i = 0, sproc = subproc; i < num_subprocesses; ++i, ++sproc) {
        if (sproc->pid && sproc->started && !sproc->finished) {
            rv = waitpid(sproc->pid, &proc_status, 0);
            if (-1 == rv) {
                WARNINGMSG("Error waiting for process #%u %d: %s",
                           i, (int)sproc->pid, strerror(errno));
            } else {
                INFOMSG("Process #%u %d exited with status %d",
                        i, (int)sproc->pid, proc_status);
            }
            sproc->finished = 1;
        }
    }

    return EXIT_SUCCESS;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
