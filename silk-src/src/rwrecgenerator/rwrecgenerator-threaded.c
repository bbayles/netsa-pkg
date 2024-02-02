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
**    To write the records to a text file, specify --text-output-file.
**
**    To write the records to a single SiLK file, specify
**    --silk-output-path.
**
**    To write the records into small incremental files (such as those
**    created by rwflowpack --output-mode=sending), specify the
**    --output-directory and --incremental-directory switches.
**
**    One of the above switches is required.  Currently only one
**    output may be specified.
**
**    The application generates random IP addreses.  Addresses in
**    0.0.0.0/1 are considered internal; addresses in 128.0.0.0/1 are
**    considered external.  All flow records are between an internal
**    and an external address.
**
**    The application must have access to a "silk.conf" site
**    configuration file, either specified by the --site-config-file
**    switch on the command line or located by the usual methods.
**
**    The various --flowtype-* switches can be used to specify the
**    flowtype (class/type) pairs that rwrecgenerator uses for its
**    flow records.  When these switches are not specfied,
**    rwrecgenerator attempts to use the flowtypes defined in the
**    "silk.conf" file for the twoway site.  Specifically, it attempts
**    to use "all/in", "all/inweb", "all/out", and "all/outweb".
**
**    The --sensor-prefix-map switch is recommended.  It maps from an
**    internal IP address to a sensor.  If it is not provided, all
**    flow records will use the first sensor in the "silk.conf" file.
**    Make certain the sensors you choose are in the class specified
**    in the --flowtype-* switches.
**
**    The code uses nrand48() to generate random values.  You may
**    specify the seed it uses with the --seed switch.
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwrecgenerator-threaded.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skdllist.h>
#include <silk/skipaddr.h>
#include <silk/sklog.h>
#include <silk/skmempool.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include "stream-cache.h"
#include "skheap-rwrec.h"

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>


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
#define INITIAL_RWREC_COUNT  0x1000

/* mask to use when creating a new IP address (except when generating
 * a host scan).  this allows us to reduce the number of IPs used.
 * Make certain the mask has the bits 0 and bits 30 turned on */
#define IP_V4_MASK  0xc31e87a5

/* size of the stream cache when making incremenatal flows */
#define STREAM_CACHE_SIZE  32

/* how often, in milliseconds to flush the incremental files */
#define INCREMENTAL_FLUSH_TIMEOUT  60000

/* constants for referencing the flowtype[] array */
typedef enum rand_flowtype_en {
    FLOWTYPE_IN, FLOWTYPE_INWEB, FLOWTYPE_OUT, FLOWTYPE_OUTWEB
} rand_flowtype_t;

/* number of flowtypes */
#define NUM_FLOWTYPES  4

/* milliseconds per hour */
#define MILLISEC_PER_HOUR  3600000

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

/* ensure that the 'efs_flags' contains something */
#define ENSURE_FLAG_SET(efs_flags) \
    ((efs_flags) ? (efs_flags) : (SYN_FLAG | ACK_FLAG | FIN_FLAG))

#define FILL_RAND_STATE_FROM_SEED(frs_xsubi, frs_seed)  \
    ((frs_xsubi)[0] = 0x330e,                           \
     (frs_xsubi)[1] = (frs_seed) & UINT16_MAX,          \
     (frs_xsubi)[2] = ((frs_seed) >> 16) & UINT16_MAX)



typedef struct recgen_state_st recgen_state_t;
struct recgen_state_st {
    /* generator function that gets called */
    int               (*generator)(recgen_state_t *);

    const char         *name;

    /* memory pool for records created by this generator */
    sk_mempool_t       *mempool;

    /* list of generated records; the records for each individual
     * event end with the 'end_of_event_rec'. */
    sk_dllist_t        *queue;

    /* thread variables for accessing this state */
    pthread_t           thread;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;

    /* this generator's idea of the current time */
    sktime_t            current_time;

    /* number of records for each event. if this is not constant, the
     * event_recs_is_variable flag will be 1 */
    uint32_t            recs_per_event;

    /* number of events available in the queue */
    uint32_t            available;

    /* max number of events to put into the queue */
    uint32_t            max_available;

    /* range of variable that determine whether this generator gets
     * called this time. */
    uint32_t            dispatch_min;
    uint32_t            dispatch_max;

    /* random number state for determining whether this generator gets
     * called this time. this must be consistent across every
     * generator and in the consumeFlows() function. */
    unsigned short      dispatch_rand[3];

    /* random number state for record generation */
    unsigned short      generate_rand[3];

    /* flags giving state of the generator */
    unsigned int        started :1;
    unsigned int        generating :1;

    /* flag stating whether the recs_per_event value is constant (0)
     * or may vary (1) */
    unsigned int        event_recs_is_variable :1;
};

typedef struct recgen_initializer_st {
    int               (*generator)(recgen_state_t *);
    const char         *name;
    uint32_t            target_percent;
    uint32_t            recs_per_event;
    uint32_t            event_recs_is_variable;
    uint32_t            max_available;
} recgen_initializer_t;


/* LOCAL FUNCTION PROTOTYPES */

static void appUsageLong(void);
static void appTeardown(void);
static void appSetup(int argc, char **argv);
static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int
parseFlowtype(
    rand_flowtype_t     which_ft,
    const char         *string);
static void emptyIncrementalDirectory(void);
static skstream_t *
openIncrementalFile(
    const cache_key_t  *key,
    void               *v_file_format);
static int generateDns(recgen_state_t *state);
static int generateFtp(recgen_state_t *state);
static int generateHttp(recgen_state_t *state);
static int generateIcmp(recgen_state_t *state);
static int generateImap(recgen_state_t *state);
static int generateOtherProto(recgen_state_t *state);
static int generatePop3(recgen_state_t *state);
static int generateSmtp(recgen_state_t *state);
static int generateTcpHostScan(recgen_state_t *state);
static int generateTcpPortScan(recgen_state_t *state);
static int generateTelnet(recgen_state_t *state);


/* LOCAL CONSTANTS */

#define RECGEN_NUM_GENERATORS 11

static const recgen_initializer_t recgen_init[] = {
    {generateHttp,        "Http",          60,     2, 0, 1200},
    {generateDns,         "Dns",           10,     2, 0,  200},
    {generateFtp,         "Ftp",            4,     2, 0,  160},
    {generateIcmp,        "Icmp",           4,     1, 0,  320},
    {generateImap,        "Imap",           4,     2, 0,  160},
    {generateOtherProto,  "OtherProto",     4,     1, 0,  160},
    {generatePop3,        "Pop3",           4,     2, 0,  160},
    {generateSmtp,        "Smtp",           4,     2, 0,  160},
    {generateTelnet,      "Telnet",         4,     4, 1,  160},
    {generateTcpHostScan, "TcpHostScan",    1,   128, 1,   10},
    {generateTcpPortScan, "TcpPortScan",    1, 65536, 0,    5}
};


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

static recgen_state_t recgen_state[RECGEN_NUM_GENERATORS];

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
static skstream_t *silk_output_path;

/* when writing a file of textual output, specifies the ascii stream
 * and the file handle on which to write them.  set by the
 * --text-output-path switch. */
static rwAsciiStream_t *text_output_path;
static FILE *text_output_fp;

/* when generating incremental files (like rwflowpack creates),
 * specifies the directory in which to copy them at the flush timeout.
 * set by the --output-directory switch. */
static const char *output_directory;

/* the working directory in which to create the incremental files.
 * set by the --incremental-directory switch. */
static const char *incremental_directory;

/* sensor prefix map that maps from IPs to sensor.  specified by the
 * --sensor-prefix-map switch. */
static skPrefixMap_t *sensor_pmap;

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

/* cache of open file handles when using the incremental dir */
static stream_cache_t *cache;

/* time when the next flush of the incremental streams occurs */
static sktime_t incr_flush;

/* the heap of sorted records */
static skrwrecheap_t *heap;

/* are we shutting down? */
static int shutting_down = 0;

/* a marker to denote the end of an event */
static const rwRec *end_of_event_rec = (rwRec*)&seed;


/* OPTIONS SETUP */

typedef enum {
    OPT_START_TIME,
    OPT_END_TIME,
    OPT_TIME_STEP,
    OPT_EVENTS_PER_STEP,
    OPT_SILK_OUTPUT_PATH,
    OPT_TEXT_OUTPUT_PATH,
    OPT_OUTPUT_DIRECTORY,
    OPT_INCREMENTAL_DIRECTORY,
    OPT_SENSOR_PREFIX_MAP,
    OPT_FLOWTYPE_IN,
    OPT_FLOWTYPE_INWEB,
    OPT_FLOWTYPE_OUT,
    OPT_FLOWTYPE_OUTWEB,
    OPT_SEED,
    OPT_EPOCH_TIME,
    OPT_INTEGER_IPS,
    OPT_ZERO_PAD_IPS,
    OPT_INTEGER_SENSORS,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED
} appOptionsEnum;

static const struct option appOptions[] = {
    {"start-time",              REQUIRED_ARG, 0, OPT_START_TIME},
    {"end-time",                REQUIRED_ARG, 0, OPT_END_TIME},
    {"time-step",               REQUIRED_ARG, 0, OPT_TIME_STEP},
    {"events-per-step",         REQUIRED_ARG, 0, OPT_EVENTS_PER_STEP},
    {"silk-output-path",        REQUIRED_ARG, 0, OPT_SILK_OUTPUT_PATH},
    {"text-output-path",        REQUIRED_ARG, 0, OPT_TEXT_OUTPUT_PATH},
    {"output-directory",        REQUIRED_ARG, 0, OPT_OUTPUT_DIRECTORY},
    {"incremental-directory",   REQUIRED_ARG, 0, OPT_INCREMENTAL_DIRECTORY},
    {"sensor-prefix-map",       REQUIRED_ARG, 0, OPT_SENSOR_PREFIX_MAP},
    {"flowtype-in",             REQUIRED_ARG, 0, OPT_FLOWTYPE_IN},
    {"flowtype-inweb",          REQUIRED_ARG, 0, OPT_FLOWTYPE_INWEB},
    {"flowtype-out",            REQUIRED_ARG, 0, OPT_FLOWTYPE_OUT},
    {"flowtype-outweb",         REQUIRED_ARG, 0, OPT_FLOWTYPE_OUTWEB},
    {"seed",                    REQUIRED_ARG, 0, OPT_SEED},
    {"epoch-time",              NO_ARG,       0, OPT_EPOCH_TIME},
    {"integer-ips",             NO_ARG,       0, OPT_INTEGER_IPS},
    {"zero-pad-ips",            NO_ARG,       0, OPT_ZERO_PAD_IPS},
    {"integer-sensors",         NO_ARG,       0, OPT_INTEGER_SENSORS},
    {"no-titles",               NO_ARG,       0, OPT_NO_TITLES},
    {"no-columns",              NO_ARG,       0, OPT_NO_COLUMNS},
    {"column-separator",        REQUIRED_ARG, 0, OPT_COLUMN_SEPARATOR},
    {"no-final-delimiter",      NO_ARG,       0, OPT_NO_FINAL_DELIMITER},
    {"delimited",               OPTIONAL_ARG, 0, OPT_DELIMITED},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    "Specify time when flows begin. Def. Start of previous hour",
    "Specify time when flows end. Def. Start of current hour",
    "Specify number of milliseconds to step forward in time. Def. Difference between start-time and end-time.",
    "Specify number of events to create at each step. Def. 1",
    "Write binary SiLK flow records to the named file.  Use '-' to write flow records to the standard output.",
    "Write text output in columnar form to the named file.",
    "Write incremental files (like those produced by rwflowpack) to this directory",
    "Specify working directory to use when creating incremental files",
    "Specify file to map source IPs to sensors.  If not provided, all flows belong to sensor 0.",
    "Specify flowtype (the class/type pair) to use for incoming flows that are not web records.  Def. 'all/in'",
    "Specify flowtype to use for incoming web records. Def. 'all/inweb'",
    "Specify flowtype to use for outgoing web records. Def. 'all/out'",
    "Specify flowtype to use for outgoing web records. Def. 'all/outweb'",
    "Specify seed to use for random number generator",
    "Print times in UNIX epoch seconds. Def. No",
    "Print IP numbers as integers. Def. Canonical form",
    "Print IP numbers in zero-padded canonical form. Def. No",
    "Print sensor as an integer. Def. Sensor name",
    "Do not print column titles. Def. Print titles",
    "Disable fixed-width columnar output. Def. Columnar",
    "Use specified character between columns. Def. '|'",
    "Suppress column delimiter at end of line. Def. No",
    "Shortcut for --no-columns --no-final-del --column-sep=CHAR",
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
#define USAGE_MSG                                                             \
    ("[SWITCHES] [FILES]\n"                                                   \
     "\tDoes nothing right now because no one has told this application\n"    \
     "\twhat it needs to do.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skCompMethodOptionsUsage(fh);
    sksiteOptionsUsage(fh);
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
    recgen_state_t *rg_state;
    size_t i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* done */
    shutting_down = 1;

    /* signal all condition variables */
    for (i = 0, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_state)
    {
        if (rg_state->started) {
            pthread_mutex_lock(&rg_state->mutex);
            pthread_cond_broadcast(&rg_state->cond);
            pthread_mutex_unlock(&rg_state->mutex);
        }
    }

    /* join with the threads */
    for (i = 0, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_state)
    {
        if (rg_state->started) {
            pthread_join(rg_state->thread, NULL);
        }
    }

    /* destory outputs */
    if (cache) {
        skCacheDestroy(cache);
    }

    skStreamDestroy(&silk_output_path);

    if (text_output_path) {
        rwAsciiStreamDestroy(&text_output_path);
        text_output_path = NULL;
    }
    if (text_output_fp) {
        fclose(text_output_fp);
    }

    if (sensor_pmap) {
        skPrefixMapDelete(sensor_pmap);
    }
    if (heap) {
        skRwrecHeapDestroy(heap);
    }

    for (i = 0, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_state)
    {
        if (rg_state->queue) {
            void *elem;
            while (0 == skDLListPopHead(rg_state->queue, &elem)) {
                if (end_of_event_rec != elem) {
                    skMemPoolElementFree(rg_state->mempool, elem);
                }
            }
            skDLListDestroy(rg_state->queue);
        }
        if (rg_state->mempool) {
            skMemoryPoolDestroy(&rg_state->mempool);
        }
    }

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
    struct timeval tv;
    sk_file_header_t *hdr;
    const recgen_initializer_t *rg_init;
    recgen_state_t *rg_state;
    double sum1, sum2;
    size_t i;
#if RECGEN_USE_HEAP
    const rwRec *rwrec;
#endif
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    assert(RECGEN_NUM_GENERATORS
           == (sizeof(recgen_init)/ sizeof(recgen_init[0])));

    /* register the application */
    skAppRegister(argv[0]);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(flowtype, SK_INVALID_FLOWTYPE, sizeof(flowtype));

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* setup the log and register options */
    if (sklogSetup(SKLOG_FEATURE_SYSLOG)) {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* create the ascii stream */
    if (rwAsciiStreamCreate(&text_output_path)) {
        skAppPrintErr("Unable to create ascii stream");
        exit(EXIT_FAILURE);
    }
    rwAsciiAppendFields(text_output_path, field_list,
                        sizeof(field_list)/sizeof(field_list[0]));
    rwAsciiSetIPv6Policy(text_output_path, SK_IPV6POLICY_ASV4);

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
            exit(EXIT_FAILURE);
        }
        if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_INWEB]) {
            if (parseFlowtype(FLOWTYPE_INWEB, "all/inweb")) {
                exit(EXIT_FAILURE);
            }
        }
    }
    if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_OUT]) {
        if (parseFlowtype(FLOWTYPE_OUT, "all/out")) {
            exit(EXIT_FAILURE);
        }
        if (SK_INVALID_FLOWTYPE == flowtype[FLOWTYPE_OUTWEB]) {
            if (parseFlowtype(FLOWTYPE_OUTWEB, "all/outweb")) {
                exit(EXIT_FAILURE);
            }
        }
    }

    /* get default sensor is sensor prefix map is not specified */
    if (NULL == sensor_pmap) {
        char class_name[256];
        sensor_iter_t iter;

        sksiteClassSensorIterator(
            sksiteFlowtypeGetClassID(flowtype[FLOWTYPE_IN]),
            &iter);
        if (sksiteSensorIteratorNext(&iter, &default_sensor) == 0) {
            sksiteFlowtypeGetClass(class_name, sizeof(class_name),
                                   flowtype[FLOWTYPE_IN]);
            skAppPrintErr("No sensors in the class %s", class_name);
            exit(EXIT_FAILURE);
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
        }
    } else if (end_time < start_time) {
        char time_str[SKTIMESTAMP_STRLEN];
        skAppPrintErr("Invalid %s '%s': Occurs before %s '%s'",
                      appOptions[OPT_END_TIME].name,
                      sktimestamp_r(time_str, end_time, 0),
                      appOptions[OPT_START_TIME].name,
                      sktimestamp(start_time, 0));;
        exit(EXIT_FAILURE);
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
        && NULL == text_output_fp)
    {
        skAppPrintErr("One of the output switches is required");
        skAppUsage();
    }
    if ((output_directory && (silk_output_path || text_output_fp))
        || (silk_output_path && text_output_fp))
    {
        skAppPrintErr("Only one output switch may be specified");
        skAppUsage();
    }

    /* need both or neither directory switches */
    if (output_directory) {
        if (NULL == incremental_directory) {
            skAppPrintErr("Must specify --%s when --%s is specified",
                          appOptions[OPT_INCREMENTAL_DIRECTORY].name,
                          appOptions[OPT_OUTPUT_DIRECTORY].name);
            exit(EXIT_FAILURE);
        }
    } else if (incremental_directory) {
        skAppPrintErr("May only specify --%s when --%s is also specified",
                      appOptions[OPT_INCREMENTAL_DIRECTORY].name,
                      appOptions[OPT_OUTPUT_DIRECTORY].name);
        exit(EXIT_FAILURE);
    }

    /* set header for a single silk output file */
    if (silk_output_path) {
        hdr = skStreamGetSilkHeader(silk_output_path);
        if ((rv = skHeaderSetFileFormat(hdr, FT_RWGENERIC))
            || (rv = skHeaderSetCompressionMethod(hdr, comp_method)))
        {
            skStreamPrintLastErr(silk_output_path, rv, &skAppPrintErr);
            skStreamDestroy(&silk_output_path);
            exit(EXIT_FAILURE);
        }
    }

    if (sklogOptionsVerify()) {
        skAppUsage();
    }

    /* input looks good; register the teardown function */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* Set up and open the logger */
    sklogEnableThreadedLogging();
    sklogDisableRotation();
    sklogOpen();
    sklogCommandLine(argc, argv);

    /* initialize pseudo-random number generator */
    if (UINT32_MAX == seed) {
        /* cons up a seed; constants are what perl uses */
        gettimeofday(&tv, NULL);
        seed = (((uint32_t)1000003 * tv.tv_sec + (uint32_t)3 * tv.tv_usec)
                & INT32_MAX);
    }
    NOTICEMSG(("Using seed of %" PRIu32), seed);

    /* destroy or bind the ascii stream */
    if (text_output_fp) {
        rwAsciiSetOutputHandle(text_output_path, text_output_fp);
    } else {
        rwAsciiStreamDestroy(&text_output_path);
        text_output_path = NULL;
    }

    /* create the stream cache if necessary */
    if (output_directory) {
        cache = skCacheCreate(STREAM_CACHE_SIZE, openIncrementalFile);
        if (NULL == cache) {
            CRITMSG("Unable to create stream cache");
            exit(EXIT_FAILURE);
        }
        /* set next flush time */
        incr_flush = start_time + INCREMENTAL_FLUSH_TIMEOUT;

        /* remove any files from the incremental directory */
        emptyIncrementalDirectory();
    }

#if RECGEN_USE_HEAP
    /* create the heap */
    heap = skRwrecHeapCreate(INITIAL_RWREC_COUNT);
    if (!heap) {
        CRITMSG("Unable to create heap");
        exit(EXIT_FAILURE);
    }
#endif

    /* INITIALIZE THE STATE */
    /* find the sum of the relative weight of each event */
    sum1 = 0.0;
    for (i = 0, rg_init = recgen_init;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_init)
    {
        sum1 += (double)rg_init->target_percent / rg_init->recs_per_event;
    }

    /* initialize each entry of the recgen_state[], using values from
     * the recgen_init[] array.  In addition, figure out the range of
     * dispatch values for each entry in the table, given that there
     * are 1<<31 possible random values, and we want the number of
     * FLOW records produced to be near the target_percent. */
    sum2 = 0.0;
    for (i = 0, rg_init = recgen_init, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_init, ++rg_state)
    {
        /* initialize thread vars */
        pthread_mutex_init(&rg_state->mutex, NULL);
        pthread_cond_init(&rg_state->cond, NULL);

        /* random number seeds */
        FILL_RAND_STATE_FROM_SEED(rg_state->dispatch_rand, seed);
        FILL_RAND_STATE_FROM_SEED(rg_state->generate_rand,
                                  ((seed << (2*(i+1)))
                                   | (seed >> (32 - 2*(i+1)))));

        /* each thread has its own idea of current time */
        rg_state->current_time  = start_time;

        /* copy constant values from the initializer */
        rg_state->generator              = rg_init->generator;
        rg_state->name                   = rg_init->name;
        rg_state->recs_per_event         = rg_init->recs_per_event;
        rg_state->event_recs_is_variable = rg_init->event_recs_is_variable;
        rg_state->max_available          = rg_init->max_available;
        rg_state->available              = 0;

        /* create memory pool and the queue */
        if (skMemoryPoolCreate(&rg_state->mempool, sizeof(rwRec),
                               rg_init->recs_per_event*rg_init->max_available))
        {
            CRITMSG("Unable to create memory pool");
            exit(EXIT_FAILURE);
        }
        rg_state->queue          = skDLListCreate(NULL);
        if (NULL == rg_state->queue) {
            CRITMSG("Unable to create DLList");
            exit(EXIT_FAILURE);
        }

        /* set range of values that determine when to use this
         * generator */
        rg_state->dispatch_min   = (uint32_t)sum2;

        sum2 += ((double)rg_init->target_percent / rg_init->recs_per_event
                 * (double)(UINT32_C(1) << 31) / sum1);

        rg_state->dispatch_max   = (uint32_t)sum2;
    }

#if 0
    /* print the values and exit. */
    for (i = 0, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_state)
    {
        fprintf(stderr, "%2u  %10u => %10u\n",
                (unsigned)i, rg_state->dispatch_min, rg_state->dispatch_max);
    }
    fprintf(stderr, "%f   %u   %f\n", sum2, (1 << 31),
            (((double)(UINT32_C(1) << 31)) - sum2));
    exit(0);
#endif  /* 0 */

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
    int ispipe;
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
        rv = skStringParseUint64(&tmp64, opt_arg, 1, INT64_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        time_step = (sktime_t)tmp64;
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
        if (text_output_fp) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        if (skOpenFile(opt_arg, 1, &text_output_fp, &ispipe)) {
            skAppPrintErr("Invalid %s '%s': Unable to open file",
                          appOptions[opt_index].name, opt_arg);
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

      case OPT_INCREMENTAL_DIRECTORY:
        if (incremental_directory) {
            skAppPrintErr("Invalid %s '%s': Switch given multiple times",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        if (!skDirExists(opt_arg)) {
            skAppPrintErr("Invalid %s '%s': Not a directory",
                          appOptions[opt_index].name, opt_arg);
            return -1;
        }
        incremental_directory = opt_arg;
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

      case OPT_EPOCH_TIME:
        rwAsciiSetTimestampFlags(text_output_path, SKTIMESTAMP_EPOCH);
        break;

      case OPT_INTEGER_IPS:
        rwAsciiSetIntegerIps(text_output_path);
        break;

      case OPT_ZERO_PAD_IPS:
        rwAsciiSetZeroPadIps(text_output_path);
        break;

      case OPT_INTEGER_SENSORS:
        rwAsciiSetIntegerSensors(text_output_path);
        break;

      case OPT_NO_TITLES:
        rwAsciiSetNoTitles(text_output_path);
        break;

      case OPT_NO_COLUMNS:
        rwAsciiSetNoColumns(text_output_path);
        break;

      case OPT_NO_FINAL_DELIMITER:
        rwAsciiSetNoFinalDelimiter(text_output_path);
        break;

      case OPT_COLUMN_SEPARATOR:
        rwAsciiSetDelimiter(text_output_path, opt_arg[0]);
        break;

      case OPT_DELIMITED:
        rwAsciiSetNoColumns(text_output_path);
        rwAsciiSetNoFinalDelimiter(text_output_path);
        if (opt_arg) {
            rwAsciiSetDelimiter(text_output_path, opt_arg[0]);
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
 *  emptyIncrementalDirectory();
 *
 *    Remove all files from the incremental directory.
 */
static void
emptyIncrementalDirectory(
    void)
{
    char path[PATH_MAX];
    struct dirent *entry;
    DIR *dir;
    int file_count = 0;
    int rv;

    dir = opendir(incremental_directory);
    if (NULL == dir) {
        CRITMSG("Fatal error: Unable to open directory '%s': %s",
                incremental_directory, strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        snprintf(path, sizeof(path), "%s/%s",
                 incremental_directory, entry->d_name);
        if (skFileExists(path)) {
            if (0 == file_count) {
                DEBUGMSG("Removing files from '%s'", incremental_directory);
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
 *    Open a new file in the incremental directory to hold records
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
     * everything excpet the filename with the incremental
     * directory */
    sksiteGeneratePathname(tmpbuf, sizeof(tmpbuf),
                           key->flowtype_id, key->sensor_id,
                           key->time_stamp, "", NULL, &fname);
    snprintf(filename, sizeof(filename), "%s/%s",
             incremental_directory, fname);

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
 *    incremental_directory to the output_directory.
 */
static void
flushIncrementalFiles(
    void)
{
    int tmp_fd;
    char path[PATH_MAX];
    char newpath[PATH_MAX];
    struct dirent *entry;
    DIR *dir;
    int file_count = 0;
    int moved = 0;
    int rv;

    if (skCacheLockAndCloseAll(cache)) {
        skCacheUnlock(cache);
        CRITMSG("Error closing incremental files -- shutting down");
        exit(EXIT_FAILURE);
    }

    /* Open the incremental directory loop over the files in the
     * directory. */
    dir = opendir(incremental_directory);
    if (NULL == dir) {
        CRITMSG("Fatal error: Unable to open directory '%s': %s",
                incremental_directory, strerror(errno));
        skCacheUnlock(cache);
        exit(EXIT_FAILURE);
    }

    DEBUGMSG("Moving files to %s...", output_directory);
    while ((entry = readdir(dir)) != NULL) {
        /* ignore dot-files */
        if ('.' == entry->d_name[0]) {
            continue;
        }
        ++file_count;

        /* Copy each file to a unique name */
        snprintf(path, sizeof(path), "%s/%s",
                 incremental_directory, entry->d_name);
        snprintf(newpath, sizeof(newpath), "%s/%s.XXXXXX",
                 output_directory, entry->d_name);
        tmp_fd = mkstemp(newpath);
        if (tmp_fd == -1) {
            ERRMSG("Could not create and open temporary file '%s': %s",
                   newpath, strerror(errno));
            continue;
        }
        close(tmp_fd);
        rv = skMoveFile(path, newpath);
        if (rv != 0) {
            ERRMSG("Could not move file '%s' to '%s': %s",
                   path, newpath, strerror(rv));
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
            rwRecMemSetDIP(rec, &ip);
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
            rwRecMemSetSIP(rec, &ip);
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
    } else if (text_output_path) {
        rwAsciiPrintRec(text_output_path, rec);
    }

    return 0;
}


/*
 *  getIpsAndHighPort(&sip, &dip, &high_port, xsubi);
 *
 *    Given 'xsubi'---the current parameters of the pseudo-random
 *    number generator---fill the memory pointed at by 'sip' and 'dip'
 *    with IP addresses, and fill 'high_port' with an ephemeral port
 *    when 'high_port' is not NULL.
 */
static void
getIpsAndHighPort(
    skipaddr_t         *sip,
    skipaddr_t         *dip,
    uint16_t           *high_port,
    unsigned short      rand_state[])
{
    uint32_t sip_v4;
    uint32_t dip_v4;
    uint32_t bits;

    /* use one random number to create both IPs. If LSB is
     * OFF, the number is the basis for the sip; otherwise the
     * dip.  Form other number by shifting random number.  If
     * MSB of neither IP is high, set the MSB of the IP that
     * is the unshifted random number.  */
    bits = IP_V4_MASK & (uint32_t)nrand48(rand_state);

    if (0 == (bits & 0xFF000000)) {
        /* make certain first octet is non-zero */
        bits |= 0x02000000;
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

    skipaddrSetV4(sip, &sip_v4);
    skipaddrSetV4(dip, &dip_v4);

    if (high_port) {
        bits = (uint32_t)nrand48(rand_state);
        *high_port = GET_MASKED_BITS(bits, 10, 16);
        if (*high_port < 1024) {
            *high_port += 1024;
        }
    }
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
    sk_mempool_t       *mempool,
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
    recgen_state_t     *state)
{
    skipaddr_t source;
    skipaddr_t target;
    rwRec first_rec;
    rwRec *r;
    uint16_t sport;
    uint16_t dport = 0;
    uint16_t j;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t stime_step;
    uint16_t sport_start;
    uint16_t sport_cycle;
    uint32_t bits;
    uint8_t flags;

    getIpsAndHighPort(&source, &target, NULL, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    sport_start = 2048 + GET_MASKED_BITS(bits, 0, 15);
    sport_cycle = 33 + GET_MASKED_BITS(bits, 15, 7);
    dur = 1 + GET_MASKED_BITS(bits, 22, 4);
    stime_step = 1 + dur + GET_MASKED_BITS(bits, 26, 5);
    flags = GET_MASKED_BITS(bits, 20, 8) ? GET_MASKED_BITS(bits, 20, 8) : 0xFF;

    RWREC_CLEAR(&first_rec);
    rwRecMemSetSIP(&first_rec, &source);
    rwRecMemSetDIP(&first_rec, &target);
    rwRecSetSPort(&first_rec, sport_start + sport_cycle);
    rwRecSetDPort(&first_rec, dport);
    rwRecSetProto(&first_rec, IPPROTO_TCP);
    rwRecSetPkts(&first_rec, 1);
    rwRecSetBytes(&first_rec, 40);
    rwRecSetStartTime(&first_rec, my_stime);
    rwRecSetElapsed(&first_rec, dur);
    rwRecSetInitFlags(&first_rec, flags);
    rwRecSetTcpState(&first_rec, SK_TCPSTATE_EXPANDED);

    r = newRecord(state->mempool, &first_rec);
    if (NULL == r) {
        return -1;
    }
    if (skDLListPushTail(state->queue, r)) {
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
                r = newRecord(state->mempool, &first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecSetSPort(r, sport);
                rwRecSetDPort(r, dport);
                rwRecSetStartTime(r, my_stime);
                if (skDLListPushTail(state->queue, r)) {
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
                r = newRecord(state->mempool, &first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecSetSPort(r, sport);
                rwRecSetDPort(r, dport);
                rwRecSetStartTime(r, my_stime);
                if (skDLListPushTail(state->queue, r)) {
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
    recgen_state_t     *state)
{
    const uint16_t dports[] = {139, 138, 1434, 9474, 6000, 22, 25, 80};
    skipaddr_t source;
    skipaddr_t target;
    rwRec first_rec;
    rwRec *r;
    uint16_t sport;
    uint16_t dport;
    uint8_t flags;
    uint16_t j;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t stime_step;
    uint16_t sport_start;
    uint16_t sport_cycle;
    uint32_t num_hosts;
    uint32_t bits;

    getIpsAndHighPort(&source, &target, NULL, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    sport_start = 2048 + GET_MASKED_BITS(bits, 0, 15);
    sport_cycle = 11 + GET_MASKED_BITS(bits, 15, 7);
    dur = 1 + GET_MASKED_BITS(bits, 22, 4);
    stime_step = 1 + dur + GET_MASKED_BITS(bits, 26, 5);

    bits = (uint32_t)nrand48(state->generate_rand);
    dport = dports[GET_MASKED_BITS(bits, 0, 3)];
    flags = GET_MASKED_BITS(bits, 3, 5) ? GET_MASKED_BITS(bits, 3, 5) : 0xFF;
    num_hosts = 1 + GET_MASKED_BITS(bits, 16, 8);

    RWREC_CLEAR(&first_rec);
    rwRecMemSetSIP(&first_rec, &source);
    rwRecMemSetDIP(&first_rec, &target);
    rwRecSetSPort(&first_rec, sport_start + sport_cycle);
    rwRecSetDPort(&first_rec, dport);
    rwRecSetProto(&first_rec, IPPROTO_TCP);
    rwRecSetPkts(&first_rec, 1);
    rwRecSetBytes(&first_rec, 40);
    rwRecSetStartTime(&first_rec, my_stime);
    rwRecSetElapsed(&first_rec, dur);
    rwRecSetInitFlags(&first_rec, flags);
    rwRecSetTcpState(&first_rec, SK_TCPSTATE_EXPANDED);

    r = newRecord(state->mempool, &first_rec);
    if (NULL == r) {
        return -1;
    }
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    do {
        if (num_hosts > sport_cycle) {
            /* no need to check num_hosts */
            for (j = 0, sport = sport_start;
                 j < sport_cycle;
                 ++j, ++sport)
            {
                skipaddrIncrement(&target);
                --num_hosts;
                r = newRecord(state->mempool, &first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecMemSetDIP(r, &target);
                rwRecSetSPort(r, sport);
                rwRecSetStartTime(r, my_stime);
                if (skDLListPushTail(state->queue, r)) {
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
                r = newRecord(state->mempool, &first_rec);
                if (NULL == r) {
                    return -1;
                }
                rwRecMemSetDIP(r, &target);
                rwRecSetSPort(r, sport);
                rwRecSetStartTime(r, my_stime);
                if (skDLListPushTail(state->queue, r)) {
                    return -1;
                }
            }
        }
        my_stime += stime_step;
    } while (num_hosts);

    /* push the end-of-event marker onto the queue */
    if (skDLListPushTail(state->queue,(void*)end_of_event_rec)){
        return -1;
    }

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
    recgen_state_t     *state)
{
    const uint32_t bpp[] = {54, 70, 56, 72, 61, 77, 121, 144, 127};
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
    rwRecSetSPort(r, high_port);
    rwRecSetDPort(r, 53);
    rwRecSetProto(r, IPPROTO_UDP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetApplication(r, 53);
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    /* Repeat for the response */
    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
    rwRecSetSPort(r, 53);
    rwRecSetDPort(r, high_port);
    rwRecSetProto(r, IPPROTO_UDP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, my_stime);
    rwRecSetElapsed(r, dur);
    rwRecSetApplication(r, 53);
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateFtp();
 *
 *    Generate a FTP request and response.
 */
static int
generateFtp(
    recgen_state_t     *state)
{
    const uint16_t server_port = 21;
    const uint32_t bpp[] = {40, 44, 46, 49, 68, 70, 0, 0, 0};
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t rest_flags;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
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


    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)nrand48(state->generate_rand);

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateHttp();
 *
 *    Generate a HTTP/HTTPS request and response.
 */
static int
generateHttp(
    recgen_state_t     *state)
{
    skipaddr_t client;
    skipaddr_t server;
    uint16_t server_port = 80;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t rest_flags;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by a 13 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 524
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 13)
            + GET_MASKED_BITS(bits, 13, 13))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 2, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    /* Repeat for the response */

    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateIcmp();
 *
 *    Generate an ICMP message
 */
static int
generateIcmp(
    recgen_state_t     *state)
{
    skipaddr_t sip;
    skipaddr_t dip;
    uint16_t dport;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    uint32_t bits;

    getIpsAndHighPort(&sip, &dip, NULL, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &sip);
    rwRecMemSetDIP(r, &dip);
    rwRecSetDPort(r, dport);
    rwRecSetProto(r, IPPROTO_ICMP);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, state->current_time);
    rwRecSetElapsed(r, dur);
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateImap(recgen_state_t *state);
 *
 *    Generate a IMAP session.
 */
static int
generateImap(
    recgen_state_t     *state)
{
    const uint16_t server_port = 143;
    const uint32_t bpp[] = {91, 95, 93, 54, 0, 0, 0, 0, 0};
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t rest_flags;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by a 12 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 262
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 12)
            + GET_MASKED_BITS(bits, 12, 12))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)nrand48(state->generate_rand);

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateOtherProto();
 *
 *    Generate traffic on another IP protocol
 */
static int
generateOtherProto(
    recgen_state_t     *state)
{
    const uint8_t protos[] = {50, 47, 58, 50, 47, 58, 50, 47, 58};
    skipaddr_t sip;
    skipaddr_t dip;
    uint8_t proto;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    uint32_t bits;

    getIpsAndHighPort(&sip, &dip, NULL, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);

    proto = protos[GET_MASKED_BITS(bits, 0, 3)];
    dur = 1 + GET_MASKED_BITS(bits, 3, 17);
    pkts = (1 + GET_MASKED_BITS(bits, 20, 3)) * (1 + (dur >> 15));
    bytes = pkts * (20 + GET_MASKED_BITS(bits, 23, 8));

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &sip);
    rwRecMemSetDIP(r, &dip);
    rwRecSetProto(r, proto);
    rwRecSetPkts(r, pkts);
    rwRecSetBytes(r, bytes);
    rwRecSetStartTime(r, state->current_time);
    rwRecSetElapsed(r, dur);
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generatePop3();
 *
 *    Generate a POP3 session.
 */
static int
generatePop3(
    recgen_state_t     *state)
{
    const uint16_t server_port = 110;
    const uint32_t bpp[] = {47, 46, 419, 425, 0, 0, 0, 0, 0};
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t rest_flags;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by an 11 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 131
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 11)
            + GET_MASKED_BITS(bits, 11, 11))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)nrand48(state->generate_rand);

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

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    /* Repeat for the response */

    bits = (uint32_t)nrand48(state->generate_rand);

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
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
    if (skDLListPushTail(state->queue, r)) {
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
    recgen_state_t     *state)
{
    const uint16_t server_port = 25;
    const uint32_t bpp[] = {44, 55, 61, 90, 102, 131, 0, 0, 0};
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t rest_flags;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
    /* compute duration (in millisec) as product of two values from 0
     * to 8 multiplied by an 11 bit value.  One of the 0-8 values is
     * weighted toward smaller numbers.  Max duration is 131
     * seconds. */
    dur = ((GET_MASKED_BITS(bits, 0, 11)
            + GET_MASKED_BITS(bits, 11, 11))
           * (1 + (bits_in_value[GET_MASKED_BITS(bits, 10, 8)]
                   * lowest_bit_in_val[GET_MASKED_BITS(bits, 18, 8)])));

    rest_flags = GET_MASKED_BITS(bits, 26, 5);


    bits = (uint32_t)nrand48(state->generate_rand);

    /* pkts will be a value between 1 and 16, weighted toward 13 */
    pkts = (1
            + bits_in_value[bits & 0xFF]
            + highest_bit_in_val[(bits >> 8) & 0xFF]);
    bits >>= 16;

    /* bytes/packet will be a value between 40 and 511, with spikes at
     * values in the bpp[] array above.  */
    if (bpp[lowest_bit_in_val[bits & 0xFF]]) {
        bytes = pkts * bpp[lowest_bit_in_val[bits & 0xFF]];
    } else {
        bytes = pkts * (((bits & 0x1FF) < 40) ? 40 : (bits & 0x1FF));
    }

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &client);
    rwRecMemSetDIP(r, &server);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }


    /* Repeat for the response */

    bits = (uint32_t)nrand48(state->generate_rand);

    /* adjust start time, duration, packets, and bytes for the
     * response */
    my_stime += GET_MASKED_BITS(bits, 0, 5);
    dur += GET_MASKED_BITS(bits, 5, 5);
    pkts += lowest_bit_in_val[GET_MASKED_BITS(bits, 10, 8)];
    bytes += GET_MASKED_BITS(bits, 18, 6);
    rest_flags = GET_MASKED_BITS(bits, 26, 5);

    r = newRecord(state->mempool, NULL);
    if (NULL == r) {
        return -1;
    }
    rwRecMemSetSIP(r, &server);
    rwRecMemSetDIP(r, &client);
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
    if (skDLListPushTail(state->queue, r)) {
        return -1;
    }

    return 0;
}


/*
 *  generateTelnet();
 *
 *    Generate a TELNET session.
 */
static int
generateTelnet(
    recgen_state_t     *state)
{
    const uint16_t server_port = 23;
    skipaddr_t client;
    skipaddr_t server;
    uint16_t high_port;
    rwRec *r;
    uint32_t pkts;
    uint32_t bytes;
    uint32_t total_dur;
    uint32_t dur;
    sktime_t my_stime = state->current_time;
    uint32_t bits;
    uint8_t init_flags = SYN_FLAG;
    uint8_t rest_flags = SYN_FLAG | ACK_FLAG;
    uint8_t tcp_state = SK_TCPSTATE_EXPANDED;

    getIpsAndHighPort(&client, &server, &high_port, state->generate_rand);

    bits = (uint32_t)nrand48(state->generate_rand);
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

        bits = (uint32_t)nrand48(state->generate_rand);

        /* assume one packet approximately every 2 to 16 seconds */
        pkts = 1 + (dur >> (11 + GET_MASKED_BITS(bits, 0, 2)));

        /* use a bpp range of 40-48 */
        bytes = pkts * (40 + bits_in_value[GET_MASKED_BITS(bits, 2, 8)]);

        r = newRecord(state->mempool, NULL);
        if (NULL == r) {
            return -1;
        }
        rwRecMemSetSIP(r, &client);
        rwRecMemSetDIP(r, &server);
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
        if (skDLListPushTail(state->queue, r)) {
            return -1;
        }

        /* handle the response */

        /* adjust packets and bytes for the other side  */
        pkts += bits_in_value[GET_MASKED_BITS(bits, 10, 8)];
        bytes += 40 * bits_in_value[GET_MASKED_BITS(bits, 10, 8)];

        r = newRecord(state->mempool, NULL);
        if (NULL == r) {
            return -1;
        }
        rwRecMemSetSIP(r, &server);
        rwRecMemSetDIP(r, &client);
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
        if (skDLListPushTail(state->queue, r)) {
            return -1;
        }

        /* adjust values */
        my_stime += dur;
        total_dur -= dur;
        init_flags |= rest_flags;
        tcp_state |= SK_TCPSTATE_TIMEOUT_STARTED;

    } while (total_dur > 0);

    /* push the end-of-event marker onto the queue */
    if (skDLListPushTail(state->queue,(void*)end_of_event_rec)){
        return -1;
    }

    return 0;
}



/*
 *  generatorLoop(state);
 *
 *    THREAD ENTRY POINT
 *
 *    Generate pseudo-random numbers and call the generator when the
 *    random number for the particular generator arises.
 */
static void *
generatorLoop(
    void               *v_state)
{
    recgen_state_t *rg_state = (recgen_state_t*)v_state;
    sigset_t sigs;
    uint32_t num_events;
    uint32_t bits;

    /* ignore signals */
    sigfillset(&sigs);
    pthread_sigmask(SIG_SETMASK, &sigs, NULL);

    INFOMSG("Starting thread for generate%s()", rg_state->name);

    /* loop until the end_time is reached */
    while (rg_state->current_time <= end_time) {
        for (num_events = 0; num_events < events_per_step; ++num_events) {
            /* decide what to do.  put 59% of traffic as HTTP, 9% as
             * DNS, and 4% to each of ICMP, SMTP, FTP, IMAP, POP3,
             * TELNET, other-proto, scans. */
            bits = (uint32_t)nrand48(rg_state->dispatch_rand);

            if (rg_state->dispatch_min <= bits
                && bits < rg_state->dispatch_max)
            {
                pthread_mutex_lock(&rg_state->mutex);
                /* do not generate more if queue is full */
                while (rg_state->available >= rg_state->max_available
                       && !shutting_down)
                {
                    pthread_cond_wait(&rg_state->cond, &rg_state->mutex);
                }
                if (shutting_down) {
                    goto END;
                }
                /* add flows to the queue */
                if (rg_state->generator(rg_state)) {
                    ERRMSG("Out of memory");
                    shutting_down = 1;
                    goto END;
                }
                if (0 == rg_state->available) {
                    DEBUGMSG("generate%s adding records to empty queue",
                            rg_state->name);
                    /* tell the consumer there are records */
                    pthread_cond_signal(&rg_state->cond);
                }
                ++rg_state->available;
                pthread_mutex_unlock(&rg_state->mutex);
            }
        }

        /* move time forward */
        rg_state->current_time += time_step;
    }

    INFOMSG("End time reached for thread generate%s()", rg_state->name);

    /* continue to deliver records that are sitting in the queue to
     * the consumer */
    pthread_mutex_lock(&rg_state->mutex);
    rg_state->generating = 0;
    while (rg_state->available && !shutting_down) {
        pthread_cond_wait(&rg_state->cond, &rg_state->mutex);
    }

  END:
    pthread_mutex_unlock(&rg_state->mutex);
    INFOMSG("Exiting thread for generate%s()", rg_state->name);
    return NULL;
}


/*
 *    Main loop to consume the flow records.
 *
 *    Uses a random number to choose what sort of event to create and
 *    calls the function to create the flow records.  Repeats until
 *    the events_per_step has been reached.  Then it increments the
 *    time window by the time_step, prints the records whose end-times
 *    have been reached, and then generates a more events until the
 *    end_time is reached.
 */
static int
consumeFlows(
    void)
{
    recgen_state_t *rg_state;
    sktime_t current_time;
    uint32_t bits;
    uint32_t num_events;
    size_t i;
    size_t j;
    unsigned short rand_state[3];
    rwRec *rwrec;

    current_time = start_time;

    FILL_RAND_STATE_FROM_SEED(rand_state, seed);

    /* loop until the end_time is reached */
    while (current_time <= end_time) {
        for (num_events = 0; num_events < events_per_step; ++num_events) {
            bits = (uint32_t)nrand48(rand_state);
            for (i = 0, rg_state = recgen_state;
                 i < RECGEN_NUM_GENERATORS;
                 ++i, ++rg_state)
            {
                if (bits < rg_state->dispatch_max) {
                    TRACEMSG((("current_time = %" PRId64 "; num_events = %"
                               PRIu32 "; event = %s"),
                              current_time, num_events, rg_state->name));
                    pthread_mutex_lock(&rg_state->mutex);

                    /* handle the case when there are not enough flow
                     * records available */
                    while (!rg_state->available && !shutting_down) {
                        if (!rg_state->generating) {
                            ERRMSG("Too few records from %s",
                                   rg_state->name);
                            shutting_down = 1;
                            break;
                        }
                        pthread_cond_wait(&rg_state->cond, &rg_state->mutex);
                    }
                    if (shutting_down) {
                        pthread_mutex_unlock(&rg_state->mutex);
                        return -1;
                    }
                    /* if queue is full, let the generator know we are
                     * taking records */
                    if (rg_state->available >= rg_state->max_available) {
                        pthread_cond_signal(&rg_state->cond);
                    }
                    --rg_state->available;
                    if (rg_state->event_recs_is_variable) {
                        /* pull records until the end_of_event_rec is
                         * found */
                        for (;;) {
                            if (skDLListPopHead(rg_state->queue,(void**)&rwrec)
                                != 0)
                            {
                                WARNINGMSG("Unexpectedly encountered"
                                           " empty queue");
                                pthread_mutex_unlock(&rg_state->mutex);
                                goto TIME_STEP;
                            }
                            if (end_of_event_rec == rwrec) {
                                break;
                            }
#if RECGEN_USE_HEAP
                            if (skRwrecHeapInsert(rwrec)) {
                            }
#else
                            if (writeRecord(rwrec)) {
                                shutting_down = 1;
                                pthread_mutex_unlock(&rg_state->mutex);
                                return -1;
                            }
                            skMemPoolElementFree(rg_state->mempool, rwrec);
#endif
                        }
                    } else {
                        for (j = 0; j < rg_state->recs_per_event; ++j) {
                            if (skDLListPopHead(rg_state->queue,(void**)&rwrec)
                                != 0)
                            {
                                WARNINGMSG("Unexpectedly encountered"
                                           " empty queue");
                                pthread_mutex_unlock(&rg_state->mutex);
                                goto TIME_STEP;
                            }
#if RECGEN_USE_HEAP
                            if (skRwrecHeapInsert(rwrec)) {
                            }
#else
                            if (writeRecord(rwrec)) {
                                shutting_down = 1;
                                pthread_mutex_unlock(&rg_state->mutex);
                                return -1;
                            }
                            skMemPoolElementFree(rg_state->mempool, rwrec);
#endif
                        }
                    }
                    pthread_mutex_unlock(&rg_state->mutex);
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
            }
            do {
                incr_flush += INCREMENTAL_FLUSH_TIMEOUT;
            } while (incr_flush <= current_time);
        }

#if RECGEN_USE_HEAP
        /* write the records */
        while (((rwrec = skRwrecHeapPeek(heap)) != NULL)
               && (rwRecGetEndTime(rwrec) <= current_time))
        {
            if (writeRecord(skRwrecHeapPop(heap))) {
            }
            skMemPoolElementFree(rg_state->mempool, rwrec);
        }
#endif
    }

    if (output_directory) {
        flushIncrementalFiles();
    }

    return 0;
}


int main(int argc, char **argv)
{
    recgen_state_t *rg_state;
    size_t i;
    int rv = EXIT_SUCCESS;

    appSetup(argc, argv);                       /* never returns on error */

    /* start all the generators */
    for (i = 0, rg_state = recgen_state;
         i < RECGEN_NUM_GENERATORS;
         ++i, ++rg_state)
    {
        rg_state->started = 1;
        rg_state->generating = 1;
        if (pthread_create(&rg_state->thread, NULL, &generatorLoop, rg_state)) {
            ERRMSG("Unable to start thread for generate%s()", rg_state->name);
            rg_state->started = 0;
            rg_state->generating = 0;
            exit(EXIT_FAILURE);
        }
    }

    /* start the consumer */
    if (consumeFlows()) {
        rv = EXIT_FAILURE;
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
