/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: flowrate.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skplugin.h>
#include <silk/rwrec.h>
#include <silk/utils.h>


/*
**  flowrate.c
**
**    Plug-in to allow filtering, sorting, counting, and printing of
**    the following values:
**
**    -- packets-per-second
**    -- bytes-per-second
**    -- bytes-per-packet (not for rwfilter; it already exists)
**    -- payload-bytes
**    -- payload-bytes-per-second
**
**    Mark Thomas
**    July 2008
*/


/* DEFINES AND TYPEDEFS */

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0

/* identifiers for the fields */
#define PCKTS_PER_SEC_KEY       1
#define BYTES_PER_SEC_KEY       2
#define BYTES_PER_PACKET_KEY    3
#define PAYLOAD_BYTES_KEY       4
#define PAYLOAD_RATE_KEY        5
#define PCKTS_PER_SEC_AGG      11
#define BYTES_PER_SEC_AGG      12
#define BYTES_PER_PACKET_AGG   13
#define PAYLOAD_BYTES_AGG      14
#define PAYLOAD_RATE_AGG       15

/* when a record's duration is 0 and a rate is being computed, assume
 * the duration is this number of MICRO (1e-6) seconds.  May be
 * changed via the --flowrate-zero-duration switch. */
#define ZERO_DURATION_DEFAULT 400

/* string version of ZERO_DURATION_DEFAULT for usage output */
#define ZERO_DURATION_STRING  "400"

/* the size of the binary value used as a key in rwsort, rwstats, and
 * rwuniq */
#define RATE_BINARY_SIZE_KEY  sizeof(uint64_t)

/* the aggregate value size in rwstats and rwuniq */
#define RATE_BINARY_SIZE_AGG  (2 * sizeof(uint64_t))

/* preferred width of textual columns */
#define RATE_TEXT_WIDTH   15

/* number of decimal places to use */
#define PRECISION               3

/* a %f format that includes PRECISION digits after the decimal */
#define FORMAT_PRECISION        FLOAT_FORMAT2(PRECISION)

/* binary values must be stored in rwuniq and rwstats.  these
 * conversions keep the PRECISION digits. values beyond PRECISION
 * digits are rounded to nearest number */
#define DOUBLE_TO_UINT64(v)     DBL_TO_INT2(v, PRECISION)
#define UINT64_TO_DOUBLE(v)     INT_TO_DBL2(v, PRECISION)

/* make values in rwcut consistent with those in rwuniq */
#define TRUNC_PRECISION(v)      UINT64_TO_DOUBLE(DOUBLE_TO_UINT64(v))

/* return a record's duration as a number of MICRO (1e-6) seconds.
 * SiLK stores duration as a number of MILLI (1e-3) seconds.  Use
 * zero_duration if the record's duration is 0. */
#define RWREC_MICRO_DURATION(r)                                         \
    ((rwRecGetElapsed(r) > 0) ? (rwRecGetElapsed(r) * 1000) : zero_duration)

/* compute a rate as a double given a volume and a duration as a
 * number of MICRO (1e-6) seconds.  Assumes duration is non-zero. */
#define COMPUTE_RATE(v, us)                     \
     ((double)(v) * 1e+6 / (double)(us))

/* compute a bytes-per-packet ratio as a double given the number of
 * bytes and the number of packets.  Assumes packet count is
 * non-zero. */
#define COMPUTE_BPP(b, p)                       \
    ((double)(b) / (double)(p))

/* calculate the packets per second of a single record */
#define PCKT_RATE_RWREC(r)                             \
    COMPUTE_RATE(rwRecGetPkts(r), RWREC_MICRO_DURATION(r))

/* calculate the bytes per second of a single record */
#define BYTE_RATE_RWREC(r)                             \
    COMPUTE_RATE(rwRecGetBytes(r), RWREC_MICRO_DURATION(r))

/* calculate the payload-bytes per second of a single record */
#define PAYLOAD_RATE_RWREC(r)                          \
    COMPUTE_RATE(getPayload(r), RWREC_MICRO_DURATION(r))

/* calculate the bytes per packet ratio of a single record */
#define BYTES_PER_PACKET_RWREC(r)                      \
    COMPUTE_BPP(rwRecGetBytes(r), rwRecGetPkts(r))


/* ah the joys of the C preprocessor...  this mess is here to allow us
 * to use the PRECISION macro as a parameter to other macros. */

#define FLOAT_FORMAT1(ff1_num)      "%." #ff1_num "f"
#define FLOAT_FORMAT2(ff2_macro)    FLOAT_FORMAT1(ff2_macro)

#define DBL_TO_INT1(d2i_v, d2i_num)                             \
    ((uint64_t)(((d2i_v) + 0.5e- ## d2i_num) * 1e+ ## d2i_num))
#define DBL_TO_INT2(d2i_v, d2i_macro)   DBL_TO_INT1(d2i_v, d2i_macro)

#define INT_TO_DBL1(i2d_v, i2d_num)             \
    ((double)(i2d_v) / 1e+ ## i2d_num)
#define INT_TO_DBL2(i2d_v, i2d_macro)   INT_TO_DBL1(i2d_v, i2d_macro)


/* structures to hold min and max values */
typedef struct double_range_st {
    double      min;
    double      max;
    unsigned    is_active :1;
} double_range_t;

typedef struct u64_range_st {
    uint64_t    min;
    uint64_t    max;
    unsigned    is_active :1;
} u64_range_t;


/* LOCAL VARIABLES */

/* the duration to use when a flow record's duration is 0.  may be set
 * by the --flowrate-zero-duration switch */
static uint64_t zero_duration = ZERO_DURATION_DEFAULT;

/* for filtering, pass records whose packets-per-second,
 * bytes-per-second, payload-bytes, and payload-bytes-per-second
 * values fall within these ranges. */
static double_range_t pckt_rate = {0, DBL_MAX, 0};
static double_range_t byte_rate = {0, DBL_MAX, 0};
static double_range_t payload_rate = {0, DBL_MAX, 0};
static u64_range_t payload_bytes = {0, UINT64_MAX, 0};

typedef enum plugin_options_en {
    OPT_FLOWRATE_ZERO_DURATION,
    OPT_PACKETS_PER_SECOND,
    OPT_BYTES_PER_SECOND,
    OPT_PAYLOAD_BYTES,
    OPT_PAYLOAD_RATE
} plugin_options_enum;

static struct option plugin_options[] = {
    {"flowrate-zero-duration",  REQUIRED_ARG, 0, OPT_FLOWRATE_ZERO_DURATION},
    {"packets-per-second",      REQUIRED_ARG, 0, OPT_PACKETS_PER_SECOND},
    {"bytes-per-second",        REQUIRED_ARG, 0, OPT_BYTES_PER_SECOND},
    {"payload-bytes",           REQUIRED_ARG, 0, OPT_PAYLOAD_BYTES},
    {"payload-rate",            REQUIRED_ARG, 0, OPT_PAYLOAD_RATE},
    {0, 0, 0, 0}                /* sentinel */
};

static const char *plugin_help[] = {
    ("Assume a flow's duration is this number of\n"
     "\tmicroseconds when computing a rate and the flow's given duration\n"
     "\tis 0 milliseconds.  Min 1.  Def. " ZERO_DURATION_STRING),
    "Packets-per-second is within decimal range X-Y.",
    "Bytes-per-second is within decimal range X-Y.",
    "Payload-byte count is within integer range X-Y.",
    "Payload-bytes-per-second is within decimal range X-Y.",
    NULL
};

/* fields for rwcut, rwuniq, etc.  this array contains both key fields
 * and aggregate value fields */
static struct plugin_fields_st {
    const char *name;
    uint32_t    val;
    const char *description;
} plugin_fields[] = {
    {"pckts/sec",       PCKTS_PER_SEC_KEY,
     "Ratio of packet count to duration"},
    {"bytes/sec",       BYTES_PER_SEC_KEY,
     "Ratio of byte count to duration"},
    {"bytes/packet",    BYTES_PER_PACKET_KEY,
     "Ratio of byte count to packet count"},
    {"payload-bytes",   PAYLOAD_BYTES_KEY,
     "Byte count minus bytes for minimal packet header"},
    {"payload-rate",    PAYLOAD_RATE_KEY,
     "Ratio of bytes of payload to duration"},
    {NULL,              UINT32_MAX, NULL},    /* end of key fields */
    {"pckts/sec",       PCKTS_PER_SEC_AGG,
     "Ratio of sum of packets to sum of durations"},
    {"bytes/sec",       BYTES_PER_SEC_AGG,
     "Ratio of sum of bytes to sum of durations"},
    {"bytes/packet",    BYTES_PER_PACKET_AGG,
     "Ratio of sum of bytes to sum of packets"},
    {"payload-bytes",   PAYLOAD_BYTES_AGG,
     "Sum of approximate bytes of payload"},
    {"payload-rate",    PAYLOAD_RATE_AGG,
     "Ratio of sum of payloads to sum of durations"},
    {NULL,              UINT32_MAX, NULL}     /* sentinel */
};




/* LOCAL FUNCTION PROTOTYPES */

static skplugin_err_t
filter(
    const rwRec        *rwrec,
    void               *cbdata,
    void              **extra);


/* FUNCTION DEFINITIONS */

/*
 *  status = optionsHandler(opt_arg, &index);
 *
 *    Handles options for the plugin.  'opt_arg' is the argument, or
 *    NULL if no argument was given.  'index' is the enum passed in
 *    when the option was registered.
 *
 *    Returns SKPLUGIN_OK on success, or SKPLUGIN_ERR if there was a
 *    problem.
 */
static skplugin_err_t
optionsHandler(
    const char         *opt_arg,
    void               *cbdata)
{
    skplugin_callbacks_t regdata;
    plugin_options_enum opt_index = *((plugin_options_enum*)cbdata);
    static int filter_registered = 0;
    int rv;

    switch (opt_index) {
      case OPT_FLOWRATE_ZERO_DURATION:
        rv = skStringParseUint64(&zero_duration, opt_arg, 1, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        /* this argument is used by all applications; do not register
         * the plug-in as a filter */
        return SKPLUGIN_OK;

      case OPT_PAYLOAD_BYTES:
        rv = skStringParseRange64(&payload_bytes.min, &payload_bytes.max,
                                  opt_arg, 0, 0, SKUTILS_RANGE_SINGLE_OPEN);
        if (rv) {
            goto PARSE_ERROR;
        }
        payload_bytes.is_active = 1;
        break;

      case OPT_PAYLOAD_RATE:
        rv = skStringParseDoubleRange(&payload_rate.min, &payload_rate.max,
                                      opt_arg, 0.0, 0.0,
                                      SKUTILS_RANGE_SINGLE_OPEN);
        if (rv) {
            goto PARSE_ERROR;
        }
        payload_rate.is_active = 1;
        break;

      case OPT_PACKETS_PER_SECOND:
        rv = skStringParseDoubleRange(&pckt_rate.min, &pckt_rate.max,
                                      opt_arg, 0.0, 0.0,
                                      SKUTILS_RANGE_SINGLE_OPEN);
        if (rv) {
            goto PARSE_ERROR;
        }
        pckt_rate.is_active = 1;
        break;

      case OPT_BYTES_PER_SECOND:
        rv = skStringParseDoubleRange(&byte_rate.min, &byte_rate.max,
                                      opt_arg, 0.0, 0.0,
                                      SKUTILS_RANGE_SINGLE_OPEN);
        if (rv) {
            goto PARSE_ERROR;
        }
        byte_rate.is_active = 1;
        break;
    }

    if (filter_registered) {
        return SKPLUGIN_OK;
    }
    filter_registered = 1;

    memset(&regdata, 0, sizeof(regdata));
    regdata.filter = filter;
    return skpinRegFilter(NULL, &regdata, NULL);

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  plugin_options[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return SKPLUGIN_ERR;
}


/*
 *  payload = getPayload(rwrec);
 *
 *    Compute the bytes of payload contained in 'rwrec' by multiplying
 *    the number of packets by the packet overhead and subtracting
 *    that from the byte count.  Return 0 if that value would be
 *    negative.
 *
 *    This function assumes minimal packet headers---that is, there
 *    are no options in the packets.  For TCP, assumes there are no
 *    TCP timestamps in the packet.  The returned value will be the
 *    maximum possible bytes of payload.
 */
static uint64_t
getPayload(
    const rwRec        *rwrec)
{
    uint64_t overhead;

#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(rwrec)) {
        /* IPv6 IP-header header with no options is 40 bytes */
        switch (rwRecGetProto(rwrec)) {
          case IPPROTO_TCP:
            /* TCP header is 20 (no TCP timestamps) */
            overhead = rwRecGetPkts(rwrec) * 60;
            break;
          case IPPROTO_UDP:
            /* UDP header is 8 bytes */
            overhead = rwRecGetPkts(rwrec) * 48;
            break;
          default:
            overhead = rwRecGetPkts(rwrec) * 40;
            break;
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* IPv4 IP-header header with no options is 20 bytes */
        switch (rwRecGetProto(rwrec)) {
          case IPPROTO_TCP:
            overhead = rwRecGetPkts(rwrec) * 40;
            break;
          case IPPROTO_UDP:
            overhead = rwRecGetPkts(rwrec) * 28;
            break;
          default:
            overhead = rwRecGetPkts(rwrec) * 20;
            break;
        }
    }

    if (overhead > rwRecGetBytes(rwrec)) {
        return 0;
    }

    return (rwRecGetBytes(rwrec) - overhead);
}


/*
 *  status = filter(rwrec, data, NULL);
 *
 *    The function actually used to implement filtering for the
 *    plugin.  Returns SKPLUGIN_FILTER_PASS if the record passes the
 *    filter, SKPLUGIN_FILTER_FAIL if it fails the filter.
 */
static skplugin_err_t
filter(
    const rwRec            *rwrec,
    void            UNUSED(*cbdata),
    void           UNUSED(**extra))
{
    uint64_t payload;
    double rate;

    /* filter by payload-bytes */
    if (payload_bytes.is_active) {
        payload = getPayload(rwrec);
        if (payload < payload_bytes.min || payload > payload_bytes.max) {
            /* failed */
            return SKPLUGIN_FILTER_FAIL;
        }
    }

    /* filter by payload-rate */
    if (payload_rate.is_active) {
        rate = PAYLOAD_RATE_RWREC(rwrec);
        if (rate < payload_rate.min || rate > payload_rate.max) {
            /* failed */
            return SKPLUGIN_FILTER_FAIL;
        }
    }

    /* filter by packets-per-second */
    if (pckt_rate.is_active) {
        rate = PCKT_RATE_RWREC(rwrec);
        if (rate < pckt_rate.min || rate > pckt_rate.max) {
            /* failed */
            return SKPLUGIN_FILTER_FAIL;
        }
    }

    /* filter by bytes-per-second */
    if (byte_rate.is_active) {
        rate = BYTE_RATE_RWREC(rwrec);
        if (rate < byte_rate.min || rate > byte_rate.max) {
            /* failed */
            return SKPLUGIN_FILTER_FAIL;
        }
    }

    return SKPLUGIN_FILTER_PASS;
}


/*
 *  status = recToTextKey(rwrec, text_val, text_len, &index, NULL);
 *
 *    Given the SiLK Flow record 'rwrec', compute the flow-rate ratio
 *    specified by '*index', and write a textual representation of
 *    that value into 'text_val', a buffer of 'text_len' characters.
 */
static skplugin_err_t
recToTextKey(
    const rwRec            *rwrec,
    char                   *text_value,
    size_t                  text_size,
    void                   *idx,
    void           UNUSED(**extra))
{
    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_KEY:
        snprintf(text_value, text_size, ("%" PRIu64), getPayload(rwrec));
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_KEY:
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(PAYLOAD_RATE_RWREC(rwrec)));
        return SKPLUGIN_OK;

      case PCKTS_PER_SEC_KEY:
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(PCKT_RATE_RWREC(rwrec)));
        return SKPLUGIN_OK;

      case BYTES_PER_SEC_KEY:
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(BYTE_RATE_RWREC(rwrec)));
        return SKPLUGIN_OK;

      case BYTES_PER_PACKET_KEY:
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(BYTES_PER_PACKET_RWREC(rwrec)));
        return SKPLUGIN_OK;

    }
    return SKPLUGIN_ERR_FATAL;
}


/*
 *  status = recToBinKey(rwrec, bin_val, &index, NULL);
 *
 *    Given the SiLK Flow record 'rwrec', compute the flow-rate ratio
 *    specified by '*index', and write a binary representation of
 *    that value into 'bin_val'.
 */
static skplugin_err_t
recToBinKey(
    const rwRec            *rwrec,
    uint8_t                *bin_value,
    void                   *idx,
    void           UNUSED(**extra))
{
    uint64_t val_u64;

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_KEY:
        val_u64 = getPayload(rwrec);
        break;
      case PAYLOAD_RATE_KEY:
        val_u64 = DOUBLE_TO_UINT64(PAYLOAD_RATE_RWREC(rwrec));
        break;
      case PCKTS_PER_SEC_KEY:
        val_u64 = DOUBLE_TO_UINT64(PCKT_RATE_RWREC(rwrec));
        break;
      case BYTES_PER_SEC_KEY:
        val_u64 = DOUBLE_TO_UINT64(BYTE_RATE_RWREC(rwrec));
        break;
      case BYTES_PER_PACKET_KEY:
        val_u64 = DOUBLE_TO_UINT64(BYTES_PER_PACKET_RWREC(rwrec));
        break;
      default:
        return SKPLUGIN_ERR_FATAL;
    }

    val_u64 = hton64(val_u64);
    memcpy(bin_value, &val_u64, RATE_BINARY_SIZE_KEY);
    return SKPLUGIN_OK;
}


/*
 *  status = binToTextKey(bin_val, text_val, text_len, &index);
 *
 *    Given the buffer 'bin_val' which was filled by calling
 *    recToBinKey(), write a textual representation of that value into
 *    'text_val', a buffer of 'text_len' characters.
 */
static skplugin_err_t
binToTextKey(
    const uint8_t      *bin_value,
    char               *text_value,
    size_t              text_size,
    void               *idx)
{
    uint64_t val_u64;

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_KEY:
        memcpy(&val_u64, bin_value, RATE_BINARY_SIZE_KEY);
        snprintf(text_value, text_size, ("%" PRIu64),
                 ntoh64(val_u64));
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_KEY:
      case PCKTS_PER_SEC_KEY:
      case BYTES_PER_SEC_KEY:
      case BYTES_PER_PACKET_KEY:
        memcpy(&val_u64, bin_value, RATE_BINARY_SIZE_KEY);
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 UINT64_TO_DOUBLE(ntoh64(val_u64)));
        return SKPLUGIN_OK;
    }

    return SKPLUGIN_ERR_FATAL;
}


static skplugin_err_t
addRecToBinAgg(
    const rwRec            *rwrec,
    uint8_t                *dest,
    void                   *idx,
    void           UNUSED(**extra))
{
    uint64_t val[2];

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_AGG:
        memcpy(val, dest, sizeof(uint64_t));
        val[0] += getPayload(rwrec);
        memcpy(dest, val, sizeof(uint64_t));
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_AGG:
        memcpy(val, dest, RATE_BINARY_SIZE_AGG);
        val[0] += getPayload(rwrec);
        val[1] += RWREC_MICRO_DURATION(rwrec);
        memcpy(dest, val, RATE_BINARY_SIZE_AGG);
        return SKPLUGIN_OK;

      case PCKTS_PER_SEC_AGG:
        memcpy(val, dest, RATE_BINARY_SIZE_AGG);
        val[0] += rwRecGetPkts(rwrec);
        val[1] += RWREC_MICRO_DURATION(rwrec);
        memcpy(dest, val, RATE_BINARY_SIZE_AGG);
        return SKPLUGIN_OK;

      case BYTES_PER_SEC_AGG:
        memcpy(val, dest, RATE_BINARY_SIZE_AGG);
        val[0] += rwRecGetBytes(rwrec);
        val[1] += RWREC_MICRO_DURATION(rwrec);
        memcpy(dest, val, RATE_BINARY_SIZE_AGG);
        return SKPLUGIN_OK;

      case BYTES_PER_PACKET_AGG:
        memcpy(val, dest, RATE_BINARY_SIZE_AGG);
        val[0] += rwRecGetBytes(rwrec);
        val[1] += rwRecGetPkts(rwrec);
        memcpy(dest, val, RATE_BINARY_SIZE_AGG);
        return SKPLUGIN_OK;
    }
    return SKPLUGIN_ERR_FATAL;
}


static skplugin_err_t
binToTextAgg(
    const uint8_t      *bin,
    char               *text_value,
    size_t              text_size,
    void               *idx)
{
    uint64_t val[2];

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_AGG:
        memcpy(val, bin, sizeof(uint64_t));
        snprintf(text_value, text_size, ("%" PRIu64), val[0]);
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_AGG:
      case PCKTS_PER_SEC_AGG:
      case BYTES_PER_SEC_AGG:
        memcpy(val, bin, RATE_BINARY_SIZE_AGG);
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(COMPUTE_RATE(val[0], val[1])));
        return SKPLUGIN_OK;

      case BYTES_PER_PACKET_AGG:
        memcpy(val, bin, RATE_BINARY_SIZE_AGG);
        snprintf(text_value, text_size, FORMAT_PRECISION,
                 TRUNC_PRECISION(COMPUTE_BPP(val[0], val[1])));
        return SKPLUGIN_OK;
    }

    return SKPLUGIN_ERR_FATAL;
}


static skplugin_err_t
binMergeAgg(
    uint8_t            *bin_a,
    const uint8_t      *bin_b,
    void               *idx)
{
    uint64_t val_a[2];
    uint64_t val_b[2];

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_AGG:
        memcpy(val_a, bin_a, sizeof(uint64_t));
        memcpy(val_b, bin_b, sizeof(uint64_t));
        val_a[0] += val_b[0];
        memcpy(bin_a, val_a, sizeof(uint64_t));
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_AGG:
      case PCKTS_PER_SEC_AGG:
      case BYTES_PER_SEC_AGG:
      case BYTES_PER_PACKET_AGG:
        memcpy(val_a, bin_a, RATE_BINARY_SIZE_AGG);
        memcpy(val_b, bin_b, RATE_BINARY_SIZE_AGG);
        val_a[0] += val_b[0];
        val_a[1] += val_b[1];
        memcpy(bin_a, val_a, RATE_BINARY_SIZE_AGG);
        return SKPLUGIN_OK;
    }
    return SKPLUGIN_ERR_FATAL;
}


static skplugin_err_t
binCompareAgg(
    int                *cmp,
    const uint8_t      *bin_a,
    const uint8_t      *bin_b,
    void               *idx)
{
    uint64_t val_a[2];
    uint64_t val_b[2];
    double ratio_a, ratio_b;

    switch (*((unsigned int*)(idx))) {
      case PAYLOAD_BYTES_AGG:
        memcpy(val_a, bin_a, sizeof(uint64_t));
        memcpy(val_b, bin_b, sizeof(uint64_t));
        *cmp = ((val_a[0] < val_b[0]) ? -1 : (val_a[0] > val_b[0]));
        return SKPLUGIN_OK;

      case PAYLOAD_RATE_AGG:
      case PCKTS_PER_SEC_AGG:
      case BYTES_PER_SEC_AGG:
        memcpy(val_a, bin_a, RATE_BINARY_SIZE_AGG);
        memcpy(val_b, bin_b, RATE_BINARY_SIZE_AGG);
        ratio_a = COMPUTE_RATE(val_a[0], val_a[1]);
        ratio_b = COMPUTE_RATE(val_b[0], val_b[1]);
        *cmp = ((ratio_a < ratio_b) ? -1 : (ratio_a > ratio_b));
        return SKPLUGIN_OK;

      case BYTES_PER_PACKET_AGG:
        memcpy(val_a, bin_a, RATE_BINARY_SIZE_AGG);
        memcpy(val_b, bin_b, RATE_BINARY_SIZE_AGG);
        ratio_a = COMPUTE_BPP(val_a[0], val_a[1]);
        ratio_b = COMPUTE_BPP(val_b[0], val_b[1]);
        *cmp = ((ratio_a < ratio_b) ? -1 : (ratio_a > ratio_b));
        return SKPLUGIN_OK;
    }
    return SKPLUGIN_ERR_FATAL;
}



/* the registration function called by skplugin.c */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*pi_data))
{
    int i;
    skplugin_field_t *field;
    skplugin_err_t rv;
    skplugin_callbacks_t regdata;

    /* Check API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    assert((sizeof(plugin_options)/sizeof(struct option))
           == (sizeof(plugin_help)/sizeof(char*)));

    /* register the options for rwfilter.  when the option is given,
     * we call skpinRegFilter() to register the filter function.
     * NOTE: Skip the first entry in the plugin_options[] array. */
    for (i = 1; plugin_options[i].name; ++i) {
        rv = skpinRegOption2(plugin_options[i].name,
                             plugin_options[i].has_arg, plugin_help[i],
                             NULL, &optionsHandler,
                             (void*)&plugin_options[i].val,
                             1, SKPLUGIN_FN_FILTER);
        if (SKPLUGIN_OK != rv && SKPLUGIN_ERR_DID_NOT_REGISTER != rv) {
            return rv;
        }
    }

    /* the first entry in the plugin_options[] array is usable by all
     * applications */
    rv = skpinRegOption2(plugin_options[0].name,
                         plugin_options[0].has_arg, plugin_help[0],
                         NULL, &optionsHandler,
                         (void*)&plugin_options[0].val,
                         3, SKPLUGIN_FN_FILTER, SKPLUGIN_FN_REC_TO_TEXT,
                         SKPLUGIN_FN_REC_TO_BIN);
    if (SKPLUGIN_OK != rv && SKPLUGIN_ERR_DID_NOT_REGISTER != rv) {
        return rv;
    }

    /* register the key fields to use for rwcut, rwuniq, rwsort,
     * rwstats */
    memset(&regdata, 0, sizeof(regdata));
    regdata.column_width = RATE_TEXT_WIDTH;
    regdata.bin_bytes    = RATE_BINARY_SIZE_KEY;
    regdata.rec_to_text  = recToTextKey;
    regdata.rec_to_bin   = recToBinKey;
    regdata.bin_to_text  = binToTextKey;

    for (i = 0; plugin_fields[i].name; ++i) {
        rv = skpinRegField(&field, plugin_fields[i].name,
                           plugin_fields[i].description,
                           &regdata, (void*)&plugin_fields[i].val);
        if (SKPLUGIN_OK != rv) {
            return rv;
        }
    }

    /* register the aggregate value fields to use for rwuniq and
     * rwstats */
    memset(&regdata, 0, sizeof(regdata));
    regdata.column_width    = RATE_TEXT_WIDTH;
    regdata.bin_bytes       = RATE_BINARY_SIZE_AGG;
    regdata.add_rec_to_bin  = addRecToBinAgg;
    regdata.bin_to_text     = binToTextAgg;
    regdata.bin_merge       = binMergeAgg;
    regdata.bin_compare     = binCompareAgg;

    for (++i; plugin_fields[i].name; ++i) {
        if (PAYLOAD_BYTES_AGG == plugin_fields[i].val) {
            /* special case size of payload-bytes */
            regdata.bin_bytes = sizeof(uint64_t);
            rv = skpinRegField(&field, plugin_fields[i].name,
                               plugin_fields[i].description,
                               &regdata, (void*)&plugin_fields[i].val);
            regdata.bin_bytes = RATE_BINARY_SIZE_AGG;
        } else {
            rv = skpinRegField(&field, plugin_fields[i].name,
                               plugin_fields[i].description,
                               &regdata, (void*)&plugin_fields[i].val);
        }
        if (SKPLUGIN_OK != rv) {
            return rv;
        }
    }

    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
