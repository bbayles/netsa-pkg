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
 *  filteropts.c
 *
 *  Suresh Konda
 *
 *  parsing and setting up filter options
 *
 *  10/21/01
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwfiltercheck.c 35b901fd2f56 2023-03-10 19:46:07Z mthomas $");

#include "rwfilter.h"
#include <silk/skipset.h>
#include <silk/skcountry.h>


/* TYPEDEFS AND DEFINES */

/* whether to support --bytes-per-second and --packets-per-second */
#ifndef RATE_FILTERS
#  define RATE_FILTERS 0
#endif

/* number of ports and protocols */
#define MAX_PORTS      65536
#define MAX_PROTOCOLS    256

/* number of sensors and flow-types; these must agree with rwrec.h */
#define MAX_SENSORS    65536
#define MAX_FLOW_TYPES   256

/* number of TCP flag checks we support */
#define MAX_TCPFLAG_CHECKS      16

/* number of attribute checks we support */
#define MAX_ATTRIBUTE_CHECKS        8

/* number of filter checks.  Approx equal to number of options */
#define FILTER_CHECK_MAX 64

/* number of IP Wildcards, IPsets, lists of CIDR blocks */
#define IP_INDEX_COUNT     4

#define SK_STRINGIFY(sk_s_token)         #sk_s_token
#define SK_EXPAND_STRINGIFY(sk_es_macro) SK_STRINGIFY(sk_es_macro)

/* indexes into the arrays of IP Wildcards, IPsets, CIDR blocks */
enum ip_index {
    SRC=0, DST, ANY, NHIP,
    _IP_INDEX_FINAL_ /* must be last */
};

/* holds a range */
typedef struct uint64_range_st {
    uint64_t min;
    uint64_t max;
} uint64_range_t;

typedef struct double_range_st {
    double min;
    double max;
} double_range_t;

/*
 *  CHECK_RANGE(v, r)
 *
 *    Returns 1 if value 'v' is within the range 'r'; 0 otherwise.
 */
#define CHECK_RANGE(v, r)   ((((v) < (r).min) || ((v) > (r).max)) ? 0 : 1)


/* holds TCP flags high/mask; e.g., S/SA */
typedef struct high_mask_st {
    uint8_t  high;
    uint8_t  mask;
} high_mask_t;

/* Test to see if TCP flags in 'var' meet the requirements of 'high_mask' */
#define CHECK_TCP_HIGH_MASK(var, high_mask) \
    TCP_FLAG_TEST_HIGH_MASK((var), (high_mask).high, (high_mask).mask)

/* The filters */
typedef struct filter_checks_st {
    /* times */
    uint64_range_t sTime, eTime, active_time, elapsed;

    /* flow volume */
    uint64_range_t bytes, pkts;

    /* flow rates */
    double_range_t bytes_per_packet;
#if RATE_FILTERS
    double_range_t bytes_per_second, packets_per_second;
#endif

    /* IP CIDR Block Values */
    skcidr_t *cidr_list[IP_INDEX_COUNT];
    unsigned int cidr_list_len[IP_INDEX_COUNT];
    int cidr_negated[IP_INDEX_COUNT];

    /* IP Wildcard Values */
    skIPWildcard_t ipwild[IP_INDEX_COUNT];
    int ipwild_negate[IP_INDEX_COUNT];

    /* IP sets */
    skipset_t *ipset[IP_INDEX_COUNT];
    int ipset_reject[IP_INDEX_COUNT];

    /* Source and Dest ports */
    sk_bitmap_t *sPort;
    sk_bitmap_t *dPort;
    sk_bitmap_t *any_port;

    /* IP Protocol */
    sk_bitmap_t *proto;

    /* ICMP type and code */
    sk_bitmap_t *icmp_type;
    sk_bitmap_t *icmp_code;

    /* sensors and class/type */
    sk_bitmap_t *sID;
    sk_bitmap_t *flow_type;

    /* SNMP interfaces */
    sk_bitmap_t *input_index;
    sk_bitmap_t *output_index;
    sk_bitmap_t *any_index;

    /* Country Codes */
    sk_bitmap_t *scc;
    sk_bitmap_t *dcc;
    sk_bitmap_t *any_cc;

    /* tcp flags (old style tcp flags) */
    uint8_t flags;

    /* flags_all, flags_init, flags_session */
    high_mask_t flags_all[MAX_TCPFLAG_CHECKS];
    high_mask_t flags_init[MAX_TCPFLAG_CHECKS];
    high_mask_t flags_session[MAX_TCPFLAG_CHECKS];
    uint8_t count_flags_all;
    uint8_t count_flags_init;
    uint8_t count_flags_session;

    /* TCP state aka attributes */
    high_mask_t attributes[MAX_ATTRIBUTE_CHECKS];
    uint8_t count_attributes;

    /* application */
    sk_bitmap_t *application;

    /* ip-version */
    sk_ipv6policy_t ipv6_policy;

    /*
     *  entry in checkSet[i] == checkNumber if desired.  maxCheckseUsed
     *  is the number of checks actually used in this run
     */
    uint8_t checkSet[FILTER_CHECK_MAX];
    uint8_t check_count;

} filter_checks_t;



/* LOCAL VARIABLES */

static filter_checks_t static_checks;
static filter_checks_t * const checks = &static_checks;


/* OPTION SETUP */

/* struct implementer uses to define options */
typedef struct filter_switch_st {
    struct option   option;
    const char     *help;
} filter_switch_t;

enum {
    OPT_STIME = 0, OPT_ETIME, OPT_ACTIVE_TIME, OPT_DURATION,
    OPT_SPORT, OPT_DPORT, OPT_APORT, OPT_PROTOCOL,
    OPT_ICMP_TYPE, OPT_ICMP_CODE,
    OPT_BYTES, OPT_PACKETS,
    OPT_BYTES_PER_PACKET,
#if RATE_FILTERS
    OPT_BYTES_PER_SECOND, OPT_PACKETS_PER_SECOND,
#endif

    /* ordering for the IP Octet Maps and IPsets must be consistent
     * with that given by the ip_index enum. */
    OPT_SCIDR, OPT_DCIDR, OPT_ANY_CIDR, OPT_NHCIDR,
    OPT_NOT_SCIDR, OPT_NOT_DCIDR, OPT_NOT_ANY_CIDR, OPT_NOT_NHCIDR,

    OPT_SADDRESS, OPT_DADDRESS, OPT_ANY_ADDRESS, OPT_NEXT_HOP_ID,
    OPT_NOT_SADDRESS, OPT_NOT_DADDRESS,
    OPT_NOT_ANY_ADDRESS, OPT_NOT_NEXT_HOP_ID,

    OPT_SET_SIP, OPT_SET_DIP, OPT_SET_ANY, OPT_SET_NHIP,
    OPT_NOT_SET_SIP, OPT_NOT_SET_DIP, OPT_NOT_SET_ANY, OPT_NOT_SET_NHIP,

    OPT_INPUT_INDEX, OPT_OUTPUT_INDEX, OPT_ANY_INDEX,

    OPT_TCP_FLAGS,
    OPT_FIN_FLAG, OPT_SYN_FLAG, OPT_RST_FLAG, OPT_PSH_FLAG,
    OPT_ACK_FLAG, OPT_URG_FLAG, OPT_ECE_FLAG, OPT_CWR_FLAG,
    OPT_FLAGS_ALL, OPT_FLAGS_INITIAL, OPT_FLAGS_SESSION,

    OPT_ATTRIBUTES, OPT_APPLICATION, OPT_IP_VERSION,

    OPT_SCC, OPT_DCC, OPT_ANY_CC,

    OPT_SENSORS, OPT_FLOW_TYPE,
    _OPT_FINAL_OPTION_ /* must be last */
};

/* options as used by getopt_long() */
static struct option *filterOptions = NULL;

/* options and their help strings */
static filter_switch_t filterSwitch[] = {
    {{"stime",              REQUIRED_ARG, 0, OPT_STIME},
     ("Start time is within this time window:\n"
      "\tYYYY/MM/DD[:HH[:MM[:SS[.sss]]]][-YYYY/MM/DD[:HH[:MM[:SS[.sss]]]]]\n"
      "\tIf no window closing time, use start time. Window closing\n"
      "\ttime is rounded to final millisecond of specified precision.")},
    {{"etime",              REQUIRED_ARG, 0, OPT_ETIME},
     ("Ending time is within this time window.")},
    {{"active-time",        REQUIRED_ARG, 0, OPT_ACTIVE_TIME},
     ("Flow was active at any time during this time window.")},
    {{"duration",           REQUIRED_ARG, 0, OPT_DURATION},
     ("Duration in seconds falls within decimal range X-Y.  Use\n"
      "\tfloating point values to denote milliseconds.")},

    {{"sport",              REQUIRED_ARG, 0, OPT_SPORT},
     ("Source port is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},
    {{"dport",              REQUIRED_ARG, 0, OPT_DPORT},
     ("Destination port is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},
    {{"aport",              REQUIRED_ARG, 0, OPT_APORT},
     ("Source or destination port is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},
    {{"protocol",           REQUIRED_ARG, 0, OPT_PROTOCOL},
     ("Protocol is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 255.")},

    {{"icmp-type",          REQUIRED_ARG, 0, OPT_ICMP_TYPE},
     ("ICMP Type is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 255;\n"
      "\tadditionally, verifies records as ICMP or ICMPv6")},
    {{"icmp-code",          REQUIRED_ARG, 0, OPT_ICMP_CODE},
     ("ICMP Code is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 255;\n"
      "\tadditionally, verifies records as ICMP or ICMPv6")},

    {{"bytes",              REQUIRED_ARG, 0, OPT_BYTES},
     ("Byte count is within the integer range N-M.")},
    {{"packets",            REQUIRED_ARG, 0, OPT_PACKETS},
     ("Packet count is within the integer range N-M.")},
    {{"bytes-per-packet",   REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},
     ("Byte-per-packet count is within decimal range X-Y.")},
#if RATE_FILTERS
    {{"bytes-per-second",   REQUIRED_ARG, 0, OPT_BYTES_PER_SECOND},
     ("Bytes-per-second count is within decimal range X-Y.")},
    {{"packets-per-second", REQUIRED_ARG, 0, OPT_PACKETS_PER_SECOND},
     ("Packets-per-second count is within decimal range X-Y.")},
#endif

    /* IP CIDR blocks (like Wildcards but accept a list of values) */
    {{"scidr",              REQUIRED_ARG, 0, OPT_SCIDR},
     ("Source address matches a value in this comma separated\n"
      "\tlist of IPs and/or CIDR blocks.")},
    {{"dcidr",              REQUIRED_ARG, 0, OPT_DCIDR},
     ("Destination address matches a value in this comma separated\n"
      "\tlist of IPs and/or CIDR blocks.")},
    {{"any-cidr",           REQUIRED_ARG, 0, OPT_ANY_CIDR},
     ("Source or destination address matches a value in this comma\n"
      "\tseparated list of IPs and/or CIDR blocks.")},
    {{"nhcidr",             REQUIRED_ARG, 0, OPT_NHCIDR},
     ("Next Hop address matches a value in this comma separated\n"
      "\tlist of IPs and/or CIDR blocks.")},
    {{"not-scidr",          REQUIRED_ARG, 0, OPT_NOT_SCIDR},
     ("Source address does not match a value in this comma\n"
      "\tseparated list of IPs and/or CIDR blocks.")},
    {{"not-dcidr",          REQUIRED_ARG, 0, OPT_NOT_DCIDR},
     ("Destination address does not match a value in this comma\n"
      "\tseparated this list of IPs and/or CIDR blocks.")},
    {{"not-any-cidr",       REQUIRED_ARG, 0, OPT_NOT_ANY_CIDR},
     ("Neither source nor destination address matches a value\n"
      "\tin this comma separated list of IPs and/or CIDR blocks.")},
    {{"not-nhcidr",         REQUIRED_ARG, 0, OPT_NOT_NHCIDR},
     ("Next Hop address does not match a value in this comma\n"
      "\tseparated list of IPs and/or CIDR blocks.")},

    /* Wildcard IPs */
    {{"saddress",           REQUIRED_ARG, 0, OPT_SADDRESS},
     ("Source address matches this wildcard IP.\n"
      "\tWildcard IP is an IP address in the canonical form where each block\n"
      "\tof the IP is a number, a range, a comma-separated list of numbers\n"
      "\tand/or ranges, or 'x' for the entire range of values.")},
    {{"daddress",           REQUIRED_ARG, 0, OPT_DADDRESS},
     ("Destination address matches this Wildcard IP.")},
    {{"any-address",        REQUIRED_ARG, 0, OPT_ANY_ADDRESS},
     ("Source or destination address matches this Wildcard IP.")},
    {{"next-hop-id",        REQUIRED_ARG, 0, OPT_NEXT_HOP_ID},
     ("Next Hop address matches this Wildcard IP.")},
    {{"not-saddress",       REQUIRED_ARG, 0, OPT_NOT_SADDRESS},
     ("Source address does not match this Wildcard IP.")},
    {{"not-daddress",       REQUIRED_ARG, 0, OPT_NOT_DADDRESS},
     ("Destination address does not match this Wildcard IP.")},
    {{"not-any-address",    REQUIRED_ARG, 0, OPT_NOT_ANY_ADDRESS},
     ("Neither source nor destination address matches\n"
      "\tthis Wildcard IP.")},
    {{"not-next-hop-id",    REQUIRED_ARG, 0, OPT_NOT_NEXT_HOP_ID},
     ("Next Hop address does not match this Wildcard IP.")},

    /* IP sets */
    {{"sipset",             REQUIRED_ARG, 0, OPT_SET_SIP},
     ("Source address is in this IPset")},
    {{"dipset",             REQUIRED_ARG, 0, OPT_SET_DIP},
     ("Destination address is in this set")},
    {{"anyset",             REQUIRED_ARG, 0, OPT_SET_ANY},
     ("Either source or destination address is in this set")},
    {{"nhipset",            REQUIRED_ARG, 0, OPT_SET_NHIP},
     ("Next Hop address is in this set")},
    {{"not-sipset",         REQUIRED_ARG, 0, OPT_NOT_SET_SIP},
     ("Source address is not in this set")},
    {{"not-dipset",         REQUIRED_ARG, 0, OPT_NOT_SET_DIP},
     ("Destination address is not in this set")},
    {{"not-anyset",         REQUIRED_ARG, 0, OPT_NOT_SET_ANY},
     ("Neither source nor destination address is in this set")},
    {{"not-nhipset",        REQUIRED_ARG, 0, OPT_NOT_SET_NHIP},
     ("Next Hop address is not in this set")},

    {{"input-index",        REQUIRED_ARG, 0, OPT_INPUT_INDEX},
     ("SNMP input interface is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},
    {{"output-index",       REQUIRED_ARG, 0, OPT_OUTPUT_INDEX},
     ("SNMP output interface is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},
    {{"any-index",          REQUIRED_ARG, 0, OPT_ANY_INDEX},
     ("SNMP input or output is contained in this list.\n"
      "\tA comma separated list of numbers and ranges between 0 and 65535.")},

    {{"tcp-flags",          REQUIRED_ARG, 0, OPT_TCP_FLAGS},
     ("TCP flags match any value in the list [FSRPAUEC] where\n"
      "\tF=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR")},

    {{"flags-all",          REQUIRED_ARG, 0, OPT_FLAGS_ALL},
     ("Union of TCP flags on all packets match the masked flags\n"
      "\tcollection specified by <high-flags>/<mask-flags>, where <mask> may\n"
      "\tbe any combination of 'FSRPAUEC-' (where '-' means all flags) and\n"
      "\tmust not be empty, and <high> must be a subset of <mask> and may be\n"
      "\tempty. May specify a comma-separated list of up to "
      SK_EXPAND_STRINGIFY(MAX_TCPFLAG_CHECKS) " <high>/<mask>\n"
      "\tpairs.")},
    {{"flags-initial",      REQUIRED_ARG, 0, OPT_FLAGS_INITIAL},
     ("TCP flags on first packet match <high>/<mask>.  See\n"
      "\tthe description of --flags-all for details.")},
    {{"flags-session",      REQUIRED_ARG, 0, OPT_FLAGS_SESSION},
     ("TCP flags on all but first packet match <high>/<mask>.\n"
      "\tSee the description of --flags-all for details.")},

    {{"fin-flag",           REQUIRED_ARG, 0, OPT_FIN_FLAG},
     ("FIN flag is present if arg is 1, absent if arg is 0")},
    {{"syn-flag",           REQUIRED_ARG, 0, OPT_SYN_FLAG},
     ("SYN flag is present if arg is 1, absent if arg is 0")},
    {{"rst-flag",           REQUIRED_ARG, 0, OPT_RST_FLAG},
     ("RST flag is present if arg is 1, absent if arg is 0")},
    {{"psh-flag",           REQUIRED_ARG, 0, OPT_PSH_FLAG},
     ("PSH flag is present if arg is 1, absent if arg is 0")},
    {{"ack-flag",           REQUIRED_ARG, 0, OPT_ACK_FLAG},
     ("ACK flag is present if arg is 1, absent if arg is 0")},
    {{"urg-flag",           REQUIRED_ARG, 0, OPT_URG_FLAG},
     ("URG flag is present if arg is 1, absent if arg is 0")},
    {{"ece-flag",           REQUIRED_ARG, 0, OPT_ECE_FLAG},
     ("ECE flag is present if arg is 1, absent if arg is 0")},
    {{"cwr-flag",           REQUIRED_ARG, 0, OPT_CWR_FLAG},
     ("CWR flag is present if arg is 1, absent if arg is 0")},

    {{"attributes",         REQUIRED_ARG, 0, OPT_ATTRIBUTES},
     ("Flow attributes match the masked collection <high>/<mask>,\n"
      "\twhere <mask> may be any combination of 'CFST-' (where '-' means\n"
      "\tall flags) and must not be empty, and <high> must be a subset of\n"
      "\t<mask> and may be empty.  Flow attributes are characteristics\n"
      "\tdetermined by the flow generation sofware:\n"
      "\tC - Flow is a continuation of timed-out flow record (see 'T')\n"
      "\tF - Additional non-ACK packets were seen after a FIN packet\n"
      "\tS - All packets that comprise the flow record are the same size\n"
      "\tT - Flow was closed prematurely because active timeout was reached\n"
      "\tMay specify a comma-separated list of up to "
      SK_EXPAND_STRINGIFY(MAX_ATTRIBUTE_CHECKS) " <high>/<mask> pairs")},
    {{"application",        REQUIRED_ARG, 0, OPT_APPLICATION},
     ("Packet signature indicates one of these applications or\n"
      "\tservices, a comma separated list of integers. Indicate application\n"
      "\tby its standard port: HTTP=80,SMTP=25,DNS=53,etc")},

    {{"ip-version",         REQUIRED_ARG, 0, OPT_IP_VERSION},
#if SK_ENABLE_IPV6
     ("IP Version is contained in this list. Def 4,6")
#else
     ("IP Version is contained in this list. Def 4\n"
      "\tIPv6 support not available. All IPv6 flows will be ignored")
#endif
    },

    {{"scc",                REQUIRED_ARG, 0, OPT_SCC},
     ("Source address maps to one of these countries, a comma\n"
      "\tseparated list of two-letter country codes (IANA ccTLD)")},
    {{"dcc",                REQUIRED_ARG, 0, OPT_DCC},
     ("Destination address maps to one of these countries")},
    {{"any-cc",             REQUIRED_ARG, 0, OPT_ANY_CC},
     ("Source or destination address maps to one of these countries")},

    {{0, 0, 0, 0}, /* sentinel */
     NULL}
};


#if RATE_FILTERS
/* Allow previous shortcuts for options to work */
static struct option options_compat[] = {
    /* --packets vs --packets-per-second */
    {"packet",              REQUIRED_ARG, 0, OPT_PACKETS},
    {"packe",               REQUIRED_ARG, 0, OPT_PACKETS},
    {"pack",                REQUIRED_ARG, 0, OPT_PACKETS},
    {"pac",                 REQUIRED_ARG, 0, OPT_PACKETS},

    /* --bytes-per-packet vs --bytes-per-second */
    {"bytes-per-",          REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},
    {"bytes-per",           REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},
    {"bytes-pe",            REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},
    {"bytes-p",             REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},
    {"bytes-",              REQUIRED_ARG, 0, OPT_BYTES_PER_PACKET},

    {0, 0, 0, 0}            /* sentinel */
};
#endif  /* RATE_FILTERS */


/* LOCAL FUNCTION DECLARARTIONS */

static int
parseCidrList(
    skcidr_t          **cidr_list,
    unsigned int       *cidr_list_len,
    int                 opt_index,
    const char         *opt_arg);
static int
parseListToBitmap(
    sk_bitmap_t       **bitmap,
    uint32_t            bitmap_size,
    int                 opt_index,
    const char         *opt_arg);
static int
parseRangeTime(
    uint64_range_t     *p_vr,
    int                 opt_index,
    const char         *s_time);
static int
parseRangeInteger(
    uint64_range_t     *range,
    int                 opt_index,
    const char         *range_string);
static int
parseRangeDecimal(
    double_range_t     *range,
    int                 opt_index,
    const char         *range_string);
static int
parseFlags(
    int                 opt_index,
    const char         *opt_arg);
static int
setFilterCheckBinaryFlag(
    int                 opt_index,
    const char         *opt_arg);
static int
parseAttributes(
    int                 opt_index,
    const char         *opt_arg);
static int
parseCountryCodes(
    sk_bitmap_t       **bitmap,
    int                 opt_index,
    const char         *opt_arg);


/* FUNCTION DEFINITIONS */

/* Print usage to specified file handle */
void
filterUsage(
    FILE               *fh)
{
    int i;

    fprintf(fh, ("\nPARTITIONING SWITCHES determine whether to pass"
                 " or fail a flow-record.\n\tThe flow will fail unless"
                 " each of the following is true:\n\n"));
    for (i = 0; filterSwitch[i].option.name; i++) {
        fprintf(fh, "--%s %s. %s\n", filterSwitch[i].option.name,
                SK_OPTION_HAS_ARG(filterSwitch[i].option),
                filterSwitch[i].help);
    }
}


/*
 *    The options handler for the switches that this file registers.
 *
 *    Parses the user's values to the switches and fills in the global
 *    'checks' variable.  Returns 0 on success or 1 on failure.
 */
static int
filterOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    static int option_seen[FILTER_CHECK_MAX];
    int check_key = opt_index;
    int found_dup = 0;
    int rv = 1;
    int i;

    /* Some duplicate switch tests need to be handled in particular
     * ways. */
    switch (opt_index) {
      case OPT_SCIDR:
      case OPT_DCIDR:
      case OPT_ANY_CIDR:
      case OPT_NHCIDR:
      case OPT_NOT_SCIDR:
      case OPT_NOT_DCIDR:
      case OPT_NOT_ANY_CIDR:
      case OPT_NOT_NHCIDR:
        {
            int ip_partner = (opt_index + (((opt_index < OPT_NOT_SCIDR)
                                            ? 1 : -1) * IP_INDEX_COUNT));
            if (option_seen[opt_index]) {
                skAppPrintErr("A --%s filter has already been set",
                              filterOptions[opt_index].name);
                return 1;
            }
            if (option_seen[ip_partner]) {
                skAppPrintErr(("A --%s filter has already been set;\n"
                               "\tonly one of --%s and --%s are allowed"),
                              filterOptions[ip_partner].name,
                              filterOptions[opt_index].name,
                              filterOptions[ip_partner].name);
                return 1;
            }
            check_key = ((opt_index - OPT_SCIDR) % IP_INDEX_COUNT
                        + OPT_SCIDR);
        }
        option_seen[opt_index] = 1;
        break;

      case OPT_SADDRESS:
      case OPT_DADDRESS:
      case OPT_ANY_ADDRESS:
      case OPT_NEXT_HOP_ID:
      case OPT_NOT_SADDRESS:
      case OPT_NOT_DADDRESS:
      case OPT_NOT_ANY_ADDRESS:
      case OPT_NOT_NEXT_HOP_ID:
        {
            int ip_partner = (opt_index + (((opt_index < OPT_NOT_SADDRESS)
                                            ? 1 : -1) * IP_INDEX_COUNT));
            if (option_seen[opt_index]) {
                skAppPrintErr("A --%s filter has already been set",
                              filterOptions[opt_index].name);
                return 1;
            }
            if (option_seen[ip_partner]) {
                skAppPrintErr(("A --%s filter has already been set;\n"
                               "\tonly one of --%s and --%s are allowed"),
                              filterOptions[ip_partner].name,
                              filterOptions[opt_index].name,
                              filterOptions[ip_partner].name);
                return 1;
            }
            check_key = ((opt_index - OPT_SADDRESS) % IP_INDEX_COUNT
                        + OPT_SADDRESS);
        }
        option_seen[opt_index] = 1;
        break;

      case OPT_SET_SIP:
      case OPT_SET_DIP:
      case OPT_SET_ANY:
      case OPT_SET_NHIP:
      case OPT_NOT_SET_SIP:
      case OPT_NOT_SET_DIP:
      case OPT_NOT_SET_ANY:
      case OPT_NOT_SET_NHIP:
        {
            int ip_partner = (opt_index + (((opt_index < OPT_NOT_SET_SIP)
                                            ? 1 : -1) * IP_INDEX_COUNT));
            if (option_seen[opt_index]) {
                skAppPrintErr("A --%s filter has already been set",
                              filterOptions[opt_index].name);
                return 1;
            }
            if (option_seen[ip_partner]) {
                skAppPrintErr(("A --%s filter has already been set;\n"
                               "\tonly one of --%s and --%s are allowed"),
                              filterOptions[ip_partner].name,
                              filterOptions[opt_index].name,
                              filterOptions[ip_partner].name);
                return 1;
            }
            check_key = ((opt_index - OPT_SET_SIP) % IP_INDEX_COUNT
                        + OPT_SET_SIP);
        }
        option_seen[opt_index] = 1;
        break;

      case OPT_FIN_FLAG:
      case OPT_SYN_FLAG:
      case OPT_RST_FLAG:
      case OPT_PSH_FLAG:
      case OPT_ACK_FLAG:
      case OPT_URG_FLAG:
      case OPT_ECE_FLAG:
      case OPT_CWR_FLAG:
        if (option_seen[opt_index]) {
            skAppPrintErr("A --%s filter has already been set",
                          filterOptions[opt_index].name);
            return 1;
        }
        check_key = OPT_FLAGS_ALL;
        option_seen[opt_index] = 1;
        break;

      case OPT_FLAGS_ALL:
      case OPT_FLAGS_INITIAL:
      case OPT_FLAGS_SESSION:
        /* these can be repeated */
        break;

      default:
        if (option_seen[opt_index]) {
            skAppPrintErr("A --%s filter has already been set",
                          filterOptions[opt_index].name);
            return 1;
        }
        option_seen[opt_index] = 1;
        break;
    }

    /* check that this is not a repeated check */
    for (i = 0; i < checks->check_count; ++i) {
        if (check_key == checks->checkSet[i]) {
            found_dup = 1;
            break;
        }
    }

    if (found_dup == 0) {
        /* First time for this check */
        checks->checkSet[checks->check_count] = check_key;
        checks->check_count++;
    }


    /* Parse the parameter to the check */
    switch (opt_index) {
      case OPT_STIME:
        rv = parseRangeTime(&checks->sTime, opt_index, opt_arg);
        break;

      case OPT_ETIME:
        rv = parseRangeTime(&checks->eTime, opt_index, opt_arg);
        break;

      case OPT_ACTIVE_TIME:
        rv = parseRangeTime(&checks->active_time, opt_index, opt_arg);
        break;

      case OPT_DURATION:
        {
            /* parse values as floating point seconds, then convert to
             * milliseconds */
            double_range_t r;
            rv = parseRangeDecimal(&r, opt_index, opt_arg);
            if (0 == rv) {
                if (r.min > ((double)UINT64_MAX / 1e3)) {
                    checks->elapsed.min = UINT64_MAX;
                } else {
                    checks->elapsed.min = (uint64_t)(r.min * 1e3);
                }
                if (r.max > ((double)UINT64_MAX / 1e3)) {
                    checks->elapsed.max = UINT64_MAX;
                } else {
                    checks->elapsed.max = (uint64_t)(r.max * 1e3);
                }
            }
        }
        break;

      case OPT_SPORT:
        rv = parseListToBitmap(&(checks->sPort), MAX_PORTS,
                               opt_index, opt_arg);
        break;

      case OPT_DPORT:
        rv = parseListToBitmap(&(checks->dPort), MAX_PORTS,
                               opt_index, opt_arg);
        break;

      case OPT_APORT:
        rv = parseListToBitmap(&(checks->any_port), MAX_PORTS,
                               opt_index, opt_arg);
        break;

      case OPT_PROTOCOL:
        rv = parseListToBitmap(&(checks->proto), MAX_PROTOCOLS,
                               opt_index, opt_arg);
        break;

      case OPT_ICMP_TYPE:
        rv = parseListToBitmap(&(checks->icmp_type), MAX_PORTS >> 8,
                               opt_index, opt_arg);
        break;

      case OPT_ICMP_CODE:
        rv = parseListToBitmap(&(checks->icmp_code), MAX_PORTS >> 8,
                               opt_index, opt_arg);
        break;

      case OPT_BYTES:
        rv = parseRangeInteger(&checks->bytes, opt_index, opt_arg);
        break;

      case OPT_PACKETS:
        rv = parseRangeInteger(&checks->pkts, opt_index, opt_arg);
        break;

      case OPT_BYTES_PER_PACKET:
        rv = parseRangeDecimal(&checks->bytes_per_packet, opt_index, opt_arg);
        break;

#if RATE_FILTERS
      case OPT_BYTES_PER_SECOND:
        rv = parseRangeDecimal(&checks->bytes_per_second, opt_index, opt_arg);
        break;

      case OPT_PACKETS_PER_SECOND:
        rv = parseRangeDecimal(&checks->packets_per_second, opt_index, opt_arg);
        break;
#endif  /* RATE_FILTERS */

      case OPT_SCIDR:
      case OPT_DCIDR:
      case OPT_ANY_CIDR:
      case OPT_NHCIDR:
      case OPT_NOT_SCIDR:
      case OPT_NOT_DCIDR:
      case OPT_NOT_ANY_CIDR:
      case OPT_NOT_NHCIDR:
        {
            int ip_idx = (opt_index - OPT_SCIDR);
            if (ip_idx >= IP_INDEX_COUNT) {
                ip_idx -= IP_INDEX_COUNT;
                checks->cidr_negated[ip_idx] = 1;
            }
            rv = parseCidrList(&checks->cidr_list[ip_idx],
                               &checks->cidr_list_len[ip_idx],
                               opt_index, opt_arg);
        }
        break;

      case OPT_SADDRESS:
      case OPT_DADDRESS:
      case OPT_ANY_ADDRESS:
      case OPT_NEXT_HOP_ID:
      case OPT_NOT_SADDRESS:
      case OPT_NOT_DADDRESS:
      case OPT_NOT_ANY_ADDRESS:
      case OPT_NOT_NEXT_HOP_ID:
        {
            int ip_idx = (opt_index - OPT_SADDRESS);
            if (ip_idx >= IP_INDEX_COUNT) {
                ip_idx -= IP_INDEX_COUNT;
                checks->ipwild_negate[ip_idx] = 1;
            }
            rv = skStringParseIPWildcard(&checks->ipwild[ip_idx], opt_arg);
        }
        break;

      case OPT_SET_SIP:
      case OPT_SET_DIP:
      case OPT_SET_ANY:
      case OPT_SET_NHIP:
      case OPT_NOT_SET_SIP:
      case OPT_NOT_SET_DIP:
      case OPT_NOT_SET_ANY:
      case OPT_NOT_SET_NHIP:
        {
            skstream_t *stream;
            int ip_idx = (opt_index - OPT_SET_SIP);
            if (ip_idx >= IP_INDEX_COUNT) {
                ip_idx -= IP_INDEX_COUNT;
                checks->ipset_reject[ip_idx] = 1;
            }
            rv = filterOpenInputData(&stream, SK_CONTENT_SILK, opt_arg);
            if (rv == -1) {
                /* error has been printed */
                rv = 1;
            } else if (rv == 1) {
                /* ignore the stream, but no error */
                rv = 0;
            } else {
                rv = skIPSetRead(&(checks->ipset[ip_idx]), stream);
                if (rv) {
                    if (SKIPSET_ERR_FILEIO == rv) {
                        skStreamPrintLastErr(stream,
                                             skStreamGetLastReturnValue(stream),
                                             &skAppPrintErr);
                    } else {
                        skAppPrintErr("Unable to read IPset from '%s': %s",
                                      skStreamGetPathname(stream),
                                      skIPSetStrerror(rv));
                    }
                }
                skStreamDestroy(&stream);
            }
        }
        break;

      case OPT_INPUT_INDEX:
        rv = parseListToBitmap(&(checks->input_index), SK_SNMP_INDEX_LIMIT,
                               opt_index, opt_arg);
        break;

      case OPT_OUTPUT_INDEX:
        rv = parseListToBitmap(&(checks->output_index), SK_SNMP_INDEX_LIMIT,
                               opt_index, opt_arg);
        break;

      case OPT_ANY_INDEX:
        rv = parseListToBitmap(&(checks->any_index), SK_SNMP_INDEX_LIMIT,
                               opt_index, opt_arg);
        break;

      case OPT_TCP_FLAGS:
        rv = skStringParseTCPFlags(&checks->flags, opt_arg);
        break;

      case OPT_FLAGS_ALL:
      case OPT_FLAGS_INITIAL:
      case OPT_FLAGS_SESSION:
        rv = parseFlags(opt_index, opt_arg);
        break;

        /*
         * This section is all flag wonking
         */
      case OPT_FIN_FLAG:
      case OPT_SYN_FLAG:
      case OPT_RST_FLAG:
      case OPT_PSH_FLAG:
      case OPT_ACK_FLAG:
      case OPT_URG_FLAG:
      case OPT_ECE_FLAG:
      case OPT_CWR_FLAG:
        rv = setFilterCheckBinaryFlag(opt_index, opt_arg);
        break;

      case OPT_ATTRIBUTES:
        rv = parseAttributes(opt_index, opt_arg);
        break;

      case OPT_APPLICATION:
        rv = parseListToBitmap(&(checks->application), MAX_PORTS,
                               opt_index, opt_arg);
        break;

      case OPT_IP_VERSION:
        {
            uint32_t *ipversion;
            uint32_t count;
#if SK_ENABLE_IPV6
            rv = skStringParseNumberList(&ipversion, &count, opt_arg, 4, 6, 2);
#else
            rv = skStringParseNumberList(&ipversion, &count, opt_arg, 4, 4, 1);
#endif
            if (rv != 0) {
                break;
            }
            /* verify no --ip-version=5 */
            if ((ipversion[0] == 5) || ((count == 2) && (ipversion[1] == 5))) {
                rv = 1;
                break;
            }
            if (count == 2) {
                ipversion[0] += ipversion[1];
            }
            switch (ipversion[0]) {
              case 4:
              case 8:
                checks->ipv6_policy = SK_IPV6POLICY_IGNORE;
                break;
              case 6:
              case 12:
                checks->ipv6_policy = SK_IPV6POLICY_ONLY;
                break;
              case 10:
                checks->ipv6_policy = SK_IPV6POLICY_MIX;
                break;
              default:
                skAbortBadCase(ipversion[0]);
            }
            free(ipversion);
        }
        break;

      case OPT_SCC:
        rv = parseCountryCodes(&checks->scc, opt_index, opt_arg);
        break;

      case OPT_DCC:
        rv = parseCountryCodes(&checks->dcc, opt_index, opt_arg);
        break;

      case OPT_ANY_CC:
        rv = parseCountryCodes(&checks->any_cc, opt_index, opt_arg);
        break;

      default:
        skAbortBadCase(opt_index);
    }

    /* Additional tests now that the data has been parsed */
    if (rv == 0) {
        switch (opt_index) {
          case OPT_ICMP_TYPE:
          case OPT_ICMP_CODE:
          case OPT_PROTOCOL:
            if ((option_seen[OPT_ICMP_TYPE] || option_seen[OPT_ICMP_CODE])
                && option_seen[OPT_PROTOCOL])
            {
#if SK_ENABLE_IPV6
                const char *proto_list = "1 or 58";
#else
                const char *proto_list = "1";
#endif

                if (!skBitmapGetBit((checks->proto), IPPROTO_ICMP)
#if SK_ENABLE_IPV6
                    && !skBitmapGetBit((checks->proto), IPPROTO_ICMPV6)
#endif
                    )
                {
                    skAppPrintErr(("An --%s value was given but --%s"
                                   " does not include %s"),
                                  (option_seen[OPT_ICMP_TYPE]
                                   ? filterOptions[OPT_ICMP_TYPE].name
                                   : filterOptions[OPT_ICMP_CODE].name),
                                  filterOptions[OPT_PROTOCOL].name,
                                  proto_list);
                    return 1;
                }
            }
            break;

          default:
            break;
        }
    }

    if (rv != 0) {
        skAppPrintErr("Error processing --%s option: '%s'",
                      filterOptions[opt_index].name, opt_arg);
        return 1;
    }
    return 0;                     /* OK */
}


#if RATE_FILTERS
/*
 *    The options handler for the compatibility switches that this
 *    file registers.
 *
 *    Prints a warning on stderr when stderr is a terminal and then
 *    passes the option off to filterOptionsHandler() for processing.
 */
static int
compatOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    if (FILEIsATty(stderr)) {
        skAppPrintErr(("COMPATIBILITY WARNING: The prefix you are using for\n"
                       "\tthe --%s switch is no longer unique.\n"
                       "\tThis will be an error in a future SiLK release."
                       "  Continuing..."),
                      filterOptions[opt_index].name);
    }
    return filterOptionsHandler(cData, opt_index, opt_arg);
}
#endif  /* RATE_FILTERS */


/*
 *  pass = filterCheck(&rwrec)
 *
 *    Check the rw record 'rwrec' against all of the checks the user
 *    specified.  If the record fails any check, RWF_PASS is returned.
 *    If the record passes all of the checks, RWF_FAIL is returned.
 */
checktype_t
filterCheck(
    const rwRec        *rwrec)
{
    unsigned int i;
    int j;
    int wanted;
    skipaddr_t ip1;
    skipaddr_t ip2;
    skcidr_t *cidr;

/* If (test) is zero, the record fails the filter and a non-zero value
 * is returned.  Else we continue with additional checks. */
#define FILTER_CHECK(test) \
    if (test) {/*pass*/} else return RWF_FAIL


    for (j = 0; j < checks->check_count; j++) {
        switch (checks->checkSet[j]) {

          case OPT_STIME:
            FILTER_CHECK(CHECK_RANGE((uint64_t)rwRecGetStartTime(rwrec),
                                     checks->sTime));
            break;

          case OPT_ETIME:
            FILTER_CHECK(CHECK_RANGE((uint64_t)rwRecGetEndTime(rwrec),
                                     checks->eTime));
            break;

          case OPT_ACTIVE_TIME:
            /* to pass the record; check that flow's start time is
             * less than the max value of range and that flow's end
             * time is greater than the min value of the range. */
            FILTER_CHECK((uint64_t)rwRecGetStartTime(rwrec)
                         <= checks->active_time.max);
            FILTER_CHECK((uint64_t)rwRecGetEndTime(rwrec)
                         >= checks->active_time.min);
            break;

          case OPT_DURATION:
            FILTER_CHECK(CHECK_RANGE(rwRecGetElapsed(rwrec),
                                     checks->elapsed));
            break;

          case OPT_SPORT:
            FILTER_CHECK(skBitmapGetBit(checks->sPort, rwRecGetSPort(rwrec)));
            break;

          case OPT_DPORT:
            FILTER_CHECK(skBitmapGetBit(checks->dPort, rwRecGetDPort(rwrec)));
            break;

          case OPT_APORT:
            FILTER_CHECK(skBitmapGetBit(checks->any_port, rwRecGetSPort(rwrec))
                         || skBitmapGetBit(checks->any_port,
                                           rwRecGetDPort(rwrec)));
            break;

          case OPT_PROTOCOL:
            FILTER_CHECK(skBitmapGetBit(checks->proto, rwRecGetProto(rwrec)));
            break;

          case OPT_ICMP_TYPE:
            FILTER_CHECK(rwRecIsICMP(rwrec)
                         && skBitmapGetBit(checks->icmp_type,
                                           rwRecGetIcmpType(rwrec)));
            break;

          case OPT_ICMP_CODE:
            FILTER_CHECK(rwRecIsICMP(rwrec)
                         && skBitmapGetBit(checks->icmp_code,
                                           rwRecGetIcmpCode(rwrec)));
            break;

          case OPT_BYTES:
            FILTER_CHECK(CHECK_RANGE(rwRecGetBytes(rwrec), checks->bytes));
            break;

          case OPT_PACKETS:
            FILTER_CHECK(CHECK_RANGE(rwRecGetPkts(rwrec), checks->pkts));
            break;

          case OPT_BYTES_PER_PACKET:
            FILTER_CHECK(CHECK_RANGE(((double)rwRecGetBytes(rwrec)
                                      / (double)rwRecGetPkts(rwrec)),
                                     checks->bytes_per_packet));
            break;

#if RATE_FILTERS
          case OPT_BYTES_PER_SECOND:
            if (rwRecGetElapsed(rwrec) > 0) {
                FILTER_CHECK(CHECK_RANGE(((double)rwRecGetBytes(rwrec)
                                          / (double)rwRecGetElapsed(rwrec)),
                                         checks->bytes_per_second));
            } else {
                /* use a one second duration */
                FILTER_CHECK(CHECK_RANGE((double)rwRecGetBytes(rwrec),
                                         checks->bytes_per_second));
            }
            break;

          case OPT_PACKETS_PER_SECOND:
            if (rwRecGetElapsed(rwrec) > 0) {
                FILTER_CHECK(CHECK_RANGE(((double)rwRecGetPkts(rwrec)
                                          / (double)rwRecGetElapsed(rwrec)),
                                         checks->packets_per_second));
            } else {
                /* use a one second duration */
                FILTER_CHECK(CHECK_RANGE((double)rwRecGetPkts(rwrec),
                                         checks->packets_per_second));
            }
            break;
#endif  /* RATE_FILTERS */

          case OPT_NOT_SCIDR:
          case OPT_SCIDR:
            rwRecMemGetSIP(rwrec, &ip1);
            wanted = checks->cidr_negated[SRC];
            for (i = 0, cidr = checks->cidr_list[SRC];
                 i < checks->cidr_list_len[SRC];
                 ++i, ++cidr)
            {
                if (skcidrCheckIP(cidr, &ip1)) {
                    wanted = !wanted;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_NOT_DCIDR:
          case OPT_DCIDR:
            rwRecMemGetDIP(rwrec, &ip1);
            wanted = checks->cidr_negated[DST];
            for (i = 0, cidr = checks->cidr_list[DST];
                 i < checks->cidr_list_len[DST];
                 ++i, ++cidr)
            {
                if (skcidrCheckIP(cidr, &ip1)) {
                    wanted = !wanted;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_NOT_NHCIDR:
          case OPT_NHCIDR:
            rwRecMemGetNhIP(rwrec, &ip1);
            wanted = checks->cidr_negated[NHIP];
            for (i = 0, cidr = checks->cidr_list[NHIP];
                 i < checks->cidr_list_len[NHIP];
                 ++i, ++cidr)
            {
                if (skcidrCheckIP(cidr, &ip1)) {
                    wanted = !wanted;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_NOT_ANY_CIDR:
          case OPT_ANY_CIDR:
            rwRecMemGetSIP(rwrec, &ip1);
            rwRecMemGetDIP(rwrec, &ip2);
            wanted = checks->cidr_negated[ANY];
            for (i = 0, cidr = checks->cidr_list[ANY];
                 i < checks->cidr_list_len[ANY];
                 ++i, ++cidr)
            {
                if (skcidrCheckIP(cidr, &ip1)
                    || skcidrCheckIP(cidr, &ip2))
                {
                    wanted = !wanted;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_NOT_SADDRESS:
          case OPT_SADDRESS:
            /* Check if record's sIP matches the bitmap.  The record
             * FAILS the filter when the result of the check MATCHES
             * the status of the negate flag.  E.g., the record
             * matches the address-bitmap (skIPWildcardCheckIp()==1)
             * and the user entered --not-saddr (ipwild_negate==1).
             * Since the record FAILS when the values are equal, it
             * will PASS when they are not-equal; i.e., when the
             * XOR(^) of the two values is true.
             */
            rwRecMemGetSIP(rwrec, &ip1);
            FILTER_CHECK(skIPWildcardCheckIp(&checks->ipwild[SRC], &ip1)
                         ^ checks->ipwild_negate[SRC]);
            break;

          case OPT_NOT_DADDRESS:
          case OPT_DADDRESS:
            rwRecMemGetDIP(rwrec, &ip1);
            FILTER_CHECK(skIPWildcardCheckIp(&checks->ipwild[DST], &ip1)
                         ^ checks->ipwild_negate[DST]);
            break;

          case OPT_NOT_NEXT_HOP_ID:
          case OPT_NEXT_HOP_ID:
            rwRecMemGetNhIP(rwrec, &ip1);
            FILTER_CHECK(skIPWildcardCheckIp(&checks->ipwild[NHIP], &ip1)
                         ^ checks->ipwild_negate[NHIP]);
            break;

          case OPT_NOT_ANY_ADDRESS:
          case OPT_ANY_ADDRESS:
            rwRecMemGetSIP(rwrec, &ip1);
            rwRecMemGetDIP(rwrec, &ip2);
            FILTER_CHECK((skIPWildcardCheckIp(&checks->ipwild[ANY], &ip1)
                          | skIPWildcardCheckIp(&checks->ipwild[ANY], &ip2))
                         ^ checks->ipwild_negate[ANY]);
            break;

          case OPT_NOT_SET_SIP:
          case OPT_SET_SIP:
            /* As with OPT_SADDRESS, for the record to pass the
             * filter, the result of the check must not equal the
             * result of the negate flag. */
            FILTER_CHECK(skIPSetCheckRecordSIP(checks->ipset[SRC], rwrec)
                         ^ checks->ipset_reject[SRC]);
            break;

          case OPT_NOT_SET_DIP:
          case OPT_SET_DIP:
            FILTER_CHECK(skIPSetCheckRecordDIP(checks->ipset[DST], rwrec)
                         ^ checks->ipset_reject[DST]);
            break;

          case OPT_NOT_SET_NHIP:
          case OPT_SET_NHIP:
            FILTER_CHECK(skIPSetCheckRecordNhIP(checks->ipset[NHIP], rwrec)
                         ^ checks->ipset_reject[NHIP]);
            break;

          case OPT_NOT_SET_ANY:
          case OPT_SET_ANY:
            FILTER_CHECK((skIPSetCheckRecordSIP(checks->ipset[ANY], rwrec)
                          | skIPSetCheckRecordDIP(checks->ipset[ANY], rwrec))
                         ^ checks->ipset_reject[ANY]);
            break;

          case OPT_INPUT_INDEX:
            FILTER_CHECK(skBitmapGetBit(checks->input_index,
                                        rwRecGetInput(rwrec)));
            break;

          case OPT_OUTPUT_INDEX:
            FILTER_CHECK(skBitmapGetBit(checks->output_index,
                                        rwRecGetOutput(rwrec)));
            break;

          case OPT_ANY_INDEX:
            FILTER_CHECK(skBitmapGetBit(checks->any_index,rwRecGetInput(rwrec))
                         || skBitmapGetBit(checks->any_index,
                                           rwRecGetOutput(rwrec)));
            break;

            /*
             * TCP check.  Passes if there's an intersection between
             * the raised flags and the filter flags.
             */
          case OPT_TCP_FLAGS:
            FILTER_CHECK(checks->flags & rwRecGetFlags(rwrec));
            break;

          case OPT_FLAGS_ALL:
            wanted = 0;
            for (i = 0; i < checks->count_flags_all; ++i) {
                if (CHECK_TCP_HIGH_MASK(rwRecGetFlags(rwrec),
                                        checks->flags_all[i]))
                {
                    wanted = 1;
                    break; /* wanted */
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_FLAGS_INITIAL:
            wanted = 0;
            for (i = 0; i < checks->count_flags_init; ++i) {
                if (CHECK_TCP_HIGH_MASK(rwRecGetInitFlags(rwrec),
                                        checks->flags_init[i]))
                {
                    wanted = 1;
                    break; /* wanted */
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_FLAGS_SESSION:
            wanted = 0;
            for (i = 0; i < checks->count_flags_session; ++i) {
                if (CHECK_TCP_HIGH_MASK(rwRecGetRestFlags(rwrec),
                                        checks->flags_session[i]))
                {
                    wanted = 1;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_ATTRIBUTES:
            wanted = 0;
            for (i = 0; i < checks->count_attributes; ++i) {
                if (CHECK_TCP_HIGH_MASK(rwRecGetTcpState(rwrec),
                                        checks->attributes[i]))
                {
                    wanted = 1;
                    break;
                }
            }
            FILTER_CHECK(wanted);
            break;

          case OPT_APPLICATION:
            FILTER_CHECK(skBitmapGetBit(checks->application,
                                        rwRecGetApplication(rwrec)));
            break;

          case OPT_IP_VERSION:
            switch (checks->ipv6_policy) {
              case SK_IPV6POLICY_MIX:
                break;
              case SK_IPV6POLICY_ONLY:
                FILTER_CHECK(rwRecIsIPv6(rwrec));
                break;
              case SK_IPV6POLICY_IGNORE:
                FILTER_CHECK(!rwRecIsIPv6(rwrec));
                break;
              case SK_IPV6POLICY_ASV4:
              case SK_IPV6POLICY_FORCE:
                /* can't happen */
                skAbortBadCase(checks->ipv6_policy);
            }
            break;

          case OPT_SENSORS:
            FILTER_CHECK(skBitmapGetBit(checks->sID, rwRecGetSensor(rwrec)));
            break;

          case OPT_FLOW_TYPE:
            FILTER_CHECK(skBitmapGetBit(checks->flow_type,
                                        rwRecGetFlowType(rwrec)));
            break;

          case OPT_SCC:
            rwRecMemGetSIP(rwrec, &ip1);
            FILTER_CHECK(skBitmapGetBit(checks->scc,
                                        skCountryLookupCode(&ip1)));
            break;

          case OPT_DCC:
            rwRecMemGetDIP(rwrec, &ip1);
            FILTER_CHECK(skBitmapGetBit(checks->dcc,
                                        skCountryLookupCode(&ip1)));
            break;

          case OPT_ANY_CC:
            rwRecMemGetSIP(rwrec, &ip1);
            rwRecMemGetDIP(rwrec, &ip2);
            FILTER_CHECK(skBitmapGetBit(checks->any_cc,
                                        skCountryLookupCode(&ip1))
                         || skBitmapGetBit(checks->any_cc,
                                           skCountryLookupCode(&ip2)));
            break;

          default:
            skAbortBadCase(checks->checkSet[j]);
        }
    } /* outer for */

    return RWF_PASS;                     /* WANTED! */
}


/*
 *  pass = filterCheckFile(stream, ip_dir)
 *
 *    Check whether the SiLK Packed data file 'stream' contains records
 *    that match the user's query.  This function uses information
 *    from the file's header and/or outside the data file---such as
 *    external IPsets or Bloom filters located in the 'ip_dir'---to
 *    see if pathname should be opened and its records read.
 *
 *    Returns 1 if the file at 'pathname' should be skipped, 0 if the
 *    file should be read, and -1 on error.
 */
int
filterCheckFile(
    skstream_t         *stream,
    const char  UNUSED(*ip_dir))
{
    sk_header_entry_t *pfh;
    sktime_t t = -1;
    int wanted;
    int i;
    int j;
    int skip_file = 0;
    sk_file_header_t *hdr;
    sk_file_format_t file_format;

/*
**    char ippath[PATH_MAX];
**    skIPSet_t *set[2] = {NULL, NULL};
**    int tried_set[2] = {0, 0};
**    const char *suffix_set[2] = {".sip", ".dip"};
**
**#define LOAD_IPSET(idx)                                         \
**    {                                                           \
**        if (tried_set[(idx)] == 0) {                            \
**            tried_set[(idx)] = 1;                               \
**            if (ip_dir != NULL) {                               \
**                snprintf(ippath, sizeof(ippath), "%s%s",        \
**                         ip_dir, suffix_set[(idx)]);            \
**                skIPSetLoad(&(set[(idx)]), ippath);             \
**            }                                                   \
**        }                                                       \
**    }
*/

    hdr = skStreamGetSilkHeader(stream);
    file_format = skHeaderGetFileFormat(hdr);

    /* get handle to the header and the file's start time */
    pfh = skHeaderGetFirstMatch(hdr, SK_HENTRY_PACKEDFILE_ID);
    if (pfh) {
        t = skHentryPackedfileGetStartTime(pfh);
    }

    for (j = 0; ((0 == skip_file) && (j < checks->check_count)); ++j) {

        switch (checks->checkSet[j]) {
          case OPT_STIME:
            /* ignore files where the range of possible start-times
             * for this file is outside the sTime window; that is,
             * where the range is either completely below or
             * completely above the window */
            if ((t != -1)
                && ((t > (sktime_t)checks->sTime.max)
                    || ((t + 3600999) < (sktime_t)checks->sTime.min)))
            {
                skip_file = 1;
            }
            break;

          case OPT_ETIME:
            /* ignore files where the possible end-time range (this
             * hour or the next hour allowing for durations of 3600)
             * is outside the eTime window */
            if ((t != -1)
                && ((t > (sktime_t)checks->eTime.max)
                    || ((t + 7200999) < (sktime_t)checks->sTime.min)))
            {
                skip_file = 1;
            }
            break;

          case OPT_ACTIVE_TIME:
            /* ignore files where the end time range is outside the
             * active time window---start time range is a sub-range of
             * the possible end-times */
            if ((t != -1)
                && ((t > (sktime_t)checks->active_time.max)
                    || ((t + 7200999) < (sktime_t)checks->active_time.min)))
            {
                skip_file = 1;
            }
            break;

          case OPT_PROTOCOL:
            if (skBitmapGetBit(checks->proto, 6) == 0) {
                /* user is not interested in TCP flows; ignore files
                 * containing web-only data */
                switch (file_format) {
                  case FT_RWAUGWEB:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

/*
**          case OPT_SADDRESS:
**            if (set[SRC] == NULL) {
**                LOAD_IPSET(SRC);
**                if (set[SRC] == NULL) {
**                    break;
**                }
**            }
**            skip_file = !skIPSetCheckIPWildcard(set[SRC],
**                                                &checks->ipwild[SRC]);
**            break;
**
**          case OPT_SET_SIP:
**#if 1
**            if (set[SRC] == NULL) {
**                LOAD_IPSET(SRC);
**                if (set[SRC] == NULL) {
**                    break;
**                }
**            }
**            skip_file = !skIPSetCheckIPSet(set[SRC], checks->ipset[SRC]);
**#else
**            snprintf(ippath, sizeof(ippath), "%s%s",
**                     ip_dir, suffix_set[SRC]);
**            skip_file = skIPSetCheckIPSetFile(checks->ipset[SRC],
**                                              ippath, NULL);
**#endif
**            break;
**
**          case OPT_DADDRESS:
**            if (set[DST] == NULL) {
**                LOAD_IPSET(DST);
**                if (set[DST] == NULL) {
**                    break;
**                }
**            }
**            skip_file = !skIPSetCheckIPWildcard(set[DST],
**                                                &checks->ipwild[DST]);
**            break;
**
**          case OPT_SET_DIP:
**#if 1
**            if (set[DST] == NULL) {
**                LOAD_IPSET(DST);
**                if (set[DST] == NULL) {
**                    break;
**                }
**            }
**            skip_file = !skIPSetCheckIPSet(set[DST], checks->ipset[DST]);
**#else
**            snprintf(ippath, sizeof(ippath), "%s%s",
**                     ip_dir, suffix_set[DST]);
**            skip_file = skIPSetCheckIPSetFile(checks->ipset[DST],
**                                              ippath, NULL);
**#endif
**            break;
**
**          case OPT_ANY_ADDRESS:
**            if (set[SRC] == NULL) {
**                LOAD_IPSET(SRC);
**            }
**            if (set[SRC]) {
**                wanted = skIPSetCheckIPWildcard(set[SRC],
**                                                &checks->ipwild[ANY]);
**                if (wanted == 1) {
**                    break;
**                }
**            }
**            if (set[DST] == NULL) {
**                LOAD_IPSET(DST);
**            }
**            if (set[DST]) {
**                skip_file =
**                    !skIPSetCheckIPWildcard(set[DST], &checks->ipwild[ANY]);
**            }
**            break;
**
**          case OPT_SET_ANY:
**            if (set[SRC] == NULL) {
**                LOAD_IPSET(SRC);
**            }
**            if (set[SRC]) {
**                wanted = skIPSetCheckIPSet(set[SRC], checks->ipset[ANY]);
**                if (wanted == 1) {
**                    break;
**                }
**            }
**            if (set[DST] == NULL) {
**                LOAD_IPSET(DST);
**            }
**            if (set[DST]) {
**                skip_file = !skIPSetCheckIPSet(set[DST], checks->ipset[ANY]);
**            }
**            break;
*/

          case OPT_NEXT_HOP_ID:
            {
                skipaddr_t ip;
                memset(&ip, 0, sizeof(skipaddr_t));
                if (skIPWildcardCheckIp(&checks->ipwild[NHIP], &ip) == 0) {
                    /* user wants flows where nhIP is non-zero; ignore
                     * files that do not have nhIP info */
                    switch (file_format) {
                      case FT_RWAUGMENTED:
                      case FT_RWAUGWEB:
                      case FT_RWAUGSNMPOUT:
                      case FT_RWIPV6:
                      case FT_RWSPLIT:
                      case FT_RWWWW:
                        skip_file = 1;
                        break;
                    }
                }
            }
            break;

/*
**          case OPT_SET_NHIP:
**            if (skIPSetCheckAddress(checks->ipset[NHIP], 0) == 0) {
**                // user wants flows were nhIP is non-zero; ignore
**                // files that do not have nhIP info
**                switch (file_format) {
**                  case FT_RWAUGMENTED:
**                  case FT_RWAUGWEB:
**                  case FT_RWAUGSNMPOUT:
**                  case FT_RWIPV6:
**                  case FT_RWSPLIT:
**                  case FT_RWWWW:
**                    skip_file = 1;
**                    break;
**                }
**            }
**            break;
*/

          case OPT_INPUT_INDEX:
            if (skBitmapGetBit(checks->input_index, 0) == 0) {
                /* user wants flows were input is non-zero; ignore
                 * files that do not have incoming SNMP info */
                switch (file_format) {
                  case FT_RWAUGMENTED:
                  case FT_RWAUGWEB:
                  case FT_RWAUGSNMPOUT:
                  case FT_RWIPV6:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_OUTPUT_INDEX:
            if (skBitmapGetBit(checks->output_index, 0) == 0) {
                /* user wants flows were output is non-zero; ignore
                 * files that do not have outgoing SNMP info */
                switch (file_format) {
                  case FT_RWAUGMENTED:
                  case FT_RWAUGWEB:
                  case FT_RWIPV6:
                  case FT_RWNOTROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_ANY_INDEX:
            if (skBitmapGetBit(checks->any_index, 0) == 0) {
                /* user wants flows were either input or output is
                 * non-zero; ignore files that do not have outgoing
                 * SNMP info */
                switch (file_format) {
                  case FT_RWAUGMENTED:
                  case FT_RWAUGWEB:
                  case FT_RWIPV6:
                  case FT_RWNOTROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_FLAGS_INITIAL:
            wanted = 0;
            for (i = 0; i < checks->count_flags_init; ++i) {
                if (CHECK_TCP_HIGH_MASK(0, checks->flags_init[i])) {
                    wanted = 1;
                    break; /* wanted */
                }
            }
            if (wanted == 0) {
                /* user only wants flows where initial flags has some
                 * non-zero value; ignore files that do not have
                 * initial flags info */
                switch (file_format) {
                  case FT_RWNOTROUTED:
                  case FT_RWROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_FLAGS_SESSION:
            wanted = 0;
            for (i = 0; i < checks->count_flags_session; ++i) {
                if (CHECK_TCP_HIGH_MASK(0, checks->flags_session[i])) {
                    wanted = 1;
                    break;
                }
            }
            if (wanted == 0) {
                /* user only wants flows where session flags has some
                 * non-zero value; ignore files that do not have
                 * session flags info */
                switch (file_format) {
                  case FT_RWNOTROUTED:
                  case FT_RWROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_ATTRIBUTES:
            wanted = 0;
            for (i = 0; i < checks->count_attributes; ++i) {
                if (CHECK_TCP_HIGH_MASK(0, checks->attributes[i])) {
                    wanted = 1;
                    break;
                }
            }
            if (wanted == 0) {
                /* user only wants flows where attributes has some
                 * non-zero value; ignore files that do not have
                 * attributes info */
                switch (file_format) {
                  case FT_RWNOTROUTED:
                  case FT_RWROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_APPLICATION:
            if (skBitmapGetBit(checks->application, 0) == 0) {
                /* user wants flows were application is non-zero;
                 * ignore files that do not have this info */
                switch (file_format) {
                  case FT_RWNOTROUTED:
                  case FT_RWROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

          case OPT_IP_VERSION:
            if (checks->ipv6_policy == SK_IPV6POLICY_ONLY) {
                /* the user wants only IPv6 data; ignore files that
                 * contain only IPv4 data */
                switch (file_format) {
                  case FT_RWAUGMENTED:
                  case FT_RWAUGROUTING:
                  case FT_RWAUGWEB:
                  case FT_RWAUGSNMPOUT:
                  case FT_RWFILTER:
                  case FT_FLOWCAP:
                  case FT_RWGENERIC:
                  case FT_RWNOTROUTED:
                  case FT_RWROUTED:
                  case FT_RWSPLIT:
                  case FT_RWWWW:
                    skip_file = 1;
                    break;
                }
            }
            break;

#if 0
          case OPT_SENSORS:
            FILTER_CHECK(skBitmapGetBit(checks->sID, rwRecGetSensor(rwrec)));
            break;

          case OPT_FLOW_TYPE:
            FILTER_CHECK(skBitmapGetBit(checks->flow_type,
                                        rwRecGetFlowType(rwrec)));
            break;
#endif
          default:
            break;
        }
    }

/*
**    if (set[SRC]) {
**        skIPSetDelete(&set[SRC]);
**    }
**    if (set[DST]) {
**        skIPSetDelete(&set[DST]);
**    }
*/

    return skip_file;
}


/*
 * int filterSetup()
 *
 * SUMMARY:
 *
 * Called by the application to let the filter library setup for
 * options processing.
 *
 * RETURNS:
 *
 * on failure, returns 1
 * on success, returns 0
 *
 * SIDE EFFECTS:
 *
 * Initializes the filter library options with the options processing library.
 *
 * NOTES:
 *
 */
int
filterSetup(
    void)
{
    int i;

    /* make certain we have enough space  */
    assert(_OPT_FINAL_OPTION_ < FILTER_CHECK_MAX);
    assert(_IP_INDEX_FINAL_ == IP_INDEX_COUNT);

    /* make certain enums are in sync */
    assert((OPT_SET_SIP  - OPT_SET_SIP)==(OPT_NOT_SET_SIP  - OPT_NOT_SET_SIP));
    assert((OPT_SET_DIP  - OPT_SET_SIP)==(OPT_NOT_SET_DIP  - OPT_NOT_SET_SIP));
    assert((OPT_SET_ANY  - OPT_SET_SIP)==(OPT_NOT_SET_ANY  - OPT_NOT_SET_SIP));
    assert((OPT_SET_NHIP - OPT_SET_SIP)==(OPT_NOT_SET_NHIP - OPT_NOT_SET_SIP));

    /* clear memory */
    memset(checks, 0, sizeof(filter_checks_t));

    /* copy options from filterSwitch[] to filterOptions[] */
    if (filterOptions == NULL) {
        filterOptions = ((struct option*)
                         calloc(sizeof(filterSwitch)/sizeof(filter_switch_t),
                                sizeof(struct option)));
        for (i = 0; filterSwitch[i].option.name != NULL; ++i) {
            memcpy(&(filterOptions[i]), &(filterSwitch[i].option),
                   sizeof(struct option));
        }
    }

    /* register the options */
    if (skOptionsRegister(filterOptions, &filterOptionsHandler, NULL)
#if RATE_FILTERS
        || skOptionsRegister(options_compat, &compatOptionsHandler, NULL)
#endif
        )
    {
        return 1;
    }

    return 0;
}


/*
 * void filterTeardown()
 *
 */
void
filterTeardown(
    void)
{
    int i;

    if (checks->sPort) {
        skBitmapDestroy(&checks->sPort);
        checks->sPort = NULL;
    }
    if (checks->dPort) {
        skBitmapDestroy(&checks->dPort);
        checks->dPort = NULL;
    }
    if (checks->any_port) {
        skBitmapDestroy(&checks->any_port);
        checks->any_port = NULL;
    }
    if (checks->proto) {
        skBitmapDestroy(&checks->proto);
        checks->proto = NULL;
    }
    if (checks->icmp_type) {
        skBitmapDestroy(&checks->icmp_type);
        checks->icmp_type = NULL;
    }
    if (checks->icmp_code) {
        skBitmapDestroy(&checks->icmp_code);
        checks->icmp_code = NULL;
    }
    if (checks->sID) {
        skBitmapDestroy(&checks->sID);
        checks->sID = NULL;
    }
    if (checks->flow_type) {
        skBitmapDestroy(&checks->flow_type);
        checks->flow_type = NULL;
    }
    if (checks->input_index) {
        skBitmapDestroy(&checks->input_index);
        checks->input_index = NULL;
    }
    if (checks->output_index) {
        skBitmapDestroy(&checks->output_index);
        checks->output_index = NULL;
    }
    if (checks->any_index) {
        skBitmapDestroy(&checks->any_index);
        checks->any_index = NULL;
    }
    if (checks->application) {
        skBitmapDestroy(&checks->application);
        checks->application = NULL;
    }
    if (checks->scc) {
        skBitmapDestroy(&checks->scc);
        checks->scc = NULL;
    }
    if (checks->dcc) {
        skBitmapDestroy(&checks->dcc);
        checks->dcc = NULL;
    }
    if (checks->any_cc) {
        skBitmapDestroy(&checks->any_cc);
        checks->any_cc = NULL;
    }
    for (i = 0; i < IP_INDEX_COUNT; ++i) {
        if (checks->ipset[i]) {
            skIPSetDestroy(&checks->ipset[i]);
            checks->ipset[i] = NULL;
        }
        if (checks->cidr_list[i]) {
            free(checks->cidr_list[i]);
            checks->cidr_list[i] = NULL;
        }
    }
    if (filterOptions) {
        free(filterOptions);
        filterOptions = NULL;
    }
    skCountryTeardown();
}


/* Return number of checks active. */
int
filterGetCheckCount(
    void)
{
    return checks->check_count;
}


/*
 *  status = filterGetFGlobFilters();
 *
 *    Create filter checks that correspond to the --sensor, --class,
 *    --type switches from the fglob() code by getting those values
 *    from fglob and creating filters for them.
 */
int
filterGetFGlobFilters(
    void)
{
    int rv;

    /* Let fglob fill in the bitmaps with the sensors and class/types
     * to filter over. */
    rv = fglobSetFilters(&(checks->sID), &(checks->flow_type));

    if (rv < 0) {
        /* error */
        return rv;
    }
    if (rv & 1) {
        /* need to filter over sensor */
        checks->checkSet[checks->check_count] = OPT_SENSORS;
        checks->check_count++;
    }
    if (rv & 2) {
        /* need to filter over class/type */
        checks->checkSet[checks->check_count] = OPT_FLOW_TYPE;
        checks->check_count++;
    }

    return 0;
}


/*
 *  ok = parseCidrList(&cidr_list, &cidr_list_len, opt_index, opt_arg);
 *
 *    Parse 'opt_arg' as a list containting IPs and CIDR blocks,
 *    storing in result in a newly created array of skcidr_t's that
 *    will be created at the location designated by 'cidr_list'.
 *    Record the length of the list in 'cidr_list_len'.  If parsing
 *    fails, do not create the list and print an error using
 *    'opt_index' as the index of the option the function was
 *    attempting to parse.
 */
static int
parseCidrList(
    skcidr_t          **cidr_list,
    unsigned int       *cidr_list_len,
    int                 opt_index,
    const char         *opt_arg)
{
    char *token_list = NULL;
    char *next_token;
    char *token;
    int count;
    skipaddr_t ipaddr;
    uint32_t cidr_len;
    skcidr_t *cidr;
    int rv = -1;

    /* make a modifiable version of the argument */
    token_list = strdup(opt_arg);
    if (NULL == token_list) {
        skAppPrintOutOfMemory("copy CIDR list");
        goto END;
    }

    /* count number of tokens in input */
    count = 1;
    for (token = token_list; (token = strchr(token, ',')) != NULL; ++token) {
        ++count;
    }

    /* create list of skcidr_t. add 1 for final NULL to be end-of-list
     * marker */
    *cidr_list = (skcidr_t*)calloc(1+count, sizeof(skcidr_t));
    if (NULL == *cidr_list) {
        skAppPrintOutOfMemory("CIDR list");
        goto END;
    }
    cidr = *cidr_list;

    /* parse the argument as a comma separated list of tokens */
    next_token = token_list;
    while ((token = strsep(&next_token, ",")) != NULL) {
        /* check for empty token (e.g., double comma) */
        if ('\0' == *token) {
            continue;
        }

        rv = skStringParseCIDR(&ipaddr, &cidr_len, token);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          filterOptions[opt_index].name, token,
                          skStringParseStrerror(rv));
            goto END;
        }

        assert((cidr - *cidr_list) < count);
        skcidrSetFromIPAddr(cidr, &ipaddr, cidr_len);
        ++cidr;
    }

    *cidr_list_len = (cidr - *cidr_list);

    /* Success */
    rv = 0;

  END:
    if (token_list) {
        free(token_list);
    }
    if (rv != 0) {
        if (*cidr_list) {
            free(*cidr_list);
            *cidr_list = NULL;
        }
    }
    return rv;
}


/*
 *  ok = parseListToBitmap(&bitmap, bitmap_size, opt_index, opt_arg);
 *
 *    Create a bitmap of 'bitmap_size' and store the bitmap at the
 *    location designated by 'bitmap'.  Then parse 'opt_arg' as an
 *    integer list and use it to fill the bitmap.  If parsing fails,
 *    destroy the bitmap and print an error using 'opt_index' as the
 *    index of the option the function was attempting to parse.
 */
static int
parseListToBitmap(
    sk_bitmap_t       **bitmap,
    uint32_t            bitmap_size,
    int                 opt_index,
    const char         *opt_arg)
{
    int rv;

    if (skBitmapCreate(bitmap, bitmap_size)) {
        skAppPrintErr("Unable to create %" PRIu32 "-element bitmap for %s",
                      bitmap_size, filterOptions[opt_index].name);
        return -1;
    }

    rv = skStringParseNumberListToBitmap(*bitmap, opt_arg);
    if (rv) {
        skAppPrintErr("Invalid %s: %s",
                      filterOptions[opt_index].name,skStringParseStrerror(rv));
        skBitmapDestroy(bitmap);
        return -1;
    }

    return 0;
}


/*
 * static int parseRangeTime(*p_vr, opt_index, *s_time)
 *
 * SUMMARY:
 *
 * Parses a time string using skStringParseDatetimeRange().  Stores
 * the result in the value_range_t pointed to by p_vr.
 *
 * PARAMETERS:
 *
 * value_range_t *p_vr = pointer to the time range storage variable
 * char *s_time = a string containing a time value to parse
 *
 * RETURNS:
 *
 * 0 on success
 * -1 on error, such as a badly formatted string, an end time occurring
 *   before a start time, etc.
 *
 * SIDE EFFECTS:
 *
 * on success, p_vr is set to [start,end], or if no end-time was parsed,
 * p_vr is set to [start,start]
 *
 * on failures, the contents of p_vr are not modified
 */
static int
parseRangeTime(
    uint64_range_t     *p_vr,
    int                 opt_index,
    const char         *s_time)
{
    sktime_t min, max;
    unsigned int max_precision = 0;
    int rv;

    /* parse the time */
    rv = skStringParseDatetimeRange(&min, &max, s_time, NULL, &max_precision);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': %s",
                      filterOptions[opt_index].name, s_time,
                      skStringParseStrerror(rv));
        return -1;
    }

    p_vr->min = (uint64_t)min;

    /* maximum */
    if (max == INT64_MAX) {
        /* there was no max date parsed */
        p_vr->max = p_vr->min;
    } else if (SK_PARSED_DATETIME_GET_PRECISION(max_precision)
               == SK_PARSED_DATETIME_FRACSEC)
    {
        /* end time already has fractional seconds */
        p_vr->max = (uint64_t)max;
    } else {
        if (SK_PARSED_DATETIME_EPOCH & max_precision) {
            /* treat a value in epoch seconds as having second
             * precision */
            max_precision = SK_PARSED_DATETIME_SECOND;
        }
        /* the max date precision is less than (courser than)
         * millisecond resolution, so "round" the date up */
        if (skDatetimeCeiling(&max, &max, max_precision) != 0) {
            return -1;
        }
        p_vr->max = (uint64_t)max;
    }

    return 0;
}


/*
 *  ok = parseRangeInteger(&range, opt_index, range_string)
 *
 *    Parse 'range_string' as either a single value '3', a range of
 *    values, '4-6', or an open-ended range '7-'.  Write the values
 *    into the 'range' structure.
 *
 *    Return 0 success.  On failure, print an error using 'opt_index'
 *    as the ID of the option that failed to parse and return 1.
 */
static int
parseRangeInteger(
    uint64_range_t     *range,
    int                 opt_index,
    const char         *range_string)
{
    int rv;

    rv = skStringParseRange64(&range->min, &range->max,
                              range_string, 0, 0,
                              SKUTILS_RANGE_SINGLE_OPEN);
    if (rv) {
        /* error */
        skAppPrintErr("Invalid %s '%s': %s",
                      filterOptions[opt_index].name, range_string,
                      skStringParseStrerror(rv));
        return 1;
    }

    return 0;
}


/*
 *  ok = parseRangeDecimal(&range, opt_index, range_string)
 *
 *    Parse 'range_string' as either a single value '3.0', a range of
 *    values, '4.1-6.4', or an open-ended range '7.9-'.  Write the
 *    values into the 'range' structure.
 *
 *    Return 0 success.  On failure, print an error using 'opt_index'
 *    as the ID of the option that failed to parse and return 1.
 */
static int
parseRangeDecimal(
    double_range_t     *range,
    int                 opt_index,
    const char         *range_string)
{
    int rv;

    rv = skStringParseDoubleRange(&range->min, &range->max,
                                  range_string, 0.0, 0.0,
                                  SKUTILS_RANGE_SINGLE_OPEN);
    if (rv) {
        /* error */
        skAppPrintErr("Invalid %s '%s': %s",
                      filterOptions[opt_index].name, range_string,
                      skStringParseStrerror(rv));
        return 1;
    }

    return 0;
}


/*
 *  status = parseFlagsHelper(opt_index, high_mask_string)
 *
 *    Parse a single HIGH/MASK pair.  Return 0 on success, and
 *    non-zero on failure.
 */
static int
parseFlagsHelper(
    int                 opt_index,
    const char         *high_mask_string)
{
    uint8_t *check_count;
    high_mask_t *h_m;
    int rv;

    /* set 'check_count' to the current number of checks for the
     * specified test, and have 'h_m' point to the location in which
     * to add the next check. */
    switch (opt_index) {
      case OPT_FLAGS_ALL:
        check_count = &checks->count_flags_all;
        h_m = &(checks->flags_all[*check_count]);
        break;
      case OPT_FLAGS_INITIAL:
        check_count = &checks->count_flags_init;
        h_m = &(checks->flags_init[*check_count]);
        break;
      case OPT_FLAGS_SESSION:
        check_count = &checks->count_flags_session;
        h_m = &(checks->flags_session[*check_count]);
        break;
      default:
        skAbortBadCase(opt_index);
    }

    if (*check_count >= MAX_TCPFLAG_CHECKS) {
        skAppPrintErr("May only specify %d %s checks",
                      MAX_TCPFLAG_CHECKS, filterOptions[opt_index].name);
        return 1;
    }

    rv = skStringParseTCPFlagsHighMask(&(h_m->high), &(h_m->mask),
                                       high_mask_string);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': %s",
                      filterOptions[opt_index].name, high_mask_string,
                      skStringParseStrerror(rv));
        return 1;
    }

    ++*check_count;
    return 0;
}


/*
 *  status = parseFlags(opt_index, opt_arg)
 *
 *    Parse the value passed to the --flags-all, --flags-initial and
 *    --flags-sesion switches, which expect a flags in the form
 *    HIGH/MASK.  Multiple HIGH/MASK sets may be specified by
 *    separating them with comma.
 *
 *    Return 0 on success, and non-zero on failure.
 */
static int
parseFlags(
    int                 opt_index,
    const char         *opt_arg)
{
    char buf[32];
    const char *cp;
    const char *sp = opt_arg;
    size_t len;

    while (*sp) {
        cp = strchr(sp, ',');

        /* if there is no ',' in the (remaining) input, just pass the
         * input to the helper function for parsing. */
        if (cp == NULL) {
            return parseFlagsHelper(opt_index, sp);
        }
        if (cp == sp) {
            /* double comma */
            ++sp;
            continue;
        }

        /* copy this flag combination into 'buf' */
        len = cp - sp;
        if (len > sizeof(buf)-1) {
            return 1;
        }
        strncpy(buf, sp, sizeof(buf));
        buf[len] = '\0';
        sp = cp + 1;
        if (parseFlagsHelper(opt_index, buf)) {
            return 1;
        }
    }

    return 0;
}


/*
 *  status = setFilterCheckBinaryFlag(opt_index, opt_arg);
 *
 *    Set the 'flagMark' and 'flagCare' for the TCP flag 'flag'
 *    according to whether 'opt_arg' parses as a 0 or a 1.
 *    'opt_index' is used to report an error.
 */
static int
setFilterCheckBinaryFlag(
    int                 opt_index,
    const char         *opt_arg)
{
    static uint8_t binary_flag_pos = MAX_TCPFLAG_CHECKS;
    uint8_t flag;
    unsigned long i;

    if (binary_flag_pos == MAX_TCPFLAG_CHECKS) {
        /* first time we've called this function */
        if (checks->count_flags_all >= MAX_TCPFLAG_CHECKS) {
            skAppPrintErr("May only specify %d tcp-flags checks",
                          MAX_TCPFLAG_CHECKS);
            return 1;
        }
        binary_flag_pos = checks->count_flags_all;
        ++checks->count_flags_all;
    }

    switch (opt_index) {
      case OPT_FIN_FLAG:  flag = FIN_FLAG;  break;
      case OPT_SYN_FLAG:  flag = SYN_FLAG;  break;
      case OPT_RST_FLAG:  flag = RST_FLAG;  break;
      case OPT_PSH_FLAG:  flag = PSH_FLAG;  break;
      case OPT_ACK_FLAG:  flag = ACK_FLAG;  break;
      case OPT_URG_FLAG:  flag = URG_FLAG;  break;
      case OPT_ECE_FLAG:  flag = ECE_FLAG;  break;
      case OPT_CWR_FLAG:  flag = CWR_FLAG;  break;
      default:
        skAbortBadCase(opt_index);
    }

    i = strtoul(opt_arg, (char **)NULL, 10);
    switch (i) {
      case 1:
        TCP_FLAG_SET_FLAG(checks->flags_all[binary_flag_pos].high, flag);
        /* FALLTHROUGH */
      case 0:
        TCP_FLAG_SET_FLAG(checks->flags_all[binary_flag_pos].mask, flag);
        break;
      default:
        skAppPrintErr("Error parsing --%s option: '%s'",
                      filterOptions[opt_index].name, opt_arg);
        return 1;
    }

    return 0;
}


/*
 *  status = parseAttributes(opt_index, opt_arg)
 *
 *    Parse the value passed to the --attributes switch, which expect
 *    a attributes in the form HIGH/MASK.  Multiple HIGH/MASK sets may
 *    be specified by separating them with comma.
 *
 *    Return 0 on success, and non-zero on failure.
 */
static int
parseAttributes(
    int                 opt_index,
    const char         *opt_arg)
{
    char buf[32];
    const char *sp = opt_arg;
    const char *cp = sp;
    const char *high_mask_string;
    high_mask_t *h_m;
    size_t len;
    int rv;

    while (cp && *sp) {
        if (checks->count_attributes >= MAX_ATTRIBUTE_CHECKS) {
            skAppPrintErr("May only specify %d %s checks",
                          MAX_ATTRIBUTE_CHECKS, filterOptions[opt_index].name);
            return 1;
        }

        cp = strchr(sp, ',');
        h_m = &(checks->attributes[checks->count_attributes]);

        /* if there is no ',' in the (remaining) input, parse the
         * rest. */
        if (cp == NULL) {
            rv = skStringParseTCPStateHighMask(&h_m->high, &h_m->mask, sp);
            high_mask_string = sp;
        } else if (cp == sp) {
            /* double comma */
            ++sp;
            continue;
        } else {
            /* copy this flag combination into 'buf' */
            len = cp - sp;
            if (len > sizeof(buf)-1) {
                return 1;
            }
            strncpy(buf, sp, sizeof(buf));
            buf[len] = '\0';
            sp = cp + 1;
            rv = skStringParseTCPStateHighMask(&h_m->high, &h_m->mask, buf);
            high_mask_string = buf;
        }
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          filterOptions[opt_index].name, high_mask_string,
                          skStringParseStrerror(rv));
            return 1;
        }
        checks->count_attributes++;
    }

    if (0 == checks->count_attributes) {
        skAppPrintErr("Invalid %s: No value was given",
                      filterOptions[opt_index].name);
        return 1;
    }

    return 0;
}


static int
parseCountryCodes(
    sk_bitmap_t       **bitmap,
    int                 opt_index,
    const char         *opt_arg)
{
    char *token_list = NULL;
    char *next_token;
    char *token;
    sk_countrycode_t code;
    int rv = -1;
    uint32_t bitmap_size;

    if (skCountrySetup(NULL, &skAppPrintErr)) {
        return -1;
    }

    bitmap_size = 1 + skCountryGetMaxCode();

    /* Create the bitmap */
    if (skBitmapCreate(bitmap, bitmap_size)) {
        skAppPrintErr("Unable to create %" PRIu32 "-element bitmap for %s",
                      bitmap_size, filterOptions[opt_index].name);
        return -1;
    }

    /* make a modifiable version of the argument */
    token_list = strdup(opt_arg);
    if (NULL == token_list) {
        skAppPrintOutOfMemory("copy country code list");
        goto END;
    }

    /* parse the argument as a comma separated list of tokens */
    next_token = token_list;
    while ((token = strsep(&next_token, ",")) != NULL) {
        /* check for empty token (e.g., double comma) */
        if ('\0' == *token) {
            continue;
        }

        code = skCountryNameToCode(token);
        if (SK_COUNTRYCODE_INVALID == code) {
            skAppPrintErr("Invalid %s '%s'",
                          filterOptions[opt_index].name, token);
            goto END;
        }
        skBitmapSetBit(*bitmap, code);
    }

    /* Success */
    rv = 0;

  END:
    if (token_list) {
        free(token_list);
    }
    if (rv != 0) {
        if (*bitmap) {
            skBitmapDestroy(bitmap);
        }
    }
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
