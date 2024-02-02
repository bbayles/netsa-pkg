/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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
**  rwsilk2ipfix.c
**
**    SiLK to IPFIX translation application
**
**    Brian Trammell
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwsilk2ipfix.c 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipfix.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* where to write --print-stat output */
#define STATS_FH stderr

/* destination for log messages; go ahead and use stderr since
 * normally there are no messages when converting SiLK to IPFIX. */
#define LOG_DESTINATION_DEFAULT  "stderr"

/* The IPFIX Private Enterprise Number for CERT */
#define IPFIX_CERT_PEN  6871

/* The observation domain to use in the output */
#define OBSERVATION_DOMAIN  0

/*
 *    These flags are used to select particular fields from the
 *    fbInfoElementSpec_t 'multiple_spec' array below.
 */
/* IP version */
#define REC_V6            (1u <<  0)
#define REC_V4            (1u <<  1)
/* for protocols with no ports */
#define REC_NO_PORTS      (1u <<  2)
/* for ICMP records */
#define REC_ICMP          (1u <<  3)
/* for non-TCP records with ports (UDP, SCTP) */
#define REC_UDP           (1u <<  4)
/* for TCP records with a single flag */
#define REC_TCP           (1u <<  5)
/* for TCP records with a expanded flags */
#define REC_TCP_EXP       (1u <<  6)
/* additional flags could be added based on the type of SiLK flow
 * file; for example: whether the record has NextHopIP + SNMP ports,
 * or whether it has an app-label.  Each additional test doubles the
 * number templates to manage. */

/* only include class,type,sensor names when silk.conf file is found */
#define REC_SILK_CONF     (1u << 30)

/* do not include paddingOctets in exported templates */
#define REC_PADDING       (1u << 31)

/*
 *    External Template ID traditionally used for SiLK Flow
 *    records written to an IPFIX stream.
 */
#define SKI_RWREC_TID        0xAFEA

/*
 *    Template IDs used for each template
 */
#define TID4_NOPORTS    0x9DD0
#define TID4_ICMP       0x9DD1
#define TID4_UDP        0x9DD2
#define TID4_TCP        0x9DD3
#define TID4_TCP_EXP    0x9DD4
#if SK_ENABLE_IPV6
#define TID6_NOPORTS    0x9ED0
#define TID6_ICMP       0x9ED1
#define TID6_UDP        0x9ED2
#define TID6_TCP        0x9ED3
#define TID6_TCP_EXP    0x9ED4
#endif  /* SK_ENABLE_IPV6 */

/*
 *    Structures to map an rwRec into prior to transcoding with the
 *    template.
 *
 *    Note: There is really no need to do this; we could have just relied on
 *    the fixbuf transcoder to convert the large record with everything to the
 *    specialized export records.
 */
/* The base values, present on every flow */
struct rec_prelim_st {
    uint64_t            stime;
    uint64_t            etime;
    uint32_t            packets;
    uint32_t            bytes;
    uint16_t            ingress;
    uint16_t            egress;
    uint16_t            application;
    uint16_t            sensor;
    uint8_t             flowtype;
    uint8_t             attributes;
    uint8_t             protocol;
    uint8_t             padding1[5];
};
typedef struct rec_prelim_st rec_prelim_t;

/* The names the close the record, present on every flow if silk.conf found */
struct rec_names_st {
    fbVarfield_t        silkFlowtypeName;
    fbVarfield_t        silkClassName;
    fbVarfield_t        silkTypeName;
    fbVarfield_t        silkSensorName;
};
typedef struct rec_names_st rec_names_t;

/* IPv4 version of the close of a record */
struct rec_ip4_names_st {
    uint32_t            sip;
    uint32_t            dip;
    uint32_t            nhip;
    uint32_t            padding4;
    rec_names_t         names;
};
typedef struct rec_ip4_names_st rec_ip4_names_t;

#if SK_ENABLE_IPV6
/* IPv6 version of the close of a record */
struct rec_ip6_names_st {
    uint8_t             sip[16];
    uint8_t             dip[16];
    uint8_t             nhip[16];
    rec_names_t         names;
};
typedef struct rec_ip6_names_st rec_ip6_names_t;
#endif  /* SK_ENABLE_IPV6 */

/*
 * In all the following structures that describe the records, the padding
 * appear first so it may be combined with the padding at the end of
 * rec_prelim_t.
 */

/* When no other data, just print the core values, IPs, and names */
struct rec_noports_v4_st {
    rec_prelim_t        pre;
    rec_ip4_names_t     ips_names;
};
typedef struct rec_noports_v4_st rec_noports_v4_t;

#if SK_ENABLE_IPV6
struct rec_noports_v6_st {
    rec_prelim_t        pre;
    rec_ip6_names_t     ips_names;
};
typedef struct rec_noports_v6_st rec_noports_v6_t;
#endif  /* SK_ENABLE_IPV6 */

/* ICMP only has the icmpTypeCode in addition to core values, IPs, names */
struct rec_icmp_v4_st {
    rec_prelim_t        pre;
    uint8_t             padding1[6];
    uint16_t            icmptypecode;
    rec_ip4_names_t     ips_names;
};
typedef struct rec_icmp_v4_st rec_icmp_v4_t;

#if SK_ENABLE_IPV6
struct rec_icmp_v6_st {
    rec_prelim_t        pre;
    uint8_t             padding1[6];
    uint16_t            icmptypecode;
    rec_ip6_names_t     ips_names;
};
typedef struct rec_icmp_v6_st rec_icmp_v6_t;
#endif  /* SK_ENABLE_IPV6 */

/* UDP adds the ports to the core values, IPs, and names */
struct rec_udp_v4_st {
    rec_prelim_t        pre;
    uint8_t             padding1[4];
    uint16_t            sport;
    uint16_t            dport;
    rec_ip4_names_t     ips_names;
};
typedef struct rec_udp_v4_st rec_udp_v4_t;

#if SK_ENABLE_IPV6
struct rec_udp_v6_st {
    rec_prelim_t        pre;
    uint8_t             padding1[4];
    uint16_t            sport;
    uint16_t            dport;
    rec_ip6_names_t     ips_names;
};
typedef struct rec_udp_v6_st rec_udp_v6_t;
#endif  /* SK_ENABLE_IPV6 */

/* TCP adds flags and ports to the core values, IPs, and names */
struct rec_tcp_v4_st {
    rec_prelim_t        pre;
    uint8_t             padding1[3];
    uint8_t             flags_all;
    uint16_t            sport;
    uint16_t            dport;
    rec_ip4_names_t     ips_names;
};
typedef struct rec_tcp_v4_st rec_tcp_v4_t;

#if SK_ENABLE_IPV6
struct rec_tcp_v6_st {
    rec_prelim_t        pre;
    uint8_t             padding1[3];
    uint8_t             flags_all;
    uint16_t            sport;
    uint16_t            dport;
    rec_ip6_names_t     ips_names;
};
typedef struct rec_tcp_v6_st rec_tcp_v6_t;
#endif  /* SK_ENABLE_IPV6 */

/* Expanded TCP adds flags and ports to the core values, IPs, and names */
struct rec_tcp_exp_v4_st {
    rec_prelim_t        pre;
    uint8_t             padding1;
    uint8_t             flags_init;
    uint8_t             flags_rest;
    uint8_t             flags_all;
    uint16_t            sport;
    uint16_t            dport;
    rec_ip4_names_t     ips_names;
};
typedef struct rec_tcp_exp_v4_st rec_tcp_exp_v4_t;

#if SK_ENABLE_IPV6
struct rec_tcp_exp_v6_st {
    rec_prelim_t        pre;
    uint8_t             padding1;
    uint8_t             flags_init;
    uint8_t             flags_rest;
    uint8_t             flags_all;
    uint16_t            sport;
    uint16_t            dport;
    rec_ip6_names_t     ips_names;
};
typedef struct rec_tcp_exp_v6_st rec_tcp_exp_v6_t;
#endif  /* SK_ENABLE_IPV6 */


/* LOCAL VARIABLE DEFINITIONS */

/*
 *    Defines the fields contained by the various templates.
 */
static fbInfoElementSpec_t multiple_spec[] = {
    /* sTime */
    {(char *)"flowStartMilliseconds",    8,  0},
    /* eTime */
    {(char *)"flowEndMilliseconds",      8,  0},
    /* pkts */
    {(char *)"packetDeltaCount",         4,  0},
    /* bytes */
    {(char *)"octetDeltaCount",          4,  0},
    /* input, output */
    {(char *)"ingressInterface",         2,  0},
    {(char *)"egressInterface",          2,  0},
    /* application */
    {(char *)"silkAppLabel",             2,  0},
    /* sID */
    {(char *)"silkSensorId",             2,  0},
    /* flow_type */
    {(char *)"silkFlowtypeId",           1,  0},
    /* attributes */
    {(char *)"silkTCPState",             1,  0},
    /* proto */
    {(char *)"protocolIdentifier",       1,  0},
    /* 5 bytes of rec_prelim_t->padding1 combined with next padding1 */

    /* if no_ports, just the rec_prelim_t->padding1 */
    {(char *)"paddingOctets",            5,  REC_NO_PORTS | REC_PADDING},

    /* if ICMP, 5 + 6 bytes of padding, then icmpTypeCode */
    {(char *)"paddingOctets",            11, REC_ICMP | REC_PADDING},
    {(char *)"icmpTypeCodeIPv4",         2,  REC_ICMP | REC_V4},
    {(char *)"icmpTypeCodeIPv6",         2,  REC_ICMP | REC_V6},

    /* if UDP, 5 + 4 bytes of padding, then ports */
    {(char *)"paddingOctets",            9,  REC_UDP | REC_PADDING},
    {(char *)"sourceTransportPort",      2,  REC_UDP},
    {(char *)"destinationTransportPort", 2,  REC_UDP},

    /* if TCP, 5 + 3 bytes of padding, then flags_all and ports */
    {(char *)"paddingOctets",            8,  REC_TCP | REC_PADDING},
    {(char *)"tcpControlBits",           1,  REC_TCP},
    {(char *)"sourceTransportPort",      2,  REC_TCP},
    {(char *)"destinationTransportPort", 2,  REC_TCP},

    /* if expanded TCP, 5 + 1 bytes of padding, then flags and ports  */
    {(char *)"paddingOctets",            6,  REC_TCP_EXP | REC_PADDING},
    {(char *)"initialTCPFlags",          1,  REC_TCP_EXP},
    {(char *)"unionTCPFlags",            1,  REC_TCP_EXP},
    {(char *)"tcpControlBits",           1,  REC_TCP_EXP},
    {(char *)"sourceTransportPort",      2,  REC_TCP_EXP},
    {(char *)"destinationTransportPort", 2,  REC_TCP_EXP},

    /* sIP -- one of these is used */
    {(char *)"sourceIPv6Address",        16, REC_V6},
    {(char *)"sourceIPv4Address",        4,  REC_V4},
    /* dIP -- one of these is used */
    {(char *)"destinationIPv6Address",   16, REC_V6},
    {(char *)"destinationIPv4Address",   4,  REC_V4},
    /* nhIP -- one of these is used */
    {(char *)"ipNextHopIPv6Address",     16, REC_V6},
    {(char *)"ipNextHopIPv4Address",     4,  REC_V4},

    /* padding4 if IPv4 */
    {(char *)"paddingOctets",            4,  REC_V4 | REC_PADDING},

    {(char *)"silkFlowtypeName",         FB_IE_VARLEN, REC_SILK_CONF},
    {(char *)"silkClassName",            FB_IE_VARLEN, REC_SILK_CONF},
    {(char *)"silkTypeName",             FB_IE_VARLEN, REC_SILK_CONF},
    {(char *)"silkSensorName",           FB_IE_VARLEN, REC_SILK_CONF},

    /* done */
    FB_IESPEC_NULL
};


/*
 *    Enterprise information elements to add to the information model.
 */
static fbInfoElement_t info_elements[] = {
    /* Extra fields produced by yaf for SiLK records */
    FB_IE_INIT_FULL("initialTCPFlags",      IPFIX_CERT_PEN,  14,  1,
                    FB_IE_FLAGS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE,
                    0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("unionTCPFlags",        IPFIX_CERT_PEN,  15,  1,
                    FB_IE_FLAGS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE,
                    0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("silkFlowtypeId",       IPFIX_CERT_PEN,  30,  1,
                    FB_IE_IDENTIFIER | FB_IE_F_ENDIAN,
                    0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("silkSensorId"  ,       IPFIX_CERT_PEN,  31,  2,
                    FB_IE_IDENTIFIER | FB_IE_F_ENDIAN,
                    0, 0,  FB_UINT_16, NULL),
    FB_IE_INIT_FULL("silkTCPState",         IPFIX_CERT_PEN,  32,  1,
                    FB_IE_FLAGS | FB_IE_F_ENDIAN,
                    0, 0,  FB_UINT_8, NULL),
    FB_IE_INIT_FULL("silkAppLabel",         IPFIX_CERT_PEN,  33,  2,
                    FB_IE_IDENTIFIER | FB_IE_F_ENDIAN,
                    0, 0,  FB_UINT_16, NULL),
    FB_IE_INIT_FULL("silkFlowtypeName",     IPFIX_CERT_PEN, 938,  FB_IE_VARLEN,
                    FB_IE_DEFAULT,
                    0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkClassName",        IPFIX_CERT_PEN, 939,  FB_IE_VARLEN,
                    FB_IE_DEFAULT,
                    0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkTypeName",         IPFIX_CERT_PEN, 940,  FB_IE_VARLEN,
                    FB_IE_DEFAULT,
                    0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkSensorName",       IPFIX_CERT_PEN, 941,  FB_IE_VARLEN,
                    FB_IE_DEFAULT,
                    0, 0, FB_STRING, NULL),
    FB_IE_NULL
};


/* for looping over input */
static sk_options_ctx_t *optctx = NULL;

/* the IPFIX output file; use stdout if no name provided */
static sk_fileptr_t ipfix_output;

/* disable export of the elements that use silk.conf to get the names of the
 * sensor, class, and type */
static int no_site_name_elements = 0;

/* whether the silk.conf file was successfully loaded */
static int have_silk_conf = 0;

/* whether to print statistics */
static int print_statistics = 0;

/* whether to use a single template or many templates */
static int single_template = 0;

/* the IPFIX infomation model */
static fbInfoModel_t *model = NULL;

/* the fixbuf session */
static fbSession_t *session = NULL;

/* the fixbuf output buffer */
static fBuf_t *fbuf = NULL;


/* OPTIONS SETUP */

typedef enum {
    OPT_IPFIX_OUTPUT,
    OPT_NO_SITE_NAME_ELEMENTS,
    OPT_PRINT_STATISTICS,
    OPT_SINGLE_TEMPLATE
} appOptionsEnum;

static struct option appOptions[] = {
    {"ipfix-output",            REQUIRED_ARG, 0, OPT_IPFIX_OUTPUT},
    {"no-site-name-elements",   NO_ARG,       0, OPT_NO_SITE_NAME_ELEMENTS},
    {"print-statistics",        NO_ARG,       0, OPT_PRINT_STATISTICS},
    {"single-template",         NO_ARG,       0, OPT_SINGLE_TEMPLATE},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    ("Write IPFIX records to the specified path. Def. stdout"),
    ("Do not export the elements that use the\n"
     "\tsite configuration file to get the names of the flowtype, class,\n"
     "\ttype, and sensor."),
    ("Print the count of processed records. Def. No"),
    ("Use a single template for all IPFIX records. Def. No.\n"
     "\tThis switch creates output identical to that produced by SiLK 3.11.0\n"
     "\tand earlier."),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static size_t logprefix(char *buffer, size_t bufsize);


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
    ("[SWITCHES] [SILK_FILES]\n"                                              \
     "\tReads SiLK Flow records from files named on the command line or\n"    \
     "\tfrom the standard input, converts them to an IPFIX format, and\n"     \
     "\twrites the IPFIX records to the named file or the standard output.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsCtxOptionsUsage(optctx, fh);
    sksiteOptionsUsage(fh);
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

    if (ipfix_output.of_fp) {
        skFileptrClose(&ipfix_output, &skAppPrintErr);
    }

    if (fbuf) {
        fBufFree(fbuf);
        fbuf = NULL;
    }
    if (session) {
        fbSessionFree(session);
        session = NULL;
    }
    if (model) {
        fbInfoModelFree(model);
        model = NULL;
    }

    /* set level to "warning" to avoid the "Stopped logging" message */
    sklogSetLevel("warning");
    sklogTeardown();

    skOptionsCtxDestroy(&optctx);
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
    unsigned int optctx_flags;
    int logmask;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* enable the logger */
    sklogSetup(0);
    sklogSetStampFunction(&logprefix);
    sklogSetDestination(LOG_DESTINATION_DEFAULT);

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* set up libflowsource */
    skIPFIXSourcesSetup();

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    have_silk_conf = (0 == sksiteConfigure(0));
    if (no_site_name_elements) {
        have_silk_conf = 0;
    }

    /* set level to "warning" to avoid the "Started logging" message */
    logmask = sklogGetMask();
    sklogSetLevel("warning");
    sklogOpen();
    sklogSetMask(logmask);

    /* open the provided output file or use stdout */
    if (NULL == ipfix_output.of_name) {
        ipfix_output.of_name = "-";
        ipfix_output.of_fp = stdout;
    } else {
        rv = skFileptrOpen(&ipfix_output, SK_IO_WRITE);
        if (rv) {
            skAppPrintErr("Could not open IPFIX output file '%s': %s",
                          ipfix_output.of_name, skFileptrStrerror(rv));
            exit(EXIT_FAILURE);
        }

        if (SK_FILEPTR_IS_PROCESS == ipfix_output.of_type) {
            skAppPrintErr("Writing to gzipped files is not supported");
            exit(EXIT_FAILURE);
        }
    }

    if (FILEIsATty(ipfix_output.of_fp)) {
        skAppPrintErr("Will not write binary data to the terminal");
        exit(EXIT_FAILURE);
    }

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
    switch ((appOptionsEnum)opt_index) {
      case OPT_IPFIX_OUTPUT:
        if (ipfix_output.of_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        ipfix_output.of_name = opt_arg;
        break;

      case OPT_NO_SITE_NAME_ELEMENTS:
        no_site_name_elements = 1;
        break;

      case OPT_PRINT_STATISTICS:
        print_statistics = 1;
        break;

      case OPT_SINGLE_TEMPLATE:
        single_template = 1;
        break;
    }

    return 0;  /* OK */
}


/*
 *    Prefix any log messages from libflowsource with the program name
 *    instead of the standard logging tag.
 */
static size_t
logprefix(
    char               *buffer,
    size_t              bufsize)
{
    return (size_t)snprintf(buffer, bufsize, "%s: ", skAppName());
}


static int
toipfix_one_template(
    void)
{
    /* Map each rwRec into this structure, which matches the template
     * below. Ensure it is padded to 64bits */
    struct fixrec_st {
        uint64_t            flowStartMilliseconds;      /*   0-  7 */
        uint64_t            flowEndMilliseconds;        /*   8- 15 */

        uint8_t             sourceIPv6Address[16];      /*  16- 31 */
        uint8_t             destinationIPv6Address[16]; /*  32- 47 */

        uint32_t            sourceIPv4Address;          /*  48- 51 */
        uint32_t            destinationIPv4Address;     /*  52- 55 */

        uint16_t            sourceTransportPort;        /*  56- 57 */
        uint16_t            destinationTransportPort;   /*  58- 59 */

        uint32_t            ipNextHopIPv4Address;       /*  60- 63 */
        uint8_t             ipNextHopIPv6Address[16];   /*  64- 79 */
        uint32_t            ingressInterface;           /*  80- 83 */
        uint32_t            egressInterface;            /*  84- 87 */

        uint64_t            packetDeltaCount;           /*  88- 95 */
        uint64_t            octetDeltaCount;            /*  96-103 */

        uint8_t             protocolIdentifier;         /* 104     */
        uint8_t             silkFlowtypeId;             /* 105     */
        uint16_t            silkSensorId;               /* 106-107 */

        uint8_t             tcpControlBits;             /* 108     */
        uint8_t             initialTCPFlags;            /* 109     */
        uint8_t             unionTCPFlags;              /* 110     */
        uint8_t             silkTCPState;               /* 111     */
        uint16_t            silkAppLabel;               /* 112-113 */
        uint8_t             pad[6];                     /* 114-119 */
    } fixrec;

    /* The elements of the template to write. This must be in sync
     * with the structure above. */
    fbInfoElementSpec_t fixrec_spec[] = {
        /* Millisecond start and end (epoch) (native time) */
        { (char*)"flowStartMilliseconds",              8, 0 },
        { (char*)"flowEndMilliseconds",                8, 0 },
        /* 4-tuple */
        { (char*)"sourceIPv6Address",                 16, 0 },
        { (char*)"destinationIPv6Address",            16, 0 },
        { (char*)"sourceIPv4Address",                  4, 0 },
        { (char*)"destinationIPv4Address",             4, 0 },
        { (char*)"sourceTransportPort",                2, 0 },
        { (char*)"destinationTransportPort",           2, 0 },
        /* Router interface information */
        { (char*)"ipNextHopIPv4Address",               4, 0 },
        { (char*)"ipNextHopIPv6Address",              16, 0 },
        { (char*)"ingressInterface",                   4, 0 },
        { (char*)"egressInterface",                    4, 0 },
        /* Counters (reduced length encoding for SiLK) */
        { (char*)"packetDeltaCount",                   8, 0 },
        { (char*)"octetDeltaCount",                    8, 0 },
        /* Protocol; sensor information */
        { (char*)"protocolIdentifier",                 1, 0 },
        { (char*)"silkFlowtypeId",                     1, 0 },
        { (char*)"silkSensorId",                       2, 0 },
        /* Flags */
        { (char*)"tcpControlBits",                     1, 0 },
        { (char*)"initialTCPFlags",                    1, 0 },
        { (char*)"unionTCPFlags",                      1, 0 },
        { (char*)"silkTCPState",                       1, 0 },
        { (char*)"silkAppLabel",                       2, 0 },
        /* pad record to 64-bit boundary */
        { (char*)"paddingOctets",                      6, 0 },
        FB_IESPEC_NULL
    };

    const uint16_t tid = SKI_RWREC_TID;
    fbTemplate_t *tmpl = NULL;
    GError *err = NULL;
    skstream_t *stream = NULL;
    rwRec rwrec;
    uint64_t rec_count = 0;
    ssize_t rv;

    memset(&fixrec, 0, sizeof(fixrec));

    /* Create the template and add the spec */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, fixrec_spec, 0, &err)) {
        skAppPrintErr("Could not create template: %s", err->message);
        g_clear_error(&err);
        fbTemplateFreeUnused(tmpl);
        return EXIT_FAILURE;
    }

    /* Add the template to the session */
    if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, &err)) {
        skAppPrintErr("Could not add template to session: %s", err->message);
        g_clear_error(&err);
        fbTemplateFreeUnused(tmpl);
        return EXIT_FAILURE;
    }
    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, &err)) {
        skAppPrintErr("Could not add template to session: %s", err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

    /* Create the output buffer with the session and an exporter
     * created from the file pointer */
    fbuf = fBufAllocForExport(session, fbExporterAllocFP(ipfix_output.of_fp));
    /* The fbuf now owns the session */
    session = NULL;

    /* Write the template */
    if (!fbSessionExportTemplates(fBufGetSession(fbuf), &err)) {
        skAppPrintErr("Could not add export templates: %s", err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

    /* Set default template for the buffer */
    if (!fBufSetInternalTemplate(fbuf, tid, &err)) {
        skAppPrintErr("Could not set internal template: %s", err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }
    if (!fBufSetExportTemplate(fbuf, tid, &err)) {
        skAppPrintErr("Could not set external template: %s", err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

    /* For each input, process each record */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            /* Convert times */
            fixrec.flowStartMilliseconds = (uint64_t)rwRecGetStartTime(&rwrec);
            fixrec.flowEndMilliseconds = (uint64_t)rwRecGetEndTime(&rwrec);

            /* Handle IP addresses */
#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(&rwrec)) {
                rwRecMemGetSIPv6(&rwrec, fixrec.sourceIPv6Address);
                rwRecMemGetDIPv6(&rwrec, fixrec.destinationIPv6Address);
                rwRecMemGetNhIPv6(&rwrec, fixrec.ipNextHopIPv6Address);
                fixrec.sourceIPv4Address = 0;
                fixrec.destinationIPv4Address = 0;
                fixrec.ipNextHopIPv4Address = 0;
            } else
#endif
            {
                memset(fixrec.sourceIPv6Address, 0,
                       sizeof(fixrec.sourceIPv6Address));
                memset(fixrec.destinationIPv6Address, 0,
                       sizeof(fixrec.destinationIPv6Address));
                memset(fixrec.ipNextHopIPv6Address, 0,
                       sizeof(fixrec.ipNextHopIPv6Address));
                fixrec.sourceIPv4Address = rwRecGetSIPv4(&rwrec);
                fixrec.destinationIPv4Address = rwRecGetDIPv4(&rwrec);
                fixrec.ipNextHopIPv4Address = rwRecGetNhIPv4(&rwrec);
            }

            /* Copy rest of record */
            fixrec.sourceTransportPort = rwRecGetSPort(&rwrec);
            fixrec.destinationTransportPort = rwRecGetDPort(&rwrec);
            fixrec.ingressInterface = rwRecGetInput(&rwrec);
            fixrec.egressInterface = rwRecGetOutput(&rwrec);
            fixrec.packetDeltaCount = rwRecGetPkts(&rwrec);
            fixrec.octetDeltaCount = rwRecGetBytes(&rwrec);
            fixrec.protocolIdentifier = rwRecGetProto(&rwrec);
            fixrec.silkFlowtypeId = rwRecGetFlowType(&rwrec);
            fixrec.silkSensorId = rwRecGetSensor(&rwrec);
            fixrec.tcpControlBits = rwRecGetFlags(&rwrec);
            fixrec.initialTCPFlags = rwRecGetInitFlags(&rwrec);
            fixrec.unionTCPFlags = rwRecGetRestFlags(&rwrec);
            fixrec.silkTCPState = rwRecGetTcpState(&rwrec);
            fixrec.silkAppLabel = rwRecGetApplication(&rwrec);

            /* Append the record to the buffer */
            if (fBufAppend(fbuf, (uint8_t *)&fixrec, sizeof(fixrec), &err)) {
                /* processed record */
                ++rec_count;
            } else {
                skAppPrintErr("Could not write IPFIX record: %s",
                              err->message);
                g_clear_error(&err);
            }
        }
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&stream);
    }

    /* finalize the output */
    if (!fBufEmit(fbuf, &err)) {
        skAppPrintErr("Could not write final IPFIX message: %s",
                      err->message);
        g_clear_error(&err);
        fbExporterClose(fBufGetExporter(fbuf));
        return EXIT_FAILURE;
    }
    fbExporterClose(fBufGetExporter(fbuf));

    fBufFree(fbuf);
    fbuf = NULL;

    /* print record count */
    if (print_statistics) {
        fprintf(STATS_FH, ("%s: Wrote %" PRIu64 " IPFIX records to '%s'\n"),
                skAppName(), rec_count, ipfix_output.of_name);
    }

    return 0;
}


static int
toipfix_multiple_templates(
    void)
{
#define TMPL_COUNT 10
    const uint16_t tid[] = {
        TID4_NOPORTS, TID4_ICMP, TID4_UDP, TID4_TCP, TID4_TCP_EXP
#if SK_ENABLE_IPV6
        , TID6_NOPORTS, TID6_ICMP, TID6_UDP, TID6_TCP, TID6_TCP_EXP
#endif
    };
    const struct tid_to_position_st {
        unsigned int    p_TID4_NOPORTS;
        unsigned int    p_TID4_ICMP;
        unsigned int    p_TID4_UDP;
        unsigned int    p_TID4_TCP;
        unsigned int    p_TID4_TCP_EXP;
#if SK_ENABLE_IPV6
        unsigned int    p_TID6_NOPORTS;
        unsigned int    p_TID6_ICMP;
        unsigned int    p_TID6_UDP;
        unsigned int    p_TID6_TCP;
        unsigned int    p_TID6_TCP_EXP;
#endif  /* SK_ENABLE_IPV6 */
    } tid_to_position = {
        0, 1, 2, 3, 4
#if SK_ENABLE_IPV6
        , 5, 6, 7, 8, 9
#endif
    };
    const uint32_t spec_flag[] = {
        REC_V4 | REC_NO_PORTS,
        REC_V4 | REC_ICMP,
        REC_V4 | REC_UDP,
        REC_V4 | REC_TCP,
        REC_V4 | REC_TCP_EXP
#if SK_ENABLE_IPV6
        ,
        REC_V6 | REC_NO_PORTS,
        REC_V6 | REC_ICMP,
        REC_V6 | REC_UDP,
        REC_V6 | REC_TCP,
        REC_V6 | REC_TCP_EXP
#endif
    };
    const unsigned int count = sizeof(tid)/sizeof(tid[0]);

    union fixrec_un {
        rec_prelim_t     pre;
#if SK_ENABLE_IPV6
        rec_noports_v6_t rec6_noports;
        rec_icmp_v6_t    rec6_icmp;
        rec_udp_v6_t     rec6_udp;
        rec_tcp_v6_t     rec6_tcp;
        rec_tcp_exp_v6_t rec6_tcp_exp;
#endif  /* SK_ENABLE_IPV6 */
        rec_noports_v4_t rec4_noports;
        rec_icmp_v4_t    rec4_icmp;
        rec_udp_v4_t     rec4_udp;
        rec_tcp_v4_t     rec4_tcp;
        rec_tcp_exp_v4_t rec4_tcp_exp;
    } fixrec;

    char flowtype[SK_MAX_STRLEN_FLOWTYPE + 1];
    char ft_class[SK_MAX_STRLEN_FLOWTYPE + 1];
    char ft_type[SK_MAX_STRLEN_FLOWTYPE + 1];
    char sensor[SK_MAX_STRLEN_SENSOR + 1];

    GError *err = NULL;
    skstream_t *stream = NULL;
    uint32_t silk_conf_flag;
    rec_names_t *names;
    rwRec rwrec;
    uint64_t rec_count = 0;
    unsigned int i;
    ssize_t rv;

    assert((sizeof(spec_flag)/sizeof(spec_flag[0])) == count);
    assert((sizeof(tid_to_position)/sizeof(tid_to_position.p_TID4_NOPORTS))
           == count);
    assert(count <= TMPL_COUNT);

    memset(flowtype, 0, sizeof(flowtype));
    memset(ft_class, 0, sizeof(ft_class));
    memset(ft_type, 0, sizeof(ft_class));
    memset(sensor, 0, sizeof(sensor));

    silk_conf_flag = (have_silk_conf) ? REC_SILK_CONF : 0;

    /* Create each template, add the spec to the template, and add the
     * template to the session */
    for (i = 0; i < count; ++i) {
        fbTemplate_t *tmpl;

        /* Create the internal template and add to the session */
        tmpl = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(
                tmpl, multiple_spec,
                spec_flag[i] | REC_PADDING | silk_conf_flag, &err))
        {
            skAppPrintErr("Could not create template: %s", err->message);
            g_clear_error(&err);
            fbTemplateFreeUnused(tmpl);
            return EXIT_FAILURE;
        }
        if (!fbSessionAddTemplate(session, TRUE, tid[i], tmpl, &err)) {
            skAppPrintErr("Could not add template to session: %s",
                          err->message);
            g_clear_error(&err);
            return EXIT_FAILURE;
        }

        /* Create the external template and add to the session */
        tmpl = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(
                tmpl, multiple_spec, spec_flag[i] | silk_conf_flag, &err))
        {
            skAppPrintErr("Could not create template: %s", err->message);
            g_clear_error(&err);
            fbTemplateFreeUnused(tmpl);
            return EXIT_FAILURE;
        }
        if (!fbSessionAddTemplate(session, FALSE, tid[i], tmpl, &err)) {
            skAppPrintErr("Could not add template to session: %s",
                          err->message);
            g_clear_error(&err);
            return EXIT_FAILURE;
        }
    }

    /* Create the output buffer with the session and an exporter
     * created from the file pointer */
    fbuf = fBufAllocForExport(session, fbExporterAllocFP(ipfix_output.of_fp));
    /* The fbuf now owns the session */
    session = NULL;

    /* Write the templates */
    if (!fbSessionExportTemplates(fBufGetSession(fbuf), &err)) {
        skAppPrintErr("Could not add export templates: %s", err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

    /* For each input, process each record */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            memset(&fixrec, 0, sizeof(fixrec));
            /* handle fields that are the same for all */
            fixrec.pre.stime = (uint64_t)rwRecGetStartTime(&rwrec);
            fixrec.pre.etime = (uint64_t)rwRecGetEndTime(&rwrec);
            fixrec.pre.packets = rwRecGetPkts(&rwrec);
            fixrec.pre.bytes = rwRecGetBytes(&rwrec);
            fixrec.pre.ingress = rwRecGetInput(&rwrec);
            fixrec.pre.egress = rwRecGetOutput(&rwrec);
            fixrec.pre.application = rwRecGetApplication(&rwrec);
            fixrec.pre.sensor = rwRecGetSensor(&rwrec);
            fixrec.pre.flowtype = rwRecGetFlowType(&rwrec);
            fixrec.pre.attributes = rwRecGetTcpState(&rwrec);
            fixrec.pre.protocol = rwRecGetProto(&rwrec);

#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(&rwrec)) {
                rec_ip6_names_t *ip6_names;

                switch (rwRecGetProto(&rwrec)) {
                  case IPPROTO_ICMP:
                  case IPPROTO_ICMPV6:
                    i = tid_to_position.p_TID6_ICMP;
                    ip6_names = &fixrec.rec6_icmp.ips_names;
                    fixrec.rec6_icmp.icmptypecode = rwRecGetDPort(&rwrec);
                    break;

                  case IPPROTO_UDP:
                  case IPPROTO_SCTP:
                    i = tid_to_position.p_TID6_UDP;
                    ip6_names = &fixrec.rec6_udp.ips_names;
                    fixrec.rec6_udp.sport = rwRecGetSPort(&rwrec);
                    fixrec.rec6_udp.dport = rwRecGetDPort(&rwrec);
                    break;

                  case IPPROTO_TCP:
                    if (rwRecGetTcpState(&rwrec) & SK_TCPSTATE_EXPANDED) {
                        i = tid_to_position.p_TID6_TCP_EXP;
                        ip6_names = &fixrec.rec6_tcp_exp.ips_names;
                        fixrec.rec6_tcp_exp.flags_init
                            = rwRecGetInitFlags(&rwrec);
                        fixrec.rec6_tcp_exp.flags_rest
                            = rwRecGetRestFlags(&rwrec);
                        fixrec.rec6_tcp_exp.flags_all = rwRecGetFlags(&rwrec);
                        fixrec.rec6_tcp_exp.sport = rwRecGetSPort(&rwrec);
                        fixrec.rec6_tcp_exp.dport = rwRecGetDPort(&rwrec);
                    } else {
                        i = tid_to_position.p_TID6_TCP;
                        ip6_names = &fixrec.rec6_tcp.ips_names;
                        fixrec.rec6_tcp.flags_all = rwRecGetFlags(&rwrec);
                        fixrec.rec6_tcp.sport = rwRecGetSPort(&rwrec);
                        fixrec.rec6_tcp.dport = rwRecGetDPort(&rwrec);
                    }
                    break;

                  default:
                    i = tid_to_position.p_TID6_NOPORTS;
                    ip6_names = &fixrec.rec6_noports.ips_names;
                    break;
                }

                rwRecMemGetSIPv6(&rwrec, ip6_names->sip);
                rwRecMemGetDIPv6(&rwrec, ip6_names->dip);
                rwRecMemGetNhIPv6(&rwrec, ip6_names->nhip);
                names = &ip6_names->names;

            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                rec_ip4_names_t *ip4_names;

                switch (rwRecGetProto(&rwrec)) {
                  case IPPROTO_ICMP:
                  case IPPROTO_ICMPV6:
                    i = tid_to_position.p_TID4_ICMP;
                    ip4_names = &fixrec.rec4_icmp.ips_names;
                    fixrec.rec4_icmp.icmptypecode = rwRecGetDPort(&rwrec);
                    break;

                  case IPPROTO_UDP:
                  case IPPROTO_SCTP:
                    i = tid_to_position.p_TID4_UDP;
                    ip4_names = &fixrec.rec4_udp.ips_names;
                    fixrec.rec4_udp.sport = rwRecGetSPort(&rwrec);
                    fixrec.rec4_udp.dport = rwRecGetDPort(&rwrec);
                    break;

                  case IPPROTO_TCP:
                    if (rwRecGetTcpState(&rwrec) & SK_TCPSTATE_EXPANDED) {
                        i = tid_to_position.p_TID4_TCP_EXP;
                        ip4_names = &fixrec.rec4_tcp_exp.ips_names;
                        fixrec.rec4_tcp_exp.flags_init
                            = rwRecGetInitFlags(&rwrec);
                        fixrec.rec4_tcp_exp.flags_rest
                            = rwRecGetRestFlags(&rwrec);
                        fixrec.rec4_tcp_exp.flags_all = rwRecGetFlags(&rwrec);
                        fixrec.rec4_tcp_exp.sport = rwRecGetSPort(&rwrec);
                        fixrec.rec4_tcp_exp.dport = rwRecGetDPort(&rwrec);
                    } else {
                        i = tid_to_position.p_TID4_TCP;
                        ip4_names = &fixrec.rec4_tcp.ips_names;
                        fixrec.rec4_tcp.flags_all = rwRecGetFlags(&rwrec);
                        fixrec.rec4_tcp.sport = rwRecGetSPort(&rwrec);
                        fixrec.rec4_tcp.dport = rwRecGetDPort(&rwrec);
                    }
                    break;

                  default:
                    i = tid_to_position.p_TID4_NOPORTS;
                    ip4_names = &fixrec.rec4_noports.ips_names;
                    break;
                }

                rwRecMemGetSIPv4(&rwrec,  &ip4_names->sip);
                rwRecMemGetDIPv4(&rwrec,  &ip4_names->dip);
                rwRecMemGetNhIPv4(&rwrec, &ip4_names->nhip);
                names = &ip4_names->names;
            }

            if (have_silk_conf) {
                names->silkFlowtypeName.buf = (uint8_t *)flowtype;
                names->silkFlowtypeName.len =
                    sksiteFlowtypeGetName(flowtype, sizeof(flowtype),
                                          fixrec.pre.flowtype);
                names->silkClassName.buf = (uint8_t *)ft_class;
                names->silkClassName.len =
                    sksiteFlowtypeGetClass(ft_class, sizeof(ft_class),
                                          fixrec.pre.flowtype);
                names->silkTypeName.buf = (uint8_t *)ft_type;
                names->silkTypeName.len =
                    sksiteFlowtypeGetType(ft_type, sizeof(ft_type),
                                          fixrec.pre.flowtype);
                names->silkSensorName.buf = (uint8_t *)sensor;
                names->silkSensorName.len =
                    sksiteSensorGetName(sensor, sizeof(sensor),
                                        fixrec.pre.sensor);
            }

            /* Set the template */
            if (!fBufSetInternalTemplate(fbuf, tid[i], &err)) {
                skAppPrintErr("Could not set internal template: %s",
                              err->message);
                g_clear_error(&err);
                return EXIT_FAILURE;
            }
            if (!fBufSetExportTemplate(fbuf, tid[i], &err)) {
                skAppPrintErr("Could not set external template: %s",
                              err->message);
                g_clear_error(&err);
                return EXIT_FAILURE;
            }

            /* Append the record to the buffer */
            if (fBufAppend(fbuf, (uint8_t *)&fixrec, sizeof(fixrec), &err)) {
                /* processed record */
                ++rec_count;
            } else {
                skAppPrintErr("Could not write IPFIX record: %s",
                              err->message);
                g_clear_error(&err);
            }
        }
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&stream);
    }

    /* finalize the output */
    if (!fBufEmit(fbuf, &err)) {
        skAppPrintErr("Could not write final IPFIX message: %s",
                      err->message);
        g_clear_error(&err);
        fbExporterClose(fBufGetExporter(fbuf));
        return EXIT_FAILURE;
    }
    fbExporterClose(fBufGetExporter(fbuf));

    fBufFree(fbuf);
    fbuf = NULL;

    /* print record count */
    if (print_statistics) {
        fprintf(STATS_FH, ("%s: Wrote %" PRIu64 " IPFIX records to '%s'\n"),
                skAppName(), rec_count, ipfix_output.of_name);
    }

    return 0;
}



int main(int argc, char **argv)
{
    appSetup(argc, argv);                       /* never returns on error */

    /* Create the info model and add CERT elements */
    model = fbInfoModelAlloc();
    fbInfoModelAddElementArray(model, info_elements);

    /* Allocate a session.  The session will be owned by the fbuf, so
     * don't save it for later freeing. */
    session = fbSessionAlloc(model);

    /* Set an observation domain */
    fbSessionSetDomain(session, OBSERVATION_DOMAIN);

    if (single_template) {
        return toipfix_one_template();
    }
    return toipfix_multiple_templates();
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
