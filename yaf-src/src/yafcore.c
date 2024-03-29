/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcore.c
 *  YAF core I/O routines
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell, Chris Inacio, Emily Ecoff
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#define _YAF_SOURCE_
#include "yafctx.h"
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <airframe/airutil.h>
#include <yaf/yafrag.h>

#define INFOMODEL_EXCLUDE_yaf_dpi 1
#define INFOMODEL_EXCLUDE_yaf_dhcp 1
#include "infomodel.h"

#ifdef YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define FBSTMLINIT(s, i, t) fbSubTemplateMultiListEntryInit(s, i, t, 1)
#define FBSTMLNEXT(p, s) fbSubTemplateMultiListGetNextEntry(p, s)

/* fixbuf 2.x uses char* as the type of the name of info elements in
 * fbInfoElementSpec_t; wrap this around string literals to quiet compiler
 * warnings */
#define C(String) (char *)String


/**
 *  These are the template ID's for the templates that YAF uses to
 *  select the output. Template ID's are maintained for a set of
 *  basic flow types data
 *
 *  BASE which gets various additions added as the flow requires,
 *
 *  FULL base plus the internal fields are added
 *
 *  EXT (extended) which has the additional records in the
 *    yaf_extime_spec (extended time specification)
 *
 *  WARNING: these need to be adjusted according to changes in the general &
 *  special dimensions.  (Then why aren't those values used here instead of
 *  needing to keep two sets of values in sync?!)
 */
#define YAF_FLOW_BASE_TID   0xB000 /* no general or special definitions */
#define YAF_FLOW_FULL_TID   0xB800 /* base plus internal YTF_INTERNAL */
#define YAF_FLOW_EXT_TID    0xB7FF /* everything except internal */

#define YAF_PROCESS_STATS_TID     0xD003
#define YAF_TOMBSTONE_TID         0xD004
#define YAF_TOMBSTONE_ACCESS_TID  0xD005
#define YAF_TYPE_METADATA_TID     0xD006
#define YAF_TEMPLATE_METADATA_TID 0xD007


#define YAF_FLOW_BASE_NAME "yaf_flow_base"
#define YAF_FLOW_FULL_NAME C("yaf_flow_full")
#define YAF_FLOW_EXT_NAME  "yaf_flow_ext"

#define YAF_PROCESS_STATS_NAME      C("yaf_process_stats")
#define YAF_TOMBSTONE_NAME          C("tombstone_record")
#define YAF_TOMBSTONE_ACCESS_NAME   C("tombstone_access")

/* 49154 - 49160 */
#define YAF_APP_FLOW_TID       0xC001 /* not used */
#define YAF_ENTROPY_FLOW_TID   0xC002
#define YAF_TCP_FLOW_TID       0xC003
#define YAF_MAC_FLOW_TID       0xC004
#define YAF_STATS_FLOW_TID     0xC005
#define YAF_P0F_FLOW_TID       0xC006
#define YAF_FPEXPORT_FLOW_TID  0xC007
#define YAF_PAYLOAD_FLOW_TID   0xC008
#define YAF_MPTCP_FLOW_TID     0xC009

#define YAF_APP_FLOW_NAME           "UNUSED" /* not used */
#define YAF_ENTROPY_FLOW_NAME       "yaf_entropy"
#define YAF_ENTROPY_FLOW_REV_NAME   "yaf_entropy_rev"
#define YAF_TCP_FLOW_NAME           "yaf_tcp"
#define YAF_TCP_FLOW_REV_NAME       "yaf_tcp_rev"
#define YAF_MAC_FLOW_NAME           "yaf_mac"
#define YAF_STATS_FLOW_NAME         "yaf_flow_stats"
#define YAF_STATS_FLOW_REV_NAME     "yaf_flow_stats_rev"
#define YAF_P0F_FLOW_NAME           "yaf_p0f"
#define YAF_P0F_FLOW_REV_NAME       "yaf_p0f_rev"
#define YAF_FPEXPORT_FLOW_NAME      "yaf_fpexport"
#define YAF_FPEXPORT_FLOW_REV_NAME  "yaf_fpexport_rev"
#define YAF_PAYLOAD_FLOW_NAME       "yaf_payload"
#define YAF_PAYLOAD_FLOW_REV_NAME   "yaf_payload_rev"
#define YAF_MPTCP_FLOW_NAME         "yaf_mptcp"
#define YAF_MPTCP_FLOW_REV_NAME     "yaf_mptcp_rev"

/**
 *  The dimensions are flags which determine which sets of fields will
 *  be exported out to an IPFIX record.  They are entries in a bitmap
 *  used to control the template. e.g. TCP flow information (seq num,
 *  tcp flags, etc.) only get added to the output record when the
 *  YTF_SILK flag is set; it only gets set when the transport protocol
 *  is set to 0x06 and YAF is ran with --silk.
 *
 *  As of 2023.11.10, bits 16-31 may be used to select elements in the
 *  template but the presence/absence of those elements is not reflected in
 *  the template ID.
 */

/** General dimensions */
#define YTF_BIF         0x0010 /* Bi-flow */

/* Special dimensions */

/* Flags for total packet & octet counters vs delta counters */
#define YTF_TOTAL       0x0001
#define YTF_DELTA       0x0002

#define YTF_MPLS        0x0004
#define YTF_NDPI        0x0008
#define YTF_SILK        0x0020
#define YTF_DAGIF       0x0040

/* Flags for full (non-reduced) packet & octet counters vs reduced */
#define YTF_FLE         0x0080
#define YTF_RLE         0x0100

/* Flags for IPv4 addresses vs IPv6 */
#define YTF_IP4         0x0200
#define YTF_IP6         0x0400

#define YTF_INTERNAL    0x0800

/* VNI - Note uses bit 16 and its presence/absence is not reflected in the
 * template ID. */
#define YTF_VNI        0x10000

/* YTF_ALL is everything _except_ RLE enabled */
#define YTF_ALL        0x10EFF

/* YTF_REV is used when reading data from the STML */
#define YTF_REV         0xFF0F

#define YTF_BIF_NAME         "bif"
#define YTF_TOTAL_NAME       "total"
#define YTF_DELTA_NAME       "delta"
#define YTF_MPLS_NAME        "mpls"
#define YTF_SILK_NAME        "silk"
#define YTF_DAGIF_NAME       "dagif"
#define YTF_FLE_NAME         "fle"
#define YTF_RLE_NAME         "rle"
#define YTF_IP4_NAME         "ip4"
#define YTF_IP6_NAME         "ip6"
#define YTF_INTERNAL_NAME    "internal"
#define YTF_ALL_NAME         "all"
#define YTF_REV_NAME         "rev"
#define YTF_NDPI_NAME        "ndpi"

/** If any of the FLE/RLE values are larger than this constant
 *  then we have to use FLE, otherwise, we choose RLE to
 *  conserve space/bandwidth etc.*/
#define YAF_RLEMAX      (1L << 31)

#define YF_PRINT_DELIM  "|"

/** include the CERT IE extensions for YAF */
#define INFOMODEL_EXCLUDE_yaf_dpi 1
#define INFOMODEL_EXCLUDE_yaf_dhcp 1
#include "infomodel.h"

/* IPFIX definition of the full YAF flow record */
static fbInfoElementSpec_t yaf_flow_spec[] = {
    /* Millisecond start and end (epoch) (native time) */
    {C("flowStartMilliseconds"),            8, 0 },
    {C("flowEndMilliseconds"),              8, 0 },
    /* Counters */
    {C("octetTotalCount"),                  8, YTF_FLE | YTF_TOTAL },
    {C("reverseOctetTotalCount"),           8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    {C("packetTotalCount"),                 8, YTF_FLE | YTF_TOTAL },
    {C("reversePacketTotalCount"),          8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    /* delta Counters */
    {C("octetDeltaCount"),                  8, YTF_FLE | YTF_DELTA },
    {C("reverseOctetDeltaCount"),           8, YTF_FLE | YTF_DELTA | YTF_BIF },
    {C("packetDeltaCount"),                 8, YTF_FLE | YTF_DELTA },
    {C("reversePacketDeltaCount"),          8, YTF_FLE | YTF_DELTA | YTF_BIF },
    /* Reduced-length counters */
    {C("octetTotalCount"),                  4, YTF_RLE | YTF_TOTAL },
    {C("reverseOctetTotalCount"),           4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    {C("packetTotalCount"),                 4, YTF_RLE | YTF_TOTAL },
    {C("reversePacketTotalCount"),          4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    /* Reduced-length delta counters */
    {C("octetDeltaCount"),                  4, YTF_RLE | YTF_DELTA },
    {C("reverseOctetDeltaCount"),           4, YTF_RLE | YTF_DELTA | YTF_BIF },
    {C("packetDeltaCount"),                 4, YTF_RLE | YTF_DELTA },
    {C("reversePacketDeltaCount"),          4, YTF_RLE | YTF_DELTA | YTF_BIF },
    /* 5-tuple and flow status */
    {C("sourceIPv6Address"),                16, YTF_IP6 },
    {C("destinationIPv6Address"),           16, YTF_IP6 },
    {C("sourceIPv4Address"),                4, YTF_IP4 },
    {C("destinationIPv4Address"),           4, YTF_IP4 },
    {C("sourceTransportPort"),              2, 0 },
    {C("destinationTransportPort"),         2, 0 },
    {C("flowAttributes"),                   2, 0 },
    {C("reverseFlowAttributes"),            2, YTF_BIF },
    {C("protocolIdentifier"),               1, 0 },
    {C("flowEndReason"),                    1, 0 },
#if defined(YAF_ENABLE_APPLABEL)
    {C("silkAppLabel"),                     2, 0 },
#else
    {C("paddingOctets"),                    2, YTF_INTERNAL },
#endif
    /* Round-trip time */
    {C("reverseFlowDeltaMilliseconds"),     4, YTF_BIF }, /*  32-bit */
    /*TCP Info would need to go here 4 SiLK & 4b padding*/
    {C("tcpSequenceNumber"),                4, YTF_SILK },
    {C("reverseTcpSequenceNumber"),         4, YTF_SILK | YTF_BIF },
    {C("initialTCPFlags"),                  1, YTF_SILK },
    {C("unionTCPFlags"),                    1, YTF_SILK },
    {C("reverseInitialTCPFlags"),           1, YTF_SILK | YTF_BIF },
    {C("reverseUnionTCPFlags"),             1, YTF_SILK | YTF_BIF },
    {C("vlanId"),                           2, 0 },
    {C("reverseVlanId"),                    2, YTF_BIF },
    {C("ingressInterface"),                 4, YTF_DAGIF },
    {C("egressInterface"),                  4, YTF_DAGIF },

    /* VNI */
    {C("yafLayer2SegmentId"),               4, YTF_VNI },
    {C("paddingOctets"),                    4, YTF_VNI | YTF_INTERNAL },

    {C("ipClassOfService"),                 1, 0 },
    {C("reverseIpClassOfService"),          1, YTF_BIF },
    {C("mplsTopLabelStackSection"),         3, YTF_MPLS },
    {C("mplsLabelStackSection2"),           3, YTF_MPLS },
    {C("mplsLabelStackSection3"),           3, YTF_MPLS },
#if defined(YAF_ENABLE_NDPI)
    {C("paddingOctets"),                    1, YTF_INTERNAL },
    {C("nDPIL7Protocol"),                   2, 0 },
    {C("nDPIL7SubProtocol"),                2, 0 },
#else
    {C("paddingOctets"),                    5, YTF_INTERNAL },
#endif /* if defined(YAF_ENABLE_NDPI) */
    {C("subTemplateMultiList"),             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};


#if defined(YAF_ENABLE_ENTROPY)
/* entropy fields */
static fbInfoElementSpec_t yaf_entropy_spec[] = {
    {C("payloadEntropy"),                   1, 0 },
    {C("reversePayloadEntropy"),            1, YTF_BIF },
    FB_IESPEC_NULL
};
#endif /* if defined(YAF_ENABLE_ENTROPY) */

static fbInfoElementSpec_t yaf_tcp_spec[] = {
    /* TCP-specific information */
    {C("tcpSequenceNumber"),                4, 0 },
    {C("initialTCPFlags"),                  1, 0 },
    {C("unionTCPFlags"),                    1, 0 },
    {C("reverseInitialTCPFlags"),           1, YTF_BIF },
    {C("reverseUnionTCPFlags"),             1, YTF_BIF },
    {C("reverseTcpSequenceNumber"),         4, YTF_BIF },
    FB_IESPEC_NULL
};

/* MAC-specific information */
static fbInfoElementSpec_t yaf_mac_spec[] = {
    {C("sourceMacAddress"),                 6, 0 },
    {C("destinationMacAddress"),            6, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_mptcp_spec[] = {
    {C("mptcpInitialDataSequenceNumber"),   8, 0 },
    {C("mptcpReceiverToken"),               4, 0 },
    {C("mptcpMaximumSegmentSize"),          2, 0 },
    {C("mptcpAddressID"),                   1, 0 },
    {C("mptcpFlags"),                       1, 0 },
    FB_IESPEC_NULL
};


#if YAF_ENABLE_P0F
static fbInfoElementSpec_t yaf_p0f_spec[] = {
    {C("osName"),                           FB_IE_VARLEN, 0 },
    {C("osVersion"),                        FB_IE_VARLEN, 0 },
    {C("osFingerPrint"),                    FB_IE_VARLEN, 0 },
    {C("reverseOsName"),                    FB_IE_VARLEN, YTF_BIF },
    {C("reverseOsVersion"),                 FB_IE_VARLEN, YTF_BIF },
    {C("reverseOsFingerPrint"),             FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
static fbInfoElementSpec_t yaf_fpexport_spec[] = {
    {C("firstPacketBanner"),                FB_IE_VARLEN, 0 },
    {C("secondPacketBanner"),               FB_IE_VARLEN, 0 },
    {C("reverseFirstPacketBanner"),         FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
/* Variable-length payload fields */
static fbInfoElementSpec_t yaf_payload_spec[] = {
    {C("payload"),                          FB_IE_VARLEN, 0 },
    {C("reversePayload"),                   FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};
#endif /* if YAF_ENABLE_PAYLOAD */

/* IPFIX definition of the YAF flow record time extension */
static fbInfoElementSpec_t yaf_extime_spec[] = {
    /* Microsecond start and end (RFC1305-style) (extended time) */
    {C("flowStartMicroseconds"),            8, 0 },
    {C("flowEndMicroseconds"),              8, 0 },
    /* Second start, end, and duration (extended time) */
    {C("flowStartSeconds"),                 4, 0 },
    {C("flowEndSeconds"),                   4, 0 },
    /* Flow durations (extended time) */
    {C("flowDurationMicroseconds"),         4, 0 },
    {C("flowDurationMilliseconds"),         4, 0 },
    /* Microsecond delta start and end (extended time) */
    {C("flowStartDeltaMicroseconds"),       4, 0 },
    {C("flowEndDeltaMicroseconds"),         4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_process_stats_spec[] = {
    {C("observationDomainId"),              4, 0 },
    {C("exportingProcessId"),               4, 0 },
    {C("exporterIPv4Address"),              4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    {C("systemInitTimeMilliseconds"),       8, 0 },
    {C("exportedFlowRecordTotalCount"),     8, 0 },
    {C("packetTotalCount"),                 8, 0 },
    {C("droppedPacketTotalCount"),          8, 0 },
    {C("ignoredPacketTotalCount"),          8, 0 },
    {C("notSentPacketTotalCount"),          8, 0 },
    {C("expiredFragmentCount"),             4, 0 },
    {C("assembledFragmentCount"),           4, 0 },
    {C("flowTableFlushEventCount"),         4, 0 },
    {C("flowTablePeakCount"),               4, 0 },
    {C("meanFlowRate"),                     4, 0 },
    {C("meanPacketRate"),                   4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_tombstone_spec[] = {
    {C("observationDomainId"),              4, 0 },
    {C("exportingProcessId"),               4, 0 },
    {C("exporterConfiguredId"),             2, 0 },
    {C("paddingOctets"),                    6, 0 },
    {C("tombstoneId"),                      4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    {C("tombstoneAccessList"),              FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_tombstone_access_spec[] = {
    {C("certToolId"),                       4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_flow_stats_spec[] = {
    {C("dataByteCount"),                            8, 0 },
    {C("averageInterarrivalTime"),                  8, 0 },
    {C("standardDeviationInterarrivalTime"),        8, 0 },
    {C("tcpUrgTotalCount"),                         4, 0 },
    {C("smallPacketCount"),                         4, 0 },
    {C("nonEmptyPacketCount"),                      4, 0 },
    {C("largePacketCount"),                         4, 0 },
    {C("firstNonEmptyPacketSize"),                  2, 0 },
    {C("maxPacketSize"),                            2, 0 },
    {C("standardDeviationPayloadLength"),           2, 0 },
    {C("firstEightNonEmptyPacketDirections"),        1, 0 },
    {C("paddingOctets"),                            1, 1 },
    {C("reverseDataByteCount"),                     8, YTF_BIF },
    {C("reverseAverageInterarrivalTime"),           8, YTF_BIF },
    {C("reverseStandardDeviationInterarrivalTime"), 8, YTF_BIF },
    {C("reverseTcpUrgTotalCount"),                  4, YTF_BIF },
    {C("reverseSmallPacketCount"),                  4, YTF_BIF },
    {C("reverseNonEmptyPacketCount"),               4, YTF_BIF },
    {C("reverseLargePacketCount"),                  4, YTF_BIF },
    {C("reverseFirstNonEmptyPacketSize"),           2, YTF_BIF },
    {C("reverseMaxPacketSize"),                     2, YTF_BIF },
    {C("reverseStandardDeviationPayloadLength"),    2, YTF_BIF },
    {C("paddingOctets"),                            2, 1 },
    FB_IESPEC_NULL
};


typedef struct yfFlowStatsRecord_st {
    uint64_t   dataByteCount;
    uint64_t   averageInterarrivalTime;
    uint64_t   standardDeviationInterarrivalTime;
    uint32_t   tcpUrgTotalCount;
    uint32_t   smallPacketCount;
    uint32_t   nonEmptyPacketCount;
    uint32_t   largePacketCount;
    uint16_t   firstNonEmptyPacketSize;
    uint16_t   maxPacketSize;
    uint16_t   standardDeviationPayloadLength;
    uint8_t    firstEightNonEmptyPacketDirections;
    uint8_t    padding[1];
    /* reverse Fields */
    uint64_t   reverseDataByteCount;
    uint64_t   reverseAverageInterarrivalTime;
    uint64_t   reverseStandardDeviationInterarrivalTime;
    uint32_t   reverseTcpUrgTotalCount;
    uint32_t   reverseSmallPacketCount;
    uint32_t   reverseNonEmptyPacketCount;
    uint32_t   reverseLargePacketCount;
    uint16_t   reverseFirstNonEmptyPacketSize;
    uint16_t   reverseMaxPacketSize;
    uint16_t   reverseStandardDeviationPayloadLength;
    uint8_t    padding2[2];
} yfFlowStatsRecord_t;

typedef struct yfTemplates_st {
    fbTemplate_t  *ipfixStatsTemplate;
    fbTemplate_t  *tombstoneRecordTemplate;
    fbTemplate_t  *tombstoneAccessTemplate;
    fbTemplate_t  *fstatsTemplate;
    fbTemplate_t  *revfstatsTemplate;
#if YAF_ENABLE_ENTROPY
    fbTemplate_t  *entropyTemplate;
    fbTemplate_t  *revEntropyTemplate;
#endif
    fbTemplate_t  *tcpTemplate;
    fbTemplate_t  *revTcpTemplate;
    fbTemplate_t  *macTemplate;
    fbTemplate_t  *mptcpTemplate;
#if YAF_ENABLE_P0F
    fbTemplate_t  *p0fTemplate;
    fbTemplate_t  *revP0fTemplate;
#endif
#if YAF_ENABLE_FPEXPORT
    fbTemplate_t  *fpexportTemplate;
    fbTemplate_t  *revFpexportTemplate;
#endif
#if YAF_ENABLE_PAYLOAD
    fbTemplate_t  *payloadTemplate;
    fbTemplate_t  *revPayloadTemplate;
#endif
} yfTemplates_t;

static yfTemplates_t yaf_tmpl;

/* IPv6-mapped IPv4 address prefix */
static uint8_t       yaf_ip6map_pfx[12] =
{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };

/* Full YAF flow record. */
typedef struct yfIpfixFlow_st {
    uint64_t                   flowStartMilliseconds;
    uint64_t                   flowEndMilliseconds;
    uint64_t                   octetTotalCount;
    uint64_t                   reverseOctetTotalCount;
    uint64_t                   packetTotalCount;
    uint64_t                   reversePacketTotalCount;
    uint64_t                   octetDeltaCount;
    uint64_t                   reverseOctetDeltaCount;
    uint64_t                   packetDeltaCount;
    uint64_t                   reversePacketDeltaCount;
    uint8_t                    sourceIPv6Address[16];
    uint8_t                    destinationIPv6Address[16];
    uint32_t                   sourceIPv4Address;
    uint32_t                   destinationIPv4Address;
    uint16_t                   sourceTransportPort;
    uint16_t                   destinationTransportPort;
    uint16_t                   flowAttributes;
    uint16_t                   reverseFlowAttributes;
    uint8_t                    protocolIdentifier;
    uint8_t                    flowEndReason;
#if YAF_ENABLE_APPLABEL
    uint16_t                   silkAppLabel;
#else
    uint8_t                    paddingOctets[2];
#endif
    int32_t                    reverseFlowDeltaMilliseconds;
    /* TCP stuff for SiLK */
    uint32_t                   tcpSequenceNumber;
    uint32_t                   reverseTcpSequenceNumber;
    uint8_t                    initialTCPFlags;
    uint8_t                    unionTCPFlags;
    uint8_t                    reverseInitialTCPFlags;
    uint8_t                    reverseUnionTCPFlags;

    /* MAC Specific Info */
    uint16_t                   vlanId;
    uint16_t                   reverseVlanId;
    uint32_t                   ingressInterface;
    uint32_t                   egressInterface;

    /* VNI */
    uint32_t                   yafLayer2SegmentId;
    uint8_t                    paddingOctets4[4];

    /* MPLS! */
    uint8_t                    ipClassOfService;
    uint8_t                    reverseIpClassOfService;
    uint8_t                    mpls_label1[3];
    uint8_t                    mpls_label2[3];
    uint8_t                    mpls_label3[3];
#if YAF_ENABLE_NDPI
    uint8_t                    paddingOctets2[1];
    uint16_t                   ndpi_master;
    uint16_t                   ndpi_sub;
#else
    uint8_t                    paddingOctets3[5];
#endif /* if YAF_ENABLE_NDPI */
    fbSubTemplateMultiList_t   subTemplateMultiList;
} yfIpfixFlow_t;


#if YAF_ENABLE_ENTROPY
typedef struct yfEntropyFlow_st {
    uint8_t   entropy;
    uint8_t   reverseEntropy;
} yfEntropyFlow_t;
#endif /* if YAF_ENABLE_ENTROPY */

typedef struct yfTcpFlow_st {
    uint32_t   tcpSequenceNumber;
    uint8_t    initialTCPFlags;
    uint8_t    unionTCPFlags;
    uint8_t    reverseInitialTCPFlags;
    uint8_t    reverseUnionTCPFlags;
    uint32_t   reverseTcpSequenceNumber;
} yfTcpFlow_t;

typedef struct yfMacFlow_st {
    uint8_t   sourceMacAddress[6];
    uint8_t   destinationMacAddress[6];
} yfMacFlow_t;

#if YAF_ENABLE_P0F
typedef struct yfP0fFlow_st {
    fbVarfield_t   osName;
    fbVarfield_t   osVersion;
    fbVarfield_t   osFingerPrint;
    fbVarfield_t   reverseOsName;
    fbVarfield_t   reverseOsVersion;
    fbVarfield_t   reverseOsFingerPrint;
} yfP0fFlow_t;
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
typedef struct yfFPExportFlow_st {
    fbVarfield_t   firstPacketBanner;
    fbVarfield_t   secondPacketBanner;
    fbVarfield_t   reverseFirstPacketBanner;
} yfFPExportFlow_t;
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
typedef struct yfPayloadFlow_st {
    fbVarfield_t   payload;
    fbVarfield_t   reversePayload;
} yfPayloadFlow_t;
#endif /* if YAF_ENABLE_PAYLOAD */

typedef struct yfIpfixExtFlow_st {
    yfIpfixFlow_t   f;
    uint64_t        flowStartMicroseconds;
    uint64_t        flowEndMicroseconds;
    uint32_t        flowStartSeconds;
    uint32_t        flowEndSeconds;
    uint32_t        flowDurationMicroseconds;
    uint32_t        flowDurationMilliseconds;
    uint32_t        flowStartDeltaMicroseconds;
    uint32_t        flowEndDeltaMicroseconds;
} yfIpfixExtFlow_t;

typedef struct yfIpfixStats_st {
    uint32_t   observationDomainId;
    uint32_t   exportingProcessId;
    uint32_t   exporterIPv4Address;
    uint32_t   observationTimeSeconds;
    uint64_t   systemInitTimeMilliseconds;
    uint64_t   exportedFlowTotalCount;
    uint64_t   packetTotalCount;
    uint64_t   droppedPacketTotalCount;
    uint64_t   ignoredPacketTotalCount;
    uint64_t   notSentPacketTotalCount;
    uint32_t   expiredFragmentCount;
    uint32_t   assembledFragmentCount;
    uint32_t   flowTableFlushEvents;
    uint32_t   flowTablePeakCount;
    uint32_t   meanFlowRate;
    uint32_t   meanPacketRate;
} yfIpfixStats_t;

typedef struct yfTombstoneRecord_st {
    uint32_t              observationDomainId;
    uint32_t              exportingProcessId;
    uint16_t              exporterConfiguredId;
    uint8_t               paddingOctets[6];
    uint32_t              tombstoneId;
    uint32_t              observationTimeSeconds;
    fbSubTemplateList_t   accessList;
} yfTombstoneRecord_t;

typedef struct yfTombstoneAccess_st {
    uint32_t   certToolId;
    uint32_t   observationTimeSeconds;
} yfTombstoneAccess_t;

/* Core library configuration variables */
/* amount of payload to export; 0 to export none */
static unsigned int yaf_core_export_payload = 0;
/* whether to map IPv4 addresses to IPv6 */
static gboolean     yaf_core_map_ipv6 = FALSE;
#if YAF_ENABLE_APPLABEL
/* limit export to these applabels; if NULL, export all */
static uint16_t *yaf_core_payload_applabels = NULL;
/* number of appLabels in `yaf_core_payload_applabels` */
static size_t yaf_core_payload_applabels_size = 0;
#endif  /* YAF_ENABLE_APPLABEL */

/**
 * yfAlignmentCheck
 *
 * this checks the alignment of the template and corresponding record
 * ideally, all this magic would happen at compile time, but it
 * doesn't currently, (can't really do it in C,) so we do it at
 * run time
 *
 *
 * @param err a Glib error structure pointer initialized with an
 *        empty error on input, if an alignment error is detected
 *        then a new error will be put into the pointer.
 *
 */
void
yfAlignmentCheck(
    void)
{
    size_t prevOffset = 0;
    size_t prevSize = 0;

#define DO_SIZE(S_, F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)
#define EA_STRING(S_, F_)                            \
    "alignment error in struct " #S_ " for element " \
    #F_ " offset %#"SIZE_T_FORMATX " size %"         \
    SIZE_T_FORMAT " (pad %"SIZE_T_FORMAT ")",        \
    (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),  \
    (SIZE_T_CAST)(offsetof(S_, F_) % DO_SIZE(S_, F_))
#define EG_STRING(S_, F_)                              \
    "gap error in struct " #S_ " for element " #F_     \
    " offset %#"SIZE_T_FORMATX " size %"SIZE_T_FORMAT, \
    (SIZE_T_CAST)offsetof(S_, F_),                     \
    DO_SIZE(S_, F_)
#define RUN_CHECKS(S_, F_, A_)                                   \
    {                                                            \
        if (((offsetof(S_, F_) % DO_SIZE(S_, F_)) != 0) && A_) { \
            g_error(EA_STRING(S_, F_));                          \
        }                                                        \
        if (offsetof(S_, F_) != (prevOffset + prevSize)) {       \
            g_error(EG_STRING(S_, F_));                          \
            return;                                              \
        }                                                        \
        prevOffset = offsetof(S_, F_);                           \
        prevSize = DO_SIZE(S_, F_);                              \
        if (0) {                                                 \
            fprintf(                                             \
                stderr,                                          \
                "%19s %40s %#6lx %3" PRId64 " %#6" PRIx64 "\n",  \
                #S_, #F_,                                        \
                offsetof(S_, F_), DO_SIZE(S_, F_),               \
                offsetof(S_, F_) + DO_SIZE(S_, F_));             \
        }                                                        \
    }

    RUN_CHECKS(yfIpfixFlow_t, flowStartMilliseconds, 1);
    RUN_CHECKS(yfIpfixFlow_t, flowEndMilliseconds, 1);
    RUN_CHECKS(yfIpfixFlow_t, octetTotalCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseOctetTotalCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, packetTotalCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, reversePacketTotalCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, octetDeltaCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseOctetDeltaCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, packetDeltaCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, reversePacketDeltaCount, 1);
    RUN_CHECKS(yfIpfixFlow_t, sourceIPv6Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, destinationIPv6Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, sourceIPv4Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, destinationIPv4Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, sourceTransportPort, 1);
    RUN_CHECKS(yfIpfixFlow_t, destinationTransportPort, 1);
    RUN_CHECKS(yfIpfixFlow_t, flowAttributes, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseFlowAttributes, 1);
    RUN_CHECKS(yfIpfixFlow_t, protocolIdentifier, 1);
    RUN_CHECKS(yfIpfixFlow_t, flowEndReason, 1);
#if YAF_ENABLE_APPLABEL
    RUN_CHECKS(yfIpfixFlow_t, silkAppLabel, 1);
#else
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets, 0);
#endif
    RUN_CHECKS(yfIpfixFlow_t, reverseFlowDeltaMilliseconds, 1);

    /* TCP stuff for SiLK only! */
    RUN_CHECKS(yfIpfixFlow_t, tcpSequenceNumber, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseTcpSequenceNumber, 1);
    RUN_CHECKS(yfIpfixFlow_t, initialTCPFlags, 1);
    RUN_CHECKS(yfIpfixFlow_t, unionTCPFlags, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseInitialTCPFlags, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseUnionTCPFlags, 1);

    RUN_CHECKS(yfIpfixFlow_t, vlanId, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseVlanId, 1);
    RUN_CHECKS(yfIpfixFlow_t, ingressInterface, 1);
    RUN_CHECKS(yfIpfixFlow_t, egressInterface, 1);

    /* VNI */
    RUN_CHECKS(yfIpfixFlow_t, yafLayer2SegmentId, 1);
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets4, 0);

    RUN_CHECKS(yfIpfixFlow_t, ipClassOfService, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseIpClassOfService, 1);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label1, 0);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label2, 0);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label3, 0);
#if YAF_ENABLE_NDPI
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets2, 0);
    RUN_CHECKS(yfIpfixFlow_t, ndpi_master, 1);
    RUN_CHECKS(yfIpfixFlow_t, ndpi_sub, 1);
#else
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets3, 0);
#endif /* if YAF_ENABLE_NDPI */
    RUN_CHECKS(yfIpfixFlow_t, subTemplateMultiList, 0);
    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfIpfixExtFlow_t, f, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartMicroseconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndMicroseconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartSeconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndSeconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMicroseconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMilliseconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartDeltaMicroseconds, 1);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndDeltaMicroseconds, 1);
    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfIpfixStats_t, observationDomainId, 1);
    RUN_CHECKS(yfIpfixStats_t, exportingProcessId, 1);
    RUN_CHECKS(yfIpfixStats_t, exporterIPv4Address, 1);
    RUN_CHECKS(yfIpfixStats_t, observationTimeSeconds, 1);
    RUN_CHECKS(yfIpfixStats_t, systemInitTimeMilliseconds, 1);
    RUN_CHECKS(yfIpfixStats_t, exportedFlowTotalCount, 1);
    RUN_CHECKS(yfIpfixStats_t, packetTotalCount, 1);
    RUN_CHECKS(yfIpfixStats_t, droppedPacketTotalCount, 1);
    RUN_CHECKS(yfIpfixStats_t, ignoredPacketTotalCount, 1);
    RUN_CHECKS(yfIpfixStats_t, notSentPacketTotalCount, 1);
    RUN_CHECKS(yfIpfixStats_t, expiredFragmentCount, 1);
    RUN_CHECKS(yfIpfixStats_t, assembledFragmentCount, 1);
    RUN_CHECKS(yfIpfixStats_t, flowTableFlushEvents, 1);
    RUN_CHECKS(yfIpfixStats_t, flowTablePeakCount, 1);
    RUN_CHECKS(yfIpfixStats_t, meanFlowRate, 1);
    RUN_CHECKS(yfIpfixStats_t, meanPacketRate, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfTombstoneRecord_t, observationDomainId, 1);
    RUN_CHECKS(yfTombstoneRecord_t, exportingProcessId, 1);
    RUN_CHECKS(yfTombstoneRecord_t, exporterConfiguredId, 1);
    RUN_CHECKS(yfTombstoneRecord_t, paddingOctets, 0);
    RUN_CHECKS(yfTombstoneRecord_t, tombstoneId, 1);
    RUN_CHECKS(yfTombstoneRecord_t, observationTimeSeconds, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfTombstoneAccess_t, certToolId, 1);
    RUN_CHECKS(yfTombstoneAccess_t, observationTimeSeconds, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfFlowStatsRecord_t, dataByteCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, averageInterarrivalTime, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, standardDeviationInterarrivalTime, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, tcpUrgTotalCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, smallPacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, nonEmptyPacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, largePacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, firstNonEmptyPacketSize, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, maxPacketSize, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, standardDeviationPayloadLength, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, firstEightNonEmptyPacketDirections, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, padding, 0);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseDataByteCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseAverageInterarrivalTime, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseStandardDeviationInterarrivalTime,
               1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseTcpUrgTotalCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseSmallPacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseNonEmptyPacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseLargePacketCount, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseFirstNonEmptyPacketSize, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseMaxPacketSize, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, reverseStandardDeviationPayloadLength, 1);
    RUN_CHECKS(yfFlowStatsRecord_t, padding2, 0);

#undef DO_SIZE
#undef EA_STRING
#undef EG_STRING
#undef RUN_CHECKS
}


void
yfWriterExportPayload(
    int   max_payload)
{
    yaf_core_export_payload = max_payload;
}

#if YAF_ENABLE_APPLABEL
void
yfWriterExportPayloadApplabels(
    const GArray  *applabels)
{
    guint i;

#if GLIB_CHECK_VERSION(2, 22, 0)
    g_assert(sizeof(long) == g_array_get_element_size((GArray *)applabels));
#endif
    if (0 == applabels->len) {
        return;
    }

    yaf_core_payload_applabels_size = applabels->len;
    yaf_core_payload_applabels = g_new(uint16_t, applabels->len);
    for (i = 0; i < applabels->len; ++i) {
        g_assert(g_array_index(applabels, long, i) >= 0);
        g_assert(g_array_index(applabels, long, i) <= UINT16_MAX);
        yaf_core_payload_applabels[i] =
            (uint16_t)g_array_index(applabels, long, i);
    }
}

static gboolean
findInApplabelArray(
    uint16_t    applabel)
{
    size_t i;
    for (i = 0; i < yaf_core_payload_applabels_size; ++i) {
        if (yaf_core_payload_applabels[i] == applabel) {
            return TRUE;
        }
    }
    return FALSE;
}
#endif  /* YAF_ENABLE_APPLABEL */

void
yfWriterExportMappedV6(
    gboolean   map_mode)
{
    yaf_core_map_ipv6 = map_mode;
}


/**
 * yfFlowPrepare
 *
 * initialize the state of a flow to be "clean" so that they
 * can be reused
 *
 */
void
yfFlowPrepare(
    yfFlow_t  *flow)
{
#if YAF_ENABLE_HOOKS
    unsigned int loop;
#endif

#if YAF_ENABLE_PAYLOAD
    flow->val.paylen = 0;
    flow->val.payload = NULL;
    flow->rval.paylen = 0;
    flow->rval.payload = NULL;
#endif /* if YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
    for (loop = 0; loop < YAF_MAX_HOOKS; loop++) {
        flow->hfctx[loop] = 0x0;
    }
#endif

    memset(flow->sourceMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
    memset(flow->destinationMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
}


/**
 * yfFlowCleanup
 *
 * cleans up after a flow is no longer needed by deallocating
 * the dynamic memory allocated to the flow (think payload)
 *
 */
void
yfFlowCleanup(
    yfFlow_t  *flow)
{
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
    }

    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPayloadCopyIn
 *
 *
 *
 *
 */
static void
yfPayloadCopyIn(
    fbVarfield_t  *payvar,
    yfFlowVal_t   *val)
{
#if YAF_ENABLE_PAYLOAD
    if (payvar->len) {
        if (!val->payload) {
            val->payload = g_malloc0(payvar->len);
        } else {
            val->payload = g_realloc(val->payload, payvar->len);
        }
        val->paylen = payvar->len;
        memcpy(val->payload, payvar->buf, payvar->len);
    } else {
        if (val->payload) {g_free(val->payload);}
        val->payload = NULL;
        val->paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfInfoModel
 *
 *
 */
static fbInfoModel_t *
yfInfoModel(
    void)
{
    static fbInfoModel_t *yaf_model = NULL;
#if YAF_ENABLE_HOOKS
    fbInfoElement_t      *yaf_hook_elements = NULL;
#endif
    if (!yaf_model) {
        yaf_model = fbInfoModelAlloc();

        infomodelAddGlobalElements(yaf_model);

#if YAF_ENABLE_HOOKS
        yaf_hook_elements = yfHookGetInfoModel();
        if (yaf_hook_elements) {
            fbInfoModelAddElementArray(yaf_model, yaf_hook_elements);
        }
#endif /* if YAF_ENABLE_HOOKS */
    }

    return yaf_model;
}


/**
 * yfAddTemplate
 *
 *    Creates a new templates.
 *
 *    Allocates a new template.  If `reverse` is true, adds all elements from
 *    `spec` to the template and adds the `YAF_BIF` bit to `tid`; otherwise
 *    only adds the elements from `spec` whose flag value is 0.  Sets the
 *    scope of the template to `scope` if non-zero.  Adds the template as an
 *    export template to `session` with tid `tid` (or `tid | YAF_BIF`),
 *    setting the name and description is metadata if enabled.  Returns the
 *    new template.  Sets `err` and returns NULL on error.
 */
static fbTemplate_t *
yfAddTemplate(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    uint16_t              tid,
    uint16_t              scope,
    const gchar          *name,
    const gchar          *description,
    gboolean              reverse,
    GError              **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = fbTemplateAlloc(model);
    uint32_t       flags = 0;
    uint16_t       rtid = tid;

    if (reverse) {
        flags = 0xffffffff;
        rtid = tid | YTF_BIF;
    }

    /* g_debug("yaf: %x (%s), %d (%x)", tid, name, reverse, */
    /*         tid | (reverse ? YTF_BIF : 0)); */

    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    if (scope) {
        fbTemplateSetOptionsScope(tmpl, scope);
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, rtid,
                                          tmpl, name, description, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    (void)name;
    (void)description;
    if (!fbSessionAddTemplate(session, FALSE, rtid, tmpl, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    return tmpl;
}


/**
 * yfInitExporterSession
 *
 *
 */
static fbSession_t *
yfInitExporterSession(
    uint32_t   domain,
    gboolean   export_meta,
    GError   **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = NULL;
    fbSession_t   *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* Create the full record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }

    if (export_meta) {
#if YAF_ENABLE_METADATA_EXPORT
        if (!fbSessionSetMetadataExportElements(
                session, TRUE, YAF_TYPE_METADATA_TID, err))
        {
            return NULL;
        }

        if (!fbSessionSetMetadataExportTemplates(
                session, TRUE, YAF_TEMPLATE_METADATA_TID, err))
        {
            return NULL;
        }
#endif /* if YAF_ENABLE_METADATA_EXPORT */
    }

    /* Add the full record template to the internal session only */
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

    /* Create the Process Stats Options Template. Scope fields are
     * exporterIPv4Address, observationDomainId, and exportingProcessID */
    yaf_tmpl.ipfixStatsTemplate = yfAddTemplate(session,
                                                yaf_process_stats_spec,
                                                YAF_PROCESS_STATS_TID, 3,
                                                YAF_PROCESS_STATS_NAME,
                                                NULL, FALSE, err);
    if (!yaf_tmpl.ipfixStatsTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_PROCESS_STATS_TID,
                              yaf_tmpl.ipfixStatsTemplate, err))
    {
        return NULL;
    }

    /* Create the Tombstone record Template. Scope fields are
     * exportingProcessID, observationDomainId, and exporterConfiguredId */
    yaf_tmpl.tombstoneRecordTemplate = yfAddTemplate(session,
                                                     yaf_tombstone_spec,
                                                     YAF_TOMBSTONE_TID, 3,
                                                     YAF_TOMBSTONE_NAME,
                                                     NULL, FALSE, err);
    if (!yaf_tmpl.tombstoneRecordTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_TID,
                              yaf_tmpl.tombstoneRecordTemplate, err))
    {
        return NULL;
    }

    /* Create the Tombstone Access SubTemplate */
    yaf_tmpl.tombstoneAccessTemplate = yfAddTemplate(session,
                                                     yaf_tombstone_access_spec,
                                                     YAF_TOMBSTONE_ACCESS_TID,
                                                     0,
                                                     YAF_TOMBSTONE_ACCESS_NAME,
                                                     NULL, FALSE, err);
    if (!yaf_tmpl.tombstoneAccessTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_ACCESS_TID,
                              yaf_tmpl.tombstoneAccessTemplate, err))
    {
        return NULL;
    }

    /* Flow Stats Template */
    yaf_tmpl.fstatsTemplate = yfAddTemplate(session, yaf_flow_stats_spec,
                                            YAF_STATS_FLOW_TID, 0,
                                            YAF_STATS_FLOW_NAME,
                                            NULL, FALSE, err);
    if (!yaf_tmpl.fstatsTemplate) {
        return NULL;
    }

    yaf_tmpl.revfstatsTemplate = yfAddTemplate(session, yaf_flow_stats_spec,
                                               YAF_STATS_FLOW_TID, 0,
                                               YAF_STATS_FLOW_REV_NAME,
                                               NULL, TRUE, err);
    if (!yaf_tmpl.revfstatsTemplate) {
        return NULL;
    }

#if YAF_ENABLE_ENTROPY
    yaf_tmpl.entropyTemplate = yfAddTemplate(session, yaf_entropy_spec,
                                             YAF_ENTROPY_FLOW_TID, 0,
                                             YAF_ENTROPY_FLOW_NAME,
                                             NULL, FALSE, err);

    if (!yaf_tmpl.entropyTemplate) {
        return NULL;
    }

    yaf_tmpl.revEntropyTemplate = yfAddTemplate(session, yaf_entropy_spec,
                                                YAF_ENTROPY_FLOW_TID, 0,
                                                YAF_ENTROPY_FLOW_REV_NAME,
                                                NULL, TRUE, err);
    if (!yaf_tmpl.revEntropyTemplate) {
        return NULL;
    }

#endif /* if YAF_ENABLE_ENTROPY */

    yaf_tmpl.tcpTemplate = yfAddTemplate(session, yaf_tcp_spec,
                                         YAF_TCP_FLOW_TID, 0,
                                         YAF_TCP_FLOW_NAME,
                                         NULL, FALSE, err);

    if (!yaf_tmpl.tcpTemplate) {
        return NULL;
    }

    yaf_tmpl.revTcpTemplate = yfAddTemplate(session, yaf_tcp_spec,
                                            YAF_TCP_FLOW_TID, 0,
                                            YAF_TCP_FLOW_REV_NAME,
                                            NULL, TRUE, err);

    if (!yaf_tmpl.revTcpTemplate) {
        return NULL;
    }

    yaf_tmpl.macTemplate = yfAddTemplate(session, yaf_mac_spec,
                                         YAF_MAC_FLOW_TID, 0,
                                         YAF_MAC_FLOW_NAME,
                                         NULL, FALSE, err);

    if (!yaf_tmpl.macTemplate) {
        return NULL;
    }

    yaf_tmpl.mptcpTemplate = yfAddTemplate(session, yaf_mptcp_spec,
                                           YAF_MPTCP_FLOW_TID, 0,
                                           YAF_MPTCP_FLOW_NAME,
                                           NULL, FALSE, err);
    if (!yaf_tmpl.mptcpTemplate) {
        return NULL;
    }

#if YAF_ENABLE_P0F
    yaf_tmpl.p0fTemplate = yfAddTemplate(session, yaf_p0f_spec,
                                         YAF_P0F_FLOW_TID, 0,
                                         YAF_P0F_FLOW_NAME,
                                         NULL, FALSE, err);

    if (!yaf_tmpl.p0fTemplate) {
        return NULL;
    }

    yaf_tmpl.revP0fTemplate = yfAddTemplate(session, yaf_p0f_spec,
                                            YAF_P0F_FLOW_TID, 0,
                                            YAF_P0F_FLOW_REV_NAME,
                                            NULL, TRUE, err);

    if (!yaf_tmpl.revP0fTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    yaf_tmpl.fpexportTemplate = yfAddTemplate(session, yaf_fpexport_spec,
                                              YAF_FPEXPORT_FLOW_TID, 0,
                                              YAF_FPEXPORT_FLOW_NAME,
                                              NULL, FALSE, err);

    if (!yaf_tmpl.fpexportTemplate) {
        return NULL;
    }

    yaf_tmpl.revFpexportTemplate = yfAddTemplate(session, yaf_fpexport_spec,
                                                 YAF_FPEXPORT_FLOW_TID, 0,
                                                 YAF_FPEXPORT_FLOW_REV_NAME,
                                                 NULL, TRUE, err);
    if (!yaf_tmpl.revFpexportTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
    yaf_tmpl.payloadTemplate = yfAddTemplate(session, yaf_payload_spec,
                                             YAF_PAYLOAD_FLOW_TID, 0,
                                             YAF_PAYLOAD_FLOW_NAME,
                                             NULL, FALSE, err);

    if (!yaf_tmpl.payloadTemplate) {
        return NULL;
    }

    yaf_tmpl.revPayloadTemplate = yfAddTemplate(session, yaf_payload_spec,
                                                YAF_PAYLOAD_FLOW_TID, 0,
                                                YAF_PAYLOAD_FLOW_REV_NAME,
                                                NULL, TRUE, err);

    if (!yaf_tmpl.revPayloadTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_HOOKS
    /*  Add the hook template fields if available  */

    if (!yfHookGetTemplate(session)) {
        g_debug("Hook Templates could not be added to the session");
    }

#endif /* if YAF_ENABLE_HOOKS */

    /* Done. Return the session. */
    return session;
}


#ifdef HAVE_SPREAD
/**
 * yfAddTemplateSpread
 *
 *
 */
static fbTemplate_t *
yfAddTemplateSpread(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    char                **groups,
    uint16_t              tid,
    uint16_t              scope,
    const gchar          *name,
    const gchar          *description,
    gboolean              reverse,
    GError              **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = fbTemplateAlloc(model);
    uint32_t       flags = 0;
    uint16_t       rtid = tid;

    if (reverse) {
        flags = 0xffffffff;
        rtid = tid | YTF_BIF;
    }

    g_debug("yaf spread: %x (%s), %d (%x)", tid, name, reverse,
            tid | (reverse ? YTF_BIF : 0));
    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    if (scope) {
        fbTemplateSetOptionsScope(tmpl, scope);
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplatesMulticastWithMetadata(
            session, groups, FALSE, rtid, tmpl,
            (char *)name, (char *)description, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    (void)name;
    (void)description;
    if (!fbSessionAddTemplatesMulticast(session, groups, FALSE,
                                        rtid, tmpl, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    if (reverse) {
        if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, err)) {
            return NULL;
        }
    }

    return tmpl;
}


/**
 * yfInitExporterSpreadSession
 *
 *
 */
static fbSession_t *
yfInitExporterSpreadSession(
    fBuf_t            *fbuf,
    fbSession_t       *session,
    fbSpreadParams_t  *spread,
    uint32_t           domain,
    uint16_t          *spreadIndex,
    gboolean           export_meta,
    GError           **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = NULL;
#if YAF_ENABLE_HOOKS
    int            n = 0;
#endif

    if (export_meta) {
#if YAF_ENABLE_METADATA_EXPORT
        if (!fbSessionSpreadSetMetadataExportElements(
                session, spread->groups, TRUE, YAF_TYPE_METADATA_TID, err))
        {
            return NULL;
        }

        if (!fbSessionSpreadSetMetadataExportTemplates(
                session, spread->groups, TRUE, YAF_TEMPLATE_METADATA_TID, err))
        {
            return NULL;
        }
#endif /* if YAF_ENABLE_METADATA_EXPORT */
    }

    /*Create the full record template */
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }
    /* Add the full record template to the internal session only */
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

    /* Create the Process Stats Options Template. Scope fields are
     * exporterIPv4Address, observationDomainId, and exportingProcessID */
    yaf_tmpl.ipfixStatsTemplate = yfAddTemplateSpread(session,
                                                      yaf_process_stats_spec,
                                                      spread->groups,
                                                      YAF_PROCESS_STATS_TID, 3,
                                                      YAF_PROCESS_STATS_NAME,
                                                      NULL, FALSE, err);
    if (!yaf_tmpl.ipfixStatsTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_PROCESS_STATS_TID,
                              yaf_tmpl.ipfixStatsTemplate, err))
    {
        return NULL;
    }

    /* Create the Tombstone record Template. Scope fields are
     * exportingProcessID, observationDomainId, and exporterConfiguredId */
    yaf_tmpl.tombstoneRecordTemplate = yfAddTemplateSpread(session,
                                                           yaf_tombstone_spec,
                                                           spread->groups,
                                                           YAF_TOMBSTONE_TID, 3,
                                                           YAF_TOMBSTONE_NAME,
                                                           NULL, FALSE, err);
    if (!yaf_tmpl.tombstoneRecordTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_TID,
                              yaf_tmpl.tombstoneRecordTemplate, err))
    {
        return NULL;
    }

    /* Create the Tombstone Access SubTemplate */
    yaf_tmpl.tombstoneAccessTemplate =
        yfAddTemplateSpread(session,
                            yaf_tombstone_access_spec,
                            spread->groups,
                            YAF_TOMBSTONE_ACCESS_TID,
                            0,
                            YAF_TOMBSTONE_ACCESS_NAME,
                            NULL, FALSE, err);
    if (!yaf_tmpl.tombstoneAccessTemplate) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_ACCESS_TID,
                              yaf_tmpl.tombstoneAccessTemplate, err))
    {
        return NULL;
    }

    /* Flow Stats Template */
    yaf_tmpl.fstatsTemplate = yfAddTemplateSpread(session, yaf_flow_stats_spec,
                                                  spread->groups,
                                                  YAF_STATS_FLOW_TID, 0,
                                                  YAF_STATS_FLOW_NAME,
                                                  NULL, FALSE, err);
    if (!yaf_tmpl.fstatsTemplate) {
        return NULL;
    }

    yaf_tmpl.revfstatsTemplate = yfAddTemplateSpread(session,
                                                     yaf_flow_stats_spec,
                                                     spread->groups,
                                                     YAF_STATS_FLOW_TID, 0,
                                                     YAF_STATS_FLOW_REV_NAME,
                                                     NULL, TRUE, err);
    if (!yaf_tmpl.revfstatsTemplate) {
        return NULL;
    }

#if YAF_ENABLE_ENTROPY
    yaf_tmpl.entropyTemplate = yfAddTemplateSpread(session, yaf_entropy_spec,
                                                   spread->groups,
                                                   YAF_ENTROPY_FLOW_TID, 0,
                                                   YAF_ENTROPY_FLOW_NAME,
                                                   NULL, FALSE, err);

    if (!yaf_tmpl.entropyTemplate) {
        return NULL;
    }

    yaf_tmpl.revEntropyTemplate = yfAddTemplateSpread(session, yaf_entropy_spec,
                                                      spread->groups,
                                                      YAF_ENTROPY_FLOW_TID, 0,
                                                      YAF_ENTROPY_FLOW_REV_NAME,
                                                      NULL, TRUE, err);
    if (!yaf_tmpl.revEntropyTemplate) {
        return NULL;
    }

#endif /* if YAF_ENABLE_ENTROPY */

    yaf_tmpl.tcpTemplate = yfAddTemplateSpread(session, yaf_tcp_spec,
                                               spread->groups,
                                               YAF_TCP_FLOW_TID, 0,
                                               YAF_TCP_FLOW_NAME,
                                               NULL, FALSE, err);

    if (!yaf_tmpl.tcpTemplate) {
        return NULL;
    }

    yaf_tmpl.revTcpTemplate = yfAddTemplateSpread(session, yaf_tcp_spec,
                                                  spread->groups,
                                                  YAF_TCP_FLOW_TID, 0,
                                                  YAF_TCP_FLOW_REV_NAME,
                                                  NULL, TRUE, err);

    if (!yaf_tmpl.revTcpTemplate) {
        return NULL;
    }

    yaf_tmpl.macTemplate = yfAddTemplateSpread(session, yaf_mac_spec,
                                               spread->groups,
                                               YAF_MAC_FLOW_TID, 0,
                                               YAF_MAC_FLOW_NAME,
                                               NULL, FALSE, err);

    if (!yaf_tmpl.macTemplate) {
        return NULL;
    }

    yaf_tmpl.mptcpTemplate = yfAddTemplateSpread(session, yaf_mptcp_spec,
                                                 spread->groups,
                                                 YAF_MPTCP_FLOW_TID, 0,
                                                 YAF_MPTCP_FLOW_NAME,
                                                 NULL, FALSE, err);
    if (!yaf_tmpl.mptcpTemplate) {
        return NULL;
    }

#if YAF_ENABLE_P0F
    yaf_tmpl.p0fTemplate = yfAddTemplateSpread(session, yaf_p0f_spec,
                                               spread->groups,
                                               YAF_P0F_FLOW_TID, 0,
                                               YAF_P0F_FLOW_NAME,
                                               NULL, FALSE, err);

    if (!yaf_tmpl.p0fTemplate) {
        return NULL;
    }

    yaf_tmpl.revP0fTemplate = yfAddTemplateSpread(session, yaf_p0f_spec,
                                                  spread->groups,
                                                  YAF_P0F_FLOW_TID, 0,
                                                  YAF_P0F_FLOW_REV_NAME,
                                                  NULL, TRUE, err);

    if (!yaf_tmpl.revP0fTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    yaf_tmpl.fpexportTemplate = yfAddTemplateSpread(session, yaf_fpexport_spec,
                                                    spread->groups,
                                                    YAF_FPEXPORT_FLOW_TID, 0,
                                                    YAF_FPEXPORT_FLOW_NAME,
                                                    NULL, FALSE, err);

    if (!yaf_tmpl.fpexportTemplate) {
        return NULL;
    }

    yaf_tmpl.revFpexportTemplate = yfAddTemplateSpread(session,
                                                       yaf_fpexport_spec,
                                                       spread->groups,
                                                       YAF_FPEXPORT_FLOW_TID, 0,
                                                       YAF_FPEXPORT_FLOW_REV_NAME,
                                                       NULL, TRUE, err);
    if (!yaf_tmpl.revFpexportTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
    yaf_tmpl.payloadTemplate = yfAddTemplateSpread(session, yaf_payload_spec,
                                                   spread->groups,
                                                   YAF_PAYLOAD_FLOW_TID, 0,
                                                   YAF_PAYLOAD_FLOW_NAME,
                                                   NULL, FALSE, err);

    if (!yaf_tmpl.payloadTemplate) {
        return NULL;
    }

    yaf_tmpl.revPayloadTemplate = yfAddTemplateSpread(session, yaf_payload_spec,
                                                      spread->groups,
                                                      YAF_PAYLOAD_FLOW_TID, 0,
                                                      YAF_PAYLOAD_FLOW_REV_NAME,
                                                      NULL, TRUE, err);

    if (!yaf_tmpl.revPayloadTemplate) {
        return NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_HOOKS
    /*  Add the hook template fields if available  */
    while (spread->groups[n]) {
        fBufSetSpreadExportGroup(fbuf, &(spread->groups[n]), 1, err);
        if (!yfHookGetTemplate(session)) {
            g_warning("Hook Templates could not be added to the session");
            return NULL;
        }
        n++;
    }
#endif /* if YAF_ENABLE_HOOKS */
    /* Done. Return the session. */
    return session;
}


/**
 * yfSpreadGroupby
 *
 *
 */
static uint16_t
yfSpreadGroupby(
    uint8_t    spreadGroupByType,
    uint16_t   silkAppLabel,
    uint16_t   vlanId,
    uint16_t   destinationTransportPort,
    uint8_t    protocolIdentifier,
    uint8_t    ipVersion)
{
    switch (spreadGroupByType) {
      case 1:
        return destinationTransportPort;
      case 2:
        return vlanId;
      case 3:
        return silkAppLabel;
      case 4:
        return (uint16_t)protocolIdentifier;
      case 5:
        return (uint16_t)ipVersion;
      default:
        return 0;
    }
}


/**
 * yfWriterForSpread
 *
 *
 *
 */
fBuf_t *
yfWriterForSpread(
    fbSpreadParams_t  *spread,
    uint32_t           domain,
    uint16_t          *spreadGroupIndex,
    gboolean           export_metadata,
    GError           **err)
{
    fBuf_t        *fbuf = NULL;
    fbSession_t   *session;
    fbExporter_t  *exporter;
    fbInfoModel_t *model = yfInfoModel();

    session = fbSessionAlloc(model);

    spread->session = session;

    fbSessionSetDomain(session, domain);

    exporter = fbExporterAllocSpread(spread);

    fbuf = fBufAllocForExport(session, exporter);

    /* If we are using spread group by - we need to multicast templates */
    if (spreadGroupIndex) {
        if (!(session = yfInitExporterSpreadSession(fbuf, session, spread,
                                                    domain, spreadGroupIndex,
                                                    export_metadata,
                                                    err)))
        {
            goto err;
        }
    } else {
        /* initialize session and exporter */
        if (!(session = yfInitExporterSession(domain, export_metadata, err))) {
            goto err;
        }
    }

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* write YAF flow templates */

    if (!fbSessionExportTemplates(session, err)) { goto err;}
    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        goto err;
    }

    /* all done */
    return fbuf;

  err:
    if (fbuf) { fBufFree(fbuf);}

    return NULL;
}


/**
 * yfSetSpreadExportTemplate
 *
 *    The Spread version of yfSetExportTemplate().
 *
 *
 */
static gboolean
yfSetSpreadExportTemplate(
    fBuf_t            *fbuf,
    fbSpreadParams_t  *spread,
    uint32_t           flags,
    char             **groups,
    int                num_groups,
    GError           **err)
{
    fbSession_t  *session = NULL;
    fbTemplate_t *tmpl = NULL;
    uint16_t      tid = UINT16_MAX & flags;

    /* Try to set export template */

    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(yfInfoModel());

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec,
                                   (flags & (~YAF_FLOW_BASE_TID)), err))
    {
        return FALSE;
    }
    /* Multicast templates to all groups */
    if (!(fbSessionAddTemplatesMulticast(session, spread->groups, FALSE,
                                         tid, tmpl, err)))
    {
        return FALSE;
    }

    /* Now reset groups on the buffer */
    fBufSetSpreadExportGroup(fbuf, groups, num_groups, err);
    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}
#endif /* HAVE SPREAD */



/**
 * yfSetExportTemplate
 *
 *    Sets the export template to that whose ID is in the lower 16-bits of
 *    `flags`.  If the template does not exist, a new template for flow record
 *    export is created using the yaf_flow_spec[].
 *
 *    @param the TID to export or flags is used to select IEs from
 *    yaf_flow_spec[], may include elements whose presence is not reflected in
 *    the template ID.
 *
 *
 */
static gboolean
yfSetExportTemplate(
    fBuf_t    *fbuf,
    uint32_t   flags,
    GError   **err)
{
    fbSession_t  *session = NULL;
    fbTemplate_t *tmpl = NULL;
    GString      *template_name = NULL;
    uint16_t      tid = UINT16_MAX & flags;

#define TEMPLATE_NAME_INIT_LEN 32

    /* Try to set export template */
    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);

    template_name = g_string_sized_new(TEMPLATE_NAME_INIT_LEN);

    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(yfInfoModel());

    if ( (tid & YAF_FLOW_BASE_TID) == YAF_FLOW_BASE_TID) {
        g_string_append_printf(template_name, "yaf_flow");

        if (tid & YTF_DELTA) {
            g_string_append_printf(template_name, "_%s", YTF_DELTA_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_TOTAL_NAME);
        }

        if (tid & YTF_BIF) {
            g_string_append_printf(template_name, "_%s", YTF_BIF_NAME);
        }

        if (tid & YTF_SILK) {
            g_string_append_printf(template_name, "_%s", YTF_SILK_NAME);
        }

        if (tid & YTF_MPLS) {
            g_string_append_printf(template_name, "_%s", YTF_MPLS_NAME);
        }

        if (tid & YTF_RLE) {
            g_string_append_printf(template_name, "_%s", YTF_RLE_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_FLE_NAME);
        }

        if (tid & YTF_IP6) {
            g_string_append_printf(template_name, "_%s", YTF_IP6_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_IP4_NAME);
        }

        if (tid & YTF_DAGIF) {
            g_string_append_printf(template_name, "_%s", YTF_DAGIF_NAME);
        }
        if (tid & YTF_NDPI) {
            g_string_append_printf(template_name, "_%s", YTF_NDPI_NAME);
        }
    }

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec,
                                   (flags & (~YAF_FLOW_BASE_TID)), err))
    {
        return FALSE;
    }

    /*  printf("yfSetExportTemplate: %x, %s\n", tid, template_name->str); */
#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, tid, tmpl,
                                          template_name->str, NULL, err))
    {
        g_string_free(template_name, TRUE);
        return FALSE;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        g_string_free(template_name, TRUE);
        return FALSE;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    /*g_debug("adding new template %02x", tid);*/
    g_string_free(template_name, TRUE);

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}


/**
 * yfWriterForFile
 *
 *
 */
fBuf_t *
yfWriterForFile(
    const char  *path,
    uint32_t     domain,
    gboolean     export_meta,
    GError     **err)
{
    fBuf_t       *fbuf = NULL;
    fbExporter_t *exporter;
    fbSession_t  *session;

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFile(path);

    /* Create a new buffer */
    if (!(session = yfInitExporterSession(domain, export_meta, err))) {
        goto err;
    }

    fbuf = fBufAllocForExport(session, exporter);

    /* write YAF flow templates */
    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriterForFP
 *
 *
 *
 */
fBuf_t *
yfWriterForFP(
    FILE      *fp,
    uint32_t   domain,
    gboolean   export_meta,
    GError   **err)
{
    fBuf_t       *fbuf = NULL;
    fbExporter_t *exporter;
    fbSession_t  *session;

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFP(fp);
    /* Create a new buffer */
    if (!(session = yfInitExporterSession(domain, export_meta, err))) {
        goto err;
    }

    fbuf = fBufAllocForExport(session, exporter);

    /* write YAF flow templates */

    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriterForSpec
 *
 *
 *
 */
fBuf_t *
yfWriterForSpec(
    fbConnSpec_t  *spec,
    uint32_t       domain,
    gboolean       export_meta,
    GError       **err)
{
    fBuf_t       *fbuf = NULL;
    fbSession_t  *session;
    fbExporter_t *exporter;

    /* initialize session and exporter */
    if (!(session = yfInitExporterSession(domain, export_meta, err))) {
        goto err;
    }

    exporter = fbExporterAllocNet(spec);
    fbuf = fBufAllocForExport(session, exporter);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* write YAF flow templates */
    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriteOptionsDataFlows
 *
 *
 */
gboolean
yfWriteOptionsDataFlows(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yfContext_t *ctx = (yfContext_t *)yfContext;

    if (!yfWriteStatsFlow(yfContext, pcap_drop, timer, err)) {
        return FALSE;
    }
    if (!ctx->cfg->no_tombstone) {
        if (!yfWriteTombstoneFlow(yfContext, err)) {
            return FALSE;
        }
    }
    return TRUE;
}


/**
 * yfWriteStatsFlow
 *
 *
 */
gboolean
yfWriteStatsFlow(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yfIpfixStats_t  rec;
    yfContext_t    *ctx = (yfContext_t *)yfContext;
    fBuf_t         *fbuf = ctx->fbuf;
    uint32_t        mask = 0x000000FF;
    char            buf[200];
    uint32_t        total_frags = 0;
    static struct hostent *host;
    static uint32_t host_ip = 0;

#if HAVE_SPREAD
    fbSpreadParams_t *spParam = &(ctx->cfg->spreadparams);
#endif

    yfGetFlowTabStats(ctx->flowtab, &(rec.packetTotalCount),
                      &(rec.exportedFlowTotalCount),
                      &(rec.notSentPacketTotalCount),
                      &(rec.flowTablePeakCount), &(rec.flowTableFlushEvents));
    if (ctx->fragtab) {
        yfGetFragTabStats(ctx->fragtab, &(rec.expiredFragmentCount),
                          &(rec.assembledFragmentCount), &total_frags);
    } else {
        rec.expiredFragmentCount = 0;
        rec.assembledFragmentCount = 0;
    }

    if (!fbuf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Get IP of sensor for scope */
    if (!host) {
        gethostname(buf, 200);
        host = (struct hostent *)gethostbyname(buf);
        if (host) {
            host_ip = (host->h_addr[0] & mask) << 24;
            host_ip |= (host->h_addr[1] & mask) << 16;
            host_ip |= (host->h_addr[2] & mask) << 8;
            host_ip |= (host->h_addr[3] & mask);
        }
    }

    /* Rejected/Ignored Packet Total Count from decode.c */
    rec.ignoredPacketTotalCount = yfGetDecodeStats(ctx->dectx);

    /* Dropped packets - from yafcap.c & libpcap */
    rec.droppedPacketTotalCount = pcap_drop;
    rec.exporterIPv4Address = host_ip;

    rec.observationDomainId = ctx->cfg->odid;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = (int)time(NULL);

    rec.meanFlowRate =
        rec.exportedFlowTotalCount / g_timer_elapsed(timer, NULL);
    rec.meanPacketRate = rec.packetTotalCount / g_timer_elapsed(timer, NULL);

    rec.systemInitTimeMilliseconds = ctx->yaf_start_time;

    g_debug("YAF statistics: Flows: %" PRIu64 " Packets: %" PRIu64
            " Dropped: %" PRIu64 " Ignored: %" PRIu64
            " Out of Sequence: %" PRIu64
            " Expired Frags: %u Assembled Frags: %u",
            rec.exportedFlowTotalCount, rec.packetTotalCount,
            rec.droppedPacketTotalCount, rec.ignoredPacketTotalCount,
            rec.notSentPacketTotalCount, rec.expiredFragmentCount,
            rec.assembledFragmentCount);

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

#if HAVE_SPREAD
    if (ctx->cfg->spreadGroupIndex) {
        fBufSetSpreadExportGroup(fbuf, spParam->groups,
                                 ctx->cfg->numSpreadGroups, err);
    }
#endif /* if HAVE_SPREAD */

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteTombstoneFlow
 *
 *
 */
gboolean
yfWriteTombstoneFlow(
    void    *yfContext,
    GError **err)
{
    yfTombstoneRecord_t rec;
    yfContext_t        *ctx = (yfContext_t *)yfContext;
    fBuf_t             *fbuf = ctx->fbuf;
    static uint32_t     tombstoneId = 0;
    uint32_t            currentTime;
    yfTombstoneAccess_t *accessListPtr;

#if HAVE_SPREAD
    fbSpreadParams_t    *spParam = &(ctx->cfg->spreadparams);
#endif

    if (!fbuf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

#if HAVE_SPREAD
    if (ctx->cfg->spreadGroupIndex) {
        fBufSetSpreadExportGroup(fbuf, spParam->groups,
                                 ctx->cfg->numSpreadGroups, err);
    }
#endif /* if HAVE_SPREAD */

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

    memset(rec.paddingOctets, 0, sizeof(rec.paddingOctets));
    currentTime = (uint32_t)time(NULL);
    rec.tombstoneId = tombstoneId++;
    rec.exporterConfiguredId = ctx->cfg->tombstone_configured_id;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = currentTime;
    rec.observationDomainId = ctx->cfg->odid;
    accessListPtr = (yfTombstoneAccess_t *)fbSubTemplateListInit(
        &(rec.accessList), 0,
        YAF_TOMBSTONE_ACCESS_TID,
        yaf_tmpl.tombstoneAccessTemplate, 1);

    accessListPtr->certToolId = 1;
    accessListPtr->observationTimeSeconds = currentTime;

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    g_message("Sent Tombstone record: observationDomain:%d, "
              "exporterId:%d:%d, tombstoneId: %d",
              rec.observationDomainId, rec.exporterConfiguredId,
              rec.exportingProcessId, rec.tombstoneId);

    fbSubTemplateListClear(&(rec.accessList));

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteFlow
 *
 *
 *
 */
gboolean
yfWriteFlow(
    void      *yfContext,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixFlow_t  rec;
    uint32_t       wtid;
    uint16_t       etid = 0;      /* extra templates */
    fbSubTemplateMultiListEntry_t *stml = NULL;
    yfTcpFlow_t   *tcprec = NULL;
    yfMacFlow_t   *macrec = NULL;
    yfMPTCPFlow_t *mptcprec = NULL;
    int            tmplcount = 0;
    gboolean       ok;
    gboolean       stats = FALSE;
    int            loop, count;
#if YAF_ENABLE_ENTROPY
    yfEntropyFlow_t  *entropyrec;
#endif
#if YAF_ENABLE_P0F
    yfP0fFlow_t      *p0frec;
#endif
#if YAF_ENABLE_FPEXPORT
    yfFPExportFlow_t *fpexportrec;
#endif
#if YAF_ENABLE_PAYLOAD
    yfPayloadFlow_t  *payrec;
#endif
    yfContext_t      *ctx = (yfContext_t *)yfContext;
    fBuf_t           *fbuf = ctx->fbuf;
    yfFlowStatsRecord_t *statsflow = NULL;
#if HAVE_SPREAD
    char             *spgroups[25];
    int i = 0, k = 0;
    fbSpreadParams_t *spParam = &(ctx->cfg->spreadparams);
    uint16_t          spGroupBy = 0;
#endif /* if HAVE_SPREAD */

    if (ctx->cfg->no_output) {
        return TRUE;
    }

    /* copy time */
    rec.flowStartMilliseconds = flow->stime;
    rec.flowEndMilliseconds = flow->etime;
    rec.reverseFlowDeltaMilliseconds = flow->rdtime;

    /* copy addresses */
    if (yaf_core_map_ipv6 && (flow->key.version == 4)) {
        memcpy(rec.sourceIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.sourceIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.sip);
        memcpy(rec.destinationIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.destinationIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.dip);
    } else if (flow->key.version == 4) {
        rec.sourceIPv4Address = flow->key.addr.v4.sip;
        rec.destinationIPv4Address = flow->key.addr.v4.dip;
    } else if (flow->key.version == 6) {
        memcpy(rec.sourceIPv6Address, flow->key.addr.v6.sip,
               sizeof(rec.sourceIPv6Address));
        memcpy(rec.destinationIPv6Address, flow->key.addr.v6.dip,
               sizeof(rec.destinationIPv6Address));
    } else {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Illegal IP version %u", flow->key.version);
    }

    /* choose options for basic template */
    wtid = YAF_FLOW_BASE_TID;
    rec.vlanId = flow->val.vlan;
    /* right? */
    rec.reverseVlanId = flow->rval.vlan;

    /* copy key and counters */
    rec.sourceTransportPort = flow->key.sp;
    rec.destinationTransportPort = flow->key.dp;
    rec.flowAttributes = flow->val.attributes;
    rec.reverseFlowAttributes = flow->rval.attributes;
    rec.protocolIdentifier = flow->key.proto;
    rec.flowEndReason = flow->reason;

    if (ctx->cfg->deltaMode) {
        rec.octetDeltaCount = flow->val.oct;
        rec.reverseOctetDeltaCount = flow->rval.oct;
        rec.packetDeltaCount = flow->val.pkt;
        rec.reversePacketDeltaCount = flow->rval.pkt;
        wtid |= YTF_DELTA;
    } else {
        rec.octetTotalCount = flow->val.oct;
        rec.reverseOctetTotalCount = flow->rval.oct;
        rec.packetTotalCount = flow->val.pkt;
        rec.reversePacketTotalCount = flow->rval.pkt;
        wtid |= YTF_TOTAL;
    }

    rec.ingressInterface = ctx->cfg->ingressInt;
    rec.egressInterface = ctx->cfg->egressInt;

    /* VNI */
    rec.yafLayer2SegmentId = flow->key.layer2Id;

    /* Type Of Service */
    rec.ipClassOfService = flow->key.tos;
    rec.reverseIpClassOfService = flow->rtos;

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    rec.ingressInterface = flow->key.netIf;
    rec.egressInterface  = flow->key.netIf | 0x100;
#endif

#if YAF_ENABLE_SEPARATE_INTERFACES
    rec.ingressInterface = flow->val.netIf;
    if (flow->rval.pkt) {
        rec.egressInterface = flow->rval.netIf;
    } else {
        rec.egressInterface = flow->val.netIf | 0x100;
    }
#endif /* if YAF_ENABLE_SEPARATE_INTERFACES */

#if YAF_ENABLE_APPLABEL
    rec.silkAppLabel = flow->appLabel;

#if HAVE_SPREAD
    spGroupBy = yfSpreadGroupby(ctx->cfg->spreadGroupby, rec.silkAppLabel,
                                rec.vlanId, rec.destinationTransportPort,
                                rec.protocolIdentifier, flow->key.version);
#endif
#else /* if YAF_ENABLE_APPLABEL */
#if HAVE_SPREAD
    spGroupBy = yfSpreadGroupby(ctx->cfg->spreadGroupby, 0, rec.vlanId,
                                rec.destinationTransportPort,
                                rec.protocolIdentifier, flow->key.version);
#endif
#endif /* if YAF_ENABLE_APPLABEL */

#if YAF_ENABLE_NDPI
    rec.ndpi_master = flow->ndpi_master;
    rec.ndpi_sub = flow->ndpi_sub;
    wtid |= YTF_NDPI;
#endif

#if YAF_MPLS
    /* since the mpls label isn't defined as an integer in fixbuf, it's
     * not endian-converted on transcode, so we fix that here */
    /*    temp = htonl(flow->mpls->mpls_label[0]) >> 8;*/
    memcpy(rec.mpls_label1, &(flow->mpls->mpls_label[0]), 3);
    /*temp = htonl(flow->mpls->mpls_label[1]) >> 8;*/
    memcpy(rec.mpls_label2, &(flow->mpls->mpls_label[1]), 3);
    /*temp = htonl(flow->mpls->mpls_label[2]) >> 8;*/
    memcpy(rec.mpls_label3, &(flow->mpls->mpls_label[2]), 3);
#endif /* if YAF_MPLS */

#if HAVE_SPREAD
    /* Find out which groups we need to send this flow to */
    for (i = 0; i < ctx->cfg->numSpreadGroups; i++) {
        if (ctx->cfg->spreadGroupIndex[i] == spGroupBy ||
            ctx->cfg->spreadGroupIndex[i] == 0)
        {
            spgroups[k] = (spParam->groups[i]);
            k++;
        }
    }
#endif /* if HAVE_SPREAD */

    if (flow->rval.pkt) {
        wtid |= YTF_BIF;
        etid = YTF_BIF;
    }

    if (rec.protocolIdentifier == YF_PROTO_TCP) {
        if (ctx->cfg->silkmode) {
            rec.tcpSequenceNumber = flow->val.isn;
            rec.reverseTcpSequenceNumber = flow->rval.isn;
            rec.initialTCPFlags = flow->val.iflags;
            rec.reverseInitialTCPFlags = flow->rval.iflags;
            rec.unionTCPFlags = flow->val.uflags;
            rec.reverseUnionTCPFlags = flow->rval.uflags;
            wtid |= YTF_SILK;
        } else {
            tmplcount++;
        }
    }

#if YAF_MPLS
    wtid |= YTF_MPLS;
#endif

    if (flow->val.oct < YAF_RLEMAX && flow->rval.oct < YAF_RLEMAX &&
        flow->val.pkt < YAF_RLEMAX && flow->rval.pkt < YAF_RLEMAX)
    {
        wtid |= YTF_RLE;
    } else {
        wtid |= YTF_FLE;
    }

    if (yaf_core_map_ipv6 || (flow->key.version == 6)) {
        wtid |= YTF_IP6;
    } else {
        wtid |= YTF_IP4;
    }

    if (rec.ingressInterface || rec.egressInterface) {
        wtid |= YTF_DAGIF;
    }

    if (ctx->cfg->layer2IdExportMode) {
        wtid |= YTF_VNI;
    }

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    if (ctx->cfg->exportInterface) {
        wtid |= YTF_DAGIF;
    }
#endif

#if HAVE_SPREAD
    /* If we are selectively setting groups to send this to - set groups
     * on the export buffer */
    if (ctx->cfg->spreadGroupIndex) {
        if (k) {
            fBufSetSpreadExportGroup(fbuf, spgroups, k, err);
        } else {
            return TRUE;
        }
        /* Now make sure the groups have those templates */
        if (!yfSetSpreadExportTemplate(fbuf, spParam, wtid, spgroups, k, err)) {
            return FALSE;
        }
    } else {
        /* we are sending to all groups */
        if (!yfSetExportTemplate(fbuf, wtid, err)) {
            return FALSE;
        }
    }
#else /* if HAVE_SPREAD */

    if (!yfSetExportTemplate(fbuf, wtid, err)) {
        return FALSE;
    }
#endif /* if HAVE_SPREAD */

    if (ctx->cfg->macmode) {
        tmplcount++;
    }

    if (ctx->cfg->statsmode && flow->val.stats) {
        if (flow->val.stats->payoct || flow->rval.stats) {
            tmplcount++;
            stats = TRUE;
        }
    }

    if ((flow->mptcp.token)) {
        tmplcount++;
    }

#if YAF_ENABLE_PAYLOAD
    /* point to payload */
    if ((0 < yaf_core_export_payload)
        && (flow->val.paylen || flow->rval.paylen)
#if YAF_ENABLE_APPLABEL
        && (NULL == yaf_core_payload_applabels
            || findInApplabelArray(flow->appLabel))
#endif
       )
    {
        tmplcount++;
    }
    /* copy payload-derived information */

#if YAF_ENABLE_HOOKS
    tmplcount += yfHookGetTemplateCount(flow);
#endif

#if YAF_ENABLE_ENTROPY
    if (flow->val.entropy || flow->rval.entropy) {
        tmplcount++;
    }
#endif

#if YAF_ENABLE_P0F
    if (flow->val.osname || flow->val.osver ||
        flow->rval.osname || flow->rval.osver ||
        flow->val.osFingerPrint || flow->rval.osFingerPrint)
    {
        tmplcount++;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    if (flow->val.firstPacket || flow->rval.firstPacket ||
        flow->val.secondPacket)
    {
        tmplcount++;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

#endif /* if YAF_ENABLE_PAYLOAD */

    /* Initialize SubTemplateMultiList with number of templates we are to add*/
    fbSubTemplateMultiListInit(&(rec.subTemplateMultiList), 3, tmplcount);

    /* Add TCP Template - IF TCP Flow and SiLK Mode is OFF */
    if (flow->key.proto == YF_PROTO_TCP && !ctx->cfg->silkmode) {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            tcprec = (yfTcpFlow_t *)FBSTMLINIT(stml,
                                               (YAF_TCP_FLOW_TID | etid),
                                               yaf_tmpl.revTcpTemplate);
            tcprec->reverseTcpSequenceNumber = flow->rval.isn;
            tcprec->reverseInitialTCPFlags = flow->rval.iflags;
            tcprec->reverseUnionTCPFlags = flow->rval.uflags;
        } else {
            tcprec = (yfTcpFlow_t *)FBSTMLINIT(stml, YAF_TCP_FLOW_TID,
                                               yaf_tmpl.tcpTemplate);
        }
        tcprec->tcpSequenceNumber = flow->val.isn;
        tcprec->initialTCPFlags = flow->val.iflags;
        tcprec->unionTCPFlags = flow->val.uflags;
        tmplcount--;
    }

    /* Add MAC Addresses */
    if (ctx->cfg->macmode) {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        macrec = (yfMacFlow_t *)FBSTMLINIT(stml, YAF_MAC_FLOW_TID,
                                           yaf_tmpl.macTemplate);
        memcpy(macrec->sourceMacAddress, flow->sourceMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        memcpy(macrec->destinationMacAddress, flow->destinationMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        tmplcount--;
    }

    if (flow->mptcp.token) {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        mptcprec = (yfMPTCPFlow_t *)FBSTMLINIT(stml, YAF_MPTCP_FLOW_TID,
                                               yaf_tmpl.mptcpTemplate);
        memcpy(mptcprec, &(flow->mptcp), sizeof(yfMPTCPFlow_t));
        tmplcount--;
    }

#if YAF_ENABLE_PAYLOAD
    /* Add Payload Template */
    if ((0 < yaf_core_export_payload)
        && (flow->val.paylen || flow->rval.paylen)
#if YAF_ENABLE_APPLABEL
        && (NULL == yaf_core_payload_applabels
            || findInApplabelArray(flow->appLabel))
#endif
       )
    {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            payrec = (yfPayloadFlow_t *)FBSTMLINIT(stml,
                                                   YAF_PAYLOAD_FLOW_TID | etid,
                                                   yaf_tmpl.revPayloadTemplate);
            payrec->reversePayload.len = MIN(flow->rval.paylen,
                                             yaf_core_export_payload);
            payrec->reversePayload.buf = flow->rval.payload;
        } else {
            payrec = (yfPayloadFlow_t *)FBSTMLINIT(stml,
                                                   YAF_PAYLOAD_FLOW_TID,
                                                   yaf_tmpl.payloadTemplate);
        }
        payrec->payload.len = MIN(flow->val.paylen, yaf_core_export_payload);
        payrec->payload.buf = flow->val.payload;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_ENTROPY
    /* Add Entropy Template */
    if (flow->val.entropy || flow->rval.entropy) {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            entropyrec = (yfEntropyFlow_t *)FBSTMLINIT(
                stml, YAF_ENTROPY_FLOW_TID | etid, yaf_tmpl.
                revEntropyTemplate);
            entropyrec->reverseEntropy = flow->rval.entropy;
        } else {
            entropyrec = (yfEntropyFlow_t *)FBSTMLINIT(
                stml, YAF_ENTROPY_FLOW_TID, yaf_tmpl.entropyTemplate);
        }
        entropyrec->entropy = flow->val.entropy;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_ENTROPY */

#if YAF_ENABLE_P0F
    /* Add P0F Template */
    if (flow->val.osname || flow->val.osver || flow->rval.osname ||
        flow->rval.osver || flow->val.osFingerPrint || flow->rval.osFingerPrint)
    {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            p0frec = (yfP0fFlow_t *)FBSTMLINIT(stml,
                                               YAF_P0F_FLOW_TID | etid,
                                               yaf_tmpl.revP0fTemplate);
            if (NULL != flow->rval.osname) {
                p0frec->reverseOsName.buf = (uint8_t *)flow->rval.osname;
                p0frec->reverseOsName.len = strlen(flow->rval.osname);
            } else {
                p0frec->reverseOsName.len = 0;
            }
            if (NULL != flow->rval.osver) {
                p0frec->reverseOsVersion.buf = (uint8_t *)flow->rval.osver;
                p0frec->reverseOsVersion.len = strlen(flow->rval.osver);
            } else {
                p0frec->reverseOsVersion.len = 0;
            }
            if (NULL != flow->rval.osFingerPrint) {
                p0frec->reverseOsFingerPrint.buf = (uint8_t *)
                    flow->rval.osFingerPrint;
                p0frec->reverseOsFingerPrint.len =
                    strlen(flow->rval.osFingerPrint);
            } else {
                p0frec->reverseOsFingerPrint.len = 0;
            }
        } else {
            p0frec = (yfP0fFlow_t *)FBSTMLINIT(stml, YAF_P0F_FLOW_TID,
                                               yaf_tmpl.p0fTemplate);
        }
        if (NULL != flow->val.osname) {
            p0frec->osName.buf  = (uint8_t *)flow->val.osname;
            p0frec->osName.len  = strlen(flow->val.osname);
        } else {
            p0frec->osName.len = 0;
        }

        if (NULL != flow->val.osver) {
            p0frec->osVersion.buf = (uint8_t *)flow->val.osver;
            p0frec->osVersion.len = strlen(flow->val.osver);
        } else {
            p0frec->osVersion.len = 0;
        }

        if (NULL != flow->val.osFingerPrint) {
            p0frec->osFingerPrint.buf = (uint8_t *)flow->val.osFingerPrint;
            p0frec->osFingerPrint.len = strlen(flow->val.osFingerPrint);
        } else {
            p0frec->osFingerPrint.len = 0;
        }
        tmplcount--;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    /* Add FingerPrint Template */
    if (flow->val.firstPacket || flow->rval.firstPacket ||
        flow->val.secondPacket)
    {
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);

        if (etid) {
            fpexportrec = (yfFPExportFlow_t *)FBSTMLINIT(
                stml, (YAF_FPEXPORT_FLOW_TID | etid), yaf_tmpl.
                revFpexportTemplate);
            fpexportrec->reverseFirstPacketBanner.buf = flow->rval.firstPacket;
            fpexportrec->reverseFirstPacketBanner.len =
                flow->rval.firstPacketLen;
        } else {
            fpexportrec = (yfFPExportFlow_t *)FBSTMLINIT(
                stml, YAF_FPEXPORT_FLOW_TID, yaf_tmpl.fpexportTemplate);
        }
        fpexportrec->firstPacketBanner.buf = flow->val.firstPacket;
        fpexportrec->firstPacketBanner.len = flow->val.firstPacketLen;
        fpexportrec->secondPacketBanner.buf = flow->val.secondPacket;
        fpexportrec->secondPacketBanner.len = flow->val.secondPacketLen;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

    if (stats) {
        yfFlowStats_t *fwd_stats = flow->val.stats;
        yfFlowStats_t *rev_stats = flow->rval.stats;
        uint32_t pktavg = 0;

        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            statsflow = (yfFlowStatsRecord_t *)
                FBSTMLINIT(stml, (YAF_STATS_FLOW_TID | etid),
                           yaf_tmpl.revfstatsTemplate);
            statsflow->reverseTcpUrgTotalCount = rev_stats->tcpurgct;
            statsflow->reverseSmallPacketCount = rev_stats->smallpktct;
            statsflow->reverseFirstNonEmptyPacketSize =
                (uint16_t)rev_stats->firstpktsize;
            statsflow->reverseNonEmptyPacketCount = rev_stats->nonemptypktct;
            statsflow->reverseDataByteCount = rev_stats->payoct;
            statsflow->reverseMaxPacketSize = (uint16_t)rev_stats->maxpktsize;
            statsflow->reverseLargePacketCount = rev_stats->largepktct;
            if (rev_stats->nonemptypktct) {
                int32_t temp = 0;
                int32_t diff;
                count = MIN(rev_stats->nonemptypktct, 10);
                pktavg = rev_stats->payoct / rev_stats->nonemptypktct;
                for (loop = 0; loop < count; loop++) {
                    diff = (int32_t)rev_stats->pktsize[loop] - (int32_t)pktavg;
                    temp += diff * diff;
                }
                statsflow->reverseStandardDeviationPayloadLength =
                    sqrt(temp / count);
            }
            if (flow->rval.pkt > 1) {
                uint64_t time_temp = 0;
                int64_t diff;
                statsflow->reverseAverageInterarrivalTime =
                    rev_stats->aitime / (flow->rval.pkt - 1);
                count = MIN(flow->rval.pkt, 11) - 1;
                for (loop = 0; loop < count; loop++) {
                    diff = ((int64_t)rev_stats->iaarray[loop] -
                            (int64_t)statsflow->reverseAverageInterarrivalTime);
                    time_temp += diff * diff;
                }
                statsflow->reverseStandardDeviationInterarrivalTime =
                    sqrt(time_temp / count);
            }
        } else {
            statsflow = (yfFlowStatsRecord_t *)
                FBSTMLINIT(stml, YAF_STATS_FLOW_TID, yaf_tmpl.fstatsTemplate);
        }
        pktavg = 0;
        statsflow->firstEightNonEmptyPacketDirections = flow->pktdir;
        statsflow->tcpUrgTotalCount = fwd_stats->tcpurgct;
        statsflow->smallPacketCount = fwd_stats->smallpktct;
        statsflow->firstNonEmptyPacketSize = (uint16_t)fwd_stats->firstpktsize;
        statsflow->nonEmptyPacketCount = fwd_stats->nonemptypktct;
        statsflow->dataByteCount = fwd_stats->payoct;
        statsflow->maxPacketSize = (uint16_t)fwd_stats->maxpktsize;
        statsflow->largePacketCount = fwd_stats->largepktct;
        if (fwd_stats->nonemptypktct) {
            int32_t temp = 0;
            int32_t diff;
            count = MIN(fwd_stats->nonemptypktct, 10);
            pktavg = fwd_stats->payoct / fwd_stats->nonemptypktct;
            temp = 0;
            for (loop = 0; loop < count; loop++) {
                diff = (int32_t)fwd_stats->pktsize[loop] - (int32_t)pktavg;
                temp += diff * diff;
            }
            statsflow->standardDeviationPayloadLength = sqrt(temp / count);
        }
        if (flow->val.pkt > 1) {
            uint64_t time_temp = 0;
            int64_t diff;
            statsflow->averageInterarrivalTime =
                fwd_stats->aitime / (flow->val.pkt - 1);
            count = MIN(flow->val.pkt, 11) - 1;
            for (loop = 0; loop < count; loop++) {
                diff = ((int64_t)fwd_stats->iaarray[loop] -
                        (int64_t)statsflow->averageInterarrivalTime);
                time_temp += diff * diff;
            }
            statsflow->standardDeviationInterarrivalTime =
                sqrt(time_temp / count);
        }
        tmplcount--;
    }

#if YAF_ENABLE_HOOKS
    /* write hook record - only add if there are some available in list*/
    if (!yfHookFlowWrite(&(rec.subTemplateMultiList), stml, flow, err)) {
        return FALSE;
    }
#endif /* if YAF_ENABLE_HOOKS */

    /* IF UDP - Check to see if we need to re-export templates */
    /* We do not advise in using UDP (nicer than saying you're stupid) */
    if ((ctx->cfg->connspec.transport == FB_UDP) ||
        (ctx->cfg->connspec.transport == FB_DTLS_UDP))
    {
        /* 3 is the factor from RFC 5101 as a recommendation of how often
         * between timeouts to resend */
        if ((flow->etime > ctx->lastUdpTempTime) &&
            ((flow->etime - ctx->lastUdpTempTime) >
             ((ctx->cfg->yaf_udp_template_timeout) / 3)))
        {
            /* resend templates */
            ok = fbSessionExportTemplates(fBufGetSession(ctx->fbuf), err);
            ctx->lastUdpTempTime = flow->etime;
            if (!ok) {
                g_warning("Failed to renew UDP Templates: %s",
                          (*err)->message);
                g_clear_error(err);
            }
        }
        if (!(ctx->cfg->livetype)) {
            /* slow down UDP export if reading from a file */
            usleep(2);
        }
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

#if YAF_ENABLE_HOOKS
    /* clear basic lists */
    yfHookFreeLists(flow);
#endif
    /* Clear MultiList */
    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));

    return TRUE;
}


/**
 * yfWriterClose
 *
 *
 *
 */
gboolean
yfWriterClose(
    fBuf_t    *fbuf,
    gboolean   flush,
    GError   **err)
{
    gboolean ok = TRUE;

    if (flush) {
        ok = fBufEmit(fbuf, err);
    }

    fBufFree(fbuf);

    return ok;
}


/**
 * yfTemplateCallback
 *
 *
 */
static void
yfTemplateCallback(
    fbSession_t           *session,
    uint16_t               tid,
    fbTemplate_t          *tmpl,
    void                  *app_ctx,
    void                 **tmpl_ctx,
    fbTemplateCtxFree_fn  *fn)
{
    uint16_t ntid;

    ntid = tid & YTF_REV;

    if (YAF_FLOW_BASE_TID == (tid & 0xF000)) {
        fbSessionAddTemplatePair(session, tid, tid);
    }

    if (ntid == YAF_ENTROPY_FLOW_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_TCP_FLOW_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_MAC_FLOW_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_PAYLOAD_FLOW_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else {
        /* Dont decode templates yafscii doesn't care about */
        fbSessionAddTemplatePair(session, tid, 0);
    }
}


/**
 * yfInitCollectorSession
 *
 *
 *
 */
static fbSession_t *
yfInitCollectorSession(
    GError **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = NULL;
    fbSession_t   *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* Add the full record template */
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

#if YAF_ENABLE_ENTROPY
    yaf_tmpl.entropyTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.entropyTemplate, yaf_entropy_spec,
                                   0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_ENTROPY_FLOW_TID,
                              yaf_tmpl.entropyTemplate, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_ENTROPY */
    yaf_tmpl.tcpTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.tcpTemplate, yaf_tcp_spec,
                                   0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TCP_FLOW_TID,
                              yaf_tmpl.tcpTemplate, err))
    {
        return NULL;
    }

    yaf_tmpl.macTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.macTemplate, yaf_mac_spec,
                                   0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_MAC_FLOW_TID,
                              yaf_tmpl.macTemplate, err))
    {
        return NULL;
    }

#if YAF_ENABLE_P0F
    yaf_tmpl.p0fTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.p0fTemplate, yaf_p0f_spec,
                                   0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_P0F_FLOW_TID,
                              yaf_tmpl.p0fTemplate, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    yaf_tmpl.fpexportTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.fpexportTemplate,
                                   yaf_fpexport_spec, 0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FPEXPORT_FLOW_TID,
                              yaf_tmpl.fpexportTemplate, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
    yaf_tmpl.payloadTemplate = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.payloadTemplate, yaf_payload_spec,
                                   0xffffffff, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_PAYLOAD_FLOW_TID,
                              yaf_tmpl.payloadTemplate, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

    /* Add the extended record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbTemplateAppendSpecArray(tmpl, yaf_extime_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_EXT_TID, tmpl, err)) {
        return NULL;
    }

    /* Done. Return the session. */

    /** Add the template callback so we don't try to decode DPI */
    fbSessionAddNewTemplateCallback(session, yfTemplateCallback, NULL);

    return session;
}


/**
 * yfReaderForFP
 *
 *
 *
 */
fBuf_t *
yfReaderForFP(
    fBuf_t  *fbuf,
    FILE    *fp,
    GError **err)
{
    fbSession_t   *session;
    fbCollector_t *collector;

    /* Allocate a collector for the file */
    collector = fbCollectorAllocFP(NULL, fp);

    /* Allocate a buffer, or reset the collector */
    if (fbuf) {
        fBufSetCollector(fbuf, collector);
    } else {
        if (!(session = yfInitCollectorSession(err))) {goto err;}
        fbuf = fBufAllocForCollection(session, collector);
    }

    /* FIXME do a preread? */

    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfListenerForSpec
 *
 *
 *
 */
fbListener_t *
yfListenerForSpec(
    fbConnSpec_t          *spec,
    fbListenerAppInit_fn   appinit,
    fbListenerAppFree_fn   appfree,
    GError               **err)
{
    fbSession_t *session;

    if (!(session = yfInitCollectorSession(err))) {return NULL;}

    return fbListenerAlloc(spec, session, appinit, appfree, err);
}


/**
 * yfReadFlow
 *
 * read an IPFIX record in, with respect to fields YAF cares about
 *
 */
gboolean
yfReadFlow(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixFlow_t    rec;
    size_t           len;
    fbSubTemplateMultiListEntry_t *stml = NULL;
    yfTcpFlow_t     *tcprec = NULL;
    fbTemplate_t    *next_tmpl = NULL;
    yfMacFlow_t     *macrec = NULL;
#if YAF_ENABLE_ENTROPY
    yfEntropyFlow_t *entropyrec = NULL;
#endif
#if YAF_ENABLE_PAYLOAD
    yfPayloadFlow_t *payrec = NULL;
#endif

    len = sizeof(yfIpfixFlow_t);

    /* Check if Options Template - if so - ignore */
    next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
    if (next_tmpl) {
        if (fbTemplateGetOptionsScope(next_tmpl)) {
            /* Stats Msg - Don't actually Decode */
            if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
                return FALSE;
            }
            return TRUE;
        }
    } else {
        return FALSE;
    }

    /* read next YAF record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }
    if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
        return FALSE;
    }

    /* copy time */
    flow->stime = rec.flowStartMilliseconds;
    flow->etime = rec.flowEndMilliseconds;
    flow->rdtime = rec.reverseFlowDeltaMilliseconds;
    /* copy addresses */
    if (rec.sourceIPv4Address || rec.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.sourceTransportPort;
    flow->key.dp = rec.destinationTransportPort;
    flow->key.proto = rec.protocolIdentifier;
    flow->val.oct = rec.octetTotalCount;
    flow->val.pkt = rec.packetTotalCount;
    if (flow->val.oct == 0 && flow->val.pkt == 0) {
        flow->val.oct = rec.octetDeltaCount;
        flow->val.pkt = rec.packetDeltaCount;
    }
    flow->key.vlanId = rec.vlanId;
    flow->val.vlan = rec.vlanId;
    flow->rval.vlan = rec.reverseVlanId;
    flow->rval.oct = rec.reverseOctetTotalCount;
    flow->rval.pkt = rec.reversePacketTotalCount;
    flow->reason = rec.flowEndReason;

#if YAF_ENABLE_APPLABEL
    flow->appLabel = rec.silkAppLabel;
#endif
#if YAF_ENABLE_ENTROPY
    flow->val.entropy = 0;
    flow->rval.entropy = 0;
#endif
    flow->val.isn = rec.tcpSequenceNumber;
    flow->val.iflags = rec.initialTCPFlags;
    flow->val.uflags = rec.unionTCPFlags;
    flow->rval.isn = rec.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.reverseInitialTCPFlags;
    flow->rval.uflags = rec.reverseUnionTCPFlags;
    flow->key.layer2Id = rec.yafLayer2SegmentId;

    /* Get subTemplateMultiList Entry */
    while ((stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml))) {
        switch ((stml->tmplID & YTF_REV)) {
#if YAF_ENABLE_ENTROPY
          case YAF_ENTROPY_FLOW_TID:
            entropyrec =
                (yfEntropyFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                    stml, entropyrec);
            flow->val.entropy = entropyrec->entropy;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.entropy = entropyrec->reverseEntropy;
            }
            break;
#endif /* if YAF_ENABLE_ENTROPY */
          case YAF_TCP_FLOW_TID:
            tcprec = (yfTcpFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, tcprec);
            flow->val.isn = tcprec->tcpSequenceNumber;
            flow->val.iflags = tcprec->initialTCPFlags;
            flow->val.uflags = tcprec->unionTCPFlags;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.isn = tcprec->reverseTcpSequenceNumber;
                flow->rval.iflags = tcprec->reverseInitialTCPFlags;
                flow->rval.uflags = tcprec->reverseUnionTCPFlags;
            }
            break;
          case YAF_MAC_FLOW_TID:
            macrec = (yfMacFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, macrec);
            memcpy(flow->sourceMacAddr, macrec->sourceMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            memcpy(flow->destinationMacAddr, macrec->destinationMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            break;
#if YAF_ENABLE_PAYLOAD
          case YAF_PAYLOAD_FLOW_TID:
            /* copy payload */
            payrec = (yfPayloadFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, payrec);
            yfPayloadCopyIn(&payrec->payload, &flow->val);
            if ((stml->tmplID & YTF_BIF)) {
                yfPayloadCopyIn(&payrec->reversePayload, &flow->rval);
            }
            break;
#endif /* if YAF_ENABLE_PAYLOAD */
          default:
            /* don't know about this template */
            break;
        }
    }

    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));

    return TRUE;
}


/**
 * yfNTPDecode
 *
 * Decodes a 64-bit NTP time variable (in native byte order) and returns it in
 * terms of UNIX epoch milliseconds
 *
 *
 */
static uint64_t
yfNTPDecode(
    uint64_t   ntp)
{
    /* The number of seconds between the NTP epoch (Jan 1, 1900) and the UNIX
     * epoch (Jan 1, 1970).  Seventy 365-day years plus 17 leap days, at 86400
     * sec/day: ((70 * 365 + 17) * 86400) */
    const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = 0x83AA7E80ULL;
    /* NTP rollover = 1 << 32 */
    const uint64_t NTP_ROLLOVER = 0x100000000ULL;
    /* Bit to check to determine whether to round up, 1 << 31 */
    const uint64_t ONE_SHIFT_31 = 0x80000000ULL;
    /* Bit to check to determine NTP Era, 1 << 63 */
    const uint64_t ONE_SHIFT_63 = 0x8000000000000000ULL;
    /* milliseconds */
    uint64_t ms;

    /* Mask the lower 32 bits of `ntp` to get the fractional second part.
     * Divide by 2^32 to get a floating point number that is a fraction of a
     * second, and multiply by 1000 to get milliseconds, but do those in
     * reverse order and use shift for the division.  Before the shift, round
     * up if needed by checking the highest bit that is about to get chopped
     * off. */
    ms = (ntp & 0xffffffffULL) * 1000;
    ms = (ms + ((ms & ONE_SHIFT_31) << 1)) >> 32;

    /* Right shift `ntp` by 32 to get the whole seconds since 1900.  Subtract
     * the difference between the epochs to get a UNIX time, then multiply by
     * 1000 to get milliseconds.
     *
     * Use the highest bit of ntp to determine (assume) the NTP Era and add
     * NTP_ROLLOVER if Era 1; this is valid from 1968 to 2104. */
    if (ntp & ONE_SHIFT_63) {
        /* Assume NTP Era 0 */
        /* valid for 1968-01-20 03:14:08Z to 2036-02-07 06:28:15Z */
        ms += ((ntp >> 32) - NTP_EPOCH_TO_UNIX_EPOCH) * 1000;
    } else {
        /* Assume NTP Era 1 */
        /* valid for 2036-02-07 06:28:16Z to 2104-02-26 09:42:23Z */
        ms += ((ntp >> 32) + NTP_ROLLOVER - NTP_EPOCH_TO_UNIX_EPOCH) * 1000;
    }

    return ms;
}


/**
 * yfReadFlowExtended
 *
 * read an IPFIX flow record in (with respect to fields YAF cares about)
 * using YAF's extended precision time recording
 *
 */
gboolean
yfReadFlowExtended(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixExtFlow_t rec;
    fbTemplate_t    *next_tmpl = NULL;
    size_t           len;
    fbSubTemplateMultiListEntry_t *stml = NULL;
    yfTcpFlow_t     *tcprec = NULL;
    yfMacFlow_t     *macrec = NULL;
#if YAF_ENABLE_ENTROPY
    yfEntropyFlow_t *entropyrec = NULL;
#endif
#if YAF_ENABLE_PAYLOAD
    yfPayloadFlow_t *payrec = NULL;
#endif

    /* read next YAF record; retrying on missing template or EOF. */
    len = sizeof(yfIpfixExtFlow_t);
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_EXT_TID, err)) {
        return FALSE;
    }

    while (1) {
        /* Check if Options Template - if so - ignore */
        next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
        if (next_tmpl) {
            if (fbTemplateGetOptionsScope(next_tmpl)) {
                if (!(fBufNext(fbuf, (uint8_t *)&rec, &len, err))) {
                    return FALSE;
                }
                continue;
            }
        } else {
            return FALSE;
        }
        if (fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
            break;
        } else {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                /* try again on missing template */
                g_debug("skipping IPFIX data set: %s", (*err)->message);
                g_clear_error(err);
                continue;
            } else {
                /* real, actual error */
                return FALSE;
            }
        }
    }

    /* Run the Gauntlet of Time. */
    if (rec.f.flowStartMilliseconds) {
        flow->stime = rec.f.flowStartMilliseconds;
        if (rec.f.flowEndMilliseconds >= rec.f.flowStartMilliseconds) {
            flow->etime = rec.f.flowEndMilliseconds;
        } else {
            flow->etime = flow->stime + rec.flowDurationMilliseconds;
        }
    } else if (rec.flowStartMicroseconds) {
        /* Decode NTP-format microseconds */
        flow->stime = yfNTPDecode(rec.flowStartMicroseconds);
        if (rec.flowEndMicroseconds >= rec.flowStartMicroseconds) {
            flow->etime = yfNTPDecode(rec.flowEndMicroseconds);
        } else {
            flow->etime = flow->stime + (rec.flowDurationMicroseconds / 1000);
        }
    } else if (rec.flowStartSeconds) {
        /* Seconds? Well. Okay... */
        flow->stime = rec.flowStartSeconds * 1000;
        flow->etime = rec.flowEndSeconds * 1000;
    } else if (rec.flowStartDeltaMicroseconds) {
        /* Handle delta microseconds. */
        flow->stime = fBufGetExportTime(fbuf) * 1000 -
            rec.flowStartDeltaMicroseconds / 1000;
        if (rec.flowEndDeltaMicroseconds &&
            rec.flowEndDeltaMicroseconds <= rec.flowStartDeltaMicroseconds)
        {
            flow->etime = fBufGetExportTime(fbuf) * 1000 -
                rec.flowEndDeltaMicroseconds / 1000;
        } else {
            flow->etime = flow->stime + (rec.flowDurationMicroseconds / 1000);
        }
    } else {
        /* Out of time. Use current timestamp, zero duration */
        struct timeval ct;
        g_assert(!gettimeofday(&ct, NULL));
        flow->stime = ((uint64_t)ct.tv_sec * 1000) +
            ((uint64_t)ct.tv_usec / 1000);
        flow->etime = flow->stime;
    }

    /* copy private time field - reverse delta */
    flow->rdtime = rec.f.reverseFlowDeltaMilliseconds;

    /* copy addresses */
    if (rec.f.sourceIPv4Address || rec.f.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.f.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.f.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.f.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.f.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.f.sourceTransportPort;
    flow->key.dp = rec.f.destinationTransportPort;
    flow->key.proto = rec.f.protocolIdentifier;
    flow->val.oct = rec.f.octetTotalCount;
    flow->val.pkt = rec.f.packetTotalCount;
    flow->rval.oct = rec.f.reverseOctetTotalCount;
    flow->rval.pkt = rec.f.reversePacketTotalCount;
    flow->key.vlanId = rec.f.vlanId;
    flow->val.vlan = rec.f.vlanId;
    flow->rval.vlan = rec.f.reverseVlanId;
    flow->reason = rec.f.flowEndReason;
    /* Handle delta counters */
    if (!(flow->val.oct)) {
        flow->val.oct = rec.f.octetDeltaCount;
        flow->rval.oct = rec.f.reverseOctetDeltaCount;
    }
    if (!(flow->val.pkt)) {
        flow->val.pkt = rec.f.packetDeltaCount;
        flow->rval.pkt = rec.f.reversePacketDeltaCount;
    }

#if YAF_ENABLE_APPLABEL
    flow->appLabel = rec.f.silkAppLabel;
#endif
#if YAF_ENABLE_NDPI
    flow->ndpi_master = rec.f.ndpi_master;
    flow->ndpi_sub = rec.f.ndpi_sub;
#endif

#if YAF_ENABLE_ENTROPY
    flow->val.entropy = 0;
    flow->rval.entropy = 0;
#endif
    flow->val.isn = rec.f.tcpSequenceNumber;
    flow->val.iflags = rec.f.initialTCPFlags;
    flow->val.uflags = rec.f.unionTCPFlags;
    flow->rval.isn = rec.f.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.f.reverseInitialTCPFlags;
    flow->rval.uflags = rec.f.reverseUnionTCPFlags;

    while ((stml = FBSTMLNEXT(&(rec.f.subTemplateMultiList), stml))) {
        switch ((stml->tmplID & YTF_REV)) {
#if YAF_ENABLE_ENTROPY
          case YAF_ENTROPY_FLOW_TID:
            entropyrec =
                (yfEntropyFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                    stml, entropyrec);
            flow->val.entropy = entropyrec->entropy;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.entropy = entropyrec->reverseEntropy;
            }
            break;
#endif /* if YAF_ENABLE_ENTROPY */
          case YAF_TCP_FLOW_TID:
            tcprec = (yfTcpFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, tcprec);
            flow->val.isn = tcprec->tcpSequenceNumber;
            flow->val.iflags = tcprec->initialTCPFlags;
            flow->val.uflags = tcprec->unionTCPFlags;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.isn = tcprec->reverseTcpSequenceNumber;
                flow->rval.iflags = tcprec->reverseInitialTCPFlags;
                flow->rval.uflags = tcprec->reverseUnionTCPFlags;
            }
            break;
          case YAF_MAC_FLOW_TID:
            macrec = (yfMacFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, macrec);
            memcpy(flow->sourceMacAddr, macrec->sourceMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            memcpy(flow->destinationMacAddr, macrec->destinationMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            break;
#if YAF_ENABLE_PAYLOAD
          case YAF_PAYLOAD_FLOW_TID:
            /* copy payload */
            payrec = (yfPayloadFlow_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, payrec);
            yfPayloadCopyIn(&payrec->payload, &flow->val);
            if ((stml->tmplID & YTF_BIF)) {
                yfPayloadCopyIn(&payrec->reversePayload, &flow->rval);
            }
            break;
#endif /* if YAF_ENABLE_PAYLOAD */
          default:
            fbSubTemplateMultiListEntryNextDataPtr(stml, NULL);
            break;
        }
    }

    fbSubTemplateMultiListClear(&(rec.f.subTemplateMultiList));

    return TRUE;
}


/**
 * yfPrintFlags
 *
 *
 *
 */
static void
yfPrintFlags(
    GString  *str,
    uint8_t   flags)
{
    if (flags & YF_TF_ECE) {g_string_append_c(str, 'E');}
    if (flags & YF_TF_CWR) {g_string_append_c(str, 'C');}
    if (flags & YF_TF_URG) {g_string_append_c(str, 'U');}
    if (flags & YF_TF_ACK) {g_string_append_c(str, 'A');}
    if (flags & YF_TF_PSH) {g_string_append_c(str, 'P');}
    if (flags & YF_TF_RST) {g_string_append_c(str, 'R');}
    if (flags & YF_TF_SYN) {g_string_append_c(str, 'S');}
    if (flags & YF_TF_FIN) {g_string_append_c(str, 'F');}
    if (!flags) {g_string_append_c(str, '0');}
}


/**
 * yfPrintString
 *
 *
 *
 */
void
yfPrintString(
    GString   *rstr,
    yfFlow_t  *flow)
{
    char sabuf[AIR_IP6ADDR_BUF_MINSZ],
         dabuf[AIR_IP6ADDR_BUF_MINSZ];

    if (NULL == rstr) {
        return;
    }

    /* print start as date and time */
    air_mstime_g_string_append(rstr, flow->stime, AIR_TIME_ISO8601);

    /* print end as time and duration if not zero-duration */
    if (flow->stime != flow->etime) {
        g_string_append_printf(rstr, " - ");
        air_mstime_g_string_append(rstr, flow->etime, AIR_TIME_ISO8601_HMS);
        g_string_append_printf(rstr, " (%.3f sec)",
                               (flow->etime - flow->stime) / 1000.0);
    }

    /* print protocol and addresses */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }

    switch (flow->key.proto) {
      case YF_PROTO_TCP:
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x:%08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn, flow->rval.isn);
        } else {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn);
        }

        yfPrintFlags(rstr, flow->val.iflags);
        g_string_append_c(rstr, '/');
        yfPrintFlags(rstr, flow->val.uflags);
        if (flow->rval.oct) {
            g_string_append_c(rstr, ':');
            yfPrintFlags(rstr, flow->rval.iflags);
            g_string_append_c(rstr, '/');
            yfPrintFlags(rstr, flow->rval.uflags);
        }
        break;
      case YF_PROTO_UDP:
        g_string_append_printf(rstr, " udp %s:%u => %s:%u",
                               sabuf, flow->key.sp, dabuf, flow->key.dp);
        break;
      case YF_PROTO_ICMP:
        g_string_append_printf(rstr, " icmp [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      case YF_PROTO_ICMP6:
        g_string_append_printf(rstr, " icmp6 [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      default:
        g_string_append_printf(rstr, " ip %u %s => %s",
                               flow->key.proto, sabuf, dabuf);
        break;
    }

    /* print vlan tags */
    if (flow->key.vlanId) {
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " vlan %03hx:%03hx",
                                   flow->val.vlan, flow->rval.vlan);
        } else {
            g_string_append_printf(rstr, " vlan %03hx",
                                   flow->val.vlan);
        }
    }

    /* print flow counters and round-trip time */
    if (flow->rval.pkt) {
        g_string_append_printf(rstr, " (%llu/%llu <-> %llu/%llu) rtt %u ms",
                               (long long unsigned int)flow->val.pkt,
                               (long long unsigned int)flow->val.oct,
                               (long long unsigned int)flow->rval.pkt,
                               (long long unsigned int)flow->rval.oct,
                               flow->rdtime);
    } else {
        g_string_append_printf(rstr, " (%llu/%llu ->)",
                               (long long unsigned int)flow->val.pkt,
                               (long long unsigned int)flow->val.oct);
    }

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, " idle");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, " active");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, " eof");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, " rsrc");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, " force");
    }

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    if (0 != flow->appLabel) {
        g_string_append_printf(rstr, " applabel: %u", flow->appLabel);
    }
#endif
#ifdef YAF_ENABLE_NDPI
    if (0 != flow->ndpi_master) {
        if (flow->ndpi_sub) {
            g_string_append_printf(rstr, " ndpi: %u[%u]", flow->ndpi_master,
                                   flow->ndpi_sub);
        } else {
            g_string_append_printf(rstr, " ndpi: %u", flow->ndpi_master);
        }
    }
#endif /* ifdef YAF_ENABLE_NDPI */

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    if (0 != flow->val.entropy || 0 != flow->rval.entropy) {
        g_string_append_printf(rstr, " entropy: %u rev entropy: %u",
                               flow->val.entropy, flow->rval.entropy);
    }
#endif /* ifdef YAF_ENABLE_ENTROPY */

    /* finish line */
    g_string_append(rstr, "\n");

    /* print payload if necessary */
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        air_hexdump_g_string_append(rstr, "  -> ",
                                    flow->val.payload, flow->val.paylen);
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        air_hexdump_g_string_append(rstr, " <-  ",
                                    flow->rval.payload, flow->rval.paylen);
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrintDelimitedString
 *
 *
 *
 */
void
yfPrintDelimitedString(
    GString   *rstr,
    yfFlow_t  *flow,
    gboolean   yaft_mac)
{
    char           sabuf[AIR_IP6ADDR_BUF_MINSZ],
                   dabuf[AIR_IP6ADDR_BUF_MINSZ];
    GString       *fstr = NULL;
    int            loop = 0;
    unsigned short rvlan = 0;

    if (NULL == rstr) {
        return;
    }

    /* print time and duration */
    air_mstime_g_string_append(rstr, flow->stime, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    air_mstime_g_string_append(rstr, flow->etime, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s%8.3f%s",
                           YF_PRINT_DELIM, (flow->etime - flow->stime) / 1000.0,
                           YF_PRINT_DELIM);

    /* print initial RTT */
    g_string_append_printf(rstr, "%8.3f%s",
                           flow->rdtime / 1000.0, YF_PRINT_DELIM);

    /* print five tuple */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }
    g_string_append_printf(rstr, "%3u%s%40s%s%5u%s%40s%s%5u%s",
                           flow->key.proto, YF_PRINT_DELIM,
                           sabuf, YF_PRINT_DELIM, flow->key.sp, YF_PRINT_DELIM,
                           dabuf, YF_PRINT_DELIM, flow->key.dp, YF_PRINT_DELIM);

    if (yaft_mac) {
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x", flow->sourceMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->sourceMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x",
                                   flow->destinationMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->destinationMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    }

    /* print tcp flags */
    fstr = g_string_new(NULL);
    yfPrintFlags(fstr, flow->val.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->val.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_free(fstr, TRUE);

    /* print tcp sequence numbers */
    g_string_append_printf(rstr, "%08x%s%08x%s", flow->val.isn, YF_PRINT_DELIM,
                           flow->rval.isn, YF_PRINT_DELIM);

    /* print vlan tags */
    if (flow->rval.oct) {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->val.vlan,
                               YF_PRINT_DELIM, flow->rval.vlan,
                               YF_PRINT_DELIM);
    } else {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->key.vlanId,
                               YF_PRINT_DELIM, rvlan, YF_PRINT_DELIM);
    }

    /* print flow counters */
    g_string_append_printf(rstr, "%8llu%s%8llu%s%8llu%s%8llu%s",
                           (long long unsigned int)flow->val.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->val.oct,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.oct,
                           YF_PRINT_DELIM);

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "%5u%s", flow->appLabel, YF_PRINT_DELIM);
#endif

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "%3u%s%3u%s",
                           flow->val.entropy, YF_PRINT_DELIM,
                           flow->rval.entropy, YF_PRINT_DELIM);
#endif

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, "idle ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, "active ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, "eof ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, "rsrc ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, "force ");
    }

    /* finish line */
    g_string_append(rstr, "\n");

    /* not printing payload - but need to free */
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrint
 *
 *
 *
 */
gboolean
yfPrint(
    FILE      *out,
    yfFlow_t  *flow,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_new(NULL);

    yfPrintString(rstr, flow);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintDelimited
 *
 *
 *
 */
gboolean
yfPrintDelimited(
    FILE      *out,
    yfFlow_t  *flow,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_new(NULL);

    yfPrintDelimitedString(rstr, flow, yaft_mac);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing delimited flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintColumnHeaders
 *
 *
 */
void
yfPrintColumnHeaders(
    FILE      *out,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;

    rstr = g_string_new(NULL);

    g_string_append_printf(rstr, "start-time%14s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "end-time%16s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "duration%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtt%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "proto%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sip%36s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sp%4s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dip%38s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dp%4s", YF_PRINT_DELIM);
    if (yaft_mac) {
        g_string_append_printf(rstr, "srcMacAddress%5s", YF_PRINT_DELIM);
        g_string_append_printf(rstr, "destMacAddress%4s", YF_PRINT_DELIM);
    }
    g_string_append_printf(rstr, "iflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "uflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "riflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "ruflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "isn%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "risn%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "tag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "pkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "oct%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rpkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "roct%5s", YF_PRINT_DELIM);

#if YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "app%3s", YF_PRINT_DELIM);
#endif
#if YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "entropy%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rentropy%s", YF_PRINT_DELIM);
#endif

    g_string_append_printf(rstr, "end-reason");
    g_string_append(rstr, "\n");

    fwrite(rstr->str, rstr->len, 1, out);

    g_string_free(rstr, TRUE);
}
