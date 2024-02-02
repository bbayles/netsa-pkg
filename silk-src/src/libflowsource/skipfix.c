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
 *  skipfix.c
 *
 *    This file and ipfixsource.c are tightly coupled, and together
 *    they read IPFIX records and convert them to SiLK flow records.
 *
 *    This file primarly handles the conversion, and it is where the
 *    reading functions exist.
 *
 *    The ipfixsource.c file is primary about setting up and tearing
 *    down the data structures used when processing IPFIX.
 */

#define SKIPFIX_SOURCE 1
#include <silk/silk.h>

RCSIDENT("$SiLK: skipfix.c cc63053fcbc0 2023-05-03 20:44:06Z mthomas $");

#include "ipfixsource.h"
#include <silk/skipaddr.h>
#include <silk/skthread.h>

#ifdef  SKIPFIX_TRACE_LEVEL
#define TRACEMSG_LEVEL SKIPFIX_TRACE_LEVEL
#endif
#define TRACEMSG(lvl, msg)      TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Whether to process the subTemplateList element of the Tombstone
 *    record ski_tombstone_t.
 */
#ifndef SKIPFIX_ENABLE_TOMBSTONE_TIMES
#  define SKIPFIX_ENABLE_TOMBSTONE_TIMES 1
#endif

/*
 *    A context is added to incoming templates to assist when decoding
 *    records.  The context is a 32-bit bitmap, and the following
 *    determines whether to allocate the bitmap or to use the pointer
 *    itself and cast the pointer to a uintptr_t.
 */
#ifndef SKIPFIX_ALLOCATE_BITMAP
#  if SK_SIZEOF_UINTPTR_T >= 4
#    define SKIPFIX_ALLOCATE_BITMAP 0
#  else
#    define SKIPFIX_ALLOCATE_BITMAP 1
#  endif
#endif

#if SKIPFIX_ALLOCATE_BITMAP
#  define BMAP_TYPE  uint32_t
#  define BMAP_PRI   "%#010" PRIx32
#  define BMAP_TMPL_CTX_GET(m_template)                 \
    ((fbTemplateGetContext(m_template) != NULL)         \
     ? *((BMAP_TYPE *)fbTemplateGetContext(m_template)) \
     : 0)
#  define BMAP_TMPL_CTX_SET(m_ctx, m_free_fn, m_bmap)                   \
    do {                                                                \
        BMAP_TYPE *bmapp = (BMAP_TYPE *)malloc(sizeof(BMAP_TYPE));      \
        if (bmapp) {                                                    \
            *bmapp = (m_bmap);                                          \
            *(m_ctx) = bmapp;                                           \
            *(m_free_fn) = free;                                        \
        }                                                               \
    } while(0)
#else
#  define BMAP_TYPE  uintptr_t
#  ifdef PRIxPTR
#    define BMAP_PRI "%#010" PRIxPTR
#  elif SK_SIZEOF_UINTPTR_T > 4
#    define BMAP_PRI "%#010" PRIx64
#  else
#    define BMAP_PRI "%#010" PRIx32
#  endif
#  define BMAP_TMPL_CTX_GET(m_template)         \
    (BMAP_TYPE)fbTemplateGetContext(m_template)
#  define BMAP_TMPL_CTX_SET(m_ctx, m_free_fn, m_bmap)   \
    do {                                                \
        *(m_ctx) = (void*)(m_bmap);                     \
        *(m_free_fn) = NULL;                            \
    } while(0)
#endif  /* SKIPFIX_ALLOCATE_BITMAP */


/*
 *    If 'm_val' is greater then 'm_max', return 'm_max'.  Otherwise,
 *    return 'm_val' masked by 'm_max'.  (m_max & m_val).
 */
#define CLAMP_VAL(m_val, m_max)                                 \
    (((m_val) > (m_max)) ? (m_max) : ((m_max) & (m_val)))
#define CLAMP_VAL16(m_val)   CLAMP_VAL((m_val), UINT16_MAX)
#define CLAMP_VAL32(m_val)   CLAMP_VAL((m_val), UINT32_MAX)

/* One more than UINT32_MAX */
#define ROLLOVER32 ((intmax_t)UINT32_MAX + 1)

/*
 *    For NetFlow V9, when the absolute value of the magnitude of the
 *    difference between the sysUpTime and the flowStartSysUpTime is
 *    greater than this value (in milliseconds), assume one of the
 *    values has rolled over.
 */
#define MAXIMUM_FLOW_TIME_DEVIATION  ((intmax_t)INT32_MAX)


/* Values for the flowEndReason. this first set is defined by the
 * IPFIX spec */
#define SKI_END_IDLE            1
#define SKI_END_ACTIVE          2
#define SKI_END_CLOSED          3
#define SKI_END_FORCED          4
#define SKI_END_RESOURCE        5

/* SiLK will ignore flows with a flowEndReason of
 * SKI_END_YAF_INTERMEDIATE_FLOW */
#define SKI_END_YAF_INTERMEDIATE_FLOW 0x1F

/* Mask for the values of flowEndReason: want to ignore the next bit */
#define SKI_END_MASK            0x1f

/* Bits from flowEndReason: whether flow is a continuation */
#define SKI_END_ISCONT          0x80

/* Bits from flowAttributes */
#define SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE 0x01


/*  **********  Template Bitmap to Record Type  **********  */

/*
 *    Each IPFIX Template is examined by skiTemplateCallbackCtx() when
 *    it is initially received to determine how to process data
 *    represented by the template.
 *
 *    This up-front processing should reduce the overhead of needing
 *    to examining the content of every record, but at the expenses of
 *    looking at elements or templates which may never be used.
 *    Overall this should be a benefit as long as the number of
 *    records received is much higher than the number of templates
 *    received (in the TCP case, the templates are only sent once).
 *
 *    When skiTemplateCallbackCtx() examines a Data Template (that is,
 *    a non-Options Template), it may determine that a specialized
 *    function should be used to read the data.  The lower 3 bits of
 *    the bitmap detmine whether it was able to determine this, as
 *    explained in the next paragraphs:
 *
 *    xx1. If the least significant bit is high, the general purpose
 *    ski_fixrec_next() function is used to read the data, and the
 *    other 31 bits are an indication what the template contains.
 *
 *    x10. If the two LSB are 10, the data looks like NetFlow v9 and
 *    the ski_nf9rec_next() function is used to read the data.  See
 *    the note below.
 *
 *    100. If the three LSB are 100, the data looks like YAF or SiLK
 *    data and the ski_yafrec_next() function is used to read the
 *    data.  See the note below.
 *
 *    NOTE: For the NetFlow v9 and YAF/SiLK data, the lower 16 bits of
 *    the bitmap represent the template ID that should be used to
 *    process the data.  The upper 16 bits provide other bits to
 *    represent what may be present in the template.
 *
 *    The bitmap is used to determine the ski_rectype_t value that is
 *    returned by ski_rectype_next().
 */

#define BMAP_RECTYPE_MASK       0x00000007

#define BMAP_RECTYPE_YAFREC     0x00000004

#define BMAP_RECTYPE_NF9REC     0x00000002

#define BMAP_RECTYPE_FIXREC     0x00000001


/*
 *  **********  Determining What IEs a Template Contains  **********
 *
 *    The following TMPL_BIT_ieFoo macros are for setting and getting
 *    the bit associated with the ieFoo element in the bitmap
 *    associated with the template.
 */
#define TMPL_BIT_flowStartMilliseconds          (UINT32_C(1) <<  1)
#define TMPL_BIT_flowEndMilliseconds            (UINT32_C(1) <<  2)

#define TMPL_BIT_systemInitTimeMilliseconds     (UINT32_C(1) <<  3)
#define TMPL_BIT_flowStartSysUpTime             (UINT32_C(1) <<  4)

#define TMPL_BIT_flowStartMicroseconds          (UINT32_C(1) <<  5)
#define TMPL_BIT_flowEndMicroseconds            (UINT32_C(1) <<  6)

#define TMPL_BIT_flowStartNanoseconds           (UINT32_C(1) <<  7)
#define TMPL_BIT_flowEndNanoseconds             (UINT32_C(1) <<  8)

#define TMPL_BIT_flowStartSeconds               (UINT32_C(1) <<  9)
#define TMPL_BIT_flowEndSeconds                 (UINT32_C(1) << 10)

#define TMPL_BIT_flowStartDeltaMicroseconds     (UINT32_C(1) << 11)
#define TMPL_BIT_flowEndDeltaMicroseconds       (UINT32_C(1) << 12)

#define TMPL_BIT_flowDurationMicroseconds       (UINT32_C(1) << 13)
#define TMPL_BIT_flowDurationMilliseconds       (UINT32_C(1) << 14)

/*  either sourceIPv4Address or destinationIPv4Address */
#define TMPL_BIT_sourceIPv4Address              (UINT32_C(1) << 15)
/*  either sourceIPv6Address or destinationIPv6Address */
#define TMPL_BIT_sourceIPv6Address              (UINT32_C(1) << 16)

#define TMPL_BIT_firewallEvent                  (UINT32_C(1) << 17)
#define TMPL_BIT_NF_F_FW_EVENT                  (UINT32_C(1) << 18)
#define TMPL_BIT_NF_F_FW_EXT_EVENT              (UINT32_C(1) << 19)

#define TMPL_BIT_collectionTimeMilliseconds     (UINT32_C(1) << 20)
#define TMPL_BIT_observationTimeMicroseconds    (UINT32_C(1) << 21)
#define TMPL_BIT_observationTimeMilliseconds    (UINT32_C(1) << 22)
#define TMPL_BIT_observationTimeNanoseconds     (UINT32_C(1) << 23)
#define TMPL_BIT_observationTimeSeconds         (UINT32_C(1) << 24)

/*  either icmpTypeCodeIPv4 or icmpTypeCodeIPv6 */
#define TMPL_BIT_icmpTypeCodeIPv4               (UINT32_C(1) << 25)
/*  at least one of icmpTypeIPv4, icmpCodeIPv4, icmpTypeIPv6, icmpCodeIPv6 */
#define TMPL_BIT_icmpTypeIPv4                   (UINT32_C(1) << 26)

#define TMPL_BIT_postVlanId                     (UINT32_C(1) << 27)
#define TMPL_BIT_reverseVlanId                  (UINT32_C(1) << 28)

#define TMPL_BIT_reverseInitialTCPFlags         (UINT32_C(1) << 29)
#define TMPL_BIT_reverseTcpControlBits          (UINT32_C(1) << 30)


/*
 *    The following are not stored on the bitmap that is set as the
 *    template's context, but they are used when the template is
 *    examined initially.
 */

/*  octetDeltaCount */
#define TMPL_BIT_octetDeltaCount                (UINT64_C(1) << 32)
/*  packetDeltaCount */
#define TMPL_BIT_packetDeltaCount               (UINT64_C(1) << 33)
/*  octetTotalCount */
#define TMPL_BIT_octetTotalCount                (UINT64_C(1) << 34)
/*  packetTotalCount */
#define TMPL_BIT_packetTotalCount               (UINT64_C(1) << 35)
/*  either initiatorOctets or initiatorPackets */
#define TMPL_BIT_initiatorOctets                (UINT64_C(1) << 36)
/*  either responderOctets or responderPackets */
#define TMPL_BIT_responderOctets                (UINT64_C(1) << 37)
/*  either reverseOctetDeltaCount or reversePacketDeltaCount */
#define TMPL_BIT_reverseOctetDeltaCount         (UINT64_C(1) << 38)
#define TMPL_BIT_initialTCPFlags                (UINT64_C(1) << 39)
#define TMPL_BIT_reverseFlowDeltaMilliseconds   (UINT64_C(1) << 40)
#define TMPL_BIT_subTemplateMultiList           (UINT64_C(1) << 41)
/*  either postOctetDeltaCount or postPacketDeltaCount */
#define TMPL_BIT_postOctetDeltaCount            (UINT64_C(1) << 42)
/*  either postOctetTotalCount or postPacketTotalCount */
#define TMPL_BIT_postOctetTotalCount            (UINT64_C(1) << 43)
/*  certToolId (YAF 2.11) */
#define TMPL_BIT_certToolId                     (UINT64_C(1) << 44)
/*  exportingProcessId and observationTimeSeconds are the
 *  tombstone_access values for YAF 2.10 */
#define TMPL_BIT_exportingProcessId             (UINT64_C(1) << 45)

/* The following are only checked in options templates, so the bit
 * position here can repeat those above */
/* both IE49,IE50 (samplerMode, samplerRandomInterval) are present */
#define TMPL_BIT_samplerMode                    (UINT32_C(1) <<  1)
/* both IE35,IE34 (samplingAlgorithm, samplingInterval) are present */
#define TMPL_BIT_samplingAlgorithm              (UINT32_C(1) <<  2)
#define TMPL_BIT_flowTableFlushEventCount       (UINT32_C(1) <<  3)
#define TMPL_BIT_flowTablePeakCount             (UINT32_C(1) <<  4)
#define TMPL_BIT_tombstoneId                    (UINT32_C(1) <<  5)

/*
 *    Groupings of various bits.
 */

#define TMPL_MASK_GAUNTLET_OF_TIME              \
    (TMPL_BIT_collectionTimeMilliseconds   |    \
     TMPL_BIT_flowDurationMicroseconds     |    \
     TMPL_BIT_flowDurationMilliseconds     |    \
     TMPL_BIT_flowEndDeltaMicroseconds     |    \
     TMPL_BIT_flowEndMicroseconds          |    \
     TMPL_BIT_flowEndMilliseconds          |    \
     TMPL_BIT_flowEndNanoseconds           |    \
     TMPL_BIT_flowEndSeconds               |    \
     TMPL_BIT_flowStartDeltaMicroseconds   |    \
     TMPL_BIT_flowStartMicroseconds        |    \
     TMPL_BIT_flowStartMilliseconds        |    \
     TMPL_BIT_flowStartNanoseconds         |    \
     TMPL_BIT_flowStartSeconds             |    \
     TMPL_BIT_flowStartSysUpTime           |    \
     TMPL_BIT_observationTimeMicroseconds  |    \
     TMPL_BIT_observationTimeMilliseconds  |    \
     TMPL_BIT_observationTimeNanoseconds   |    \
     TMPL_BIT_observationTimeSeconds       |    \
     TMPL_BIT_systemInitTimeMilliseconds)

#define TMPL_MASK_IPADDRESS                     \
    (TMPL_BIT_sourceIPv4Address |               \
     TMPL_BIT_sourceIPv6Address)

#define TMPL_MASK_VOLUME_YAF                    \
    (TMPL_BIT_octetTotalCount  |                \
     TMPL_BIT_packetTotalCount |                \
     TMPL_BIT_octetDeltaCount  |                \
     TMPL_BIT_packetDeltaCount)

#define TMPL_MASK_TIME_MILLI_YAF                \
    (TMPL_BIT_flowStartMilliseconds |           \
     TMPL_BIT_flowEndMilliseconds)

#define TMPL_MASK_VOLUME_NF9                    \
    (TMPL_BIT_octetDeltaCount     |             \
     TMPL_BIT_packetDeltaCount    |             \
     TMPL_BIT_octetTotalCount     |             \
     TMPL_BIT_packetTotalCount    |             \
     TMPL_BIT_initiatorOctets     |             \
     TMPL_BIT_responderOctets     |             \
     TMPL_BIT_postOctetDeltaCount |             \
     TMPL_BIT_postOctetTotalCount)

#define TMPL_MASK_TIME_SYSUP                    \
    (TMPL_BIT_systemInitTimeMilliseconds |      \
     TMPL_BIT_flowStartSysUpTime)

#define TMPL_MASK_TIME_MILLI_NF9                \
    (TMPL_BIT_flowStartMilliseconds |           \
     TMPL_BIT_observationTimeMilliseconds)

#define TMPL_MASK_TIME_NF9                      \
    (TMPL_MASK_TIME_SYSUP |                     \
     TMPL_MASK_TIME_MILLI_NF9)

#define TMPL_MASK_YAFREC                        \
    (TMPL_MASK_IPADDRESS |                      \
     TMPL_MASK_VOLUME_YAF |                     \
     TMPL_MASK_TIME_MILLI_YAF |                 \
     TMPL_BIT_reverseOctetDeltaCount |          \
     TMPL_BIT_initialTCPFlags |                 \
     TMPL_BIT_icmpTypeCodeIPv4 |                \
     TMPL_BIT_reverseVlanId |                   \
     TMPL_BIT_reverseInitialTCPFlags |          \
     TMPL_BIT_reverseTcpControlBits |           \
     TMPL_BIT_reverseFlowDeltaMilliseconds |    \
     TMPL_BIT_subTemplateMultiList)

#define TMPL_MASK_NF9REC                        \
    (TMPL_MASK_IPADDRESS |                      \
     TMPL_MASK_VOLUME_NF9 |                     \
     TMPL_MASK_TIME_NF9 |                       \
     TMPL_BIT_icmpTypeCodeIPv4 |                \
     TMPL_BIT_icmpTypeIPv4 |                    \
     TMPL_BIT_postVlanId |                      \
     TMPL_BIT_firewallEvent |                   \
     TMPL_BIT_NF_F_FW_EVENT |                   \
     TMPL_BIT_NF_F_FW_EXT_EVENT)

#define ASSERT_IE_NAME_IS(aini_ie, aini_name)                           \
    assert(TMPL_BIT_ ## aini_name                                       \
           && 0==strcmp(fbTemplateFieldGetName(aini_ie), #aini_name))

/*
 *  **********  "Give Me Everything" Template for Import  **********
 *
 *    This is the template and a matching struct used for reading
 *    generic flow records.  The template and struct are used by
 *    ski_fixrec_next() when reading data.
 *
 *    The template contains all the IPFIX fields that SiLK supports
 *    when importing data.
 *
 *    The type for these records is SKI_RECTYPE_FIXREC
 */

#define SKI_FIXREC_TID          0xAFEB

#define SKI_FIXREC_PADDING  2

static fbInfoElementSpec_t ski_fixrec_spec[] = {
    /* Ports, Protocol */
    { (char*)"sourceTransportPort",                2, 0 },
    { (char*)"destinationTransportPort",           2, 0 },
    { (char*)"protocolIdentifier",                 1, 0 },
    /* TCP Flags (reverse values below) */
    { (char*)"tcpControlBits",                     1, 0 },
    { (char*)"initialTCPFlags",                    1, 0 },
    { (char*)"unionTCPFlags",                      1, 0 },
    /* Router interfaces */
    { (char*)"ingressInterface",                   4, 0 },
    { (char*)"egressInterface",                    4, 0 },
    /* Volume, as Delta (reverse values below) */
    { (char*)"packetDeltaCount",                   8, 0 },
    { (char*)"octetDeltaCount",                    8, 0 },
    /* Volume, as Total (reverse values below) */
    { (char*)"packetTotalCount",                   8, 0 },
    { (char*)"octetTotalCount",                    8, 0 },
    /* Volume, yet more */
    { (char*)"initiatorPackets",                   8, 0 },
    { (char*)"initiatorOctets",                    8, 0 },
    { (char*)"responderPackets",                   8, 0 },
    { (char*)"responderOctets",                    8, 0 },
    /* Flow attributes (reverse value below) */
    { (char*)"flowAttributes",                     2, 0 },
    /* SiLK Fields */
    { (char*)"silkAppLabel",                       2, 0 },
    { (char*)"silkFlowSensor",                     2, 0 },
    { (char*)"silkFlowType",                       1, 0 },
    { (char*)"silkTCPState",                       1, 0 },
    /* Vlan IDs */
    { (char*)"vlanId",                             2, 0 },
    { (char*)"postVlanId",                         2, 0 },
    /* Firewall events */
    { (char*)"firewallEvent",                      1, 0 },
    { (char*)"NF_F_FW_EVENT",                      1, 0 },
    { (char*)"NF_F_FW_EXT_EVENT",                  2, 0 },
    /* ICMP */
    { (char*)"icmpTypeCodeIPv4",                   2, 0 },
    { (char*)"icmpTypeIPv4",                       1, 0 },
    { (char*)"icmpCodeIPv4",                       1, 0 },
    { (char*)"icmpTypeCodeIPv6",                   2, 0 },
    { (char*)"icmpTypeIPv6",                       1, 0 },
    { (char*)"icmpCodeIPv6",                       1, 0 },
    /* Millisecond start and end (epoch) (native time) */
    { (char*)"flowStartMilliseconds",              8, 0 },
    { (char*)"flowEndMilliseconds",                8, 0 },
    /* SysUpTime, used to handle Netflow v9 SysUpTime offset times */
    { (char*)"systemInitTimeMilliseconds",         8, 0 },
    { (char*)"flowStartSysUpTime",                 4, 0 },
    { (char*)"flowEndSysUpTime",                   4, 0 },
    /* Microsecond start and end (RFC1305-style) */
    { (char*)"flowStartMicroseconds",              8, 0 },
    { (char*)"flowEndMicroseconds",                8, 0 },
    /* Nanosecond start and end (RFC1305-style) */
    { (char*)"flowStartNanoseconds",               8, 0 },
    { (char*)"flowEndNanoseconds",                 8, 0 },
    /* Second start and end */
    { (char*)"flowStartSeconds",                   4, 0 },
    { (char*)"flowEndSeconds",                     4, 0 },
    /* Microsecond delta start and end */
    { (char*)"flowStartDeltaMicroseconds",         4, 0 },
    { (char*)"flowEndDeltaMicroseconds",           4, 0 },
    /* Flow durations */
    { (char*)"flowDurationMicroseconds",           4, 0 },
    { (char*)"flowDurationMilliseconds",           4, 0 },
    /* Collection time and Observation time */
    { (char*)"collectionTimeMilliseconds",         8, 0 },
    { (char*)"observationTimeMilliseconds",        8, 0 },
    { (char*)"observationTimeMicroseconds",        8, 0 },
    { (char*)"observationTimeNanoseconds",         8, 0 },
    { (char*)"observationTimeSeconds",             4, 0 },
    /* IPv4 Addresses */
    { (char*)"sourceIPv4Address",                  4, 0 },
    { (char*)"destinationIPv4Address",             4, 0 },
    { (char*)"ipNextHopIPv4Address",               4, 0 },
    /* IPv6 Addresses */
    { (char*)"sourceIPv6Address",                 16, 0 },
    { (char*)"destinationIPv6Address",            16, 0 },
    { (char*)"ipNextHopIPv6Address",              16, 0 },
    /* Volumes as flow leaves the router or middlebox */
    { (char*)"postPacketDeltaCount",               8, 0 },
    { (char*)"postOctetDeltaCount",                8, 0 },
    { (char*)"postPacketTotalCount",               8, 0 },
    { (char*)"postOctetTotalCount",                8, 0 },
    /* End reason */
    { (char*)"flowEndReason",                      1, 0 },
    /* TCP Flags (reverse) */
    { (char*)"reverseTcpControlBits",              1, 0 },
    { (char*)"reverseInitialTCPFlags",             1, 0 },
    { (char*)"reverseUnionTCPFlags",               1, 0 },
    /* Initial packet roundtrip */
    { (char*)"reverseFlowDeltaMilliseconds",       4, 0 },
    /* Volume, as Delta (reverse) */
    { (char*)"reversePacketDeltaCount",            8, 0 },
    { (char*)"reverseOctetDeltaCount",             8, 0 },
    /* Volume, as Total (reverse) */
    { (char*)"reversePacketTotalCount",            8, 0 },
    { (char*)"reverseOctetTotalCount",             8, 0 },
    /* Vlan IDs (reverse) */
    { (char*)"reverseVlanId",                      2, 0 },
    { (char*)"reversePostVlanId",                  2, 0 },
    /* Flow attributes (reverse) */
    { (char*)"reverseFlowAttributes",              2, 0 },
#if SKI_FIXREC_PADDING != 0
    { (char*)"paddingOctets",     SKI_FIXREC_PADDING, 0 },
#endif
    { (char*)"subTemplateMultiList",               0, 0 },
    FB_IESPEC_NULL
};

typedef struct ski_fixrec_st {
    uint16_t        sourceTransportPort;            /*   0-  1 */
    uint16_t        destinationTransportPort;       /*   2-  3 */

    uint8_t         protocolIdentifier;             /*   4     */
    uint8_t         tcpControlBits;                 /*   5     */
    uint8_t         initialTCPFlags;                /*   6     */
    uint8_t         unionTCPFlags;                  /*   7     */

    uint32_t        ingressInterface;               /*   8- 11 */
    uint32_t        egressInterface;                /*  12- 15 */

    uint64_t        packetDeltaCount;               /*  16- 23 */
    uint64_t        octetDeltaCount;                /*  24- 31 */

    uint64_t        packetTotalCount;               /*  32- 39 */
    uint64_t        octetTotalCount;                /*  40- 47 */

    uint64_t        initiatorPackets;               /*  48- 55 */
    uint64_t        initiatorOctets;                /*  56- 63 */

    uint64_t        responderPackets;               /*  64- 71 */
    uint64_t        responderOctets;                /*  72- 79 */

    /* Flow attribute flags (reverse value below) */
    uint16_t        flowAttributes;                 /*  80- 81 */

    /* SiLK valuee */
    uint16_t        silkAppLabel;                   /*  82- 83 */
    uint16_t        silkFlowSensor;                 /*  84- 85 */
    uint8_t         silkFlowType;                   /*  86     */
    uint8_t         silkTCPState;                   /*  87     */

    /* vlan IDs (reverse values below) */
    uint16_t        vlanId;                         /*  88- 89 */
    uint16_t        postVlanId;                     /*  90- 91 */

    /* Firewall events */
    uint8_t         firewallEvent;                  /*  92     */
    uint8_t         NF_F_FW_EVENT;                  /*  93     */
    uint16_t        NF_F_FW_EXT_EVENT;              /*  94- 95 */

    /* ICMP */
    uint16_t        icmpTypeCodeIPv4;               /*  96- 97 */
    uint8_t         icmpTypeIPv4;                   /*  98     */
    uint8_t         icmpCodeIPv4;                   /*  99     */
    uint16_t        icmpTypeCodeIPv6;               /* 100-101 */
    uint8_t         icmpTypeIPv6;                   /* 102     */
    uint8_t         icmpCodeIPv6;                   /* 103     */

    /* Time can be represented in many different formats: */
    uint64_t        flowStartMilliseconds;          /* 104-111 */
    uint64_t        flowEndMilliseconds;            /* 112-119 */

    /* SysUpTime: used for flow{Start,End}SysUpTime calculations.
     * Needed to support Netflow v9 in particular. */
    uint64_t        systemInitTimeMilliseconds;     /* 120-127 */

    /* Start and end time as delta from the system init time.  Needed
     * to support Netflow v9. */
    uint32_t        flowStartSysUpTime;             /* 128-131 */
    uint32_t        flowEndSysUpTime;               /* 132-135 */

    /* start time as NTP microseconds (RFC1305); may either have end
     * Time in same format or as an flowDurationMicroseconds value. */
    uint64_t        flowStartMicroseconds;          /* 136-143 */
    uint64_t        flowEndMicroseconds;            /* 144-151 */

    /* start time as NTP nanoseconds (RFC1305) */
    uint64_t        flowStartNanoseconds;           /* 152-159 */
    uint64_t        flowEndNanoseconds;             /* 160-167 */

    /* start time and end times as seconds since UNIX epoch. no
     * flowDuration field */
    uint32_t        flowStartSeconds;               /* 168-171 */
    uint32_t        flowEndSeconds;                 /* 172-175 */

    /* start time as delta (negative microsec offsets) from the export
     * time; may either have end time in same format or a
     * flowDurationMicroseconds value */
    uint32_t        flowStartDeltaMicroseconds;     /* 176-179 */
    uint32_t        flowEndDeltaMicroseconds;       /* 180-183 */

    /* elapsed time as either microsec or millisec.  used when the
     * flowEnd time is not given. */
    uint32_t        flowDurationMicroseconds;       /* 184-187 */
    uint32_t        flowDurationMilliseconds;       /* 188-191 */

    /* Collection time and Observation time */
    uint64_t        collectionTimeMilliseconds;     /* 192-199 */
    uint64_t        observationTimeMilliseconds;    /* 200-207 */
    uint64_t        observationTimeMicroseconds;    /* 208-215 */
    uint64_t        observationTimeNanoseconds;     /* 216-223 */
    uint32_t        observationTimeSeconds;         /* 224-227 */

    uint32_t        sourceIPv4Address;              /* 228-231 */
    uint32_t        destinationIPv4Address;         /* 232-235 */
    uint32_t        ipNextHopIPv4Address;           /* 236-239 */

    uint8_t         sourceIPv6Address[16];          /* 240-255 */
    uint8_t         destinationIPv6Address[16];     /* 256-271 */
    uint8_t         ipNextHopIPv6Address[16];       /* 272-287 */

    /* egress volume; used when ingress volume is 0 */
    uint64_t        postPacketDeltaCount;           /* 288-295 */
    uint64_t        postOctetDeltaCount;            /* 296-303 */
    uint64_t        postPacketTotalCount;           /* 304-311 */
    uint64_t        postOctetTotalCount;            /* 312-319 */

    uint8_t         flowEndReason;                  /* 320     */

    /* Flags for the reverse flow: */
    uint8_t         reverseTcpControlBits;          /* 321     */
    uint8_t         reverseInitialTCPFlags;         /* 322     */
    uint8_t         reverseUnionTCPFlags;           /* 323     */

    /* start time of reverse flow, as millisec offset from start time
     * of forward flow */
    uint32_t        reverseFlowDeltaMilliseconds;   /* 324-327 */

    uint64_t        reversePacketDeltaCount;        /* 328-335 */
    uint64_t        reverseOctetDeltaCount;         /* 336-343 */
    uint64_t        reversePacketTotalCount;        /* 344-351 */
    uint64_t        reverseOctetTotalCount;         /* 352-359 */

    /* vlan IDs (reverse) */
    uint16_t        reverseVlanId;                  /* 360-361 */
    uint16_t        reversePostVlanId;              /* 362-363 */

    /* Flow attribute flags (reverse) */
    uint16_t        reverseFlowAttributes;          /* 364-365 */

    /* padding */
#if SKI_FIXREC_PADDING != 0
    uint8_t         paddingOctets[SKI_FIXREC_PADDING];/* 366-367 */
#endif

    /* TCP flags from yaf (when it is run without --silk) */
    fbSubTemplateMultiList_t stml;
} ski_fixrec_t;


/*
 *  **********  YAF/SiLK Template for Import  **********
 *
 *    These are templates used for reading records we know are coming
 *    from SiLK or YAF.  The templates and struct are used
 *    by ski_yafrec_next() when reading data.
 *
 *    The type for these records is SKI_RECTYPE_YAFREC
 */

/*
 *    There are several templates defined here.  The following
 *    YAFREC_* macros determine which elements in the
 *    ski_yafrec_spec[] are used.  For the template that uses the
 *    elements, the correspong bits are set to high in the
 *    SKI_YAFREC_TID below.
 *
 *    On SKI_YAFREC_TID, high bits are 2, 12, 13, 14
 */
#define YAFREC_UNI          (1 <<  3)
#define YAFREC_BI           (1 <<  4)

#define YAFREC_ONLY_IP4     (1 <<  5)
#define YAFREC_ONLY_IP6     (1 <<  6)
#define YAFREC_IP_BOTH      (1 <<  7)

#define YAFREC_DELTA        (1 <<  8)
#define YAFREC_TOTAL        (1 <<  9)

#define YAFREC_STML         (1 << 10)

#define SKI_YAFREC_TID      0x7004
#if (SKI_YAFREC_TID & BMAP_RECTYPE_MASK) != BMAP_RECTYPE_YAFREC
#error "bad SKI_YAFREC_TID value"
#endif

static fbInfoElementSpec_t ski_yafrec_spec[] = {
    /* Ports, Protocol */
    { (char*)"sourceTransportPort",                2, 0 },
    { (char*)"destinationTransportPort",           2, 0 },
    { (char*)"protocolIdentifier",                 1, 0 },
    /* TCP Flags (reverse values below) */
    { (char*)"tcpControlBits",                     1, 0 },
    { (char*)"initialTCPFlags",                    1, 0 },
    { (char*)"unionTCPFlags",                      1, 0 },
    /* Router interfaces */
    { (char*)"ingressInterface",                   4, 0 },
    { (char*)"egressInterface",                    4, 0 },
    /* Volume, as either Delta or Total */
    { (char*)"packetDeltaCount",                   8, YAFREC_DELTA },
    { (char*)"octetDeltaCount",                    8, YAFREC_DELTA },
    { (char*)"packetTotalCount",                   8, YAFREC_TOTAL },
    { (char*)"octetTotalCount",                    8, YAFREC_TOTAL },
    /* Flow attributes (reverse value below) */
    { (char*)"flowAttributes",                     2, 0 },
    /* SiLK Fields */
    { (char*)"silkAppLabel",                       2, 0 },
    { (char*)"silkFlowSensor",                     2, 0 },
    { (char*)"silkFlowType",                       1, 0 },
    { (char*)"silkTCPState",                       1, 0 },
    /* Millisecond start and end (epoch) (native time) */
    { (char*)"flowStartMilliseconds",              8, 0 },
    { (char*)"flowEndMilliseconds",                8, 0 },
    /* Vlan IDs */
    { (char*)"vlanId",                             2, 0 },
    { (char*)"postVlanId",                         2, 0 },
    /* ICMP, either IPv4 or IPv6 */
    { (char*)"icmpTypeCodeIPv4",                   2, YAFREC_IP_BOTH },
    { (char*)"icmpTypeCodeIPv4",                   2, YAFREC_ONLY_IP4 },
    { (char*)"icmpTypeCodeIPv6",                   2, YAFREC_ONLY_IP6 },
    /* End reason */
    { (char*)"flowEndReason",                      1, 0 },
    /* TOS */
    { (char*)"ipClassOfService",                   1, 0 },
    /* IPv4 Addresses; if no IPv4 addresses, add 16 bytes of padding */
    { (char*)"paddingOctets",                     16, YAFREC_ONLY_IP6 },
    { (char*)"sourceIPv4Address",                  4, YAFREC_IP_BOTH },
    { (char*)"destinationIPv4Address",             4, YAFREC_IP_BOTH },
    { (char*)"ipNextHopIPv4Address",               4, YAFREC_IP_BOTH },
    { (char*)"sourceIPv4Address",                  4, YAFREC_ONLY_IP4 },
    { (char*)"destinationIPv4Address",             4, YAFREC_ONLY_IP4 },
    { (char*)"ipNextHopIPv4Address",               4, YAFREC_ONLY_IP4 },
    /* If both IPv4 and IPv6 addresses are present, add 4 bytes of
     * padding.  If this is an IPv4 bi-flow, add 4 bytes of padding
     * and 48 bytes of padding to skip the IPv6 addresess.  If an
     * IPv4-uniflow, this is the end of the record, and pad to the
     * end. */
    { (char*)"paddingOctets",                      4, YAFREC_IP_BOTH },
    { (char*)"paddingOctets",                     52, (YAFREC_ONLY_IP4
                                                       | YAFREC_BI) },
    { (char*)"paddingOctets",                     84, (YAFREC_ONLY_IP4
                                                       | YAFREC_UNI) },
    /* Ingore the IPv6 addresses for an IPv4 bi-flow */
    /* IPv6 Addresses */
    { (char*)"sourceIPv6Address",                 16, YAFREC_IP_BOTH },
    { (char*)"destinationIPv6Address",            16, YAFREC_IP_BOTH },
    { (char*)"ipNextHopIPv6Address",              16, YAFREC_IP_BOTH },
    { (char*)"sourceIPv6Address",                 16, YAFREC_ONLY_IP6 },
    { (char*)"destinationIPv6Address",            16, YAFREC_ONLY_IP6 },
    { (char*)"ipNextHopIPv6Address",              16, YAFREC_ONLY_IP6 },
    /* Ignore the the reverse elements for a uniflow record that is
     * either IPv6 only or has both IPv4 and IPv6 IPs. */
    { (char*)"paddingOctets",                     32, (YAFREC_IP_BOTH
                                                       | YAFREC_UNI) },
    { (char*)"paddingOctets",                     32, (YAFREC_ONLY_IP6
                                                       | YAFREC_UNI) },
    /* Volume (reverse), as either Delta or Total */
    { (char*)"reversePacketDeltaCount",            8, (YAFREC_DELTA
                                                       | YAFREC_BI) },
    { (char*)"reverseOctetDeltaCount",             8, (YAFREC_DELTA
                                                       | YAFREC_BI) },
    { (char*)"reversePacketTotalCount",            8, (YAFREC_TOTAL
                                                       | YAFREC_BI) },
    { (char*)"reverseOctetTotalCount",             8, (YAFREC_TOTAL
                                                       | YAFREC_BI) },
    /* Initial packet roundtrip */
    { (char*)"reverseFlowDeltaMilliseconds",       4, YAFREC_BI },
    /* Vlan IDs (reverse) */
    { (char*)"reverseVlanId",                      2, YAFREC_BI },
    { (char*)"reversePostVlanId",                  2, YAFREC_BI },
    /* Flow attributes (reverse) */
    { (char*)"reverseFlowAttributes",              2, YAFREC_BI },
    /* TCP Flags (reverse) */
    { (char*)"reverseTcpControlBits",              1, YAFREC_BI },
    { (char*)"reverseInitialTCPFlags",             1, YAFREC_BI },
    { (char*)"reverseUnionTCPFlags",               1, YAFREC_BI },
    { (char*)"reverseIpClassOfService",            1, YAFREC_BI },
    { (char*)"paddingOctets",                      2, YAFREC_BI },
    { (char*)"subTemplateMultiList",               0, YAFREC_STML },
    FB_IESPEC_NULL
};

typedef struct ski_yafrec_st {
    uint16_t        sourceTransportPort;            /*   0-  1 */
    uint16_t        destinationTransportPort;       /*   2-  3 */

    uint8_t         protocolIdentifier;             /*   4     */
    uint8_t         tcpControlBits;                 /*   5     */
    uint8_t         initialTCPFlags;                /*   6     */
    uint8_t         unionTCPFlags;                  /*   7     */

    uint32_t        ingressInterface;               /*   8- 11 */
    uint32_t        egressInterface;                /*  12- 15 */

    /* may also hold packetTotalCount and octetTotalCount values */
    uint64_t        packetDeltaCount;               /*  16- 23 */
    uint64_t        octetDeltaCount;                /*  24- 31 */

    /* Flow attribute flags (reverse value below) */
    uint16_t        flowAttributes;                 /*  32- 33 */

    /* SiLK valuee */
    uint16_t        silkAppLabel;                   /*  34- 35 */
    uint16_t        silkFlowSensor;                 /*  36- 37 */
    uint8_t         silkFlowType;                   /*  38     */
    uint8_t         silkTCPState;                   /*  39     */

    /* Time can be represented in many different formats: */
    uint64_t        flowStartMilliseconds;          /*  40- 55 */
    uint64_t        flowEndMilliseconds;            /*  48- 63 */

    /* vlan IDs (reverse values below) */
    uint16_t        vlanId;                         /*  56- 57 */
    uint16_t        postVlanId;                     /*  58- 59 */

    /* ICMP, may be icmpTypeCodeIPv4 or icmpTypeCodeIPv6 */
    uint16_t        icmpTypeCode;                   /*  60- 61 */
    uint8_t         flowEndReason;                  /*  62     */
    uint8_t         ipClassOfService;               /*  63     */

    uint32_t        sourceIPv4Address;              /*  64- 67 */
    uint32_t        destinationIPv4Address;         /*  68- 71 */
    uint32_t        ipNextHopIPv4Address;           /*  72- 75 */
    uint32_t        paddingOctets_1;                /*  76- 79 */

    uint8_t         sourceIPv6Address[16];          /*  80- 95 */
    uint8_t         destinationIPv6Address[16];     /*  96-111 */
    uint8_t         ipNextHopIPv6Address[16];       /* 112-127 */

    /* may also hold reversePacketTotalCount and
     * reverseOctetTotalCount values */
    uint64_t        reversePacketDeltaCount;        /* 128-135 */
    uint64_t        reverseOctetDeltaCount;         /* 136-143 */

    /* start time of reverse flow, as millisec offset from start time
     * of forward flow */
    uint32_t        reverseFlowDeltaMilliseconds;   /* 144-147 */

    /* vlan IDs (reverse) */
    uint16_t        reverseVlanId;                  /* 148-149 */
    uint16_t        reversePostVlanId;              /* 150-151 */

    /* Flow attribute flags (reverse) */
    uint16_t        reverseFlowAttributes;          /* 152-153 */

   /* Flags for the reverse flow: */
    uint8_t         reverseTcpControlBits;          /* 154     */
    uint8_t         reverseInitialTCPFlags;         /* 155     */
    uint8_t         reverseUnionTCPFlags;           /* 156     */
    uint8_t         reverseIpClassOfService;        /* 157     */
    uint16_t        paddingOctets_2;                /* 158-159 */

    /* TCP flags from yaf (when it is run without --silk) */
    fbSubTemplateMultiList_t stml;                  /* 160-... */
} ski_yafrec_t;


/*
 *  **********  YAF SubTemplateMultiList TCP Info Template  **********
 *
 *    Use the following to read TCP flags that YAF has exported in an
 *    IPFIX subTemplateMultiList.
 */

/* Incoming Template ID used by YAF for a subTemplateMultiList item
 * containing only forward TCP flags information. */
#define SKI_YAF_TCP_FLOW_TID    0xC003

/* Bit in the incoming Template ID that yaf sets for templates
 * containing reverse elements */
#define SKI_YAF_REVERSE_BIT     0x0010

/* Internal Template ID */
#define SKI_TCP_STML_TID        0xAFEC

static fbInfoElementSpec_t ski_tcp_stml_spec[] = {
    { (char*)"initialTCPFlags",                    1, 0 },
    { (char*)"unionTCPFlags",                      1, 0 },
    { (char*)"reverseInitialTCPFlags",             1, 0 },
    { (char*)"reverseUnionTCPFlags",               1, 0 },
    FB_IESPEC_NULL
};

typedef struct ski_tcp_stml_st {
    uint8_t         initialTCPFlags;
    uint8_t         unionTCPFlags;
    uint8_t         reverseInitialTCPFlags;
    uint8_t         reverseUnionTCPFlags;
} ski_tcp_stml_t;


/*
 *  **********  YAF Statistics Options Template  **********
 *
 *    Information for statistics information exported by YAF.  The
 *    template and structure are based on the yaf 2.3.0 manual page.
 *    The templates and struct are used by ski_yafstats_next() when
 *    reading data.
 *
 *    The type for these records is SKI_RECTYPE_YAFSTATS
 *
 *    These types are defined in ipfixsource.h so they may be shared
 *    with ipfixsource.c and that the source structure may contain
 *    them.
 *
 *    #define SKI_YAFSTATS_TID        0xD000
 *
 *    static fbInfoElementSpec_t ski_yafstats_spec[] = {...};
 *
 *    typedef struct ski_yafstats_st { ... } ski_yafstats_t;
 *
 */



/*
 *  **********  NetFlowV9 Data Template  **********
 *
 *    Define the list of information elements and the corresponding
 *    struct for reading common NetFlowV9 records.  The templates and
 *    struct are used by ski_nf9rec_next() when reading data.
 *
 *    The type for these records is SKI_RECTYPE_NF9REC
 */

/*
 *    There are several templates defined here.  The following macros
 *    determine which elements in the ski_nf9rec_spec[] are used.  For
 *    the template that uses the elements, the correspong bits are set
 *    to high in the SKI_NF9REC_TID below.
 *
 *    On SKI_NF9REC_TID, high bits are 1, 13, 14.
 */
#define NF9REC_DELTA        (1 <<  2)
#define NF9REC_TOTAL        (1 <<  3)
#define NF9REC_INITIATOR    (1 <<  4)

#define NF9REC_IP4          (1 <<  5)
#define NF9REC_IP6          (1 <<  6)

#define NF9REC_SYSUP        (1 <<  7)
#define NF9REC_MILLI        (1 <<  8)

#define SKI_NF9REC_TID      0x6002
#if (SKI_NF9REC_TID & BMAP_RECTYPE_MASK) != BMAP_RECTYPE_NF9REC
#error "bad SKI_NF9REC_TID value"
#endif

static fbInfoElementSpec_t ski_nf9rec_spec[] = {
    /* Ports, Protocol */
    { (char*)"sourceTransportPort",                2, 0 },
    { (char*)"destinationTransportPort",           2, 0 },
    { (char*)"protocolIdentifier",                 1, 0 },
    /* TCP Flags */
    { (char*)"tcpControlBits",                     1, 0 },
    /* End reason */
    { (char*)"flowEndReason",                      1, 0 },
    /* TOS */
    { (char*)"ipClassOfService",                   1, 0 },
    /* Router interfaces */
    { (char*)"ingressInterface",                   4, 0 },
    { (char*)"egressInterface",                    4, 0 },
    /* Volume, in one of three different ways; initiatorOctets has
     * matching responderOctets.  This does not handle OUT_BYTES(23)
     * and OUT_PACKETS(24) IEs, that fixbuf translates to reverse
     * Delta elements */
    { (char*)"packetDeltaCount",                   8, NF9REC_DELTA },
    { (char*)"octetDeltaCount",                    8, NF9REC_DELTA },
    { (char*)"postPacketDeltaCount",               8, NF9REC_DELTA },
    { (char*)"postOctetDeltaCount",                8, NF9REC_DELTA },
    { (char*)"packetTotalCount",                   8, NF9REC_TOTAL },
    { (char*)"octetTotalCount",                    8, NF9REC_TOTAL },
    { (char*)"postPacketTotalCount",               8, NF9REC_TOTAL },
    { (char*)"postOctetTotalCount",                8, NF9REC_TOTAL },
    { (char*)"initiatorPackets",                   8, NF9REC_INITIATOR},
    { (char*)"initiatorOctets",                    8, NF9REC_INITIATOR },
    { (char*)"responderPackets",                   8, NF9REC_INITIATOR},
    { (char*)"responderOctets",                    8, NF9REC_INITIATOR },
    /* SysUpTime, used to handle Netflow v9 SysUpTime offset times */
    { (char*)"systemInitTimeMilliseconds",         8, NF9REC_SYSUP },
    { (char*)"flowStartSysUpTime",                 4, NF9REC_SYSUP },
    { (char*)"flowEndSysUpTime",                   4, NF9REC_SYSUP },
    /* Millisecond start and end. Note that end uses the
     * observationTime value, though the structure calls it
     * flowEndMilliseconds. */
    { (char*)"flowStartMilliseconds",              8, NF9REC_MILLI },
    { (char*)"observationTimeMilliseconds",        8, NF9REC_MILLI },
    /* Vlan IDs */
    { (char*)"vlanId",                             2, 0 },
    { (char*)"postVlanId",                         2, 0 },
    /* ICMP, either IPv4 or IPv6 */
    { (char*)"icmpTypeCodeIPv4",                   2, NF9REC_IP4 },
    { (char*)"icmpTypeIPv4",                       1, NF9REC_IP4 },
    { (char*)"icmpCodeIPv4",                       1, NF9REC_IP4 },
    { (char*)"icmpTypeCodeIPv6",                   2, NF9REC_IP6 },
    { (char*)"icmpTypeIPv6",                       1, NF9REC_IP6 },
    { (char*)"icmpCodeIPv6",                       1, NF9REC_IP6 },
    /* IPv4 Addresses */
    { (char*)"sourceIPv4Address",                  4, NF9REC_IP4 },
    { (char*)"destinationIPv4Address",             4, NF9REC_IP4 },
    { (char*)"ipNextHopIPv4Address",               4, NF9REC_IP4 },
    /* Pad to the firewall event: 3*(16-4)+4 */
    { (char*)"paddingOctets",                     40, NF9REC_IP4 },
    /* IPv6 Addresses */
    { (char*)"sourceIPv6Address",                 16, NF9REC_IP6 },
    { (char*)"destinationIPv6Address",            16, NF9REC_IP6 },
    { (char*)"ipNextHopIPv6Address",              16, NF9REC_IP6 },

    /* Firewall events */
    { (char*)"paddingOctets",                      4, NF9REC_IP6 },
    { (char*)"firewallEvent",                      1, 0 },
    { (char*)"NF_F_FW_EVENT",                      1, 0 },
    { (char*)"NF_F_FW_EXT_EVENT",                  2, 0 },
    FB_IESPEC_NULL
};

typedef struct ski_nf9rec_st {
    uint16_t        sourceTransportPort;            /*   0-  1 */
    uint16_t        destinationTransportPort;       /*   2-  3 */

    uint8_t         protocolIdentifier;             /*   4     */
    uint8_t         tcpControlBits;                 /*   5     */
    uint8_t         flowEndReason;                  /*   6     */
    uint8_t         ipClassOfService;               /*   7     */

    uint32_t        ingressInterface;               /*   8- 11 */
    uint32_t        egressInterface;                /*  12- 15 */

    /* may also hold packetTotalCount and octetTotalCount,
     * initiatorPackets and initiatorOctets */
    uint64_t        packetDeltaCount;               /*  16- 23 */
    uint64_t        octetDeltaCount;                /*  24- 31 */

    /* postPacketDeltaCount and postOctetDeltaCount; or
     * postPacketTotalCount and postPacketTotalCount; or
     * responderPackets and responderOctets when the NF9REC_INITIATOR
     * bit is set */
    uint64_t        postPacketDeltaCount;           /*  32- 39 */
    uint64_t        postOctetDeltaCount;            /*  40- 47 */

    union nf9rec_time_un {
        /* Traditional NetFlow time uses SysUptime */
        struct nf9rec_time_sysup_st {
            uint64_t        systemInitTimeMilliseconds;     /*  48- 55 */
            uint32_t        flowStartSysUpTime;             /*  56- 59 */
            uint32_t        flowEndSysUpTime;               /*  60- 63 */
        }           sysup;
        struct nf9rec_time_milli_st {
            uint64_t        flowStartMilliseconds;          /*  48- 55 */
            uint64_t        flowEndMilliseconds;            /*  56- 63 */
        }           milli;
    }               t;

    /* vlan IDs (reverse values below) */
    uint16_t        vlanId;                         /*  64- 65 */
    uint16_t        postVlanId;                     /*  66- 67 */

    /* ICMP, may be icmpTypeCodeIPv4 or icmpTypeCodeIPv6 */
    uint16_t        icmpTypeCode;                   /*  68- 69 */
    /* ICMP, may be icmpTypeIPv4 or icmpTypeIPv6 */
    uint8_t         icmpType;                       /*  70     */
    /* ICMP, may be icmpCodeIPv4 or icmpCodeIPv6 */
    uint8_t         icmpCode;                       /*  71     */

    union nf9rec_addr_un {
        struct nf9rec_ip4_st {
            uint32_t        sourceIPv4Address;              /*  72- 75 */
            uint32_t        destinationIPv4Address;         /*  76- 79 */
            uint32_t        ipNextHopIPv4Address;           /*  80- 83 */
        }           ip4;
        struct nf9rec_ip6_st {
            uint8_t         sourceIPv6Address[16];          /*  72- 87 */
            uint8_t         destinationIPv6Address[16];     /*  88-103 */
            uint8_t         ipNextHopIPv6Address[16];       /* 104-119 */
        }           ip6;
    }               addr;

    uint32_t        paddingOctets;                  /* 120-123 */
    /* Firewall events */
    uint8_t         firewallEvent;                  /* 124     */
    uint8_t         NF_F_FW_EVENT;                  /* 125     */
    uint16_t        NF_F_FW_EXT_EVENT;              /* 126-127 */
} ski_nf9rec_t;


/*
 *  **********  Tombstone Record Options Template  **********
 *
 *    Define the list of information elements and the corresponding
 *    structs for reading YAF Options Template records that contain a
 *    tombstone counter.  The templates and structs are used by
 *    ski_tombstone_next() when reading data.
 *
 *    The type for these records is SKI_RECTYPE_TOMBSTONE
 *
 *    The records include a subTemplateList represented by
 *    ski_tombstone_access_spec[], ski_tombstone_access_t, and
 *    SKI_TOMBSTONE_ACCESS_TID.
 */

#define SKI_TOMBSTONE_TID           0xAFEE

/* the internal template id */
#define SKI_TOMBSTONE_ACCESS_TID    0xAFE9

/* the external template id for the timestamp list */
#define SKI_YAF_TOMBSTONE_ACCESS    0xD002

/* tombstoneId, exporterConfiguredId, exporterUniqueId, certToolId,
 * and tombstoneAccessList are CERT_PEN elements, IDs 550-554 */
static fbInfoElementSpec_t ski_tombstone_spec[] = {
    { (char*)"observationDomainId",       4, 0 },    /* 149 */
    { (char*)"exportingProcessId",        4, 0 },    /* 144 */
    { (char*)"exporterConfiguredId",      2, 0 },    /* CERT_PEN, 551 */
    { (char*)"exporterUniqueId",          2, 0 },    /* CERT_PEN, 552 */
    { (char*)"paddingOctets",             4, 0 },    /* 210 */
    { (char*)"tombstoneId",               4, 0 },    /* CERT_PEN, 550 */
    { (char*)"observationTimeSeconds",    4, 0 },    /* 322 */
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    { (char*)"subTemplateList",           0, 0 },    /* 292 */
#if FIXBUF_CHECK_VERSION(2,3,0)
    /* because fixbuf < 2.3.0 does not decode list-type elements
     * correctly, only use the element with fixbuf >= 2.3.0. */
    { (char*)"tombstoneAccessList",       0, 0 },    /* CERT_PEN, 554 */
#endif
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */
    FB_IESPEC_NULL
};

typedef struct ski_tombstone_st {
    uint32_t    observationDomainId;            /*  0 -  3 */
    uint32_t    exportingProcessId;             /*  4 -  7 */
    uint16_t    exporterConfiguredId;           /*  8 -  9 */
    uint16_t    exporterUniqueId;               /* 10 - 11 */
    uint32_t    paddingOctets;                  /* 12 - 15 */
    uint32_t    tombstoneId;                    /* 16 - 19 */
    uint32_t    observationTimeSeconds;         /* 20 - 23 */
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    fbSubTemplateList_t stl;                    /* 24...   */
#if FIXBUF_CHECK_VERSION(2,3,0)
    fbSubTemplateList_t tombstoneAccessList;    /* ...     */
#endif
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */
} ski_tombstone_t;


/* The template used by the subTemplateList */
static fbInfoElementSpec_t ski_tombstone_access_spec[] = {
    { (char*)"certToolId",                4, 0 },    /* CERT_PEN, 553 */
    { (char*)"exportingProcessId",        4, 0 },    /* 144 */
    { (char*)"observationTimeSeconds",    4, 0 },    /* 322 */
    FB_IESPEC_NULL
};

typedef struct ski_tombstone_access_st {
    uint32_t certToolId;
    uint32_t exportingProcessId;
    uint32_t observationTimeSeconds;
} ski_tombstone_access_t;



/*
 *  **********  NetFlowV9 Sampling Options Template  **********
 *
 *    Define the list of information elements and the corresponding
 *    struct for reading NetFlowV9 Options Template records that
 *    contain sampling information.  The template and struct are used
 *    by ski_nf9sampling_next() when reading data.
 *
 *    The type for these records is SKI_RECTYPE_NF9SAMPLING
 */

#define SKI_NF9SAMPLING_TID     0xAFEF

#define SKI_NF9SAMPLING_PADDING 5

static fbInfoElementSpec_t ski_nf9sampling_spec[] = {
    { (char*)"samplingInterval",          4, 0 },    /* 34 */

    { (char*)"flowSamplerRandomInterval", 4, 1 },    /* 50, current fixbuf */
    { (char*)"samplerRandomInterval",     4, 2 },    /* 50, future fixbuf */

    { (char*)"samplingAlgorithm",         1, 0 },    /* 35 */

    { (char*)"flowSamplerMode",           1, 1 },    /* 49, current fixbuf */
    { (char*)"samplerMode",               1, 2 },    /* 49, future fixbuf */

    { (char*)"flowSamplerID",             1, 1 },    /* 48, current fixbuf */
    { (char*)"samplerId",                 1, 2 },    /* 48, future fixbuf */

#if SKI_NF9SAMPLING_PADDING != 0
    { (char*)"paddingOctets",             SKI_NF9SAMPLING_PADDING, 0 },
#endif
    FB_IESPEC_NULL
};

typedef struct ski_nf9sampling_st {
    uint32_t    samplingInterval;
    uint32_t    samplerRandomInterval;
    uint8_t     samplingAlgorithm;
    uint8_t     samplerMode;
    uint8_t     samplerId;
#if SKI_NF9SAMPLING_PADDING != 0
    uint8_t     paddingOctets[SKI_NF9SAMPLING_PADDING];
#endif
} ski_nf9sampling_t;


/*
 *  **********  Simple Template for Ignoring Data  **********
 *
 *    Simple template for reading data that is thrown away.  The
 *    template and struct are used by ski_ignore_next() when reading
 *    data.
 *
 *    The type for these records is SKI_RECTYPE_IGNORE
 */

#define SKI_IGNORE_TID          0x4444

static fbInfoElementSpec_t ski_ignore_spec[] = {
    { (char*)"systemInitTimeMilliseconds",         8, 0 },
    FB_IESPEC_NULL
};

typedef struct ski_ignore_st {
    uint64_t    systemInitTimeMilliseconds;
} ski_ignore_t;


/*
 *  **********  Union Across All Record Types  **********
 */

/* Types of IPFIX records.  Returned by ski_rectype_next(). */
typedef enum ski_rectype_en {
    SKI_RECTYPE_ERROR,
    SKI_RECTYPE_FIXREC,
    SKI_RECTYPE_YAFREC,
    SKI_RECTYPE_NF9REC,
    SKI_RECTYPE_YAFSTATS,
    SKI_RECTYPE_TOMBSTONE,
    SKI_RECTYPE_NF9SAMPLING,
    SKI_RECTYPE_IGNORE
} ski_rectype_t;

#if TRACEMSG_LEVEL >= 2
static const char *ski_rectype_name[] = {
    "SKI_RECTYPE_ERROR",
    "SKI_RECTYPE_FIXREC",
    "SKI_RECTYPE_YAFREC",
    "SKI_RECTYPE_NF9REC",
    "SKI_RECTYPE_YAFSTATS",
    "SKI_RECTYPE_TOMBSTONE",
    "SKI_RECTYPE_NF9SAMPLING",
    "SKI_RECTYPE_IGNORE"
};
#endif

struct ski_record_st {
    /* Template used to read this record */
    fbTemplate_t       *tmpl;
    /* The bitmap value that is tmpl's context */
    BMAP_TYPE           bmap;
    /* The ID of tmpl */
    uint16_t            tid;
    /* The record type that is decided from the bitmap */
    ski_rectype_t       rectype;
    /* A pointer to the forward rwRec to be filled */
    rwRec              *fwd_rec;
    /* A pointer to the reverse rwRec to be filled */
    rwRec              *rev_rec;
    /* The IPFIX record */
    union data_un {
        ski_fixrec_t        fixrec;
        ski_yafrec_t        yafrec;
        ski_nf9rec_t        nf9rec;
        ski_yafstats_t      yafstats;
        ski_tombstone_t     tombstone;
        ski_nf9sampling_t   nf9sampling;
        ski_ignore_t        ignore;
    }                   data;
};
typedef struct ski_record_st ski_record_t;



/*
 *  **********  FUNCTION DEFINITIONS  **********
 */

/*  Create macros to assist in creating TRACEMSG()s.  To avoid a C89
 *  compiler warning, put DEFINE_PREFIX_BUF() after other variable
 *  definitions but before any other code.  */
#if TRACEMSG_LEVEL < 2
#define DEFINE_PREFIX_BUF(varname)
#define makeTracemsgPrefix(_a, _b, _c, _d, _e, _f)
#else
#define DEFINE_PREFIX_BUF(varname)    char varname [512]
/*
 *    Format the probe name, template id, domain, and template pointer
 *    in a string buffer.
 */
static char *
makeTracemsgPrefix(
    char               *buf,
    size_t              buflen,
    const char         *probe_name,
    uint32_t            domain,
    uint16_t            tid,
    const fbTemplate_t *tmpl)
{
    snprintf(buf, buflen, "'%s': Template %#06x, domain %#x, [%p]",
             probe_name, tid, domain, (void *)tmpl);
    return buf;
}
#endif  /* TRACEMSG_LEVEL */

/*
 *    The skiTemplateCallbackCtx() callback is invoked whenever the
 *    session receives a new template.  This function must have the
 *    signature defined by a typedef defined by libfixbuf.
 *
 *    In fixbuf 2.x, the callback is set by calling
 *    fbSessionAddNewTemplateCallback() and its signature is given by
 *    'fbNewTemplateCallback_fn'.  In fixbuf 1.x, it is set by calling
 *    fbSessionAddTemplateCtxCallback2() and its signature is
 *    'fbTemplateCtxCallback2_fn'.
 *
 *    One purpose of the callback is the tell fixbuf how to process
 *    items in a subTemplateMultiList.  We tell fixbuf to map from
 *    the two templates that yaf uses for TCP flags (one of which has
 *    reverse elements and one of which does not) to the struct used
 *    in this file.
 *
 *    The callback also examines the template and sets a context
 *    pointer that contains high bits for certain information
 *    elements.  See the detailed comment above the "struct elem_st"
 *    definition.
 *
 *    Finally, if the probe has the SOURCE_LOG_TEMPLATES flag set or
 *    the global `show_templates` is true (the environment variable
 *    named by SKI_ENV_PRINT_TEMPLATES controls this), the templates
 *    are printed to the log file.  (`show_templates` is defined in
 *    probeconf.c.)
 */
static void
skiTemplateCallbackCtx(
    fbSession_t            *session,
    uint16_t                tid,
    fbTemplate_t           *tmpl,
    void                   *app_ctx,
    void                  **ctx,
#if FIXBUF_CHECK_VERSION(2,0,0)
    fbTemplateCtxFree_fn
#else
    fbTemplateCtxFree2_fn
#endif
    *ctx_free_fn)
{
#define TMPL_PROC_MSG2(is_option, wp2_tmpl_name)                        \
    DEBUGMSG(("'%s': Processing " is_option "template %#06x (%u),"      \
              " domain %#x, with the %s template"),                     \
             name, tid, tid, domain, (wp2_tmpl_name))

#define TMPL_PROC_MSG(wp_name)     TMPL_PROC_MSG2("", wp_name)
#define TMPL_PROC_MSG_OPT(wp_name) TMPL_PROC_MSG2("options ", wp_name)

    fbCollector_t *coll;
    const fbTemplateField_t *ie;
    const char *name;
    int show_tmpl;
    BMAP_TYPE out;
    uint64_t bmap;
    uint32_t domain;
    uint32_t count;
    uint32_t scope;
    uint32_t i;
    int known_id;
    DEFINE_PREFIX_BUF(prefix);

    TRACE_ENTRY;
    SK_UNUSED_PARAM(app_ctx);

    *ctx = NULL;
    *ctx_free_fn = NULL;

    domain = fbSessionGetDomain(session);
    count = fbTemplateCountElements(tmpl);
    scope = fbTemplateGetOptionsScope(tmpl);
    bmap = 0;
    out = 0;

    coll = fbSessionGetCollector(session);
    if (NULL == coll) {
        name = "<udp>";
        show_tmpl = show_templates;
    } else {
        const skIPFIXConnection_t *conn;
        const skIPFIXSource_t *source;
        conn = (skIPFIXConnection_t *)fbCollectorGetContext(coll);
        source = conn->source;
        name = source->name;
        show_tmpl = skpcProbeGetLogFlags(source->probe) & SOURCE_LOG_TEMPLATES;
    }

    makeTracemsgPrefix(prefix, sizeof(prefix), name, domain, tid,tmpl);
    TRACEMSG(2, ("%s skiTemplateCallbackCtx()", prefix));

    if (scope) {
        unsigned int samplingAlgorithm;
        unsigned int samplerMode;

        /* do not define any template pairs for this template */
        fbSessionAddTemplatePair(session, tid, 0);

        /* the sampling check requires multiple elements */
        samplingAlgorithm = samplerMode = 0;

        for (i = 0; i < count; ++i) {
            ie = fbTemplateGetFieldByPosition(tmpl, i);
            if (fbTemplateFieldGetPEN(ie) == 0) {
                switch (fbTemplateFieldGetId(ie)) {
                  case  34:
                  case  35:
                    /* verify that both samplingInterval and
                     * samplingAlgorithm are present */
                    ++samplingAlgorithm;
                    if (2 == samplingAlgorithm) {
                        bmap |= (1 | TMPL_BIT_samplingAlgorithm);
                    }
                    break;
                  case  49:
                  case  50:
                    /* verify that both samplerMode and
                     * samplerRandomInterval are present */
                    ++samplerMode;
                    if (2 == samplerMode) {
                        bmap |= (1 | TMPL_BIT_samplerMode);
                    }
                    break;
                }
            } else if (fbTemplateFieldGetPEN(ie) == IPFIX_CERT_PEN) {
                /* CERT PRIVATE ENTERPRISE ELEMENTS */
                switch (fbTemplateFieldGetId(ie)) {
                  case 104:
                    ASSERT_IE_NAME_IS(ie, flowTableFlushEventCount);
                    bmap |= (1 | TMPL_BIT_flowTableFlushEventCount);
                    break;
                  case 105:
                    ASSERT_IE_NAME_IS(ie, flowTablePeakCount);
                    bmap |= (1 | TMPL_BIT_flowTablePeakCount);
                    break;
                  case 550:
                    ASSERT_IE_NAME_IS(ie, tombstoneId);
                    bmap |= (1 | TMPL_BIT_tombstoneId);
                    break;
                }
            }
            TRACEMSG(
                3, ("%s bmap %#012" PRIx64 ", IE %s (%u/%u)",
                    prefix, bmap, fbTemplateFieldGetName(ie),
                    fbTemplateFieldGetPEN(ie), fbTemplateFieldGetId(ie)));
        }
        if (bmap) {
            out = (BMAP_TYPE)bmap;
            BMAP_TMPL_CTX_SET(ctx, ctx_free_fn, out);
        }
        TMPL_PROC_MSG_OPT(((bmap & (TMPL_BIT_flowTableFlushEventCount
                                    | TMPL_BIT_flowTablePeakCount))
                           ? "YAFstats"
                           : ((bmap & (TMPL_BIT_tombstoneId))
                              ? "tombstone"
                              : ((bmap & (TMPL_BIT_samplingAlgorithm
                                          | TMPL_BIT_samplerMode))
                                 ? "sampling"
                                 : "ignore"))));

    } else {
        /* populate the bitmap */
        for (i = 0; i < count; ++i) {
            ie = fbTemplateGetFieldByPosition(tmpl, i);
            if (fbTemplateFieldGetPEN(ie) == 0) {
                /* STANDARD ELEMENT */
                switch (fbTemplateFieldGetId(ie)) {
                  case   8:
                  case  12:
                    /* sourceIPv4Address and/or destinationIPv4Address */
                    bmap |= TMPL_BIT_sourceIPv4Address;
                    break;
                  case  27:
                  case  28:
                    /* sourceIPv6Address and/or destinationIPv6Address */
                    bmap |= TMPL_BIT_sourceIPv6Address;
                    break;
                  case 1:
                    /* octetDeltaCount */
                    bmap |= TMPL_BIT_octetDeltaCount;
                    break;
                  case 2:
                    /* packetDeltaCount */
                    bmap |= TMPL_BIT_packetDeltaCount;
                    break;
                  case 85:
                    /* octetTotalCount */
                    bmap |= TMPL_BIT_octetTotalCount;
                    break;
                  case 86:
                    /* packetTotalCount */
                    bmap |= TMPL_BIT_packetTotalCount;
                    break;
                  case 23:
                  case 24:
                    /* postOctetDeltaCount and/or postPacketDeltaCount */
                    bmap |= TMPL_BIT_postOctetDeltaCount;
                    break;
                  case 171:
                  case 172:
                    /* postOctetTotalCount and/or postPacketTotalCount */
                    bmap |= TMPL_BIT_postOctetTotalCount;
                    break;
                  case 32:
                  case 139:
                    /* icmpTypeCodeIPv4 and/or icmpTypeCodeIPv6 */
                    bmap |= TMPL_BIT_icmpTypeCodeIPv4;
                    break;
                  case 176:
                  case 177:
                  case 178:
                  case 179:
                    /* icmpTypeIPv4, icmpCodeIPv4, icmpTypeIPv6, and
                     * icmpCodeIPv6 all map to same position */
                    bmap |= TMPL_BIT_icmpTypeIPv4;
                    break;
                  case 231:
                  case 298:
                    /* initiatorOctets and/or initiatorPackets */
                    bmap |= TMPL_BIT_initiatorOctets;
                    break;
                  case 232:
                  case 299:
                    /* responderOctets and/or responderPackets */
                    bmap |= TMPL_BIT_responderOctets;
                    break;

                  case  22:
                    ASSERT_IE_NAME_IS(ie, flowStartSysUpTime);
                    bmap |= TMPL_BIT_flowStartSysUpTime;
                    break;
                  case  59:
                    ASSERT_IE_NAME_IS(ie, postVlanId);
                    bmap |= TMPL_BIT_postVlanId;
                    break;
                  case 144:
                    ASSERT_IE_NAME_IS(ie, exportingProcessId);
                    bmap |= TMPL_BIT_exportingProcessId;
                    break;
                  case 150:
                    ASSERT_IE_NAME_IS(ie, flowStartSeconds);
                    bmap |= TMPL_BIT_flowStartSeconds;
                    break;
                  case 151:
                    ASSERT_IE_NAME_IS(ie, flowEndSeconds);
                    bmap |= TMPL_BIT_flowEndSeconds;
                    break;
                  case 152:
                    ASSERT_IE_NAME_IS(ie, flowStartMilliseconds);
                    bmap |= TMPL_BIT_flowStartMilliseconds;
                    break;
                  case 153:
                    ASSERT_IE_NAME_IS(ie, flowEndMilliseconds);
                    bmap |= TMPL_BIT_flowEndMilliseconds;
                    break;
                  case 154:
                    ASSERT_IE_NAME_IS(ie, flowStartMicroseconds);
                    bmap |= TMPL_BIT_flowStartMicroseconds;
                    break;
                  case 155:
                    ASSERT_IE_NAME_IS(ie, flowEndMicroseconds);
                    bmap |= TMPL_BIT_flowEndMicroseconds;
                    break;
                  case 156:
                    ASSERT_IE_NAME_IS(ie, flowStartNanoseconds);
                    bmap |= TMPL_BIT_flowStartNanoseconds;
                    break;
                  case 157:
                    ASSERT_IE_NAME_IS(ie, flowEndNanoseconds);
                    bmap |= TMPL_BIT_flowEndNanoseconds;
                    break;
                  case 158:
                    ASSERT_IE_NAME_IS(ie, flowStartDeltaMicroseconds);
                    bmap |= TMPL_BIT_flowStartDeltaMicroseconds;
                    break;
                  case 159:
                    ASSERT_IE_NAME_IS(ie, flowEndDeltaMicroseconds);
                    bmap |= TMPL_BIT_flowEndDeltaMicroseconds;
                    break;
                  case 160:
                    ASSERT_IE_NAME_IS(ie, systemInitTimeMilliseconds);
                    bmap |= TMPL_BIT_systemInitTimeMilliseconds;
                    break;
                  case 161:
                    ASSERT_IE_NAME_IS(ie, flowDurationMilliseconds);
                    bmap |= TMPL_BIT_flowDurationMilliseconds;
                    break;
                  case 162:
                    ASSERT_IE_NAME_IS(ie, flowDurationMicroseconds);
                    bmap |= TMPL_BIT_flowDurationMicroseconds;
                    break;
                  case 233:
                    ASSERT_IE_NAME_IS(ie, firewallEvent);
                    bmap |= TMPL_BIT_firewallEvent;
                    break;
                  case 258:
                    ASSERT_IE_NAME_IS(ie, collectionTimeMilliseconds);
                    bmap |= TMPL_BIT_collectionTimeMilliseconds;
                    break;
                  case 293:
                    ASSERT_IE_NAME_IS(ie, subTemplateMultiList);
                    bmap |= TMPL_BIT_subTemplateMultiList;
                    break;
                  case 322:
                    ASSERT_IE_NAME_IS(ie, observationTimeSeconds);
                    bmap |= TMPL_BIT_observationTimeSeconds;
                    break;
                  case 323:
                    ASSERT_IE_NAME_IS(ie, observationTimeMilliseconds);
                    bmap |= TMPL_BIT_observationTimeMilliseconds;
                    break;
                  case 324:
                    ASSERT_IE_NAME_IS(ie, observationTimeMicroseconds);
                    bmap |= TMPL_BIT_observationTimeMicroseconds;
                    break;
                  case 325:
                    ASSERT_IE_NAME_IS(ie, observationTimeNanoseconds);
                    bmap |= TMPL_BIT_observationTimeNanoseconds;
                    break;

                  case FB_CISCO_ASA_EVENT_XTRA:
                    ASSERT_IE_NAME_IS(ie, NF_F_FW_EXT_EVENT);
                    bmap |= TMPL_BIT_NF_F_FW_EXT_EVENT;
                    break;
                  case FB_CISCO_ASA_EVENT_ID:
                    ASSERT_IE_NAME_IS(ie, NF_F_FW_EVENT);
                    bmap |= TMPL_BIT_NF_F_FW_EVENT;
                    break;
                }
            } else if (fbTemplateFieldGetPEN(ie) == FB_IE_PEN_REVERSE) {
                /* REVERSE VALUE OF STANDARD ELEMENTS */
                switch (fbTemplateFieldGetId(ie)) {
                  case 1:
                  case 2:
                    /* reverseOctetDeltaCount and/or
                     * reversePacketDeltaCount; for NetFlow v9 records
                     * they may hold post{Octet,Packet}DeltaCount when
                     * using libfixbuf prior to 1.8.0 */
                    bmap |= TMPL_BIT_reverseOctetDeltaCount;
                    break;
                  case 6:
                    ASSERT_IE_NAME_IS(ie, reverseTcpControlBits);
                    bmap |= TMPL_BIT_reverseTcpControlBits;
                    break;
                  case 58:
                    ASSERT_IE_NAME_IS(ie, reverseVlanId);
                    bmap |= TMPL_BIT_reverseVlanId;
                    break;
                }
            } else if (fbTemplateFieldGetPEN(ie) == IPFIX_CERT_PEN) {
                /* CERT PRIVATE ENTERPRISE ELEMENTS */
                switch (fbTemplateFieldGetId(ie)) {
                  case 14:
                    ASSERT_IE_NAME_IS(ie, initialTCPFlags);
                    bmap |= TMPL_BIT_initialTCPFlags;
                    break;
                  case 14 | FB_IE_VENDOR_BIT_REVERSE:
                    ASSERT_IE_NAME_IS(ie, reverseInitialTCPFlags);
                    bmap |= TMPL_BIT_reverseInitialTCPFlags;
                    break;
                  case 21:
                    ASSERT_IE_NAME_IS(ie, reverseFlowDeltaMilliseconds);
                    bmap |= TMPL_BIT_reverseFlowDeltaMilliseconds;
                    break;
                  case 553:
                    ASSERT_IE_NAME_IS(ie, certToolId);
                    bmap |= TMPL_BIT_certToolId;
                    break;
                }
            }
            TRACEMSG(
                3, ("%s bmap %#012" PRIx64 ", IE %s (%u/%u)",
                    prefix, bmap, fbTemplateFieldGetName(ie),
                    fbTemplateFieldGetPEN(ie), fbTemplateFieldGetId(ie)));
        }

        /* now that the bitmap is populated, see if it matches some
         * expected patterns */

        /* tell fixbuf how to transcode templates that appear in lists */
        if (bmap == TMPL_BIT_initialTCPFlags
            || bmap == (TMPL_BIT_initialTCPFlags
                        | TMPL_BIT_reverseInitialTCPFlags))
        {
            /* the template ID matches the ID for the YAF template
             * that contains TCP flags */
            fbSessionAddTemplatePair(session, tid, SKI_TCP_STML_TID);
            TMPL_PROC_MSG("YAF TCP flags list");
            known_id = 1;
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
        } else if ((bmap & TMPL_BIT_certToolId)
                   || ((bmap == (TMPL_BIT_exportingProcessId
                                 | TMPL_BIT_observationTimeSeconds)
                        && count == 2)))
        {
            /* the template ID matches the ID for the template that
             * contains tombstone timestamps */
            fbSessionAddTemplatePair(session, tid, SKI_TOMBSTONE_ACCESS_TID);
            TMPL_PROC_MSG("tombstone access");
            known_id = 1;
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */
        } else {
            /* do not define any template pairs for this template */
            fbSessionAddTemplatePair(session, tid, 0);
            known_id = 0;
            /* clear the exportingProcessId bit */
            bmap &= ~TMPL_BIT_exportingProcessId;
        }

        /* check whether the template may be processed by the YAF
         * template by: not using any IEs outside of those defined the
         * YAF template, by having IP addresses, by using millisecond
         * times, and by having consistent IEs for volume */
        if (known_id) {
            /* no more tests are needed */
        } else if (0 == (bmap & ~TMPL_MASK_YAFREC)
            && (bmap & TMPL_MASK_IPADDRESS)
            && (bmap & TMPL_MASK_TIME_MILLI_YAF)
            && (((bmap & TMPL_MASK_VOLUME_YAF)
                 == (TMPL_BIT_octetDeltaCount | TMPL_BIT_packetDeltaCount))
                || ((bmap & TMPL_MASK_VOLUME_YAF)
                    ==(TMPL_BIT_octetTotalCount | TMPL_BIT_packetTotalCount))))
        {
            /* Which volume element is present? */
            if ((bmap & TMPL_MASK_VOLUME_YAF)
                == (TMPL_BIT_octetDeltaCount | TMPL_BIT_packetDeltaCount))
            {
                out |= YAFREC_DELTA;
            } else {
                assert((TMPL_BIT_octetTotalCount | TMPL_BIT_packetTotalCount)
                       == (bmap & TMPL_MASK_VOLUME_YAF));
                out |= YAFREC_TOTAL;
            }
            /* Which IP addresses are present? */
            if ((bmap & TMPL_MASK_IPADDRESS) == TMPL_MASK_IPADDRESS) {
                /* Both are */
                out |= YAFREC_IP_BOTH;
            } else if (bmap & TMPL_BIT_sourceIPv6Address) {
                out |= YAFREC_ONLY_IP6;
            } else {
                assert(bmap & TMPL_BIT_sourceIPv4Address);
                out |= YAFREC_ONLY_IP4;
            }

            /* Are TCP flags available without visiting the STML? */
            if ((0 == (bmap & TMPL_BIT_initialTCPFlags))
                && (bmap & TMPL_BIT_subTemplateMultiList))
            {
                out |= YAFREC_STML;
            }
            /* Is it a uniflow or a bi flow? */
            if (bmap & TMPL_BIT_reverseFlowDeltaMilliseconds) {
                out |= YAFREC_BI;
            } else {
                out |= YAFREC_UNI;
            }
            out |= (SKI_YAFREC_TID
                    | (bmap & (TMPL_BIT_reverseVlanId |
                               TMPL_BIT_reverseTcpControlBits |
                               TMPL_BIT_reverseInitialTCPFlags |
                               TMPL_BIT_icmpTypeCodeIPv4)));
            BMAP_TMPL_CTX_SET(ctx, ctx_free_fn, out);
            TMPL_PROC_MSG("YAF");

        /* check whether the template may be processed by the NetFlow
         * v9 template by not having any IEs outside of that set */
        } else if ((0 == (bmap & ~TMPL_MASK_NF9REC))
                   && (bmap & TMPL_MASK_IPADDRESS))
        {
            /* this do{}while(0) is not a loop, it is just something that
             * "break;" works with */
            do {
                /* Which IP addresses are present? */
                if ((bmap &  TMPL_MASK_IPADDRESS)==TMPL_BIT_sourceIPv6Address){
                    out |= NF9REC_IP6;
                } else if ((bmap &  TMPL_MASK_IPADDRESS)
                           == TMPL_BIT_sourceIPv4Address)
                {
                    out |= NF9REC_IP4;
                } else {
                    /* cannot use the nf9rec template */
                    out = 0;
                    break;
                }

                /* Which time is present */
                if ((bmap & TMPL_MASK_TIME_NF9)== TMPL_MASK_TIME_SYSUP) {
                    out |= NF9REC_SYSUP;
                } else if (((bmap & TMPL_MASK_TIME_NF9)
                            == TMPL_MASK_TIME_MILLI_NF9)
                           || ((bmap & TMPL_MASK_TIME_NF9)
                               == TMPL_BIT_observationTimeMilliseconds))
                {
                    out |= NF9REC_MILLI;
                } else {
                    /* cannot use the nf9rec template */
                    out = 0;
                    break;
                }

                /* Which volume is present */
                if (((bmap & TMPL_MASK_VOLUME_NF9)
                     & (TMPL_BIT_initiatorOctets
                        | TMPL_BIT_responderOctets))
                    && 0 == ((bmap & TMPL_MASK_VOLUME_NF9)
                             & ~(TMPL_BIT_initiatorOctets
                                 | TMPL_BIT_responderOctets)))
                {
                    out |= NF9REC_INITIATOR;
                } else if (((bmap & TMPL_MASK_VOLUME_NF9)
                            & (TMPL_BIT_octetDeltaCount
                               | TMPL_BIT_packetDeltaCount
                               | TMPL_BIT_postOctetDeltaCount))
                           && 0 == ((bmap & TMPL_MASK_VOLUME_NF9)
                                    & ~(TMPL_BIT_octetDeltaCount
                                        | TMPL_BIT_packetDeltaCount
                                        | TMPL_BIT_postOctetDeltaCount)))
                {
                    out |= NF9REC_DELTA;
                } else if (((bmap & TMPL_MASK_VOLUME_NF9)
                            & (TMPL_BIT_octetTotalCount
                               | TMPL_BIT_packetTotalCount
                               | TMPL_BIT_postOctetTotalCount))
                           && 0 == ((bmap & TMPL_MASK_VOLUME_NF9)
                                    & ~(TMPL_BIT_octetTotalCount
                                        | TMPL_BIT_packetTotalCount
                                        | TMPL_BIT_postOctetTotalCount)))
                {
                    out |= NF9REC_TOTAL;
                } else if (((bmap & TMPL_MASK_VOLUME_NF9) == 0)
                           && (bmap & (TMPL_BIT_firewallEvent
                                       | TMPL_BIT_NF_F_FW_EVENT)))
                {
                    out |= NF9REC_INITIATOR;
                } else {
                    /* cannot use the nf9rec template */
                    out = 0;
                    break;
                }

                out |= (SKI_NF9REC_TID
                        | (bmap & (TMPL_BIT_icmpTypeCodeIPv4 |
                                   TMPL_BIT_icmpTypeIPv4 |
                                   TMPL_BIT_firewallEvent |
                                   TMPL_BIT_NF_F_FW_EVENT |
                                   TMPL_BIT_NF_F_FW_EXT_EVENT)));
                BMAP_TMPL_CTX_SET(ctx, ctx_free_fn, out);
                TMPL_PROC_MSG("NFv9");
            } while (0);
        }

        if (*ctx != NULL || known_id != 0) {
            /* template is already handled */
        } else if (bmap) {
            out = 1 | (BMAP_TYPE)bmap;
            BMAP_TMPL_CTX_SET(ctx, ctx_free_fn, out);
            TMPL_PROC_MSG("generic");
        } else {
            TMPL_PROC_MSG("ignore");
        }
    }

#if TRACEMSG_LEVEL >= 2
    if (*ctx) {
        TRACEMSG(2, ("%s bmap " BMAP_PRI ", written", prefix, out));
    }
#endif

    if (show_tmpl) {
        char buf[0x4000];
        char *b = buf;
        ssize_t rem = sizeof(buf);
        ssize_t sz;

        *b = '\0';
        for (i = 0; i < count && rem > 2; ++i) {
            ie = fbTemplateGetFieldByPosition(tmpl, i);
            assert(b < (buf + sizeof(buf)));
            if (0 == fbTemplateFieldGetPEN(ie)) {
                sz = snprintf(b, rem, "%s %s(%u)[%u]%s",
                              ((i > 0) ? "," : ""),
                              fbTemplateFieldGetName(ie),
                              fbTemplateFieldGetId(ie),
                              fbTemplateFieldGetLen(ie),
                             ((i < scope) ? "{scope}" : ""));
            } else {
                sz = snprintf(b, rem, "%s %s(%u/%u)[%u]%s",
                              ((i > 0) ? "," : ""),
                              fbTemplateFieldGetName(ie),
                              fbTemplateFieldGetPEN(ie),
                              fbTemplateFieldGetId(ie),
                              fbTemplateFieldGetLen(ie),
                              ((i < scope) ? "{scope}" : ""));
            }
            rem -= sz;
            b += sz;
        }
        INFOMSG(("'%s': Contents of %stemplate %#06x (%u),"
                 " domain %#x, %" PRIu32 " elements:%s"),
                name, ((scope) ? "options " : ""), tid, tid,
                domain, count, buf);
    }
}


/*
 *    Initialize an fbSession object that reads from either the
 *    network or from a file.
 *
 *    This function updates the fbSession object with (1) the
 *    received-new-template callback function and (2) all the
 *    templates used when transcoding the incoming data.
 */
int
skiSessionInitReader(
    fbSession_t        *session,
    GError            **err)
{
    fbInfoModel_t   *model;
    fbTemplate_t    *tmpl;
    const uint32_t yafrec_spec_flags[] = {
        /* exported by YAF, either biflow or uniflow, either IPv4 or
         * IPv6 (never both), either delta count or total count, with
         * or without an STML */
        YAFREC_BI  | YAFREC_ONLY_IP4 | YAFREC_DELTA | YAFREC_STML,
        YAFREC_BI  | YAFREC_ONLY_IP4 | YAFREC_TOTAL | YAFREC_STML,
        YAFREC_BI  | YAFREC_ONLY_IP6 | YAFREC_DELTA | YAFREC_STML,
        YAFREC_BI  | YAFREC_ONLY_IP6 | YAFREC_TOTAL | YAFREC_STML,

        YAFREC_UNI | YAFREC_ONLY_IP4 | YAFREC_DELTA | YAFREC_STML,
        YAFREC_UNI | YAFREC_ONLY_IP4 | YAFREC_TOTAL | YAFREC_STML,
        YAFREC_UNI | YAFREC_ONLY_IP6 | YAFREC_DELTA | YAFREC_STML,
        YAFREC_UNI | YAFREC_ONLY_IP6 | YAFREC_TOTAL | YAFREC_STML,

        YAFREC_BI  | YAFREC_ONLY_IP4 | YAFREC_DELTA,
        YAFREC_BI  | YAFREC_ONLY_IP4 | YAFREC_TOTAL,
        YAFREC_BI  | YAFREC_ONLY_IP6 | YAFREC_DELTA,
        YAFREC_BI  | YAFREC_ONLY_IP6 | YAFREC_TOTAL,

        YAFREC_UNI | YAFREC_ONLY_IP4 | YAFREC_DELTA,
        YAFREC_UNI | YAFREC_ONLY_IP4 | YAFREC_TOTAL,
        YAFREC_UNI | YAFREC_ONLY_IP6 | YAFREC_DELTA,
        YAFREC_UNI | YAFREC_ONLY_IP6 | YAFREC_TOTAL,

        /* created by SiLK; always uniflow, never with an STML, always
         * delta count; may have both IPv4 and IPv6 */
        YAFREC_UNI | YAFREC_DELTA | YAFREC_IP_BOTH,
        0                       /* sentinal */
    };
    const uint32_t nf9rec_spec_flags[] = {
        NF9REC_IP4 | NF9REC_SYSUP | NF9REC_DELTA,
        NF9REC_IP4 | NF9REC_MILLI | NF9REC_DELTA,
        NF9REC_IP6 | NF9REC_SYSUP | NF9REC_DELTA,
        NF9REC_IP6 | NF9REC_MILLI | NF9REC_DELTA,

        NF9REC_IP4 | NF9REC_SYSUP | NF9REC_TOTAL,
        NF9REC_IP4 | NF9REC_MILLI | NF9REC_TOTAL,
        NF9REC_IP6 | NF9REC_SYSUP | NF9REC_TOTAL,
        NF9REC_IP6 | NF9REC_MILLI | NF9REC_TOTAL,

        NF9REC_IP4 | NF9REC_SYSUP | NF9REC_INITIATOR,
        NF9REC_IP4 | NF9REC_MILLI | NF9REC_INITIATOR,
        NF9REC_IP6 | NF9REC_SYSUP | NF9REC_INITIATOR,
        NF9REC_IP6 | NF9REC_MILLI | NF9REC_INITIATOR,

        0                       /* sentinal */
    };
    uint32_t i;
    uint16_t tid;


    /* assert that we are not replacing an existing template */
#ifdef  NDEBUG
#define ASSERT_NO_TMPL(m_session, m_tid, m_err)
#else
#define ASSERT_NO_TMPL(m_session, m_tid, m_err)                         \
    do {                                                                \
        assert(fbSessionGetTemplate(m_session, TRUE, (m_tid), m_err)    \
               == NULL);                                                \
        assert(g_error_matches(*(m_err), FB_ERROR_DOMAIN, FB_ERROR_TMPL)); \
        g_clear_error(m_err);                                           \
    } while(0)
#endif  /* #else of #ifdef NDEBUG */

    model = fbSessionGetInfoModel(session);

    /* Add the "Give me everything" record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_fixrec_spec, sampler_flags, err)){
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_FIXREC_TID, err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_FIXREC_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the TCP record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_tcp_stml_spec, 0, err)) {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_TCP_STML_TID, err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_TCP_STML_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the yaf stats record template  */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_yafstats_spec, 0, err)) {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_YAFSTATS_TID, err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_YAFSTATS_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the yaf tombstone record template  */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_tombstone_spec, 0, err)) {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_TOMBSTONE_TID, err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_TOMBSTONE_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the yaf tombstone record template  */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_tombstone_access_spec, 0, err)) {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_TOMBSTONE_ACCESS_TID, err);
    if (!fbSessionAddTemplate(
            session, TRUE, SKI_TOMBSTONE_ACCESS_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the netflow v9 sampling options template  */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(
            tmpl, ski_nf9sampling_spec, sampler_flags, err))
    {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_NF9SAMPLING_TID,err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_NF9SAMPLING_TID, tmpl, err)){
        goto ERROR;
    }

    /* Add the "do nothing/ignore record" template  */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ski_ignore_spec, 0, err)) {
        goto ERROR;
    }
    ASSERT_NO_TMPL(session, SKI_IGNORE_TID, err);
    if (!fbSessionAddTemplate(session, TRUE, SKI_IGNORE_TID, tmpl, err)) {
        goto ERROR;
    }

    /* Add the various ski_yafrec_spec templates */
    for (i = 0; yafrec_spec_flags[i] != 0; ++i) {
        tmpl = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(
                tmpl, ski_yafrec_spec, yafrec_spec_flags[i], err))
        {
            goto ERROR;
        }
        tid = (SKI_YAFREC_TID | yafrec_spec_flags[i]);
        ASSERT_NO_TMPL(session, tid, err);
        if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, err)) {
            goto ERROR;
        }
    }

    /* Add the various ski_nf9rec_spec templates */
    for (i = 0; nf9rec_spec_flags[i] != 0; ++i) {
        tmpl = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(
                tmpl, ski_nf9rec_spec, nf9rec_spec_flags[i], err))
        {
            goto ERROR;
        }
        tid = (SKI_NF9REC_TID | nf9rec_spec_flags[i]);
        ASSERT_NO_TMPL(session, tid, err);
        if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, err)) {
            goto ERROR;
        }
    }

    /* Invoke the function above when a new template arrives. */
#if FIXBUF_CHECK_VERSION(2,0,0)
    fbSessionAddNewTemplateCallback(session, &skiTemplateCallbackCtx, NULL);
#else
    fbSessionAddTemplateCtxCallback2(session, &skiTemplateCallbackCtx, NULL);
#endif

    TRACE_RETURN(1);

  ERROR:
    fbTemplateFreeUnused(tmpl);
    TRACE_RETURN(0);
}


/* **************************************************************
 * *****  Support for reading/import
 */

/**
 *    Use the external template of the next record to determine its
 *    type.
 *
 *    Fill the 'tmpl' member of 'record' with the incoming template
 *    for the next record, fill the 'bmap' member of 'record' with the
 *    bitmap settings for that template, fill the 'rectype' member of
 *    'record' with the next record's type, and return that type.
 */
static ski_rectype_t
ski_rectype_next(
    fBuf_t             *fbuf,
    ski_record_t       *record,
    GError            **err)
{
    record->tmpl = fBufNextCollectionTemplate(fbuf, &record->tid, err);
    if (record->tmpl == NULL) {
        return (record->rectype = SKI_RECTYPE_ERROR);
    }
    record->bmap = BMAP_TMPL_CTX_GET(record->tmpl);

    /* Handle Records that use an Options Template */
    if (fbTemplateGetOptionsScope(record->tmpl)) {
        if (record->bmap & (TMPL_BIT_flowTableFlushEventCount
                            | TMPL_BIT_flowTablePeakCount))
        {
            return (record->rectype = SKI_RECTYPE_YAFSTATS);
        }
        if (record->bmap & TMPL_BIT_tombstoneId) {
            return (record->rectype = SKI_RECTYPE_TOMBSTONE);
        }
        if (record->bmap
            & (TMPL_BIT_samplingAlgorithm | TMPL_BIT_samplerMode))
        {
            return (record->rectype = SKI_RECTYPE_NF9SAMPLING);
        }
        return (record->rectype = SKI_RECTYPE_IGNORE);
    }

    switch (record->bmap & BMAP_RECTYPE_MASK) {
      case 4:
        return (record->rectype = SKI_RECTYPE_YAFREC);
      case 2: case 6:
        return (record->rectype = SKI_RECTYPE_NF9REC);
      case 1: case 3: case 5: case 7:
        return (record->rectype = SKI_RECTYPE_FIXREC);
      case 0:
        break;
      default:
        skAbortBadCase(record->bmap & BMAP_RECTYPE_MASK);
    }
    return (record->rectype = SKI_RECTYPE_IGNORE);
}


/**
 *    Call fBufNext() and transcode the data into the
 *    ski_yafstats_spec template.  Return 1 on success or 0 on
 *    failure.
 */
static int
ski_yafstats_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    size_t len;
    DEFINE_PREFIX_BUF(prefix);

    SK_UNUSED_PARAM(probe);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_yafstats_next()"),
                 prefix, record->bmap));
    assert(SKI_RECTYPE_YAFSTATS == record->rectype);

    /* Set internal template to read a yaf stats record */
    if (!fBufSetInternalTemplate(fbuf, SKI_YAFSTATS_TID, err)) {
        return FALSE;
    }

    len = sizeof(record->data.yafstats);
    return fBufNext(fbuf, (uint8_t *)&record->data.yafstats, &len, err);
}


/**
 *    Update the statistics on 'source' by, for each field, adding to
 *    'source' the difference of the value the field in 'record' from
 *    the value of the field in 'previous'.  Finally, copy the values
 *    from 'current' into 'previous'.
 */
static void
ski_yafstats_update_source(
    skIPFIXSource_t    *source,
    const ski_record_t *record,
    ski_yafstats_t     *previous)
{
    const ski_yafstats_t *current;

    assert(SKI_RECTYPE_YAFSTATS == record->rectype);

    current = &record->data.yafstats;

    DEBUGMSG("'%s': Got a yaf stats record", source->name);
    TRACEMSG(1, (("'%s': "
                 "inittime %" PRIu64
                 ", dropped %" PRIu64
                 ", ignored %" PRIu64
                 ", notsent %" PRIu64
                 ", expired %" PRIu32
                 ", pkttotal %" PRIu64
                 ", exported %" PRIu64),
                 source->name,
                 current->systemInitTimeMilliseconds,
                 current->droppedPacketTotalCount,
                 current->ignoredPacketTotalCount,
                 current->notSentPacketTotalCount,
                 current->expiredFragmentCount,
                 current->packetTotalCount,
                 current->exportedFlowRecordTotalCount));

    if (current->systemInitTimeMilliseconds
        != previous->systemInitTimeMilliseconds)
    {
        memset(previous, 0, sizeof(*previous));
    }

    pthread_mutex_lock(&source->stats_mutex);                           \
    source->saw_yafstats_pkt = 1;                                      \
    source->yaf_dropped_packets += (current->droppedPacketTotalCount
                                    - previous->droppedPacketTotalCount);
    source->yaf_ignored_packets += (current->ignoredPacketTotalCount
                                    - previous->ignoredPacketTotalCount);
    source->yaf_notsent_packets += (current->notSentPacketTotalCount
                                    - previous->notSentPacketTotalCount);
    source->yaf_expired_fragments += (current->expiredFragmentCount
                                      - previous->expiredFragmentCount);
    source->yaf_processed_packets += (current->packetTotalCount
                                      - previous->packetTotalCount);
    source->yaf_exported_flows += (current->exportedFlowRecordTotalCount
                                   - previous->exportedFlowRecordTotalCount);
    pthread_mutex_unlock(&source->stats_mutex);
    *previous = *current;
}


#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
/**
 *    Add the access time 'seconds' for tool 'tool_id' to 'buffer'.
 */
static ssize_t
ski_tombstone_add_access(
    char               *buffer,
    size_t              length,
    uint32_t            seconds,
    uint32_t            tool_id)
{
    static const char *tool[] = {
        "unknown(0)", "yaf", "super_mediator", "rwflowpack", "rwflowappend",
        "mothra-packer", "pipeline"
    };
    char stime_buf[SKTIMESTAMP_STRLEN];

    sktimestamp_r(stime_buf, sktimeCreate(seconds, 0),
                  SKTIMESTAMP_UTC | SKTIMESTAMP_NOMSEC);
    if (tool_id < sizeof(tool)/sizeof(tool[0])) {
        return snprintf(buffer, length, "; process: %s, time: %sZ",
                        tool[tool_id], stime_buf);
    }
    return snprintf(buffer,length,"; process: unknown(%" PRIu32 "), time: %sZ",
                    tool_id, stime_buf);
}
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */

/**
 *    Read a YAF Options Record containing the tombstone counter and
 *    print a log message.
 */
static gboolean
ski_tombstone_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    const ski_tombstone_access_t *ts_access;
    void *stl;
#endif
    const ski_tombstone_t *ts;
    char buf[1024];
    char *b;
    size_t len;
    ssize_t sz;

    makeTracemsgPrefix(buf, sizeof(buf), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_tombstone_next()"),
                 buf, record->bmap));
    assert(SKI_RECTYPE_TOMBSTONE == record->rectype);

    /* Set internal template to read the options record */
    if (!fBufSetInternalTemplate(fbuf, SKI_TOMBSTONE_TID, err)) {
        return FALSE;
    }
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    fbSubTemplateListCollectorInit(&record->data.tombstone.stl);
#if FIXBUF_CHECK_VERSION(2,3,0)
    fbSubTemplateListCollectorInit(&record->data.tombstone.tombstoneAccessList);
#endif
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */

    len = sizeof(record->data.tombstone);
    if (!fBufNext(fbuf, (uint8_t *)&record->data.tombstone, &len, err)) {
        return FALSE;
    }
    assert(len == sizeof(ski_tombstone_t));
    ts = &record->data.tombstone;

    len = sizeof(buf);
    b = buf;

    if (ts->stl.numElements) {
        /* This tombstone record pre-dates YAF 2.11 */
        assert(0 == ts->exportingProcessId);
        sz = snprintf(b, len, ("'%s': Received tombstone record:"
                               " exporterId: %u:%u, tombstoneId: %u"),
                      skpcProbeGetName(probe), ts->exporterConfiguredId,
                      ts->exporterUniqueId, ts->tombstoneId);
        if (len < (size_t)sz) {
            goto WRITEMSG;
        }
        b += sz;
        len -= sz;

#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
        stl = NULL;
        while ((stl = fbSubTemplateListGetNextPtr(&ts->stl, stl))) {
            ts_access = (ski_tombstone_access_t *)stl;
            sz = ski_tombstone_add_access(b, len,
                                          ts_access->observationTimeSeconds,
                                          ts_access->exportingProcessId);
            if (len < (size_t)sz) {
                goto WRITEMSG;
            }
            b += sz;
            len -= sz;
        }
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */
    } else {
        /* This tombstone record is from YAF 2.11 or later */
        assert(0 == ts->exporterUniqueId);
        sz = snprintf(b, len, ("'%s': Received Tombstone record:"
                               " observationDomain:%u,"
                               " exporterId:%u:%u, tombstoneId: %u"),
                      skpcProbeGetName(probe), ts->observationDomainId,
                      ts->exporterConfiguredId, ts->exportingProcessId,
                      ts->tombstoneId);
        if (len < (size_t)sz) {
            goto WRITEMSG;
        }
        b += sz;
        len -= sz;

#if SKIPFIX_ENABLE_TOMBSTONE_TIMES && FIXBUF_CHECK_VERSION(2,3,0)
        stl = NULL;
        while ((stl = fbSubTemplateListGetNextPtr(&ts->tombstoneAccessList,
                                                  stl)))
        {
            ts_access = (ski_tombstone_access_t *)stl;
            sz = ski_tombstone_add_access(b, len,
                                          ts_access->observationTimeSeconds,
                                          ts_access->certToolId);
            if (len < (size_t)sz) {
                goto WRITEMSG;
            }
            b += sz;
            len -= sz;
        }
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */
    }

  WRITEMSG:
    buf[sizeof(buf)-1] = '\0';
    DEBUGMSG("%s", buf);

#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    fbSubTemplateListClear((fbSubTemplateList_t *)&ts->stl);
#if FIXBUF_CHECK_VERSION(2,3,0)
    fbSubTemplateListClear((fbSubTemplateList_t *)&ts->tombstoneAccessList);
#endif
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */

    return TRUE;
}


/* Determine which names are used for certain elements in the
 * information model. */
void
ski_nf9sampling_check_spec(
    void)
{
    fbInfoModel_t *model;
    const fbInfoElementSpec_t *spec;
    uint32_t flags;

    model = skiInfoModel();
    flags = 0;

    for (spec = ski_nf9sampling_spec; spec->name; ++spec) {
        if (0 == spec->flags) {
            assert(fbInfoModelGetElementByName(model, spec->name));
        }
        else if (fbInfoModelGetElementByName(model, spec->name)) {
            if (0 == flags) {
                flags = spec->flags;
            } else if (spec->flags != flags) {
                skAppPrintErr("Info Element '%s' is in model; flags = %u",
                              spec->name, flags);
                skAbort();
            }
        } else if (flags && spec->flags == flags) {
            skAppPrintErr("Info Element '%s' not in model; flags = %u",
                          spec->name, flags);
            skAbort();
        }
    }

    sampler_flags = flags;

    skiInfoModelFree();
}


/**
 *    Read a NetFlowV9 Options Record regarding the flow sampling rate
 *    and write a message to the log file.
 */
static gboolean
ski_nf9sampling_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    size_t len;

    DEFINE_PREFIX_BUF(prefix);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_nf9sampling_next()"),
                 prefix, record->bmap));
    assert(SKI_RECTYPE_NF9SAMPLING == record->rectype);

    /* Set internal template to read the options record */
    if (!fBufSetInternalTemplate(fbuf, SKI_NF9SAMPLING_TID, err)) {
        return FALSE;
    }

    len = sizeof(record->data.nf9sampling);
    if (!fBufNext(fbuf, (uint8_t *)&record->data.nf9sampling, &len, err)) {
        return FALSE;
    }
    assert(len == sizeof(ski_nf9sampling_t));

    if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_SAMPLING) {
        if (record->bmap & TMPL_BIT_samplingAlgorithm) {
            INFOMSG("'%s': Sampling Algorithm %u; Sampling Interval %u",
                    skpcProbeGetName(probe),
                    record->data.nf9sampling.samplingAlgorithm,
                    record->data.nf9sampling.samplingInterval);
        } else if (record->bmap & TMPL_BIT_samplerMode) {
            INFOMSG(("'%s': Flow Sampler Id %u; Flow Sampler Mode %u;"
                     " Flow Sampler Random Interval %u"),
                    skpcProbeGetName(probe),
                    record->data.nf9sampling.samplerId,
                    record->data.nf9sampling.samplerMode,
                    record->data.nf9sampling.samplerRandomInterval);
        }
    }
    return TRUE;
}


/**
 *    Call fBufNext() and transcode the data into the ski_ignore_spec
 *    template.  Return 1 on success or 0 on failure.
 */
static int
ski_ignore_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    size_t len;
    DEFINE_PREFIX_BUF(prefix);

    SK_UNUSED_PARAM(probe);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_ignore_next()"),
                 prefix, record->bmap));

    if (!fBufSetInternalTemplate(fbuf, SKI_IGNORE_TID, err)) {
        return FALSE;
    }

    len = sizeof(record->data.ignore);
    return fBufNext(fbuf, (uint8_t *)&record->data.ignore, &len, err);
}


/*
 *    Convert the NTP timestamp (RFC1305) contained in 'ntp' to epoch
 *    milliseconds.  The 'is_micro' field should be 0 if the function
 *    is decoding dateTimeNanoseconds and non-zero when decoding
 *    dateTimeMicroseconds.
 *
 *    An NTP timestamp is a 64 bit value that has whole seconds in the
 *    upper 32 bits and fractional seconds in the lower 32 bits.  Each
 *    fractional second represents 1/(2^32)th of a second.
 *
 *    In addition, NTP uses an epoch time of Jan 1, 1900.
 *
 *    When the 'is_micro' flag is set, decoding must ignore the 11
 *    lowest bits of the fractional part of the timestamp.
 *
 *    If 'ntp' is 0, assume the element was not in the model and
 *    return 0.
 */
static uint64_t
skiNTPDecode(
    uint64_t            ntp,
    int                 is_micro)
{
    /* the UNIX epoch as a number of seconds since NTP epoch */
#define JAN_1970  UINT64_C(0x83AA7E80)

    double frac;
    uint64_t t;

    if (!ntp) {
        return 0;
    }
    /* handle fractional seconds; convert to milliseconds */
    frac = (1000.0 * (ntp & (is_micro ? UINT32_C(0xFFFFF800) : UINT32_MAX))
            / (double)UINT64_C(0x100000000));

    /* handle whole seconds, convert to milliseconds */
    t = ((ntp >> 32) - JAN_1970) * 1000;

    return t + (uint64_t)frac;
}


/*
 *    Run the Gauntlet of Time.
 *
 *    Set the start-time and duration of the 'fwd_rec' member of
 *    'record' by checking the 'fixrec' member for the dozen or so
 *    time fields that IPFIX provides.
 */
static void
skiGauntletOfTime(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe)
{
    struct log_rec_time_st {
        /* "raw" start time from the record */
        uint64_t        start_val;
        /* name of the IE in the 'start_val' member, NULL if none */
        const char     *start_name;
        /* "raw" end time from the record */
        uint64_t        end_val;
        /* name of the IE in the 'end_val' member, NULL if none */
        const char     *end_name;
        /* "raw" duration time from the record */
        uint64_t        dur_val;
        /* name of the IE in the 'dur_val' member, NULL if none */
        const char     *dur_name;
    } log_rec_time = {
        0, NULL, 0, NULL, 0, NULL
    };
    char stime_buf[SKTIMESTAMP_STRLEN];
    uint64_t sTime, eTime;
    uint32_t duration;
    sktime_t export_time;
    intmax_t uptime, difference;
    sktime_t export_msec;
    const char *rollover_first;
    const char *rollover_last = "";
    const ski_fixrec_t *fixrec;
    rwRec *rec;

    /* which of sTime(1), duration(2), and eTime(4) were found, and
     * whether export_time(8) was used for sTime or eTime */
    unsigned int time_fields;

#define COMPUTE_DURATION(s_time, e_time)                        \
    (((e_time < s_time) || ((e_time - s_time) > UINT32_MAX))    \
     ? UINT32_MAX                                               \
     : (e_time - s_time))

#define RECORD_SET_TIME_RETURN_NO_LOG(s_time, elapsed)                  \
    rwRecSetStartTime(rec, (sktime_t)s_time);                           \
    rwRecSetElapsed(rec, elapsed);                                      \
    if (!(skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS)) {       \
        return;                                                         \
    }

    fixrec = &record->data.fixrec;
    rec = record->fwd_rec;

    TRACEMSG(3, ("bmap & time_mask: " BMAP_PRI " => " BMAP_PRI,
                 record->bmap,
                 (BMAP_TYPE)(record->bmap & TMPL_MASK_GAUNTLET_OF_TIME)));

    switch (record->bmap & TMPL_MASK_GAUNTLET_OF_TIME) {
      case (TMPL_BIT_flowStartMilliseconds | TMPL_BIT_flowEndMilliseconds):
        sTime = fixrec->flowStartMilliseconds;
        eTime = fixrec->flowEndMilliseconds;
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, COMPUTE_DURATION(sTime, eTime));
        time_fields = 5;
        log_rec_time.start_val = fixrec->flowStartMilliseconds;
        log_rec_time.start_name = "flowStartMilliseconds";
        log_rec_time.end_val = fixrec->flowEndMilliseconds;
        log_rec_time.end_name = "flowEndMilliseconds";
        break;

      case (TMPL_BIT_flowStartSeconds | TMPL_BIT_flowEndSeconds):
        sTime = sktimeCreate(fixrec->flowStartSeconds, 0);
        eTime = sktimeCreate(fixrec->flowEndSeconds, 0);
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, COMPUTE_DURATION(sTime, eTime));
        time_fields = 5;
        log_rec_time.start_val = fixrec->flowStartSeconds;
        log_rec_time.start_name = "flowStartSeconds";
        log_rec_time.end_val = fixrec->flowEndSeconds;
        log_rec_time.end_name = "flowEndSeconds";
        break;

      case (TMPL_BIT_flowStartMicroseconds | TMPL_BIT_flowEndMicroseconds):
        sTime = skiNTPDecode(fixrec->flowStartMicroseconds, 1);
        eTime = skiNTPDecode(fixrec->flowEndMicroseconds, 1);
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, COMPUTE_DURATION(sTime, eTime));
        time_fields = 5;
        log_rec_time.start_val = fixrec->flowStartMicroseconds;
        log_rec_time.start_name = "flowStartMicroseconds";
        log_rec_time.end_val = fixrec->flowEndMicroseconds;
        log_rec_time.end_name = "flowEndMicroseconds";
        break;

      case (TMPL_BIT_flowStartNanoseconds | TMPL_BIT_flowEndNanoseconds):
        sTime = skiNTPDecode(fixrec->flowStartNanoseconds, 0);
        eTime = skiNTPDecode(fixrec->flowEndNanoseconds, 0);
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, COMPUTE_DURATION(sTime, eTime));
        time_fields = 5;
        log_rec_time.start_val = fixrec->flowStartNanoseconds;
        log_rec_time.start_name = "flowStartNanoseconds";
        log_rec_time.end_val = fixrec->flowEndNanoseconds;
        log_rec_time.end_name = "flowEndNanoseconds";
        break;

      case (TMPL_BIT_flowStartDeltaMicroseconds
            | TMPL_BIT_flowEndDeltaMicroseconds):
        export_time = sktimeCreate(fBufGetExportTime(fbuf), 0);
        sTime = (export_time - fixrec->flowStartDeltaMicroseconds / 1000);
        eTime = (export_time - fixrec->flowEndDeltaMicroseconds / 1000);
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, COMPUTE_DURATION(sTime, eTime));
        time_fields = 13;
        log_rec_time.start_val = fixrec->flowStartDeltaMicroseconds;
        log_rec_time.start_name = "flowStartDeltaMicroseconds";
        log_rec_time.end_val = fixrec->flowEndDeltaMicroseconds;
        log_rec_time.end_name = "flowEndDeltaMicroseconds";
        break;

      case (TMPL_BIT_flowStartMilliseconds| TMPL_BIT_flowDurationMilliseconds):
        sTime = fixrec->flowStartMilliseconds;
        duration = fixrec->flowDurationMilliseconds;
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, duration);
        time_fields = 3;
        log_rec_time.start_val = fixrec->flowStartMilliseconds;
        log_rec_time.start_name = "flowStartMilliseconds";
        log_rec_time.dur_val = fixrec->flowDurationMilliseconds;
        log_rec_time.dur_name = "flowDurationMilliseconds";
        break;

      case (TMPL_BIT_flowStartMicroseconds| TMPL_BIT_flowDurationMicroseconds):
        sTime = skiNTPDecode(fixrec->flowStartMicroseconds, 1);
        duration = fixrec->flowDurationMicroseconds / 1000;
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, duration);
        time_fields = 3;
        log_rec_time.start_val = fixrec->flowStartMicroseconds;
        log_rec_time.start_name = "flowStartMicroseconds";
        log_rec_time.dur_val = fixrec->flowDurationMicroseconds;
        log_rec_time.dur_name = "flowDurationMicroseconds";
        break;

      case 0:
        /* no times, set start to export time and set dur to 0 */
        sTime = sktimeCreate(fBufGetExportTime(fbuf), 0);
        RECORD_SET_TIME_RETURN_NO_LOG(sTime, 0);
        time_fields = 0;
        break;

      case (TMPL_BIT_flowStartSysUpTime | TMPL_BIT_systemInitTimeMilliseconds):
        /* Times based on flow generator system uptimes (Netflow v9) */

        /* Compute the uptime: systemInitTimeMilliseconds is the
         * absolute router boot time (msec), and libfixbuf sets it by
         * subtracting the NFv9 uptime (msec) from the record's
         * absolute export time (sec). */
        export_msec = sktimeCreate(fBufGetExportTime(fbuf), 0);
        uptime = export_msec - fixrec->systemInitTimeMilliseconds;
        if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_NF9_SYSUPTIME_SECS) {
            /* uptime was reported in seconds, not msec */
            TRACEMSG(3, (("Before adjustment: exportTimeMillisec %" PRIu64
                          ", initTimeMillisec %" PRIu64 ", upTime %" PRIdMAX
                          ", startUpTime %" PRIu32 ", endUpTime %" PRIu32
                          ", packets %" PRIu32),
                         export_msec, fixrec->systemInitTimeMilliseconds,
                         uptime, fixrec->flowStartSysUpTime,
                         fixrec->flowEndSysUpTime, rwRecGetPkts(rec)));
            uptime *= 1000;
            record->data.fixrec.systemInitTimeMilliseconds
                = export_msec - uptime;
            if (rwRecGetPkts(rec) == 1
                && (fixrec->flowEndSysUpTime < fixrec->flowStartSysUpTime))
            {
                /* sometimes the end time for single packet flows is
                 * very different than the start time. */
                record->data.fixrec.flowEndSysUpTime
                    = record->data.fixrec.flowStartSysUpTime;
            }
        }

        /* Set the duration. */
        if (fixrec->flowStartSysUpTime <= fixrec->flowEndSysUpTime) {
            rwRecSetElapsed(rec, (fixrec->flowEndSysUpTime
                                  - fixrec->flowStartSysUpTime));
        } else {
            /* assume EndTime rolled-over and start did not */
            rwRecSetElapsed(rec, (ROLLOVER32 + fixrec->flowEndSysUpTime
                                  - fixrec->flowStartSysUpTime));
            rollover_last = ", assume flowEndSysUpTime rollover";
        }
        /* Set start time. */
        difference = uptime - fixrec->flowStartSysUpTime;
        if (difference > MAXIMUM_FLOW_TIME_DEVIATION) {
            /* assume upTime is set before record is composed and
             * that start-time has rolled over. */
            rwRecSetStartTime(rec, (fixrec->systemInitTimeMilliseconds
                                    + fixrec->flowStartSysUpTime
                                    + ROLLOVER32));
            rollover_first = ", assume flowStartSysUpTime rollover";
        } else if (-difference > MAXIMUM_FLOW_TIME_DEVIATION) {
            /* assume upTime is set after record is composed and
             * that upTime has rolled over. */
            rwRecSetStartTime(rec, (fixrec->systemInitTimeMilliseconds
                                    + fixrec->flowStartSysUpTime
                                    - ROLLOVER32));
            rollover_first = ", assume sysUpTime rollover";
        } else {
            /* times look reasonable; assume no roll over */
            rwRecSetStartTime(rec, (fixrec->systemInitTimeMilliseconds
                                    + fixrec->flowStartSysUpTime));
            rollover_first = "";
        }
        if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS) {
            sktimestamp_r(stime_buf, rwRecGetStartTime(rec), SKTIMESTAMP_UTC);
            INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                     " flowStartSysUpTime=%" PRIu32
                     ", flowEndSysUpTime=%" PRIu32
                     ", systemInitTimeMilliseconds=%" PRIu64
                     ", exportTimeSeconds=%" PRIu32
                     ", calculated sysUpTime=%" PRIdMAX "%s%s"),
                    skpcProbeGetName(probe),
                    stime_buf, (double)rwRecGetElapsed(rec)/1000,
                    fixrec->flowStartSysUpTime, fixrec->flowEndSysUpTime,
                    fixrec->systemInitTimeMilliseconds,
                    fBufGetExportTime(fbuf), uptime,
                    rollover_first, rollover_last);
        }
        return;

      case (TMPL_BIT_flowStartSysUpTime):
        /* Times based on flow generator system uptimes (Netflow v9),
         * but there is no system init time and we do not know when
         * the router booted.  assume end-time is same as the record's
         * export time and set start-time accordingly. */
        if (fixrec->flowStartSysUpTime <= fixrec->flowEndSysUpTime) {
            rwRecSetElapsed(rec, (fixrec->flowEndSysUpTime
                                  - fixrec->flowStartSysUpTime));
        } else {
            /* assume EndTime rolled-over and start did not */
            rwRecSetElapsed(rec, (ROLLOVER32 + fixrec->flowEndSysUpTime
                                  - fixrec->flowStartSysUpTime));
            rollover_last = ", assume flowEndSysUpTime rollover";
        }
        /* Set start time. */
        export_msec = sktimeCreate(fBufGetExportTime(fbuf), 0);
        rwRecSetStartTime(rec, export_msec - rwRecGetElapsed(rec));
        if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS) {
            sktimestamp_r(stime_buf, rwRecGetStartTime(rec), SKTIMESTAMP_UTC);
            INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                     " flowStartSysUpTime=%" PRIu32
                     ", flowEndSysUpTime=%" PRIu32
                     ", no systemInitTimeMilliseconds"
                     ", set end to exportTimeSeconds=%" PRIu32 "%s"),
                    skpcProbeGetName(probe),
                    stime_buf, (double)rwRecGetElapsed(rec)/1000,
                    fixrec->flowStartSysUpTime, fixrec->flowEndSysUpTime,
                    fBufGetExportTime(fbuf), rollover_last);
        }
        return;

      default:
        time_fields = 0;
        /* look for all possible start times */
        if (record->bmap & TMPL_BIT_flowStartMilliseconds) {
            time_fields |= 1;
            sTime = fixrec->flowStartMilliseconds;
            log_rec_time.start_val = fixrec->flowStartMilliseconds;
            log_rec_time.start_name = "flowStartMilliseconds";
        } else if (record->bmap & TMPL_BIT_flowStartSeconds) {
            time_fields |= 1;
            sTime = UINT64_C(1000) * (uint64_t)fixrec->flowStartSeconds;
            log_rec_time.start_val = fixrec->flowStartSeconds;
            log_rec_time.start_name = "flowStartSeconds";
        } else if (record->bmap & TMPL_BIT_flowStartMicroseconds) {
            time_fields |= 1;
            sTime = skiNTPDecode(fixrec->flowStartMicroseconds, 1);
            log_rec_time.start_val = fixrec->flowStartMicroseconds;
            log_rec_time.start_name = "flowStartMicroseconds";
        } else if (record->bmap & TMPL_BIT_flowStartNanoseconds) {
            time_fields |= 1;
            sTime = skiNTPDecode(fixrec->flowStartNanoseconds, 0);
            log_rec_time.start_val = fixrec->flowStartNanoseconds;
            log_rec_time.start_name = "flowStartNanoseconds";
        } else if (record->bmap & TMPL_BIT_flowStartDeltaMicroseconds) {
            time_fields |= 9;
            sTime = (fBufGetExportTime(fbuf) * 1000
                     - fixrec->flowStartDeltaMicroseconds / 1000);
            log_rec_time.start_val = fixrec->flowStartDeltaMicroseconds;
            log_rec_time.start_name = "flowStartDeltaMicroseconds";
        } else if (record->bmap & TMPL_BIT_flowStartSysUpTime) {
            /* must be additional time fields present that prevented
             * the switch from matching; mask those out and call this
             * function again */
            BMAP_TYPE bmap_orig = record->bmap;
            record->bmap = bmap_orig & (TMPL_BIT_flowStartSysUpTime
                                        | TMPL_BIT_systemInitTimeMilliseconds);
            TRACEMSG(1, ("Unusual time fields present on record"));
            skiGauntletOfTime(fbuf, record, probe);
            record->bmap = bmap_orig;
            return;
        } else {
            sTime = 0;
        }

        /* look for all possible end times; if none found look for
         * collection/observation times */
        if (record->bmap & TMPL_BIT_flowEndMilliseconds) {
            time_fields |= 4;
            eTime = fixrec->flowEndMilliseconds;
            log_rec_time.end_val = fixrec->flowEndMilliseconds;
            log_rec_time.end_name = "flowEndMilliseconds";
        } else if (record->bmap & TMPL_BIT_flowEndSeconds) {
            time_fields |= 4;
            eTime = UINT64_C(1000) * (uint64_t)fixrec->flowEndSeconds;
            log_rec_time.end_val = fixrec->flowEndSeconds;
            log_rec_time.end_name = "flowEndSeconds";
        } else if (record->bmap & TMPL_BIT_flowEndMicroseconds) {
            time_fields |= 4;
            eTime = skiNTPDecode(fixrec->flowEndMicroseconds, 1);
            log_rec_time.end_val = fixrec->flowEndMicroseconds;
            log_rec_time.end_name = "flowEndMicroseconds";
        } else if (record->bmap & TMPL_BIT_flowEndNanoseconds) {
            time_fields |= 4;
            eTime = skiNTPDecode(fixrec->flowEndNanoseconds, 0);
            log_rec_time.end_val = fixrec->flowEndNanoseconds;
            log_rec_time.end_name = "flowEndNanoseconds";
        } else if (record->bmap & TMPL_BIT_flowEndDeltaMicroseconds) {
            time_fields |= 12;
            eTime = (fBufGetExportTime(fbuf) * 1000
                     - fixrec->flowEndDeltaMicroseconds / 1000);
            log_rec_time.end_val = fixrec->flowEndDeltaMicroseconds;
            log_rec_time.end_name = "flowEndDeltaMicroseconds";
        } else if (record->bmap & TMPL_BIT_collectionTimeMilliseconds) {
            time_fields |= 4;
            eTime = fixrec->collectionTimeMilliseconds;
            log_rec_time.end_val = fixrec->collectionTimeMilliseconds;
            log_rec_time.end_name = "collectionTimeMilliseconds";
        } else if (record->bmap & TMPL_BIT_observationTimeMilliseconds) {
            time_fields |= 4;
            eTime = fixrec->observationTimeMilliseconds;
            log_rec_time.end_val = fixrec->observationTimeMilliseconds;
            log_rec_time.end_name = "observationTimeMilliseconds";
        } else if (record->bmap & TMPL_BIT_observationTimeSeconds) {
            time_fields |= 4;
            eTime = UINT64_C(1000) * (uint64_t)fixrec->observationTimeSeconds;
            log_rec_time.end_val = fixrec->observationTimeSeconds;
            log_rec_time.end_name = "observationTimeSeconds";
        } else if (record->bmap & TMPL_BIT_observationTimeMicroseconds) {
            time_fields |= 4;
            eTime = skiNTPDecode(fixrec->observationTimeMicroseconds, 1);
            log_rec_time.end_val = fixrec->observationTimeMicroseconds;
            log_rec_time.end_name = "observationTimeMicroseconds";
        } else if (record->bmap & TMPL_BIT_observationTimeNanoseconds) {
            time_fields |= 4;
            eTime = skiNTPDecode(fixrec->observationTimeNanoseconds, 0);
            log_rec_time.end_val = fixrec->observationTimeNanoseconds;
            log_rec_time.end_name = "observationTimeNanoseconds";
        } else {
            eTime = 0;
        }

        /* look for durations */
        if (record->bmap & TMPL_BIT_flowDurationMilliseconds) {
            time_fields |= 2;
            duration = fixrec->flowDurationMilliseconds;
            log_rec_time.dur_val = fixrec->flowDurationMilliseconds;
            log_rec_time.dur_name = "flowDurationMilliseconds";
        } else if (record->bmap & TMPL_BIT_flowDurationMicroseconds) {
            time_fields |= 2;
            duration = fixrec->flowDurationMicroseconds / 1000;
            log_rec_time.dur_val = fixrec->flowDurationMicroseconds;
            log_rec_time.dur_name = "flowDurationMicroseconds";
        } else {
            duration = 0;
        }

        /* set the time fields on the record */
        switch (time_fields) {
          case 3: case 7: case 11: case 15:
            /* have start and duration; use them; ignore eTime if
             * present */
            RECORD_SET_TIME_RETURN_NO_LOG(sTime, duration);
            break;

          case 5: case 13:
            /* have start and end; use them */
            RECORD_SET_TIME_RETURN_NO_LOG(
                sTime, COMPUTE_DURATION(sTime, eTime));
            break;

          case 1: case 9:
            /* only have a start time; use it and set dur to 0 */
            RECORD_SET_TIME_RETURN_NO_LOG(sTime, 0);
            break;

          case 6: case 14:
            /* have dur and end time; compute start */
            sTime = (sktime_t)(eTime - duration);
            RECORD_SET_TIME_RETURN_NO_LOG(sTime, duration);
            break;

          case 2:
            /* only have a duration; use export time as end time */
            sTime = sktimeCreate(fBufGetExportTime(fbuf),0) - duration;
            RECORD_SET_TIME_RETURN_NO_LOG(sTime, duration);
            break;

          case 4: case 12:
            /* only have an end time; use it as start time and set dur
             * to 0 */
            RECORD_SET_TIME_RETURN_NO_LOG(eTime, 0);
            sTime = eTime;
            break;

          case 0:
            /* no times, set start to export time and set dur to 0 */
            sTime = sktimeCreate(fBufGetExportTime(fbuf), 0);
            RECORD_SET_TIME_RETURN_NO_LOG(sTime, 0);
            break;

          case 8: case 10:
          default:
            skAbortBadCase(time_fields);
        }
        /* close the default: clause */
        break;
    }

    /* Should only get here when logging was requested */
    assert(skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS);
    sktimestamp_r(stime_buf, sTime, SKTIMESTAMP_UTC);
    switch (time_fields) {
      case 3:
      case 7:
        /* stime, duration, and maybe etime (which is ignored) */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.start_name,log_rec_time.start_val,
                log_rec_time.dur_name, log_rec_time.dur_val);
        break;

      case 11:
      case 15:
        /* as above, with export time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64 ", exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.start_name,log_rec_time.start_val,
                log_rec_time.dur_name, log_rec_time.dur_val,
                fBufGetExportTime(fbuf));
        break;

      case 5:
        /* stime and etime */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.start_name,log_rec_time.start_val,
                log_rec_time.end_name, log_rec_time.end_val);
        break;

      case 13:
        /* stime and etime, with export time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64 ", exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.start_name,log_rec_time.start_val,
                log_rec_time.end_name, log_rec_time.end_val,
                fBufGetExportTime(fbuf));
        break;

      case 1:
        /* stime only */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64),
                skpcProbeGetName(probe), stime_buf, 0.0,
                log_rec_time.start_name,log_rec_time.start_val);
        break;

      case 9:
        /* stime only with an export time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf, 0.0,
                log_rec_time.start_name,log_rec_time.start_val,
                fBufGetExportTime(fbuf));
        break;

      case 6:
        /* duration and end time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.dur_name, log_rec_time.dur_val,
                log_rec_time.end_name, log_rec_time.end_val);
        break;

      case 14:
        /* duration and end time, with an export time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", %s=%" PRIu64 ", exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.dur_name, log_rec_time.dur_val,
                log_rec_time.end_name, log_rec_time.end_val,
                fBufGetExportTime(fbuf));
        break;

      case 2:
        /* duration only */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", set end to exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(rec)/1000,
                log_rec_time.dur_name, log_rec_time.dur_val,
                fBufGetExportTime(fbuf));
        break;

      case 4:
        /* end time only */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64),
                skpcProbeGetName(probe), stime_buf, 0.0,
                log_rec_time.end_name, log_rec_time.end_val);
        break;

      case 12:
        /* end time only, with export time */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " %s=%" PRIu64 ", exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf, 0.0,
                log_rec_time.end_name, log_rec_time.end_val,
                fBufGetExportTime(fbuf));
        break;

      case 0:
        /* no times */
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs based on"
                 " exportTimeSeconds=%" PRIu32),
                skpcProbeGetName(probe), stime_buf, 0.0,
                fBufGetExportTime(fbuf));
        break;

      case 8:
      case 10:
      default:
        skAbortBadCase(time_fields);
    }
}


/**
 *    Print a log message saying why a ski_fixrec_t record was ignored
 */
static void
ski_fixrec_ignore(
    const ski_fixrec_t *fixrec,
    const char         *reason)
{
    skipaddr_t ipaddr;
    char sipbuf[64];
    char dipbuf[64];

    if (!SK_IPV6_IS_ZERO(fixrec->sourceIPv6Address)) {
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &fixrec->sourceIPv6Address,
                       sipbuf, sizeof(sipbuf)))
#endif
        {
            strcpy(sipbuf, "unknown-v6");
        }
    } else {
        skipaddrSetV4(&ipaddr, &fixrec->sourceIPv4Address);
        skipaddrString(sipbuf, &ipaddr, SKIPADDR_CANONICAL);
    }
    if (!SK_IPV6_IS_ZERO(fixrec->destinationIPv6Address)) {
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &fixrec->destinationIPv6Address,
                       dipbuf, sizeof(dipbuf)))
#endif
        {
            strcpy(dipbuf, "unknown-v6");
        }
    } else {
        skipaddrSetV4(&ipaddr, &fixrec->destinationIPv4Address);
        skipaddrString(dipbuf, &ipaddr, SKIPADDR_CANONICAL);
    }

    INFOMSG(("IGNORED|%s|%s|%u|%u|%u|%" PRIu64 "|%" PRIu64 "|%s|"),
            sipbuf, dipbuf, fixrec->sourceTransportPort,
            fixrec->destinationTransportPort,fixrec->protocolIdentifier,
            ((fixrec->packetDeltaCount)
             ? fixrec->packetDeltaCount
             : ((fixrec->packetTotalCount)
                ? fixrec->packetTotalCount
                : fixrec->initiatorPackets)),
            ((fixrec->octetDeltaCount)
             ? fixrec->octetDeltaCount
             : ((fixrec->octetTotalCount)
                ? fixrec->octetTotalCount
                : fixrec->initiatorOctets)),
            reason);
}


/**
 *    Call fBufNext() and transcode the data into the ski_fixrec_spec
 *    template, then convert the structure into 0, 1, or 2 SiLK Flow
 *    records and fill the record pointers on the 'record' structure.
 *    The return value indicates the number of records converted.
 *    Return -1 on failure.
 *
 *    The reverse record is cleared via RWREC_CLEAR() when the return
 *    value is 1.
 *
 *    Return 0 if the IPFIX record should be ignored.  The forward rec
 *    will have been cleared; the reverse record is untouched.  A
 *    record can be ignored when (1)the record is IPv6 and SiLK is
 *    compiled without IPv6 support, (2)the record has a packet and/or
 *    byte count of 0, or (3)the record is explicitly marked as an
 *    "intermediate" record by yaf.
 *
 *    Return -1 on failure.  The forward rec will have been cleared;
 *    the reverse record is untouched.
 */
static int
ski_fixrec_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    fbSubTemplateMultiListEntry_t *stml;
    ski_fixrec_t *fixrec;
    size_t len;
    uint64_t pkts, bytes;
    uint64_t rev_pkts, rev_bytes;
    uint8_t tcp_state;
    uint8_t tcp_flags;
    int have_tcp_stml = 0;
    rwRec *fwd_rec;

    DEFINE_PREFIX_BUF(prefix);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_fixrec_next()"),
                 prefix, record->bmap));
    assert(SKI_RECTYPE_FIXREC == record->rectype);

    /* Get a local handle to the record and clear it */
    fwd_rec = record->fwd_rec;
    RWREC_CLEAR(fwd_rec);

    /* Set internal template to read an extended flow record */
    if (!fBufSetInternalTemplate(fbuf, SKI_FIXREC_TID, err)) {
        return -1;
    }

    /* Get the next record */
    len = sizeof(record->data.fixrec);
    if (!fBufNext(fbuf, (uint8_t *)&record->data.fixrec, &len, err)) {
        return -1;
    }
    assert(len == sizeof(ski_fixrec_t));
    fixrec = &record->data.fixrec;

    if ((fixrec->flowEndReason & SKI_END_MASK)== SKI_END_YAF_INTERMEDIATE_FLOW)
    {
        TRACEMSG(2, ("Ignored YAF intermediate uniflow"));
        return 0;
    }

    /* Ignore records with no IPs.  Ignore records that do not have
     * IPv4 addresses when SiLK was built without IPv6 support. */
    if (record->bmap & TMPL_BIT_sourceIPv4Address) {
        /* we're good */
    } else if (record->bmap & TMPL_BIT_sourceIPv6Address) {
#if !SK_ENABLE_IPV6
        ski_fixrec_ignore(fixrec, "IPv6 record");
        return 0;
#endif  /* SK_ENABLE_IPV6 */
    } else if ((skpcProbeGetQuirks(probe) & SKPC_QUIRK_MISSING_IPS) == 0) {
        ski_fixrec_ignore(fixrec, "No IP addresses");
        return 0;
    }

    if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_NF9_OUT_IS_REVERSE) {
        TRACEMSG(
            2, (("Setting reverse Octet/Packet counts (currently"
                 " %" PRIu64 "/%" PRIu64 ") to post Octet/Packet counts"
                 " (%" PRIu64 "/%" PRIu64 ") due to nf9-out-is-reverse"),
                fixrec->reverseOctetDeltaCount,fixrec->reversePacketDeltaCount,
                fixrec->postOctetDeltaCount, fixrec->postPacketDeltaCount));
        fixrec->reverseOctetDeltaCount = fixrec->postOctetDeltaCount;
        fixrec->reversePacketDeltaCount = fixrec->postPacketDeltaCount;
        fixrec->postOctetDeltaCount = fixrec->postPacketDeltaCount = 0;
    }

    /* Get the forward and reverse packet and byte counts (run the
     * Gauntlet of Volume). */
    pkts = ((fixrec->packetDeltaCount)
            ? fixrec->packetDeltaCount
            : ((fixrec->packetTotalCount)
               ? fixrec->packetTotalCount
               : ((fixrec->initiatorPackets)
                  ? fixrec->initiatorPackets
                  : ((fixrec->postPacketDeltaCount)
                     ? fixrec->postPacketDeltaCount
                     : fixrec->postPacketTotalCount))));
    bytes = ((fixrec->octetDeltaCount)
             ? fixrec->octetDeltaCount
             : ((fixrec->octetTotalCount)
                ? fixrec->octetTotalCount
                : ((fixrec->initiatorOctets)
                   ? fixrec->initiatorOctets
                   : ((fixrec->postOctetDeltaCount)
                      ? fixrec->postOctetDeltaCount
                      : fixrec->postOctetTotalCount))));

    /* I suppose we could add checks for
     * reversePost{Packet,Octet}{Delta,Total}Count here as well. */
    rev_pkts = ((fixrec->reversePacketDeltaCount)
                ? fixrec->reversePacketDeltaCount
                : ((fixrec->reversePacketTotalCount)
                   ? fixrec->reversePacketTotalCount
                   : fixrec->responderPackets));
    rev_bytes = ((fixrec->reverseOctetDeltaCount)
                 ? fixrec->reverseOctetDeltaCount
                 : ((fixrec->reverseOctetTotalCount)
                    ? fixrec->reverseOctetTotalCount
                    : fixrec->responderOctets));

    /*
     *  Handle records that represent a "firewall event" when the
     *  SKPC_QUIRK_FW_EVENT quirks value is set on the probe.  When
     *  the quirk is not set, process the records normally.
     *
     *  This code changed in SiLK 3.8.0.  Prior to SiLK 3.8.0, all
     *  firewall event status messages were dropped.
     *
     *  It seems that every record from a Cisco ASA has
     *  <strike>NF_F_FW_EVENT</strike> and NF_F_FW_EXT_EVENT
     *  information elements, so ignoring flow records with these
     *  elements means ignoring all flow records.
     *
     *  It now (2015-June) seems that the NF_F_FW_EVENT information
     *  element mentioned in the previous paragraph has been replaced
     *  with firewallEvent (IE 233).
     *
     *  firewallEvent is an official IPFIX information element, IE 233
     *
     *  NF_F_FW_EVENT is Cisco IE 40005
     *
     *  NF_F_FW_EXT_EVENT is Cisco IE 33002.
     *
     *  Note that the Cisco IE numbers cannot be used in IPFIX because
     *  IPFIX would treat them as "reverse" records.
     *
     *  References (October 2013):
     *  http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.html#wp1028202
     *  http://www.cisco.com/en/US/docs/security/asa/asa84/system/netflow/netflow.pdf
     *
     *  Values for the NF_F_FW_EXT_EVENT depend on the values for the
     *  firewallEvent or NF_F_FW_EVENT.  The following lists the
     *  FW_EVENT with sub-bullets for the NF_F_FW_EXT_EVENT.
     *
     *  0.  Ignore -- This value indicates that a field must be
     *      ignored.
     *
     *      0.  Ignore -- This value indicates that the field must be
     *          ignored.
     *
     *  1.  Flow created -- This value indicates that a new flow was
     *      created.
     *
     *  2.  Flow deleted -- This value indicates that a flow was
     *      deleted.
     *
     *    >2000.  Values above 2000 represent various reasons why a
     *            flow was terminated.
     *
     *  3.  Flow denied -- This value indicates that a flow was
     *      denied.
     *
     *    >1000.  Values above 1000 represent various reasons why a
     *            flow was denied.
     *
     *     1001.  A flow was denied by an ingress ACL.
     *
     *     1002.  A flow was denied by an egress ACL.
     *
     *     1003.  The ASA denied an attempt to connect to the (ASA's)
     *            interface service.
     *
     *     1004.  The flow was denied because the first packet on the
     *            TCP was not a TCP SYN packet.
     *
     *  5.  Flow updated -- This value indicates that a flow update
     *      timer went off or a flow was torn down.
     *
     *  The IPFIX values for the firewallEvent IE follow those for
     *  NF_F_FW_EVENT (with IPFIX providing no explanation as to what
     *  the values mean! --- some standard) and IPFIX adds the value:
     *
     *  4.  Flow alert.
     *
     *  PROCESSING RULES:
     *
     *  The term "ignore" below means that a log message is written
     *  and that no SiLK flow record is created.
     *
     *  Ignore flow records where the "flow ignore" event is present.
     *
     *  Treat records where "flow deleted" is specified as actual flow
     *  records to be processed and stored.
     *
     *  Ignore "flow created" events, since we will handle these flows
     *  when the "flow deleted" event occurs.  Also, a short-lived
     *  flow record may produce a "flow deleted" event without a "flow
     *  created" event.
     *
     *  For a "flow denied" event, write a special value into the SiLK
     *  Flow record that the writing thread can use to categorize the
     *  record as innull/outnull.
     *
     *  It is unclear how to handle "flow updated" events. If the
     *  record is only being updated, presumably SiLK will get a "flow
     *  deleted" event in the future.  However, if the flow is being
     *  torn down, will the ASA send a separate "flow deleted" event?
     *  For now (as of SiLK 3.8.0), ignore "flow updated" events.
     *
     *  Ignore "flow alert" events.
     *
     *
     *  Firewall events, byte and packet counts, and the Cisco ASA:
     *
     *  1.  Flow created events have a byte and packet count of 0;
     *  this is fine since we are ignoring these flows.
     *
     *  2.  Flow deinied events have a byte and packet count of 0.
     *  SiLK will ignore these flows unless we doctor them to have a
     *  non-zero byte and packet count, which we do when the ASA hack
     *  is enabled.
     *
     *  3.  Flow deleted events have a packet count of 0, but we have
     *  code below to work around that when the ASA hack is enabled.
     *  The flows usally have a non-zero byte count.  However, some
     *  flow records have a 0-byte count, and (July 2015) we have been
     *  told one source of these records are packets to an un-opened
     *  port.  Previouly these flows were ignored, but as of SiLK
     *  3.11.0 we doctor the records to have a byte count of 1.
     */
    if ((skpcProbeGetQuirks(probe) & SKPC_QUIRK_FW_EVENT)
        && (record->bmap & (TMPL_BIT_firewallEvent | TMPL_BIT_NF_F_FW_EVENT
                            | TMPL_BIT_NF_F_FW_EXT_EVENT)))
    {
        char msg[64];
        uint8_t event = (fixrec->firewallEvent
                         ? fixrec->firewallEvent : fixrec->NF_F_FW_EVENT);
        if (SKIPFIX_FW_EVENT_DELETED == event) {
            /* flow deleted */
            TRACEMSG(1,(("Processing flow deleted event as actual flow record;"
                         " firewallEvent=%u, NF_F_FW_EVENT=%u,"
                         " NF_F_FW_EXT_EVENT=%u"),
                      fixrec->firewallEvent, fixrec->NF_F_FW_EVENT,
                      fixrec->NF_F_FW_EXT_EVENT));
            /* these normally have a byte count, but not always */
            if (0 == bytes) {
                if (0 == pkts) {
                    TRACEMSG(1, ("Setting forward bytes and packets to 1"
                                 " for deleted firewall event"));
                    bytes = 1;
                    pkts = 1;
                } else {
                    TRACEMSG(1, ("Setting forward bytes equal to packets value"
                                 " for deleted firewall event"));
                    bytes = pkts;
                }
            } else {
                /* there is a forward byte count */
                if (0 == pkts) {
                    TRACEMSG(1, ("Setting forward packets to 1"));
                    pkts = 1;
                }
                if (rev_bytes) {
                    /* there is a reverse byte count */
                    if (0 == rev_pkts) {
                        TRACEMSG(1, ("Setting reverse packets to 1"));
                        rev_pkts = 1;
                    }
                }
            }

        } else if (SKIPFIX_FW_EVENT_DENIED == event) {
            /* flow denied */
            TRACEMSG(1, (("Processing flow denied event as actual flow record;"
                          " firewallEvent=%u, NF_F_FW_EVENT=%u,"
                          " NF_F_FW_EXT_EVENT=%u"),
                         fixrec->firewallEvent, fixrec->NF_F_FW_EVENT,
                         fixrec->NF_F_FW_EXT_EVENT));
            if (SKIPFIX_FW_EVENT_DENIED_CHECK_VALID(fixrec->NF_F_FW_EXT_EVENT))
            {
                rwRecSetMemo(fwd_rec, fixrec->NF_F_FW_EXT_EVENT);
            } else {
                rwRecSetMemo(fwd_rec, event);
            }
            /* flow denied events from the Cisco ASA have zero in the
             * bytes and packets field */
            if (0 == pkts) {
                TRACEMSG(1, ("Setting forward bytes and packets to 1"
                             " for denied firewall event"));
                bytes = 1;
                pkts = 1;
            } else if (0 == bytes) {
                TRACEMSG(1, ("Setting forward bytes equal to packets value"
                             " for denied firewall event"));
                bytes = pkts;
            }

        } else {
            /* flow created, flow updated, flow alert, or something
             * unexpected */
            if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_FIREWALL) {
                snprintf(msg, sizeof(msg), "firewallEvent=%u,extended=%u",
                         event, fixrec->NF_F_FW_EXT_EVENT);
                ski_fixrec_ignore(fixrec, msg);
            }
            return 0;
        }
    }

    /* FIXME.  What if the record has a flowDirection field that is
     * set to egress (0x01)?  Shouldn't we handle that by reversing
     * the record?  Or has fixbuf done that for us? */

    if (0 == bytes && 0 == rev_bytes) {
#if 0
        /* flow denied events from the Cisco ASA have zero in the
         * bytes and packets field */
        if ((skpcProbeGetQuirks(probe) & SKPC_QUIRK_FW_EVENT)
            && 0 == pkts
            && (SKIPFIX_FW_EVENT_DENIED == fixrec->NF_F_FW_EVENT
                || SKIPFIX_FW_EVENT_DENIED == fixrec->firewallEvent))
        {
            TRACEMSG(1, ("Setting forward bytes and packets to 1"
                         " for denied firewall event"));
            bytes = 1;
            pkts = 1;
        } else
#endif  /* 0 */
        {
            ski_fixrec_ignore(fixrec, "no forward/reverse octets");
            return 0;
        }
    }

    if (0 == pkts && 0 == rev_pkts) {
        if ((skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) == 0) {
            /* Ignore records with no volume. */
            ski_fixrec_ignore(fixrec, "no forward/reverse packets");
            return 0;
        }

        /* attempt to handle NetFlowV9 records from an ASA router that
         * have no packet count.  The code assumes all records from an
         * ASA have a byte count, though this is not always true. */
        if (bytes) {
            /* there is a forward byte count */
            if (0 == pkts) {
                TRACEMSG(1, ("Setting forward packets to 1"));
                pkts = 1;
            }
        }
        if (rev_bytes) {
            /* there is a reverse byte count */
            if (0 == rev_pkts) {
                TRACEMSG(1, ("Setting reverse packets to 1"));
                rev_pkts = 1;
            }
        }
    }

    /* If the TCP flags are in a subTemplateMultiList, copy them from
     * the list and into the record.  The fixbuf.stml gets initialized
     * by the call to fBufNext().*/
    stml = NULL;
    while ((stml = fbSubTemplateMultiListGetNextEntry(&fixrec->stml, stml))) {
        if (SKI_TCP_STML_TID != stml->tmplID) {
            fbSubTemplateMultiListEntryNextDataPtr(stml, NULL);
        } else {
            ski_tcp_stml_t *tcp = NULL;
            tcp = ((ski_tcp_stml_t*)
                   fbSubTemplateMultiListEntryNextDataPtr(stml, tcp));
            fixrec->initialTCPFlags = tcp->initialTCPFlags;
            fixrec->unionTCPFlags = tcp->unionTCPFlags;
            fixrec->reverseInitialTCPFlags = tcp->reverseInitialTCPFlags;
            fixrec->reverseUnionTCPFlags = tcp->reverseUnionTCPFlags;
            have_tcp_stml = 1;
        }
    }
    fbSubTemplateMultiListClear(&fixrec->stml);

    if (pkts && bytes) {
        /* We have forward information. */
        TRACEMSG(1, ("Read a forward fixrec record"));

        /* Handle the IP addresses */
#if SK_ENABLE_IPV6
        /* Use the IPv6 addresses if they are present and either there
         * are no IPv4 addresses or the IPv6 addresses are non-zero. */
        if ((record->bmap & TMPL_BIT_sourceIPv6Address)
            && (!(record->bmap & TMPL_BIT_sourceIPv4Address)
                || !SK_IPV6_IS_ZERO(fixrec->sourceIPv6Address)
                || !SK_IPV6_IS_ZERO(fixrec->destinationIPv6Address)))
        {
            /* Values found in IPv6 addresses--use them */
            rwRecSetIPv6(fwd_rec);
            rwRecMemSetSIPv6(fwd_rec, &fixrec->sourceIPv6Address);
            rwRecMemSetDIPv6(fwd_rec, &fixrec->destinationIPv6Address);
            rwRecMemSetNhIPv6(fwd_rec, &fixrec->ipNextHopIPv6Address);
        } else
#endif /* SK_ENABLE_IPV6 */
        {
            /* Take values from IPv4 */
            rwRecSetSIPv4(fwd_rec, fixrec->sourceIPv4Address);
            rwRecSetDIPv4(fwd_rec, fixrec->destinationIPv4Address);
            rwRecSetNhIPv4(fwd_rec, fixrec->ipNextHopIPv4Address);
        }

        /* Handle the Protocol and Ports */
        rwRecSetProto(fwd_rec, fixrec->protocolIdentifier);

        if (!rwRecIsICMP(fwd_rec)
            || (!(record->bmap & (TMPL_BIT_icmpTypeCodeIPv4
                                  | TMPL_BIT_icmpTypeIPv4))))
        {
            rwRecSetSPort(fwd_rec, fixrec->sourceTransportPort);
            rwRecSetDPort(fwd_rec, fixrec->destinationTransportPort);

        } else if (record->bmap & TMPL_BIT_icmpTypeCodeIPv4) {
            rwRecSetSPort(fwd_rec, 0);
#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(fwd_rec)) {
                rwRecSetDPort(fwd_rec, fixrec->icmpTypeCodeIPv6);
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                rwRecSetDPort(fwd_rec, fixrec->icmpTypeCodeIPv4);
            }

        } else if (record->bmap & TMPL_BIT_icmpTypeIPv4) {
            /* record has at least one of: icmpTypeIPv4 icmpCodeIPv4,
             * icmpTypeIPv6, icmpCodeIPv6 */
            rwRecSetSPort(fwd_rec, 0);
#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(fwd_rec)) {
                rwRecSetDPort(fwd_rec, ((fixrec->icmpTypeIPv6 << 8)
                                        | fixrec->icmpCodeIPv6));
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                rwRecSetDPort(fwd_rec, ((fixrec->icmpTypeIPv4 << 8)
                                        | fixrec->icmpCodeIPv4));
            }
        } else {
            skAbort();
        }

        /* Handle the SNMP or VLAN interfaces */
        if (SKPC_IFVALUE_SNMP == skpcProbeGetInterfaceValueType(probe)) {
            rwRecSetInput(fwd_rec, CLAMP_VAL16(fixrec->ingressInterface));
            rwRecSetOutput(fwd_rec, CLAMP_VAL16(fixrec->egressInterface));
        } else {
            rwRecSetInput(fwd_rec, fixrec->vlanId);
            rwRecSetOutput(fwd_rec, fixrec->postVlanId);
        }

        /* Store volume, clamping counts to 32 bits. */
        rwRecSetPkts(fwd_rec, CLAMP_VAL32(pkts));
        rwRecSetBytes(fwd_rec, CLAMP_VAL32(bytes));

    } else if (rev_pkts && rev_bytes) {
        /* We have no forward information, only reverse.  Write the
         * source and dest values from the IPFIX record to SiLK's dest
         * and source fields, respectively. */
        TRACEMSG(1, ("Read a reverse-only fixrec record"));

        /* Store volume, clamping counts to 32 bits. */
        rwRecSetPkts(fwd_rec, CLAMP_VAL32(rev_pkts));
        rwRecSetBytes(fwd_rec, CLAMP_VAL32(rev_bytes));

        /* This cannot be a bi-flow.  Clear rev_pkts and rev_bytes
         * variables now. We check this in the rev_rec code
         * below. */
        rev_pkts = rev_bytes = 0;

        /* Handle the IP addresses */
#if SK_ENABLE_IPV6
        if ((record->bmap & TMPL_BIT_sourceIPv6Address)
            && (!(record->bmap & TMPL_BIT_sourceIPv4Address)
                || !SK_IPV6_IS_ZERO(fixrec->sourceIPv6Address)
                || !SK_IPV6_IS_ZERO(fixrec->destinationIPv6Address)))
        {
            /* Values found in IPv6 addresses--use them */
            rwRecSetIPv6(fwd_rec);
            rwRecMemSetSIPv6(fwd_rec, &fixrec->destinationIPv6Address);
            rwRecMemSetDIPv6(fwd_rec, &fixrec->sourceIPv6Address);
            rwRecMemSetNhIPv6(fwd_rec, &fixrec->ipNextHopIPv6Address);
        } else
#endif /* SK_ENABLE_IPV6 */
        {
            /* Take values from IPv4 */
            rwRecSetSIPv4(fwd_rec, fixrec->destinationIPv4Address);
            rwRecSetDIPv4(fwd_rec, fixrec->sourceIPv4Address);
            rwRecSetNhIPv4(fwd_rec, fixrec->ipNextHopIPv4Address);
        }

        /* Handle the Protocol and Ports */
        rwRecSetProto(fwd_rec, fixrec->protocolIdentifier);
        if (!rwRecIsICMP(fwd_rec)) {
            rwRecSetSPort(fwd_rec, fixrec->destinationTransportPort);
            rwRecSetDPort(fwd_rec, fixrec->sourceTransportPort);
        } else if (record->bmap & TMPL_BIT_icmpTypeCodeIPv4) {
            rwRecSetSPort(fwd_rec, 0);
#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(fwd_rec)) {
                rwRecSetDPort(fwd_rec, fixrec->icmpTypeCodeIPv6);
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                rwRecSetDPort(fwd_rec, fixrec->icmpTypeCodeIPv4);
            }
        } else if (record->bmap & TMPL_BIT_icmpTypeIPv4) {
            /* record has at least one of: icmpTypeIPv4 icmpCodeIPv4,
             * icmpTypeIPv6, icmpCodeIPv6 */
            rwRecSetSPort(fwd_rec, 0);
#if SK_ENABLE_IPV6
            if (rwRecIsIPv6(fwd_rec)) {
                rwRecSetDPort(fwd_rec, ((fixrec->icmpTypeIPv6 << 8)
                                        | fixrec->icmpCodeIPv6));
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                rwRecSetDPort(fwd_rec, ((fixrec->icmpTypeIPv4 << 8)
                                        | fixrec->icmpCodeIPv4));
            }
        } else {
            /* For an ICMP record, put whichever Port field is
             * non-zero into the record's dPort field */
            rwRecSetSPort(fwd_rec, 0);
            rwRecSetDPort(fwd_rec, (fixrec->destinationTransportPort
                                    ? fixrec->destinationTransportPort
                                    : fixrec->sourceTransportPort));
        }

        /* Handle the SNMP or VLAN interfaces */
        if (SKPC_IFVALUE_SNMP == skpcProbeGetInterfaceValueType(probe)) {
            rwRecSetInput(fwd_rec, CLAMP_VAL16(fixrec->egressInterface));
            rwRecSetOutput(fwd_rec, CLAMP_VAL16(fixrec->ingressInterface));
        } else {
            if (record->bmap & TMPL_BIT_reverseVlanId) {
                /* If we have the reverse elements, use them */
                rwRecSetInput(fwd_rec, fixrec->reverseVlanId);
                rwRecSetOutput(fwd_rec, fixrec->reversePostVlanId);
            } else if (record->bmap & TMPL_BIT_postVlanId) {
                /* If we have a single vlanId, set 'input' to that value;
                 * otherwise, set 'input' to postVlanId and 'output' to
                 * vlanId. */
                rwRecSetInput(fwd_rec, fixrec->postVlanId);
                rwRecSetOutput(fwd_rec, fixrec->vlanId);
            } else {
                /* we have a single vlanId, so don't swap the values */
                rwRecSetInput(fwd_rec, fixrec->vlanId);
            }
        }

    } else {
        TRACEMSG(2, (("Found zero bytes or packets; byte=%" PRIu64 ", pkt="
                      "%" PRIu64 ", rev_byte=%" PRIu64 ", rev_pkt=%" PRIu64),
                     bytes, pkts, rev_bytes, rev_pkts));
        ski_fixrec_ignore(fixrec, "byte or packet count is zero");
        return 0;
    }

    skiGauntletOfTime(fbuf, record, probe);

    /* Copy the remainder of the record */
    rwRecSetFlowType(fwd_rec, fixrec->silkFlowType);
    rwRecSetSensor(fwd_rec, fixrec->silkFlowSensor);
    rwRecSetApplication(fwd_rec, fixrec->silkAppLabel);

    tcp_state = fixrec->silkTCPState;
    tcp_flags = (fixrec->initialTCPFlags | fixrec->unionTCPFlags);

    /* Ensure the SK_TCPSTATE_EXPANDED bit is properly set. */
    if (tcp_flags && IPPROTO_TCP == rwRecGetProto(fwd_rec)) {
        /* Flow is TCP and init|session flags had a value. */
        rwRecSetFlags(fwd_rec, tcp_flags);
        rwRecSetInitFlags(fwd_rec, fixrec->initialTCPFlags);
        rwRecSetRestFlags(fwd_rec, fixrec->unionTCPFlags);
        tcp_state |= SK_TCPSTATE_EXPANDED;
    } else {
        /* clear bit when not TCP or no separate init/session flags */
        tcp_state &= ~SK_TCPSTATE_EXPANDED;
        /* use whatever all-flags we were given; leave initial-flags
         * and session-flags unset */
        rwRecSetFlags(fwd_rec, fixrec->tcpControlBits);
    }

    /* Process the flowEndReason and flowAttributes unless one of
     * those bits is already set (via silkTCPState). */
    if (!(tcp_state
          & (SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK | SK_TCPSTATE_TIMEOUT_KILLED
             | SK_TCPSTATE_TIMEOUT_STARTED | SK_TCPSTATE_UNIFORM_PACKET_SIZE)))
    {
        /* Note active timeout */
        if ((fixrec->flowEndReason & SKI_END_MASK) == SKI_END_ACTIVE) {
            tcp_state |= SK_TCPSTATE_TIMEOUT_KILLED;
        }
        /* Note continuation */
        if (fixrec->flowEndReason & SKI_END_ISCONT) {
            tcp_state |= SK_TCPSTATE_TIMEOUT_STARTED;
        }
        /* Note flows with records of uniform size */
        if (fixrec->flowAttributes & SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE) {
            tcp_state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
        }
        rwRecSetTcpState(fwd_rec, tcp_state);
    }

    rwRecSetTcpState(fwd_rec, tcp_state);

    /* Handle the reverse record if there is one in the IPFIX record,
     * which is indicated by the value of 'rev_bytes'.*/
    if (0 == rev_bytes) {
        /* No data for reverse direction; just clear the record. */
        RWREC_CLEAR(record->rev_rec);
    } else {
        rwRec *rev_rec;
        rev_rec = record->rev_rec;

        /* We have data for reverse direction. */
        TRACEMSG(1, ("Handling reverse side of bi-flow fixrec record"));

#define COPY_FORWARD_REC_TO_REVERSE 1
#if COPY_FORWARD_REC_TO_REVERSE
        /* Initialize the reverse record with the forward
         * record  */
        RWREC_COPY(rev_rec, fwd_rec);
#else
        /* instead of copying the forward record and changing
         * nearly everything, we could just set these fields on
         * the reverse record. */
        rwRecSetProto(rev_rec, fixrec->protocolIdentifier);
        rwRecSetFlowType(rev_rec, fixrec->silkFlowType);
        rwRecSetSensor(rev_rec, fixrec->silkFlowSensor);
        rwRecSetTcpState(rev_rec, fixrec->silkTCPState);
        rwRecSetApplication(rev_rec, fixrec->silkAppLabel);
        /* does using the forward nexthop IP for the reverse
         * record make any sense?  Shouldn't we check for a
         * reverse next hop address? */
#if SK_ENABLE_IPV6
        if (rwRecIsIPv6(fwd_rec)) {
            rwRecSetIPv6(rev_rec);
            rwRecMemSetNhIPv6(rev_rec, &fixrec->ipNextHopIPv6Address);
        } else
#endif
        {
            rwRecSetNhIPv4(rev_rec, &fixrec->ipNextHopIPv4Address);
        }
#endif  /* #else clause of #if COPY_FORWARD_REC_TO_REVERSE */

        /* Reverse the IPs */
#if SK_ENABLE_IPV6
        if (rwRecIsIPv6(fwd_rec)) {
            rwRecMemSetSIPv6(rev_rec, &fixrec->destinationIPv6Address);
            rwRecMemSetDIPv6(rev_rec, &fixrec->sourceIPv6Address);
        } else
#endif
        {
            rwRecSetSIPv4(rev_rec, fixrec->destinationIPv4Address);
            rwRecSetDIPv4(rev_rec, fixrec->sourceIPv4Address);
        }

        /* Reverse the ports unless this is an ICMP record */
        if (!rwRecIsICMP(fwd_rec)) {
            rwRecSetSPort(rev_rec, rwRecGetDPort(fwd_rec));
            rwRecSetDPort(rev_rec, rwRecGetSPort(fwd_rec));
        }

        /* Reverse the SNMP or VLAN interfaces */
        if (SKPC_IFVALUE_SNMP == skpcProbeGetInterfaceValueType(probe)) {
            rwRecSetInput(rev_rec, rwRecGetOutput(fwd_rec));
            rwRecSetOutput(rev_rec, rwRecGetInput(fwd_rec));
        } else if (record->bmap & TMPL_BIT_reverseVlanId) {
            /* Reverse VLAN values exist.  Use them */
            rwRecSetInput(rev_rec, fixrec->reverseVlanId);
            rwRecSetOutput(rev_rec, fixrec->reversePostVlanId);
        } else if (record->bmap & TMPL_BIT_postVlanId) {
            /* Reverse the forward values */
            rwRecSetInput(rev_rec, fixrec->postVlanId);
            rwRecSetOutput(rev_rec, fixrec->vlanId);
        } else {
            /* we have a single vlanId, so don't swap the values */
            rwRecSetInput(rev_rec, fixrec->vlanId);
        }

        /* Set volume.  We retrieved them above */
        rwRecSetPkts(rev_rec, CLAMP_VAL32(rev_pkts));
        rwRecSetBytes(rev_rec, CLAMP_VAL32(rev_bytes));

        /* Calculate reverse start time from reverse RTT */

        /* Reverse flow's start time must be increased and its
         * duration decreased by its offset from the forward
         * record  */
        rwRecSetStartTime(rev_rec, (rwRecGetStartTime(fwd_rec)
                                    + fixrec->reverseFlowDeltaMilliseconds));
        rwRecSetElapsed(rev_rec, (rwRecGetElapsed(fwd_rec)
                                  - fixrec->reverseFlowDeltaMilliseconds));

        /* Note: the value of the 'tcp_state' variable from above is
         * what is in rwRecGetTcpState(rev_rec). */

        /* Get reverse TCP flags from the IPFIX record if they are
         * available.  Otherwise, leave the flags unchanged (using
         * those from the forward direction). */
        tcp_flags = (fixrec->reverseInitialTCPFlags
                     | fixrec->reverseUnionTCPFlags);

        if (tcp_flags && IPPROTO_TCP == rwRecGetProto(fwd_rec)) {
            /* Flow is TCP and init|session has a value. */
            TRACEMSG(2, ("Using reverse TCP flags (initial|session)"));
            rwRecSetFlags(rev_rec, tcp_flags);
            rwRecSetInitFlags(rev_rec, fixrec->reverseInitialTCPFlags);
            rwRecSetRestFlags(rev_rec, fixrec->reverseUnionTCPFlags);
            tcp_state |= SK_TCPSTATE_EXPANDED;
        } else if (record->bmap & TMPL_BIT_reverseTcpControlBits) {
            /* Use whatever is in all-flags; clear any init/session
             * flags we got from the forward rec. */
            TRACEMSG(2, ("Using reverse TCP flags (all only)"));
            rwRecSetFlags(rev_rec, fixrec->reverseTcpControlBits);
            rwRecSetInitFlags(rev_rec, 0);
            rwRecSetRestFlags(rev_rec, 0);
            tcp_state &= ~SK_TCPSTATE_EXPANDED;
        } else if (have_tcp_stml
                   || (record->bmap & TMPL_BIT_reverseInitialTCPFlags))
        {
            /* If a reverseInitialTCPFlags Element existed on the
             * template; use it even though its value is 0. */
            TRACEMSG(2, ("Setting all TCP flags to 0"));
            rwRecSetFlags(rev_rec, 0);
            rwRecSetInitFlags(rev_rec, 0);
            rwRecSetRestFlags(rev_rec, 0);
            tcp_state &= ~SK_TCPSTATE_EXPANDED;
        }
        /* else leave the flags unchanged */

        /* Handle reverse flow attributes */
        if (fixrec->reverseFlowAttributes
            & SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE)
        {
            /* ensure it is set */
            tcp_state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
        } else {
            /* ensure it it not set */
            tcp_state &= ~SK_TCPSTATE_UNIFORM_PACKET_SIZE;
        }

        rwRecSetTcpState(rev_rec, tcp_state);
    }


    /* all done */
    return ((rev_bytes > 0) ? 2 : 1);
}




/**
 *    Print a log message saying why a ski_yafrec_t record was ignored
 */
static void
ski_yafrec_ignore(
    const ski_yafrec_t *yafrec,
    const char         *reason)
{
    skipaddr_t ipaddr;
    char sipbuf[64];
    char dipbuf[64];

    if (!SK_IPV6_IS_ZERO(yafrec->sourceIPv6Address)) {
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &yafrec->sourceIPv6Address,
                       sipbuf, sizeof(sipbuf)))
#endif
        {
            strcpy(sipbuf, "unknown-v6");
        }
    } else {
        skipaddrSetV4(&ipaddr, &yafrec->sourceIPv4Address);
        skipaddrString(sipbuf, &ipaddr, SKIPADDR_CANONICAL);
    }
    if (!SK_IPV6_IS_ZERO(yafrec->destinationIPv6Address)) {
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &yafrec->destinationIPv6Address,
                       dipbuf, sizeof(dipbuf)))
#endif
        {
            strcpy(dipbuf, "unknown-v6");
        }
    } else {
        skipaddrSetV4(&ipaddr, &yafrec->destinationIPv4Address);
        skipaddrString(dipbuf, &ipaddr, SKIPADDR_CANONICAL);
    }

    INFOMSG(("IGNORED|%s|%s|%u|%u|%u|%" PRIu64 "|%" PRIu64 "|%s|"),
            sipbuf, dipbuf, yafrec->sourceTransportPort,
            yafrec->destinationTransportPort,yafrec->protocolIdentifier,
            yafrec->packetDeltaCount, yafrec->octetDeltaCount, reason);
}


/**
 *    Call fBufNext() and transcode the data into one of the
 *    ski_yafrec_spec templates, and then convert the structure into
 *    0, 1, or 2 SiLK Flow records and fill the record pointers on the
 *    'record' structure.  The return value indicates the number of
 *    records converted.  Return -1 on failure.
 */
static int
ski_yafrec_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    fbSubTemplateMultiListEntry_t *stml;
    ski_yafrec_t *yafrec;
    size_t len;
    uint8_t tcp_state;
    int have_tcp_stml = 0;
    uint16_t int_tid;
    rwRec *fwd_rec;
    rwRec *rev_rec;

    DEFINE_PREFIX_BUF(prefix);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_yafrec_next()"),
                 prefix, record->bmap));
    assert(SKI_RECTYPE_YAFREC == record->rectype);

    /* Get a local handle to the record and clear it */
    fwd_rec = record->fwd_rec;
    RWREC_CLEAR(fwd_rec);

    /* The lower 16 bits of the context is the TID of the template to
     * use to read the record. */
    int_tid = record->bmap & UINT16_MAX;
    if ((int_tid & SKI_YAFREC_TID) != SKI_YAFREC_TID) {
        TRACEMSG(1, ("ski_yafrec_next() called but TID %#06x does not match",
                     int_tid));
        return ski_ignore_next(fbuf, record, probe, err);
    }
    if (!fBufSetInternalTemplate(fbuf, int_tid, err)) {
        TRACEMSG(1, (("ski_yafrec_next() called but setting Template"
                      " TID %#06x failed: %s"), int_tid, (*err)->message));
        g_clear_error(err);
        return ski_ignore_next(fbuf, record, probe, err);
    }
    len = sizeof(record->data.yafrec);
    if (!fBufNext(fbuf, (uint8_t *)&record->data.yafrec, &len, err)) {
        return -1;
    }
    yafrec = &record->data.yafrec;
    assert((record->bmap & YAFREC_STML)
           ? (len == sizeof(ski_yafrec_t))
           : (len == offsetof(ski_yafrec_t, stml)));

    if ((yafrec->flowEndReason & SKI_END_MASK)== SKI_END_YAF_INTERMEDIATE_FLOW)
    {
        TRACEMSG(2, ("Ignored YAF intermediate uniflow"));
        return 0;
    }

    /* Ignore records that do not have IPv4 addresses when SiLK was
     * built without IPv6 support. */
#if !SK_ENABLE_IPV6
    if (record->bmap & YAFREC_ONLY_IP6) {
        ski_yafrec_ignore(yafrec, "IPv6 record");
        return 0;
    }
#endif  /* SK_ENABLE_IPV6 */

    /* Volume */
    if (yafrec->packetDeltaCount && yafrec->octetDeltaCount) {
        /* Store volume, clamping counts to 32 bits. */
        rwRecSetPkts(fwd_rec, CLAMP_VAL32(yafrec->packetDeltaCount));
        rwRecSetBytes(fwd_rec, CLAMP_VAL32(yafrec->octetDeltaCount));

        if (yafrec->reversePacketDeltaCount && yafrec->reverseOctetDeltaCount){
            TRACEMSG(1, ("Read a bi-flow yafrec record"));
            RWREC_CLEAR(record->rev_rec);
            rev_rec = record->rev_rec;
            rwRecSetPkts(rev_rec,CLAMP_VAL32(yafrec->reversePacketDeltaCount));
            rwRecSetBytes(rev_rec,CLAMP_VAL32(yafrec->reverseOctetDeltaCount));
        } else {
            TRACEMSG(1, ("Read a forward yafrec record"));
            rev_rec = NULL;
        }
    } else if (yafrec->reversePacketDeltaCount
               && yafrec->reverseOctetDeltaCount)
    {
        /* We have no forward information, only reverse.  Swap the IP
         * addresses, the ports, the SNMP interfaces, and the VLAN IDs
         * in the yafrec */
        ski_yafrec_t reversed;

        TRACEMSG(1, ("Read a reverse-only yafrec record"));
        rev_rec = NULL;

        memcpy(reversed.sourceIPv6Address, yafrec->destinationIPv6Address,
               sizeof(yafrec->sourceIPv6Address));
        memcpy(yafrec->destinationIPv6Address, yafrec->sourceIPv6Address,
               sizeof(yafrec->sourceIPv6Address));
        memcpy(yafrec->sourceIPv6Address, reversed.sourceIPv6Address,
               sizeof(yafrec->sourceIPv6Address));

        reversed.sourceIPv4Address = yafrec->destinationIPv4Address;
        yafrec->destinationIPv4Address = yafrec->sourceIPv4Address;
        yafrec->sourceIPv4Address = reversed.sourceIPv4Address;

        reversed.sourceTransportPort = yafrec->destinationTransportPort;
        yafrec->destinationTransportPort = yafrec->sourceTransportPort;
        yafrec->sourceTransportPort = reversed.sourceTransportPort;

        reversed.ingressInterface = yafrec->egressInterface;
        yafrec->egressInterface = yafrec->ingressInterface;
        yafrec->ingressInterface = reversed.ingressInterface;

        if (yafrec->reverseVlanId) {
            yafrec->vlanId = yafrec->reverseVlanId;
        }

        rwRecSetPkts(fwd_rec, CLAMP_VAL32(yafrec->reversePacketDeltaCount));
        rwRecSetBytes(fwd_rec, CLAMP_VAL32(yafrec->reverseOctetDeltaCount));

    } else {
        TRACEMSG(2, (("Found zero bytes or packets; byte=%" PRIu64 ", pkt="
                      "%" PRIu64 ", rev_byte=%" PRIu64 ", rev_pkt=%" PRIu64),
                     yafrec->octetDeltaCount, yafrec->packetDeltaCount,
                     yafrec->reverseOctetDeltaCount,
                     yafrec->reversePacketDeltaCount));
        ski_yafrec_ignore(yafrec, "byte or packet count is zero");
        return 0;
    }

    /* Simple fields */
    rwRecSetProto(fwd_rec, yafrec->protocolIdentifier);
    rwRecSetFlowType(fwd_rec, yafrec->silkFlowType);
    rwRecSetSensor(fwd_rec, yafrec->silkFlowSensor);
    rwRecSetApplication(fwd_rec, yafrec->silkAppLabel);
    if (rev_rec) {
        rwRecSetProto(rev_rec, yafrec->protocolIdentifier);
        rwRecSetFlowType(rev_rec, yafrec->silkFlowType);
        rwRecSetSensor(rev_rec, yafrec->silkFlowSensor);
        rwRecSetApplication(rev_rec, yafrec->silkAppLabel);
    }

    /* Time stamp */
    rwRecSetStartTime(fwd_rec, (sktime_t)yafrec->flowStartMilliseconds);
    if (yafrec->flowEndMilliseconds < yafrec->flowStartMilliseconds) {
        rwRecSetElapsed(fwd_rec, 0);
    } else if ((yafrec->flowEndMilliseconds - yafrec->flowStartMilliseconds)
               > UINT32_MAX)
    {
        rwRecSetElapsed(fwd_rec, UINT32_MAX);
    } else {
        rwRecSetElapsed(fwd_rec, (yafrec->flowEndMilliseconds
                                  - yafrec->flowStartMilliseconds));
    }
    if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS) {
        char stime_buf[SKTIMESTAMP_STRLEN];
        sktimestamp_r(stime_buf, rwRecGetStartTime(fwd_rec), SKTIMESTAMP_UTC);
        INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                 " flowStartMilliseconds=%" PRIu64
                 ", flowEndMilliseconds=%" PRIu64),
                skpcProbeGetName(probe), stime_buf,
                (double)rwRecGetElapsed(fwd_rec)/1000,
                yafrec->flowStartMilliseconds, yafrec->flowEndMilliseconds);
    }

    if (rev_rec) {
        /* Reverse flow's start time must be increased and its
         * duration decreased by its offset from the forward
         * record  */
        rwRecSetStartTime(rev_rec, (rwRecGetStartTime(fwd_rec)
                                    + yafrec->reverseFlowDeltaMilliseconds));
        if (rwRecGetElapsed(fwd_rec) < yafrec->reverseFlowDeltaMilliseconds) {
            rwRecSetElapsed(rev_rec, 0);
        } else {
            rwRecSetElapsed(rev_rec, (rwRecGetElapsed(fwd_rec)
                                      - yafrec->reverseFlowDeltaMilliseconds));
        }
    }

    /* IP Addresses */
#if SK_ENABLE_IPV6
    /* Use the IPv6 addresses if they are the only ones present or
     * both addresses are present and at least one of the IPv6
     * addresses is non-zero. */
    if ((record->bmap & YAFREC_ONLY_IP6)
        || ((record->bmap & YAFREC_IP_BOTH)
            && !(SK_IPV6_IS_ZERO(yafrec->sourceIPv6Address)
                 && SK_IPV6_IS_ZERO(yafrec->destinationIPv6Address))))
    {
        /* Values found in IPv6 addresses--use them */
        rwRecSetIPv6(fwd_rec);
        rwRecMemSetSIPv6(fwd_rec, &yafrec->sourceIPv6Address);
        rwRecMemSetDIPv6(fwd_rec, &yafrec->destinationIPv6Address);
        rwRecMemSetNhIPv6(fwd_rec, &yafrec->ipNextHopIPv6Address);
        if (rev_rec) {
            rwRecSetIPv6(rev_rec);
            rwRecMemSetSIPv6(rev_rec, &yafrec->destinationIPv6Address);
            rwRecMemSetDIPv6(rev_rec, &yafrec->sourceIPv6Address);
            rwRecMemSetNhIPv6(rev_rec, &yafrec->ipNextHopIPv6Address);
        }
    } else
#endif /* SK_ENABLE_IPV6 */
    {
        /* Take values from IPv4 */
        rwRecSetSIPv4(fwd_rec, yafrec->sourceIPv4Address);
        rwRecSetDIPv4(fwd_rec, yafrec->destinationIPv4Address);
        rwRecSetNhIPv4(fwd_rec, yafrec->ipNextHopIPv4Address);
        if (rev_rec) {
            rwRecSetSIPv4(rev_rec, yafrec->destinationIPv4Address);
            rwRecSetDIPv4(rev_rec, yafrec->sourceIPv4Address);
            rwRecSetNhIPv4(rev_rec, yafrec->ipNextHopIPv4Address);
        }
    }

    /* SNMP or VLAN interfaces */
    if (SKPC_IFVALUE_SNMP == skpcProbeGetInterfaceValueType(probe)) {
        rwRecSetInput(fwd_rec, CLAMP_VAL16(yafrec->ingressInterface));
        rwRecSetOutput(fwd_rec, CLAMP_VAL16(yafrec->egressInterface));
        if (rev_rec) {
            rwRecSetInput(rev_rec, CLAMP_VAL16(yafrec->egressInterface));
            rwRecSetOutput(rev_rec, CLAMP_VAL16(yafrec->ingressInterface));
        }
    } else {
        rwRecSetInput(fwd_rec, yafrec->vlanId);
        rwRecSetOutput(fwd_rec, 0);
        if (rev_rec) {
            if (record->bmap & TMPL_BIT_reverseVlanId) {
                /* Reverse VLAN value exists.  Use it */
                rwRecSetInput(rev_rec, yafrec->reverseVlanId);
                rwRecSetOutput(rev_rec, 0);
            } else {
                /* we have a single vlanId, so don't swap the values */
                rwRecSetInput(rev_rec, yafrec->vlanId);
                rwRecSetOutput(rev_rec, 0);
            }
        }
    }

    /* Attributes, ICMP Type/Code, Ports, TCP Flags */
    tcp_state = yafrec->silkTCPState;

    /* Process the flowEndReason and flowAttributes unless one of
     * those bits is already set (via silkTCPState). */
    if (!(tcp_state
          & (SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK | SK_TCPSTATE_TIMEOUT_KILLED
             | SK_TCPSTATE_TIMEOUT_STARTED | SK_TCPSTATE_UNIFORM_PACKET_SIZE)))
    {
        /* Note active timeout */
        if ((yafrec->flowEndReason & SKI_END_MASK) == SKI_END_ACTIVE) {
            tcp_state |= SK_TCPSTATE_TIMEOUT_KILLED;
        }
        /* Note continuation */
        if (yafrec->flowEndReason & SKI_END_ISCONT) {
            tcp_state |= SK_TCPSTATE_TIMEOUT_STARTED;
        }
        /* Note flows with records of uniform size */
        if (yafrec->flowAttributes & SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE) {
            tcp_state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
        }
    }

    if (IPPROTO_TCP != yafrec->protocolIdentifier) {
        /* Free STML list memory */
        if (record->bmap & YAFREC_STML) {
            fbSubTemplateMultiListClear(&yafrec->stml);
        }

        /* For TCP Flags, use whatever value was given in
         * tcpControlBits; ensure expanded bit in tcp_state is off. */
        rwRecSetFlags(fwd_rec, yafrec->tcpControlBits);
        tcp_state &= ~SK_TCPSTATE_EXPANDED;
        rwRecSetTcpState(fwd_rec, tcp_state);

        if (rev_rec) {
            /* Use reverse value if given; else foward value */
            if (record->bmap & TMPL_BIT_reverseTcpControlBits) {
                rwRecSetFlags(rev_rec, yafrec->reverseTcpControlBits);
            } else {
                rwRecSetFlags(rev_rec, yafrec->tcpControlBits);
            }

            /* Handle reverse flow attributes */
            if (yafrec->reverseFlowAttributes
                & SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE)
            {
                /* ensure it is set */
                tcp_state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            } else {
                /* ensure it it not set */
                tcp_state &= ~SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            }
            rwRecSetTcpState(rev_rec, tcp_state);
        }

        if (!rwRecIsICMP(fwd_rec)) {
            /* Use whatever values are in sport and dport */
            rwRecSetSPort(fwd_rec, yafrec->sourceTransportPort);
            rwRecSetDPort(fwd_rec, yafrec->destinationTransportPort);
            if (rev_rec) {
                rwRecSetSPort(rev_rec, yafrec->destinationTransportPort);
                rwRecSetDPort(rev_rec, yafrec->sourceTransportPort);
            }
        } else {
            /* ICMP Record */
            /* Store ((icmpType << 8) | icmpCode) in the dPort */
            rwRecSetSPort(fwd_rec, 0);
            if (record->bmap & TMPL_BIT_icmpTypeCodeIPv4) {
                rwRecSetDPort(fwd_rec, yafrec->icmpTypeCode);
            } else {
                rwRecSetDPort(fwd_rec, yafrec->destinationTransportPort);
            }

            if (rev_rec) {
                /* use the same sPort and dPort values */
                rwRecSetSPort(rev_rec, 0);
                rwRecSetDPort(rev_rec, rwRecGetDPort(fwd_rec));
            }
        }
    } else {
        /* Record is TCP */
        rwRecSetSPort(fwd_rec, yafrec->sourceTransportPort);
        rwRecSetDPort(fwd_rec, yafrec->destinationTransportPort);
        if (rev_rec) {
            rwRecSetSPort(rev_rec, yafrec->destinationTransportPort);
            rwRecSetDPort(rev_rec, yafrec->sourceTransportPort);
        }

        if (record->bmap & YAFREC_STML) {
            /* The TCP flags are in a subTemplateMultiList, copy them
             * from the list to the record.  The yafrec->stml gets
             * initialized by the call to fBufNext().*/
            stml = NULL;
            while ((stml = fbSubTemplateMultiListGetNextEntry(&yafrec->stml,
                                                              stml)))
            {
                if (SKI_TCP_STML_TID != stml->tmplID) {
                    fbSubTemplateMultiListEntryNextDataPtr(stml, NULL);
                } else {
                    ski_tcp_stml_t *tcp = NULL;
                    tcp = ((ski_tcp_stml_t*)
                           fbSubTemplateMultiListEntryNextDataPtr(stml, tcp));
                    yafrec->initialTCPFlags = tcp->initialTCPFlags;
                    yafrec->unionTCPFlags = tcp->unionTCPFlags;
                    yafrec->reverseInitialTCPFlags
                        = tcp->reverseInitialTCPFlags;
                    yafrec->reverseUnionTCPFlags = tcp->reverseUnionTCPFlags;
                    have_tcp_stml = 1;
                }
            }
            fbSubTemplateMultiListClear(&yafrec->stml);
        }

        if (yafrec->initialTCPFlags | yafrec->unionTCPFlags) {
            rwRecSetInitFlags(fwd_rec, yafrec->initialTCPFlags);
            rwRecSetRestFlags(fwd_rec, yafrec->unionTCPFlags);
            rwRecSetFlags(fwd_rec, (yafrec->initialTCPFlags
                                    | yafrec->unionTCPFlags));
            tcp_state |= SK_TCPSTATE_EXPANDED;
        } else {
            rwRecSetFlags(fwd_rec, yafrec->tcpControlBits);
            tcp_state &= ~SK_TCPSTATE_EXPANDED;
        }
        rwRecSetTcpState(fwd_rec, tcp_state);

        if (rev_rec) {
            /* Get reverse TCP flags from the IPFIX record if they are
             * available.  Otherwise, use those from the forward
             * direction. */
            if (yafrec->reverseInitialTCPFlags | yafrec->reverseUnionTCPFlags){
                rwRecSetInitFlags(rev_rec, yafrec->reverseInitialTCPFlags);
                rwRecSetRestFlags(rev_rec, yafrec->reverseUnionTCPFlags);
                rwRecSetFlags(rev_rec, (yafrec->reverseInitialTCPFlags
                                        | yafrec->reverseUnionTCPFlags));
                tcp_state |= SK_TCPSTATE_EXPANDED;

            } else if (record->bmap & TMPL_BIT_reverseTcpControlBits) {
                /* Use whatever is in all-flags; clear any init/session
                 * flags we got from the forward fwd_rec. */
                TRACEMSG(2, ("Using reverse TCP flags (all only)"));
                rwRecSetFlags(rev_rec, yafrec->reverseTcpControlBits);
                rwRecSetInitFlags(rev_rec, 0);
                rwRecSetRestFlags(rev_rec, 0);
                tcp_state &= ~SK_TCPSTATE_EXPANDED;
            } else if (have_tcp_stml
                       || (record->bmap & TMPL_BIT_reverseInitialTCPFlags))
            {
                /* If a reverseInitialTCPFlags Element existed on the
                 * template; use it even though its value is 0. */
                TRACEMSG(2, ("Setting all TCP flags to 0"));
                rwRecSetFlags(rev_rec, 0);
                rwRecSetInitFlags(rev_rec, 0);
                rwRecSetRestFlags(rev_rec, 0);
                tcp_state &= ~SK_TCPSTATE_EXPANDED;
            } else {
                /* Use foward flags */
                rwRecSetInitFlags(rev_rec, rwRecGetInitFlags(fwd_rec));
                rwRecSetRestFlags(rev_rec, rwRecGetRestFlags(fwd_rec));
                rwRecSetFlags(rev_rec, rwRecGetFlags(fwd_rec));
            }

            /* Handle reverse flow attributes */
            if (yafrec->reverseFlowAttributes
                & SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE)
            {
                /* ensure it is set */
                tcp_state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            } else {
                /* ensure it it not set */
                tcp_state &= ~SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            }
            rwRecSetTcpState(rev_rec, tcp_state);
        }
    }

    /* all done */
    return ((rev_rec) ? 2 : 1);
}


/**
 *    Print a log message saying why a ski_nf9rec_t record was ignored
 */
static void
ski_nf9rec_ignore(
    const ski_record_t *record,
    const char         *reason)
{
    const ski_nf9rec_t *nf9rec = &record->data.nf9rec;
    skipaddr_t ipaddr;
    char sipbuf[64];
    char dipbuf[64];

    if (record->bmap & NF9REC_IP6) {
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &nf9rec->addr.ip6.sourceIPv6Address,
                       sipbuf, sizeof(sipbuf)))
#endif
        {
            strcpy(sipbuf, "unknown-v6");
        }
#ifdef SK_HAVE_INET_NTOP
        if (!inet_ntop(AF_INET6, &nf9rec->addr.ip6.destinationIPv6Address,
                       dipbuf, sizeof(dipbuf)))
#endif
        {
            strcpy(dipbuf, "unknown-v6");
        }
    } else {
        skipaddrSetV4(&ipaddr, &nf9rec->addr.ip4.sourceIPv4Address);
        skipaddrString(sipbuf, &ipaddr, SKIPADDR_CANONICAL);
        skipaddrSetV4(&ipaddr, &nf9rec->addr.ip4.destinationIPv4Address);
        skipaddrString(dipbuf, &ipaddr, SKIPADDR_CANONICAL);
    }

    INFOMSG(("IGNORED|%s|%s|%u|%u|%u|%" PRIu64 "|%" PRIu64 "|%s|"),
            sipbuf, dipbuf, nf9rec->sourceTransportPort,
            nf9rec->destinationTransportPort,nf9rec->protocolIdentifier,
            nf9rec->packetDeltaCount, nf9rec->octetDeltaCount, reason);
}


/**
 *    Call fBufNext() and transcode the data into one of the
 *    ski_nf9rec_spec templates, and then convert the structure into
 *    0, 1, or 2 SiLK Flow records and fill the record pointers on the
 *    'record' structure.  The return value indicates the number of
 *    records converted.  Return -1 on failure.
 */
static int
ski_nf9rec_next(
    fBuf_t                 *fbuf,
    ski_record_t           *record,
    const skpc_probe_t     *probe,
    GError                **err)
{
    char stime_buf[SKTIMESTAMP_STRLEN];
    ski_nf9rec_t *nf9rec;
    size_t len;
    uint16_t int_tid;
    rwRec *fwd_rec;
    rwRec *rev_rec;

    DEFINE_PREFIX_BUF(prefix);
    makeTracemsgPrefix(prefix, sizeof(prefix), skpcProbeGetName(probe),
                       fbSessionGetDomain(fBufGetSession(fbuf)),
                       record->tid, record->tmpl);
    TRACEMSG(2, (("%s bmap " BMAP_PRI ", read by ski_nf9rec_next()"),
                 prefix, record->bmap));
    assert(SKI_RECTYPE_NF9REC == record->rectype);

    /* Get a local handle to the record and clear it */
    fwd_rec = record->fwd_rec;
    RWREC_CLEAR(fwd_rec);
    rev_rec = NULL;

    /* The lower 16 bits of the context is the TID of the template to
     * use to read the record. */
    int_tid = record->bmap & UINT16_MAX;
    if ((int_tid & SKI_NF9REC_TID) != SKI_NF9REC_TID) {
        TRACEMSG(1, ("ski_nf9rec_next() called but TID %#06x does not match",
                     int_tid));
        return ski_ignore_next(fbuf, record, probe, err);
    }
    if (!fBufSetInternalTemplate(fbuf, int_tid, err)) {
        TRACEMSG(1, (("ski_nf9rec_next() called but setting Template"
                      " TID %#06x failed: %s"), int_tid, (*err)->message));
        g_clear_error(err);
        return ski_ignore_next(fbuf, record, probe, err);
    }
    len = sizeof(record->data.nf9rec);
    if (!fBufNext(fbuf, (uint8_t *)&record->data.nf9rec, &len, err)) {
        return -1;
    }
    assert(len == sizeof(ski_nf9rec_t));
    nf9rec = &record->data.nf9rec;

    /* Ignore records that do not have IPv4 addresses when SiLK was
     * built without IPv6 support. */
#if !SK_ENABLE_IPV6
    if (record->bmap & NF9REC_IP6) {
        ski_nf9rec_ignore(record, "IPv6 record");
        return 0;
    }
#endif  /* SK_ENABLE_IPV6 */

    /* When the nf9-out-is-reverse quirk is set, flip a bit on the
     * record's bitmap so volume is treated as initiator/responder. */
    if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_NF9_OUT_IS_REVERSE) {
        TRACEMSG(2, (("Modifying record bmap from " BMAP_PRI " to " BMAP_PRI
                      " due to nf9-out-is-reverse"),
                     record->bmap, record->bmap | NF9REC_INITIATOR));
        record->bmap |= NF9REC_INITIATOR;
    }

    /* Handle the firewall settings and check for reverse (responder)
     * volume.  See the big comment in ski_fixrec_next() for all the
     * gory details on firewall rules. */
    if (record->bmap & (TMPL_BIT_firewallEvent | TMPL_BIT_NF_F_FW_EVENT
                        | TMPL_BIT_NF_F_FW_EXT_EVENT))
    {
        /* Handle firewall events */
        char msg[64];
        uint8_t event = (nf9rec->firewallEvent
                         ? nf9rec->firewallEvent : nf9rec->NF_F_FW_EVENT);
        if (SKIPFIX_FW_EVENT_DENIED == event) {
            /* flow denied; there should be no reverse record */
            TRACEMSG(1, (("Processing flow denied event as actual flow record;"
                          " firewallEvent=%u, NF_F_FW_EVENT=%u,"
                          " NF_F_FW_EXT_EVENT=%u"),
                         nf9rec->firewallEvent, nf9rec->NF_F_FW_EVENT,
                         nf9rec->NF_F_FW_EXT_EVENT));
            if (SKIPFIX_FW_EVENT_DENIED_CHECK_VALID(nf9rec->NF_F_FW_EXT_EVENT))
            {
                rwRecSetMemo(fwd_rec, nf9rec->NF_F_FW_EXT_EVENT);
            } else {
                rwRecSetMemo(fwd_rec, event);
            }
            /* flow denied events from the Cisco ASA typically have
             * zero in the bytes and packets field */
            if (nf9rec->octetDeltaCount) {
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
                if (nf9rec->packetDeltaCount) {
                    rwRecSetPkts(
                        fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
                } else {
                    TRACEMSG(1, ("Setting forward packets to 1"
                                 " for denied firewall event"));
                    rwRecSetPkts(fwd_rec, 1);
                }
            } else if (nf9rec->postOctetDeltaCount
                       && !(record->bmap & NF9REC_INITIATOR))
            {
                /* postOctet value is non-zero and it is not
                 * responderOctets; use in place of standard value */
                rwRecSetBytes(fwd_rec,
                              CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                if (nf9rec->postPacketDeltaCount) {
                    rwRecSetPkts(fwd_rec,
                                 CLAMP_VAL32(nf9rec->postPacketDeltaCount));
                } else {
                    TRACEMSG(1, ("Setting forward packets to 1 for denied"
                                 " firewall event (postOctets non-zero)"));
                    rwRecSetPkts(fwd_rec, 1);
                }
            } else if (nf9rec->packetDeltaCount) {
                TRACEMSG(1, ("Setting forward bytes equal to packets value"
                             " for denied firewall event"));
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
                rwRecSetPkts(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
            } else {
                TRACEMSG(1, ("Setting forward bytes and packets to 1"
                             " for denied firewall event"));
                rwRecSetBytes(fwd_rec, 1);
                rwRecSetPkts(fwd_rec, 1);
            }

        } else if (SKIPFIX_FW_EVENT_DELETED != event) {
            /* flow created, flow updated, flow alert, or something
             * unexpected. These are ignored */
            if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_FIREWALL) {
                snprintf(msg, sizeof(msg), "firewallEvent=%u,extended=%u",
                         event, nf9rec->NF_F_FW_EXT_EVENT);
                ski_nf9rec_ignore(record, msg);
            }
            return 0;
        } else {
            /* flow deleted */
            TRACEMSG(1,(("Processing flow deleted event as actual flow record;"
                         " firewallEvent=%u, NF_F_FW_EVENT=%u,"
                         " NF_F_FW_EXT_EVENT=%u"),
                        nf9rec->firewallEvent, nf9rec->NF_F_FW_EVENT,
                        nf9rec->NF_F_FW_EXT_EVENT));
            /* these normally have a byte count, but not always */
            if (nf9rec->octetDeltaCount) {
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
                if (nf9rec->packetDeltaCount) {
                    rwRecSetPkts(
                        fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
                } else {
                    TRACEMSG(1, ("Setting forward packets to 1"
                                 " for deleted firewall event"));
                    rwRecSetPkts(fwd_rec, 1);
                }
            } else if (nf9rec->postOctetDeltaCount
                       && !(record->bmap & NF9REC_INITIATOR))
            {
                /* postOctet value is non-zero and it is not
                 * responderOctets; use in place of standard value */
                rwRecSetBytes(fwd_rec,
                              CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                if (nf9rec->postPacketDeltaCount) {
                    rwRecSetPkts(fwd_rec,
                                 CLAMP_VAL32(nf9rec->postPacketDeltaCount));
                } else {
                    TRACEMSG(1, ("Setting forward packets to 1 for deleted"
                                 " firewall event (postOctets non-zero)"));
                    rwRecSetPkts(fwd_rec, 1);
                }
            } else if (nf9rec->packetDeltaCount) {
                TRACEMSG(1, ("Setting forward bytes equal to packets value"
                             " for deleted firewall event"));
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
                rwRecSetPkts(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
            } else {
                TRACEMSG(1, ("Setting forward bytes and packets to 1"
                             " for deleted firewall event"));
                rwRecSetBytes(fwd_rec, 1);
                rwRecSetPkts(fwd_rec, 1);
            }

            /* handle reverse record */
            if (!(record->bmap & NF9REC_INITIATOR)) {
                /* There is no reverse data */
            } else if (nf9rec->postOctetDeltaCount) {
                /* there is a reverse byte count: postOctet and
                 * postPacket members hold responder values */
                RWREC_CLEAR(record->rev_rec);
                rev_rec = record->rev_rec;
                rwRecSetBytes(
                    rev_rec, CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                if (nf9rec->postPacketDeltaCount) {
                    rwRecSetPkts(
                        rev_rec, CLAMP_VAL32(nf9rec->postPacketDeltaCount));
                } else {
                    TRACEMSG(1, ("Setting reverse packets to 1"
                                 " for deleted firewall event"));
                    rwRecSetPkts(rev_rec, 1);
                }
            } else if (nf9rec->postPacketDeltaCount) {
                /* there is a reverse packet count */
                RWREC_CLEAR(record->rev_rec);
                rev_rec = record->rev_rec;
                TRACEMSG(1, ("Setting reverse bytes equal to packets value"
                             " for deleted firewall event"));
                rwRecSetBytes(
                    rev_rec, CLAMP_VAL32(nf9rec->postPacketDeltaCount));
                rwRecSetPkts(
                    rev_rec, CLAMP_VAL32(nf9rec->postPacketDeltaCount));
            }
            /* else no reverse record */
        }
    } else if (!(record->bmap & NF9REC_INITIATOR)) {
        /* there is no firewall event data and no reverse data; set
         * forward data */
        if (nf9rec->octetDeltaCount) {
            /* use the forward octet count which is non-zero */
            if (nf9rec->packetDeltaCount) {
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
                rwRecSetPkts(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
            } else if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
                TRACEMSG(1, ("Setting forward packets to 1"
                             " outside of firewall event handler"));
                rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
                rwRecSetPkts(fwd_rec, 1);
            } else {
                ski_nf9rec_ignore(record, "No forward packets");
                return 0;
            }
        } else if (nf9rec->postOctetDeltaCount) {
            /* postOctet value is non-zero and it is not
             * responderOctets; use in place of standard value */
            if (nf9rec->postPacketDeltaCount) {
                rwRecSetBytes(fwd_rec,
                              CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                rwRecSetPkts(fwd_rec,
                             CLAMP_VAL32(nf9rec->postPacketDeltaCount));
            } else if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
                TRACEMSG(1, ("Setting forward packets to 1"
                             " outside of firewall event handler"));
                rwRecSetBytes(fwd_rec,
                              CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                rwRecSetPkts(fwd_rec, 1);
            } else {
                ski_nf9rec_ignore(record, "No forward packets");
                return 0;
            }
        } else {
            ski_nf9rec_ignore(record, "No forward octets");
            return 0;
        }
    } else if (nf9rec->octetDeltaCount) {
        /* the template included initiatorOctets & responderOctets and
         * there is forward volume */
        if (nf9rec->packetDeltaCount) {
            rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
            rwRecSetPkts(fwd_rec, CLAMP_VAL32(nf9rec->packetDeltaCount));
        } else if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
            TRACEMSG(1, ("Setting forward packets to 1"
                         " outside of firewall event handler"));
            rwRecSetBytes(fwd_rec, CLAMP_VAL32(nf9rec->octetDeltaCount));
            rwRecSetPkts(fwd_rec, 1);
        } else {
            ski_nf9rec_ignore(record, "No forward packets");
            return 0;
        }
        if (nf9rec->postOctetDeltaCount) {
            /* there is a reverse byte count (responderOctets) */
            if (nf9rec->postPacketDeltaCount) {
                RWREC_CLEAR(record->rev_rec);
                rev_rec = record->rev_rec;
                rwRecSetBytes(
                    rev_rec, CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                rwRecSetPkts(
                    rev_rec, CLAMP_VAL32(nf9rec->postPacketDeltaCount));
            } else if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
                RWREC_CLEAR(record->rev_rec);
                rev_rec = record->rev_rec;
                TRACEMSG(1, ("Setting reverse packets to 1"
                             " outside of firewall event handler"));
                rwRecSetBytes(
                    rev_rec, CLAMP_VAL32(nf9rec->postOctetDeltaCount));
                rwRecSetPkts(rev_rec, 1);
            } else {
                TRACEMSG(
                    1, ("Ignoring reverse bytes since no reverse packets"));
            }
        }
    } else if (nf9rec->postOctetDeltaCount) {
        /* reverse only record */
        ski_nf9rec_ignore(record,
                          "No forward octets (reverse octets are non-zero)");
        return 0;
    } else {
        ski_nf9rec_ignore(record, "No forward/reverse octets");
        return 0;
    }

    TRACEMSG(1, ("Read a %s nf9rec record", ((rev_rec)?"bi-flow":"forward")));

    /* Handle the IP addresses */
#if SK_ENABLE_IPV6
    if (record->bmap & NF9REC_IP6) {
        rwRecSetIPv6(fwd_rec);
        rwRecMemSetSIPv6(fwd_rec, nf9rec->addr.ip6.sourceIPv6Address);
        rwRecMemSetDIPv6(fwd_rec, nf9rec->addr.ip6.destinationIPv6Address);
        rwRecMemSetNhIPv6(fwd_rec, nf9rec->addr.ip6.ipNextHopIPv6Address);
        if (rev_rec) {
            rwRecSetIPv6(rev_rec);
            rwRecMemSetSIPv6(rev_rec, &nf9rec->addr.ip6.destinationIPv6Address);
            rwRecMemSetDIPv6(rev_rec, &nf9rec->addr.ip6.sourceIPv6Address);
            rwRecMemSetNhIPv6(rev_rec, &nf9rec->addr.ip6.ipNextHopIPv6Address);
        }
    } else
#endif /* SK_ENABLE_IPV6 */
    {
        /* Take values from IPv4 */
        rwRecSetSIPv4(fwd_rec, nf9rec->addr.ip4.sourceIPv4Address);
        rwRecSetDIPv4(fwd_rec, nf9rec->addr.ip4.destinationIPv4Address);
        rwRecSetNhIPv4(fwd_rec, nf9rec->addr.ip4.ipNextHopIPv4Address);
        if (rev_rec) {
            rwRecSetSIPv4(rev_rec, nf9rec->addr.ip4.destinationIPv4Address);
            rwRecSetDIPv4(rev_rec, nf9rec->addr.ip4.sourceIPv4Address);
            rwRecSetNhIPv4(rev_rec, nf9rec->addr.ip4.ipNextHopIPv4Address);
        }
    }

    /* Time stamp */
    if (record->bmap & NF9REC_MILLI) {
        if (0 == nf9rec->t.milli.flowStartMilliseconds) {
            rwRecSetStartTime(
                fwd_rec, (sktime_t)nf9rec->t.milli.flowEndMilliseconds);
            rwRecSetElapsed(fwd_rec, 0);
        } else {
            int64_t dur = (nf9rec->t.milli.flowEndMilliseconds
                           - nf9rec->t.milli.flowStartMilliseconds);
            rwRecSetStartTime(
                fwd_rec, (sktime_t)nf9rec->t.milli.flowStartMilliseconds);
            if (dur < 0) {
                rwRecSetElapsed(fwd_rec, 0);
            } else if (dur > (int64_t)UINT32_MAX) {
                rwRecSetElapsed(fwd_rec, UINT32_MAX);
            } else {
                rwRecSetElapsed(fwd_rec, (uint32_t)dur);
            }
        }
        if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS) {
            sktimestamp_r(stime_buf, rwRecGetStartTime(fwd_rec),
                          SKTIMESTAMP_UTC);
            INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                     " flowStartMilliseconds=%" PRIu64
                     ", flowEndMilliseconds=%" PRIu64),
                    skpcProbeGetName(probe), stime_buf,
                    (double)rwRecGetElapsed(fwd_rec)/1000,
                    nf9rec->t.milli.flowStartMilliseconds,
                    nf9rec->t.milli.flowEndMilliseconds);
        }
    } else {
        /* Times based on flow generator system uptimes (Netflow v9) */
        intmax_t uptime, difference;
        sktime_t export_msec;
        const char *rollover_first;
        const char *rollover_last = "";

        assert(record->bmap & NF9REC_SYSUP);

        /* Compute the uptime: systemInitTimeMilliseconds is the
         * absolute router boot time (msec), and libfixbuf sets it by
         * subtracting the NFv9 uptime (msec) from the record's
         * absolute export time (sec). */
        export_msec = sktimeCreate(fBufGetExportTime(fbuf), 0);
        uptime = export_msec - nf9rec->t.sysup.systemInitTimeMilliseconds;
        if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_NF9_SYSUPTIME_SECS) {
            /* uptime was reported in seconds, not msec */
            TRACEMSG(2, (("Before adjustment: exportTimeMillisec %" PRIu64
                          ", initTimeMillisec %" PRIu64 ", uptime %" PRIdMAX
                          ", startUpTime %" PRIu32 ", endUpTime %" PRIu32
                          ", packets %" PRIu32),
                         export_msec,
                         nf9rec->t.sysup.systemInitTimeMilliseconds,
                         uptime, nf9rec->t.sysup.flowStartSysUpTime,
                         nf9rec->t.sysup.flowEndSysUpTime,
                         rwRecGetPkts(fwd_rec)));
            uptime *= 1000;
            nf9rec->t.sysup.systemInitTimeMilliseconds = export_msec - uptime;
            if (rwRecGetPkts(fwd_rec) == 1
                && (nf9rec->t.sysup.flowEndSysUpTime
                    < nf9rec->t.sysup.flowStartSysUpTime))
            {
                /* sometimes the end time for single packet flows is
                 * very different than the start time. */
                nf9rec->t.sysup.flowEndSysUpTime
                    = nf9rec->t.sysup.flowStartSysUpTime;
            }
        }

        /* Compute duration */
        if (nf9rec->t.sysup.flowStartSysUpTime
            <= nf9rec->t.sysup.flowEndSysUpTime)
        {
            rwRecSetElapsed(fwd_rec, (nf9rec->t.sysup.flowEndSysUpTime
                                      - nf9rec->t.sysup.flowStartSysUpTime));
        } else {
            /* assume EndTime rolled-over and start did not */
            rwRecSetElapsed(
                fwd_rec, (ROLLOVER32 + nf9rec->t.sysup.flowEndSysUpTime
                          - nf9rec->t.sysup.flowStartSysUpTime));
            rollover_last = ", assume flowEndSysUpTime rollover";
        }
        /* Compute uptime, checking for rollover */
        difference = uptime - nf9rec->t.sysup.flowStartSysUpTime;
        if (difference > MAXIMUM_FLOW_TIME_DEVIATION) {
            /* assume upTime is set before record is composed and
             * that start-time has rolled over. */
            rwRecSetStartTime(
                fwd_rec, (nf9rec->t.sysup.systemInitTimeMilliseconds
                          + nf9rec->t.sysup.flowStartSysUpTime
                          + ROLLOVER32));
            rollover_first = ", assume flowStartSysUpTime rollover";
        } else if (-difference > MAXIMUM_FLOW_TIME_DEVIATION) {
            /* assume upTime is set after record is composed and
             * that upTime has rolled over. */
            rwRecSetStartTime(
                fwd_rec, (nf9rec->t.sysup.systemInitTimeMilliseconds
                          + nf9rec->t.sysup.flowStartSysUpTime
                          - ROLLOVER32));
            rollover_first = ", assume sysUpTime rollover";
        } else {
            /* times look reasonable; assume no roll over */
            rwRecSetStartTime(
                fwd_rec, (nf9rec->t.sysup.systemInitTimeMilliseconds
                          + nf9rec->t.sysup.flowStartSysUpTime));
            rollover_first = "";
        }
        if (skpcProbeGetLogFlags(probe) & SOURCE_LOG_TIMESTAMPS) {
            sktimestamp_r(
                stime_buf, rwRecGetStartTime(fwd_rec), SKTIMESTAMP_UTC);
            INFOMSG(("'%s': Set sTime=%sZ, dur=%.3fs from incoming record"
                     " flowStartSysUpTime=%" PRIu32
                     ", flowEndSysUpTime=%" PRIu32
                     ", systemInitTimeMilliseconds=%" PRIu64
                     ", exportTimeSeconds=%" PRIu32
                     ", calculated sysUpTime=%" PRIdMAX "%s%s"),
                    skpcProbeGetName(probe),
                    stime_buf, (double)rwRecGetElapsed(fwd_rec)/1000,
                    nf9rec->t.sysup.flowStartSysUpTime,
                    nf9rec->t.sysup.flowEndSysUpTime,
                    nf9rec->t.sysup.systemInitTimeMilliseconds,
                    fBufGetExportTime(fbuf), uptime,
                    rollover_first, rollover_last);
        }
    }

    /* SNMP or VLAN interfaces */
    if (SKPC_IFVALUE_SNMP == skpcProbeGetInterfaceValueType(probe)) {
        rwRecSetInput(fwd_rec, CLAMP_VAL16(nf9rec->ingressInterface));
        rwRecSetOutput(fwd_rec, CLAMP_VAL16(nf9rec->egressInterface));
    } else {
        rwRecSetInput(fwd_rec, nf9rec->vlanId);
        rwRecSetOutput(fwd_rec, nf9rec->postVlanId);
    }

    /* Check for active timeout flag in the flowEndReason */
    if ((nf9rec->flowEndReason & SKI_END_MASK) == SKI_END_ACTIVE) {
        rwRecSetTcpState(fwd_rec, SK_TCPSTATE_TIMEOUT_KILLED);
    }

    rwRecSetProto(fwd_rec, nf9rec->protocolIdentifier);

    /* For TCP Flags, use whatever value was given in tcpControlBits,
     * regardless of protocol */
    rwRecSetFlags(fwd_rec, nf9rec->tcpControlBits);
    if (!rwRecIsICMP(fwd_rec)) {
        /* Use whatever values are in sport and dport, regardless of
         * protocol */
        rwRecSetSPort(fwd_rec, nf9rec->sourceTransportPort);
        rwRecSetDPort(fwd_rec, nf9rec->destinationTransportPort);
        if (rev_rec) {
            rwRecSetSPort(rev_rec, nf9rec->destinationTransportPort);
            rwRecSetDPort(rev_rec, nf9rec->sourceTransportPort);
        }
    } else {
        /* ICMP Record */
        /* Store ((icmpType << 8) | icmpCode) in the dPort if
         * available; else use the dport */
        rwRecSetSPort(fwd_rec, 0);
        if (record->bmap & TMPL_BIT_icmpTypeCodeIPv4) {
            rwRecSetDPort(fwd_rec, nf9rec->icmpTypeCode);
        } else if (record->bmap & TMPL_BIT_icmpTypeIPv4) {
            rwRecSetDPort(fwd_rec,((nf9rec->icmpType << 8)| nf9rec->icmpCode));
        } else {
            rwRecSetDPort(fwd_rec, nf9rec->destinationTransportPort);
        }
        if (rev_rec) {
            rwRecSetSPort(rev_rec, 0);
            rwRecSetDPort(rev_rec, rwRecGetDPort(fwd_rec));
        }
    }

    if (rev_rec) {
        rwRecSetStartTime(rev_rec, rwRecGetStartTime(fwd_rec));
        rwRecSetElapsed(rev_rec, rwRecGetElapsed(fwd_rec));
        rwRecSetInput(rev_rec, rwRecGetOutput(fwd_rec));
        rwRecSetOutput(rev_rec, rwRecGetInput(fwd_rec));
        rwRecSetTcpState(rev_rec, rwRecGetTcpState(fwd_rec));
        rwRecSetProto(fwd_rec, nf9rec->protocolIdentifier);
    }

    /* all done */
    return ((rev_rec) ? 2 : 1);
}


/*
 *    Helper function for ipfix_reader().
 *
 *    Handle the result of converting an IPFIX record to SiLK Flow
 *    records on 'source': update statistics, store the reverse record
 *    (if any) into the circular buffer, and move to the next location
 *    in the circular buffer.  The expected values for 'read_result'
 *    are 0 (record ignored), 1 (uni-flow), and 2 (bi-flow).
 */
static void
ipfix_reader_update_circbuf(
    skIPFIXSource_t    *source,
    int                 read_result)
{
#if !SOURCE_LOG_MAX_PENDING_WRITE
#define circbuf_count_addr  NULL
#else
#define circbuf_count_addr  &circbuf_count
    uint32_t circbuf_count;
#endif

    switch (read_result) {
      case 0:
        /* Ignore record */
        pthread_mutex_lock(&source->stats_mutex);
        ++source->ignored_flows;
        pthread_mutex_unlock(&source->stats_mutex);
        break;

      case 1:
        /* We have filled the empty source->current_record slot.
         * Advance to the next record location.  */
        if (skCircBufGetWriterBlock(
                source->circbuf, &source->current_record, circbuf_count_addr))
        {
            assert(source->stopped);
            break;
        }
        pthread_mutex_lock(&source->stats_mutex);
        ++source->forward_flows;
#if SOURCE_LOG_MAX_PENDING_WRITE
        if (circbuf_count > source->max_pending) {
            source->max_pending = circbuf_count;
        }
#endif
        pthread_mutex_unlock(&source->stats_mutex);
        break;

      case 2:
        /* copy reverse record into the circular buf */
        if (skCircBufGetWriterBlock(
                source->circbuf, &source->current_record, NULL))
        {
            assert(source->stopped);
            break;
        }
        memcpy(source->current_record, &source->rvbuf, sizeof(source->rvbuf));
        if (skCircBufGetWriterBlock(
                source->circbuf, &source->current_record, circbuf_count_addr))
        {
            assert(source->stopped);
            break;
        }
        pthread_mutex_lock(&source->stats_mutex);
        ++source->forward_flows;
        ++source->reverse_flows;
#if SOURCE_LOG_MAX_PENDING_WRITE
        if (circbuf_count > source->max_pending) {
            source->max_pending = circbuf_count;
        }
#endif
        pthread_mutex_unlock(&source->stats_mutex);
        break;

      default:
        skAbortBadCase(read_result);
    }
}


/*
 *    THREAD ENTRY POINT
 *
 *    The ipfix_reader() function is the main thread for listening to
 *    data from a single fbListener_t object.  It is passed the
 *    skIPFIXSourceBase_t object containing that fbListener_t object.
 *    This thread is started from the ipfixSourceCreateFromSockaddr()
 *    function.
 */
void *
ipfix_reader(
    void               *vsource_base)
{
#define IS_UDP (base->connspec->transport == FB_UDP)
    skIPFIXSourceBase_t *base = (skIPFIXSourceBase_t *)vsource_base;
    skIPFIXConnection_t *conn = NULL;
    skIPFIXSource_t *source = NULL;
    GError *err = NULL;
    fBuf_t *fbuf = NULL;
    int rv;

    TRACE_ENTRY;

    /* Ignore all signals */
    skthread_ignore_signals();

    /* Communicate that the thread has started */
    pthread_mutex_lock(&base->mutex);
    pthread_cond_signal(&base->cond);
    base->started = 1;
    base->running = 1;
    DEBUGMSG("fixbuf listener started for [%s]:%s",
             base->connspec->host ? base->connspec->host : "*",
             base->connspec->svc);
    pthread_mutex_unlock(&base->mutex);

    TRACEMSG(3, ("base %p started for [%s]:%s",
                 base, base->connspec->host ? base->connspec->host : "*",
                 base->connspec->svc));

    /* Loop until destruction of the base object */
    while (!base->destroyed) {

        /* wait for a new connection */
        fbuf = fbListenerWait(base->listener, &err);
        if (NULL == fbuf) {
            if (NULL == err) {
                /* got an unknown error---treat as fatal */
                NOTICEMSG("fixbuf listener shutting down:"
                          " unknown error from fbListenerWait");
                break;
            }

            if (g_error_matches(err,SK_IPFIXSOURCE_DOMAIN,SK_IPFIX_ERROR_CONN))
            {
                /* the callback rejected the connection (TCP only) */
                DEBUGMSG("fixbuf listener rejected connection: %s",
                         err->message);
                g_clear_error(&err);
                continue;
            }

            /* FB_ERROR_NLREAD indicates interrupted read, either
             * because the socket received EINTR or because
             * fbListenerInterrupt() was called.
             *
             * FB_ERROR_EOM indicates an end-of-message, and needs to
             * be ignored when running in manual mode. */
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD)
                || g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM))
            {
                TRACEMSG(1, (("fixbuf listener received %s"
                              " while waiting for a connection: %s"),
                             ((FB_ERROR_EOM == err->code)
                              ? "end-of-message" : "interrupted read"),
                             err->message));
                g_clear_error(&err);
                continue;
            }

            /* treat any other error as fatal */
            NOTICEMSG(("fixbuf listener shutting down: %s"
                       " (d=%" PRIu32 ",c=%" PRId32 ")"),
                      err->message, (uint32_t)err->domain, (int32_t)err->code);
            g_clear_error(&err);
            break;
        }

        /* Make sure the fbuf is in manual mode.  Manual mode is
         * required to multiplex among multiple collectors using
         * fbListenerWait().  Without this, fBufNext() blocks once the
         * buffer is empty until it has messages again.  Instead, we
         * want to switch to a different fbuf once we read all records
         * in the current buffer. */
        fBufSetAutomaticMode(fbuf, 0);

#if 0
        /* Added #if 0 since this should not be needed; the callback
         * is added to the session when the session is allocated. */

        /* Invoke a callback when a new template arrives that tells
         * fixbuf how to map from the subTemplateMultiList used by YAF
         * for TCP information to our internal strucure. */
        skiAddSessionCallback(fBufGetSession(fbuf));
#endif  /* 0 */

        /* Loop over fBufNext() until the buffer empties, we begin to
         * shutdown, or there is an error.  All the ski_*_next()
         * functions call fBufNext() internally. */
        conn = NULL;
        while (!base->destroyed) {
            ski_rectype_t rectype;
            ski_record_t record;

            /* Determine what type of record is next; this calls
             * fBufNextCollectionTemplate(), and gives error at end of
             * message */
            rectype = ski_rectype_next(fbuf, &record, &err);

            if (!conn) {
                /* Get the connection data associated with this fBuf_t
                 * object.  In manual mode this loop processes a
                 * single msg, which must have a single source. */
                conn = ((skIPFIXConnection_t *)
                        fbCollectorGetContext(fBufGetCollector(fbuf)));
                if (conn == NULL) {
                    /* If conn is NULL, we must have rejected a UDP
                     * connection from the appInit function. */
                    assert(rectype == SKI_RECTYPE_ERROR);
                    TRACEMSG(2, ("<UNKNOWN>: %s", ski_rectype_name[rectype]));
                    break;
                }
                source = conn->source;
                assert(source != NULL);

                TRACEMSG(5, ("'%s': conn = %p, source = %p, fbuf = %p",
                             source->name, conn, source, fbuf));

                /* If this source is stopped, end the connection. If
                 * source is told to stop while processing msg, the
                 * circbuf will inform us. */
                if (source->stopped) {
                    TRACEMSG(1, (("'%s': Closing connection since"
                                  " source is stopping"), source->name));
                    if (!IS_UDP) {
                        fBufFree(fbuf);
                        fbuf = NULL;
                    }
                    if (rectype == SKI_RECTYPE_ERROR) {
                        g_clear_error(&err);
                    }
                    break;
                }
            }

            /* There is a 'break' statement after this switch(), so
             * any "normal" event (no error condition and buffer is
             * not empty) must use 'continue' after processing to
             * continue the loop.  Any 'break' indicates an error. */
            switch (rectype) {
              case SKI_RECTYPE_ERROR:
                TRACEMSG(2, ("'%s': %s",
                             source->name, ski_rectype_name[rectype]));
                break;          /* error */

              case SKI_RECTYPE_IGNORE:
                /* An unknown/ignored template */
                if (!ski_ignore_next(fbuf, &record, source->probe, &err)){
                    /* should have been able to read something */
                    TRACEMSG(2, ("'%s': %s and ski_ignore_next() is FALSE",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                continue;

              case SKI_RECTYPE_YAFSTATS:
                if (!ski_yafstats_next(fbuf, &record, source->probe, &err)){
                    /* should have been able to read the stats */
                    TRACEMSG(2, ("'%s': %s and ski_yafstats_next() is FALSE",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                ski_yafstats_update_source(
                    source, &record, &conn->prev_yafstats);
                continue;

              case SKI_RECTYPE_TOMBSTONE:
                if (!ski_tombstone_next(fbuf, &record, source->probe, &err)){
                    TRACEMSG(2, ("'%s': %s and ski_tombstone_next() is FALSE",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                continue;

              case SKI_RECTYPE_NF9SAMPLING:
                if (!ski_nf9sampling_next(fbuf, &record, source->probe, &err)){
                    /* should have been able to read something */
                    TRACEMSG(2, ("'%s': %s and ski_nf9sampling_next() is FALSE",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                continue;

              case SKI_RECTYPE_FIXREC:
                assert(source->current_record);
                record.fwd_rec = source->current_record;
                record.rev_rec = &source->rvbuf;
                rv = ski_fixrec_next(fbuf, &record, source->probe, &err);
                if (-1 == rv) {
                    TRACEMSG(2, ("'%s': %s and ski_fixrec_next() returned -1",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                ipfix_reader_update_circbuf(source, rv);
                continue;

              case SKI_RECTYPE_YAFREC:
                assert(source->current_record);
                record.fwd_rec = source->current_record;
                record.rev_rec = &source->rvbuf;
                rv = ski_yafrec_next(fbuf, &record, source->probe, &err);
                if (-1 == rv) {
                    TRACEMSG(2, ("'%s': %s and ski_yafrec_next() returned -1",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                ipfix_reader_update_circbuf(source, rv);
                continue;

              case SKI_RECTYPE_NF9REC:
                assert(source->current_record);
                record.fwd_rec = source->current_record;
                record.rev_rec = &source->rvbuf;
                rv = ski_nf9rec_next(fbuf, &record, source->probe, &err);
                if (-1 == rv) {
                    TRACEMSG(2, ("'%s': %s and ski_nf9rec_next() returned -1",
                                 source->name, ski_rectype_name[rectype]));
                    break;      /* error */
                }
                ipfix_reader_update_circbuf(source, rv);
                continue;
            } /* switch (rectype) */

            /* If we get here, stop reading from the current fbuf.
             * This may be because the fbuf is empty, because we are
             * shutting down, or due to an error. */
            break;
        }
        /* Finished with current IPFIX message, encountered an error
         * while processing message, or we are shutting down */

        /* Handle FB_ERROR_NLREAD and FB_ERROR_EOM returned by
         * fBufNext() in the same way as when they are returned by
         * fbListenerWait().
         *
         * FB_ERROR_NLREAD is also returned when a previously rejected
         * UDP client attempts to send more data. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD)
            || g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM))
        {
            TRACEMSG(1, ("'%s': Ignoring %s: %s",
                         (conn ? source->name : "<UNKNOWN>"),
                         ((FB_ERROR_EOM == err->code)
                          ? "end-of-message" : "interrupted read"),
                         err->message));
            /* Do not free the fbuf here.  The fbuf is owned by the
             * listener, and will be freed when the listener is freed.
             * Calling fBufFree() here would cause fixbuf to forget
             * the current template, which would cause it to ignore
             * records until a new template is transmitted. */
            g_clear_error(&err);
            continue;
        }

        /* SK_IPFIX_ERROR_CONN indicates that a new UDP "connection"
         * was rejected by the appInit function in a multi-UDP
         * libfixbuf session.  Do not free the fbuf since we do not
         * have a connection yet; wait for another connection. */
        if (g_error_matches(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN)) {
            assert(IS_UDP);
            INFOMSG("Closing connection: %s", err->message);
            g_clear_error(&err);
            continue;
        }

        /* Handle shutdown events */
        if (base->destroyed) {
            break;
        }

        /* Source has stopped, loop for the next source. */
        if (conn && source->stopped) {
            continue;
        }

        /* The remainder of the code in this while() block assumes
         * that 'source' is valid, which is only true if 'conn' is
         * non-NULL.  Trap that here, just in case. */
        if (NULL == conn) {
            if (NULL == err) {
                /* give up when error code is unknown */
                NOTICEMSG("'<UNKNOWN>': fixbuf listener shutting down:"
                          " unknown error from fBufNext");
                break;
            }
            DEBUGMSG("Ignoring packet: %s (d=%" PRIu32 ",c=%" PRId32 ")",
                     err->message, (uint32_t)err->domain, (int32_t)err->code);
            g_clear_error(&err);
            continue;
        }

        /* FB_ERROR_NETFLOWV9 indicates an anomalous netflow v9
         * record; these do not disturb fixbuf state, and so should be
         * ignored. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9)) {
            DEBUGMSG("'%s': Ignoring NetFlowV9 record: %s",
                     source->name, err->message);
            g_clear_error(&err);
            continue;
        }

        /* FB_ERROR_SFLOW indicates an anomalous sFlow
         * record; these do not disturb fixbuf state, and so should be
         * ignored. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW)) {
            DEBUGMSG("'%s': Ignoring sFlow record: %s",
                     source->name, err->message);
            g_clear_error(&err);
            continue;
        }

        /* FB_ERROR_TMPL indicates a set references a template ID for
         * which there is no template.  Log and continue. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            DEBUGMSG("'%s': Ignoring data set: %s",
                     source->name, err->message);
            g_clear_error(&err);
            continue;
        }

        /* FB_ERROR_IPFIX indicates invalid IPFIX.  We could simply
         * choose to log and continue; instead we choose to log, close
         * the connection, and continue. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX)) {
            if (IS_UDP) {
                DEBUGMSG("'%s': Ignoring invalid IPFIX: %s",
                         source->name, err->message);
            } else {
                INFOMSG("'%s': Closing connection; received invalid IPFIX: %s",
                        source->name, err->message);
                fBufFree(fbuf);
                fbuf = NULL;
            }
            g_clear_error(&err);
            continue;
        }

        /* FB_ERROR_EOF indicates that the connection associated with
         * this fBuf_t object has finished.  In this case, free the
         * fBuf_t object to close the connection.  Do not free the
         * fBuf_t for UDP connections, since these UDP-based fBuf_t
         * objects are freed with the listener. */
        if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
            if (!IS_UDP) {
                INFOMSG("'%s': Closing connection: %s",
                        source->name, err->message);
                fBufFree(fbuf);
                fbuf = NULL;
            }
            g_clear_error(&err);
            continue;
        }

        /* Handle an unexpected error generated by fixbuf */
        if (err && err->domain == FB_ERROR_DOMAIN) {
            if (IS_UDP) {
                DEBUGMSG(("'%s': Ignoring UDP packet: %s"
                          " (d=%" PRIu32 ",c=%" PRId32 ")"),
                         source->name, err->message,
                         (uint32_t)err->domain, (int32_t)err->code);
            } else {
                INFOMSG(("'%s': Closing connection: %s"
                         " (d=%" PRIu32 ",c=%" PRId32 ")"),
                        source->name, err->message,
                        (uint32_t)err->domain, (int32_t)err->code);
                fBufFree(fbuf);
                fbuf = NULL;
            }
            g_clear_error(&err);
            continue;
        }

        /* In the event of an unhandled error, end the thread. */
        if (NULL == err) {
            NOTICEMSG(("'%s': fixbuf listener shutting down:"
                       " unknown error from fBufNext"),
                      source->name);
        } else {
            NOTICEMSG(("'%s': fixbuf listener shutting down: %s"
                       " (d=%" PRIu32 ",c=%" PRId32 ")"),
                      source->name, err->message,
                      (uint32_t)err->domain, (int32_t)err->code);
            g_clear_error(&err);
        }
        break;
    }

    TRACEMSG(3, ("base %p exited while() loop", base));

    /* Free the fbuf if it exists.  (If it's UDP, it will be freed by
     * the destruction of the listener below.) */
    if (fbuf && !IS_UDP) {
        TRACEMSG(3, ("base %p calling fBufFree", base));
        fBufFree(fbuf);
    }

    /* Note that the thread is ending, and wait for
     * skIPFIXSourceDestroy() to mark this as destroyed */
    DEBUGMSG("fixbuf listener ending for [%s]:%s...",
             base->connspec->host ? base->connspec->host : "*",
             base->connspec->svc);
    pthread_mutex_lock(&base->mutex);
    while (!base->destroyed) {
        pthread_cond_wait(&base->cond, &base->mutex);
    }

    TRACEMSG(3, ("base %p is set to destroyed", base));

    /* Destroy the fbListener_t object.  This destroys the fbuf if the
     * stream is UDP. */
    ipfixSourceBaseFreeListener(base);

    /* Notify skIPFIXSourceDestroy() that the thread is ending */
    base->running = 0;
    pthread_cond_signal(&base->cond);
    DEBUGMSG("fixbuf listener ended for [%s]:%s.",
             base->connspec->host ? base->connspec->host : "*",
             base->connspec->svc);

    pthread_mutex_unlock(&base->mutex);

    TRACE_RETURN(NULL);
#undef IS_UDP
}


/*
 *    Requests a record from the file-based IPFIX source 'source'.
 *
 *    Returns 0 on success, -1 on failure.
 */
int
ipfixSourceGetRecordFromFile(
    skIPFIXSource_t        *source,
    rwRec                  *ipfix_rec)
{
    ski_record_t record;
    GError *err = NULL;
    int rv;

    TRACE_ENTRY;

    /* Reading from a file */
    pthread_mutex_lock(&source->base->mutex);
    assert(source->readbuf);

    if (source->reverse) {
        /* A reverse record exists from the previous flow */
        memcpy(ipfix_rec, &source->rvbuf, sizeof(*ipfix_rec));
        ++source->reverse_flows;
        source->reverse = 0;
    } else {
        /* Initialize the control variable for the do{}while() loop.
         * 0: ignore; 1: uniflow; 2: biflow; -1: error */
        rv = 0;
        do {
            /* Similar to the switch() block in ipfix_reader() above */
            switch (ski_rectype_next(source->readbuf, &record, &err)) {
              case SKI_RECTYPE_ERROR:
                rv = -1;
                break;          /* error */

              case SKI_RECTYPE_NF9SAMPLING:
              case SKI_RECTYPE_IGNORE:
                if (!ski_ignore_next(
                        source->readbuf, &record, source->probe, &err))
                {
                    /* should have been able to read something */
                    TRACEMSG(2, ("'%s': %s and ski_ignore_next() is FALSE",
                                 source->name,
                                 ski_rectype_name[record.rectype]));
                    rv = -1;
                    break;      /* error */
                }
                continue;

              case SKI_RECTYPE_YAFSTATS:
                if (!ski_yafstats_next(
                        source->readbuf, &record, source->probe, &err))
                {
                    /* should have been able to read the stats */
                    TRACEMSG(2, ("'%s': %s and ski_yafstats_next() is FALSE",
                                 source->name,
                                 ski_rectype_name[record.rectype]));
                    rv = -1;
                    break;      /* error */
                }
                ski_yafstats_update_source(
                    source, &record, &source->prev_yafstats);
                continue;

              case SKI_RECTYPE_TOMBSTONE:
                if (!ski_tombstone_next(
                        source->readbuf, &record, source->probe, &err))
                {
                    TRACEMSG(2, ("'%s': %s and ski_tombstone_next() is FALSE",
                                 source->name,
                                 ski_rectype_name[record.rectype]));
                    rv = -1;
                    break;      /* error */
                }
                continue;

              case SKI_RECTYPE_FIXREC:
                record.fwd_rec = ipfix_rec;
                record.rev_rec = &source->rvbuf;
                rv = ski_fixrec_next(source->readbuf, &record,
                                     source->probe, &err);
                if (rv == 0) {
                    ++source->ignored_flows;
                }
                break;

              case SKI_RECTYPE_YAFREC:
                record.fwd_rec = ipfix_rec;
                record.rev_rec = &source->rvbuf;
                rv = ski_yafrec_next(source->readbuf, &record,
                                     source->probe, &err);
                if (rv == 0) {
                    ++source->ignored_flows;
                }
                break;

              case SKI_RECTYPE_NF9REC:
                record.fwd_rec = ipfix_rec;
                record.rev_rec = &source->rvbuf;
                rv = ski_nf9rec_next(source->readbuf, &record,
                                     source->probe, &err);
                if (rv == 0) {
                    ++source->ignored_flows;
                }
                break;

              default:
                skAppPrintErr("Unexpected record type");
                skAbort();
            }
        } while (rv == 0);  /* Continue while current record is ignored */

        if (rv == -1) {
            /* End of file or other problem */
            g_clear_error(&err);
            pthread_mutex_unlock(&source->base->mutex);
            TRACE_RETURN(-1);
        }

        assert(rv == 1 || rv == 2);
        ++source->forward_flows;

        /* We have the next flow.  Set reverse if there is a
         * reverse record.  */
        source->reverse = (rv == 2);
    }

    pthread_mutex_unlock(&source->base->mutex);

    TRACE_RETURN(0);
}




/*
 *    The check-struct application calls the skiCheckDataStructure()
 *    function, and that function requires access to the C structures
 *    and templates that are local to this file.
 *
 *    The check-struct.c file contains both the
 *    skiCheckDataStructure() function and a main() function to use
 *    for the application.  The skiCheckDataStructure() is defined
 *    when SKIPFIX_SOURCE is defined, otherwise the main() function is
 *    defined.
 */
#include "check-struct.c"


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
