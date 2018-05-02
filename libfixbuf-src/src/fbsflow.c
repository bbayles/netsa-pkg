/**
 *@internal
 *
 * @file fbsflow.c
 *
 * This implements a SFlow convertor for translating into IPFIX
 * within the fixbuf structure
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2008-2018 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Emily Sarneso <ecoff@cert.org>
 * ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of the libfixbuf system and related source code is subject to the terms
 * of the following licenses:
 *
 * Copyright 2018 Carnegie Mellon University. All Rights Reserved.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 * ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 * BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 * LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 * EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 * MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 * ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 * COPYRIGHT INFRINGEMENT.
 *
 * Released under a GNU-Lesser GPL 3.0-style license, please see
 * License.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for
 * public release and unlimited distribution.  Please see Copyright
 * notice for non-US Government use and distribution.
 *
 * Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 * Trademark Office by Carnegie Mellon University.
 *
 * @OPENSOURCE_HEADER_END@
 * ------------------------------------------------------------------------
 *
 * @Author:  $Author$
 * @Date:    $Date$
 * @Version: $Revision$
 *
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#include "fbcollector.h"
#include <sys/time.h>
#include <pthread.h>


#ifndef FB_SFLOW_DEBUG
#   define FB_SFLOW_DEBUG 0
#endif

#define SFLOW_TID 0xEEEE
#define SFLOW_OPT_TID 0xEEEF

#define SF_MAX_SEQ_DIFF 100
#define SF_OUT_OF_ORDER 10
#define SF_REBOOT_SECS  60 * 1000 /* 1 min in milliseconds */

#define FB_SFLOW_ETHER  1
#define FB_SFLOW_IPv4   0x0800
#define FB_SFLOW_IPv6   0x86DD
#define FB_SFLOW_8021Q  0x8100
#define FB_SFLOW_MPLS   0x8847

#if HAVE_ALIGNED_ACCESS_REQUIRED

#define fb_ntohll(x) (x)
#define fb_htonll(x) fb_ntohll(x)

/**
 * this set of macros for reading and writing U16's and U32's
 * uses memcpy's to avoid tripping over alignment issues on
 * platforms that cannot do unaligned access (e.g. SPARC, Alpha,
 * etc).  The next section, after the else, does not use memcpy's
 * and operates just fine on architectures that don't crash
 * from an unaligned access (x86, PowerPC, etc.)
 */

/**
 * READU16INC
 *
 * read U16 and increment
 *
 * read a U16 value from ptr, it assumes the pointer
 * is properly aligned and pointing at the correct
 * place; and then increment ptr appropriately
 * according to its size to adjust for reading a
 * U16; increments it 2-bytes
 *
 * does network to host translation
 */
#define READU16INC(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        memcpy(&ru16_t16val, ru16_t16ptr, sizeof(uint16_t)); \
        assignee = g_ntohs(ru16_t16val); \
        ptr += sizeof(*ru16_t16ptr) / sizeof(*ptr); \
    }

#define READU16(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        memcpy(&ru16_t16val, ru16_t16ptr, sizeof(uint16_t)); \
        assignee = g_ntohs(ru16_t16val); \
    }

#define WRITEU16(ptr,value) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = g_htons(value); \
        memcpy(ru16_t16ptr, &ru16_t16val, sizeof(uint16_t)); \
    }


/**
 * READU32INC
 *
 * read U32 and increment ptr
 *
 * read a U32 from the ptr given in ptr, it assumes
 * it is aligned and positioned correctly, then
 * increment the ptr appropriately based on its
 * size and having read a U32 to increment it
 * 4-bytes ahead
 *
 * does network to host translation
 */
#define READU32INC(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0;                        \
        memcpy(&ru32_t32val, ru32_t32ptr, sizeof(uint32_t));    \
        assignee = g_ntohl(ru32_t32val);                        \
        ptr += sizeof(*ru32_t32ptr) / sizeof(*ptr);             \
    }


#define READU32(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0; \
        memcpy(&ru32_t32val, ru32_t32ptr, sizeof(uint32_t)); \
        assignee = g_ntohl(ru32_t32val); \
    }

#define WRITEU32(ptr,value) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = g_htonl(value); \
        memcpy(ru32_t32ptr, &ru32_t32val, sizeof(uint32_t)); \
    }

#else


#define fb_ntohll(x) \
    ((((uint64_t)g_ntohl((uint32_t)((x) & 0xffffffff))) << 32)  \
     | g_ntohl((uint32_t)(((x) >> 32) & 0xffffffff)))
#define fb_htonll(x) fb_ntohll(x)


/**
 * READU16INC
 *
 * read U16 and increment
 *
 * read a U16 value from ptr, it assumes the pointer
 * is properly aligned and pointing at the correct
 * place; and then increment ptr appropriately
 * according to its size to adjust for reading a
 * U16; increments it 2-bytes
 *
 * does network to host translation
 */
#define READU16INC(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        ru16_t16val = g_ntohs(*ru16_t16ptr); \
        assignee = ru16_t16val; \
        ptr += sizeof(*ru16_t16ptr) / sizeof(*ptr); \
    }

#define READU16(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        ru16_t16val = g_ntohs(*ru16_t16ptr); \
        assignee = ru16_t16val; \
    }

#define WRITEU16(ptr,value) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        *ru16_t16ptr = g_htons(value); \
    }


/**
 * READU32INC
 *
 * read U32 and increment ptr
 *
 * read a U32 from the ptr given in ptr, it assumes
 * it is aligned and positioned correctly, then
 * increment the ptr appropriately based on its
 * size and having read a U32 to increment it
 * 4-bytes ahead
 *
 * does network to host translation
 */
#define READU32INC(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
    uint32_t ru32_t32val = 0; \
    ru32_t32val = g_ntohl(*ru32_t32ptr); \
    assignee = ru32_t32val; \
    ptr += sizeof(*ru32_t32ptr) / sizeof(*ptr); \
    }


#define READU32(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0; \
        ru32_t32val = g_ntohl(*ru32_t32ptr); \
        assignee = ru32_t32val; \
    }

#define WRITEU32(ptr,value) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        *ru32_t32ptr = g_htonl(value); \
    }

#endif


static fbInfoElementSpec_t sflow_spec[] = {
    { "sourceIPv6Address",              16, 0 },
    { "destinationIPv6Address",         16, 0 },
    { "ipNextHopIPv6Address",           16, 0 },
    { "bgpNextHopIPv6Address",          16, 0 },
    { "collectorIPv6Address",           16, 0 },
    { "collectionTimeMilliseconds",     8, 0 },
    { "systemInitTimeMilliseconds",     8, 0 },
    { "collectorIPv4Address",           4, 0 },
    { "protocolIdentifier",             1, 0 },
    { "ipClassOfService",               1, 0 },
    { "sourceIPv4PrefixLength",         1, 0 },
    { "destinationIPv4PrefixLength",    1, 0 },
    { "sourceIPv4Address",              4, 0 },
    { "destinationIPv4Address",         4, 0 },
    { "octetTotalCount",                4, 0 },
    { "packetTotalCount",               4, 0 },
    { "ingressInterface",               4, 0 },
    { "egressInterface",                4, 0 },
    { "sourceMacAddress",               6, 0 },
    { "destinationMacAddress",          6, 0 },
    { "ipNextHopIPv4Address",           4, 0 },
    { "bgpSourceAsNumber",              4, 0 },
    { "bgpDestinationAsNumber",         4, 0 },
    { "bgpNextHopIPv4Address",          4, 0 },
    { "samplingPacketInterval",         4, 0 },
    { "samplingPopulation",             4, 0 },
    { "droppedPacketTotalCount",        4, 0 },
    { "selectorId",                     4, 0 },
    { "vlanId",                         2, 0 },
    { "sourceTransportPort",            2, 0 },
    { "destinationTransportPort",       2, 0 },
    { "tcpControlBits",                 2, 0 },
    { "dot1qVlanId",                    2, 0 },
    { "postDot1qVlanId",                2, 0 },
    { "dot1qPriority",                  1, 0 },
    FB_IESPEC_NULL
};

typedef struct fbSFlowRecord_st{
    /* IPv6 or raw packet data */
    uint8_t               sourceIPv6Address[16];
    uint8_t               destinationIPv6Address[16];
    /* extended router data */
    uint8_t               nextHopIPv6Address[16];
    /* extended gateway data */
    uint8_t               bgpNextHopIPv6Address[16];
    /* flow header data */
    uint8_t               collectorIPv6Address[16];
    uint64_t              collectionTimeMilliseconds;
    uint64_t              systemUpTime;
    uint32_t              collectorIPv4Address;
    /* IPv4/6 data or raw packet data */
    uint8_t               protocolIdentifier;
    uint8_t               ipClassOfService;
    /* format 1002 next hop src/dst mask */
    uint8_t               sourceIPv4PrefixLength;
    uint8_t               destinationIPv4PrefixLength;
    /* IPv4 or raw packet data */
    uint32_t              sourceIPv4Address;
    uint32_t              destinationIPv4Address;
    /* flow header data */
    uint32_t              octetTotalCount;
    uint32_t              packetTotalCount;
    uint32_t              ingressInterface;
    uint32_t              egressInterface;
    /* ethernet frame data, ip, or raw packet data */
    uint8_t               sourceMacAddress[6];
    uint8_t               destinationMacAddress[6];
    /* extended router data */
    uint32_t              nextHopIPv4Address;
    /* extended gateway data */
    uint32_t              bgpSourceAsNumber;
    uint32_t              bgpDestinationAsNumber;
    uint32_t              bgpNextHopIPv4Address;
    /* flow sample fields */
    uint32_t              samplingPacketInterval;
    uint32_t              samplingPopulation;
    uint32_t              droppedPacketTotalCount;
    uint32_t              selectorId;
    /* IPv4/6 data or raw packet data */
    uint16_t              vlanId;
    uint16_t              sourceTransportPort;
    uint16_t              destinationTransportPort;
    uint16_t              tcpControlBits;
    /* extended switch data */
    uint16_t              dot1qVlanId;
    uint16_t              postDot1qVlanId;
    uint8_t               dot1qPriority;
} fbSFlowRecord_t;

static fbInfoElementSpec_t sflow_ctr_spec[] = {
    { "collectorIPv6Address",             16, 0 },
    { "collectionTimeMilliseconds",       8, 0 },
    { "systemInitTimeMilliseconds",       8, 0 },
    { "collectorIPv4Address",             4, 0 },
    { "ingressInterface",                 4, 0 },
    { "octetTotalCount",                  8, 0 },
    { "ingressInterfaceType",             4, 0 },
    { "packetTotalCount",                 4, 0 },
    { "ingressMulticastPacketTotalCount", 4, 0 },
    { "ingressBroadcastPacketTotalCount", 4, 0 },
    { "notSentPacketTotalCount",          4, 0 },
    { "droppedPacketTotalCount",          4, 0 },
    { "postOctetTotalCount",              8, 0 },
    { "ignoredPacketTotalCount",          4, 0 },
    { "postPacketTotalCount",             4, 0 },
    { "egressBroadcastPacketTotalCount",  4, 0 },
    { "selectorId",                       4, 0 },
    FB_IESPEC_NULL
};

typedef struct fbSFlowCounterRecord_st {
    uint8_t          ipv6[16];
    uint64_t         ctime;
    uint64_t         sysuptime;
    uint32_t         ipv4;
    uint32_t         ingress;
    uint64_t         inoct;
    uint32_t         ingressType;
    uint32_t         inpkt;
    uint32_t         inmulti;
    uint32_t         inbroad;
    uint32_t         indiscard;
    uint32_t         inerr;
    uint64_t         outoct;
    uint32_t         inunknown;
    uint32_t         outpkt;
    uint32_t         outbroad;
    uint32_t         agentid;
} fbSFlowCounterRecord_t;



/**
 * IPv4 header structure, without options.
 */
typedef struct fbHdrIPv4_st{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    /** IP header length in 32-bit words. */
    unsigned int    ip_hl:4,
    /** IP version. Always 4 for IPv4 packets.*/
        ip_v:4;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
    /** IP version. Always 4 for IPv4 packets.*/
    unsigned int    ip_v:4,
    /** IP header length in 32-bit words. */
        ip_hl:4;
#else
#error Cannot determine byte order while defining IP header structure.
#endif
    /** Type of Service */
    uint8_t         ip_tos;
    /** Total IP datagram length including header in bytes */
    uint16_t        ip_len;
    /** Fragment identifier */
    uint16_t        ip_id;
    /** Fragment offset and flags */
    uint16_t        ip_off;
    /** Time to live in routing hops */
    uint8_t         ip_ttl;
    /** Protocol identifier */
    uint8_t         ip_p;
    /** Header checksum */
    uint16_t        ip_sum;
    /** Source IPv4 address */
    uint32_t        ip_src;
    /** Destination IPv4 address */
    uint32_t        ip_dst;
} fbHdrIPv4_t;

/**
 * IPv6 header structure.
 */
typedef struct fbHdrIPv6_st {
    /** Version, traffic class, and flow ID. Use YF_VCF6_ macros to access. */
    uint32_t        ip6_vcf;
    /**
     * Payload length. Does NOT include IPv6 header (40 bytes), but does
     * include subsequent extension headers, upper layer headers, and payload.
     */
    uint16_t        ip6_plen;
    /** Next header identifier. Use YF_PROTO_ macros. */
    uint8_t         ip6_nxt;
    /** Hop limit */
    uint8_t         ip6_hlim;
    /** Source IPv6 address */
    uint8_t         ip6_src[16];
    /** Destination IPv6 address */
    uint8_t         ip6_dst[16];
} fbHdrIPv6_t;


typedef struct fbCollectorSFlowSession_st {
    /** potential sflow samples missed */
    uint32_t                    sflowMissed;
    /** current sFlow seq num */
    uint32_t                    sflowSeqNum;
    /** Flow Sample seq number */
    uint32_t                    sflowFlowSeqNum;
    /** Counter Sample seq number */
    uint32_t                    sflowCounterSeqNum;
} fbCollectorSFlowSession_t;

/** defines the extra state needed to convert from sFlow to IPFIX */
struct fbCollectorSFlowState_st {
    uint64_t                      ptime;
    uint32_t                      observation_id;
    uint32_t                      samples;
    fbCollectorSFlowSession_t     *session;
    fbSession_t                   *exsession;
    fbSession_t                   *cosession;
    fbInfoModel_t                 *model;
    fBuf_t                        *fbuf;
    uint8_t                       *ipfixBuffer;
    GHashTable                    *domainHash;
    pthread_mutex_t               ts_lock;
};


static void         sessionDestroyHelper(
    gpointer datum)
{
    g_slice_free(fbCollectorSFlowSession_t, datum);
}


static gboolean sflowAppendRec(
    fbCollector_t *collector,
    fbSFlowRecord_t *sflowrec,
    GError        **err)
{
    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;

    /* appending new record */

    if (!fBufSetExportTemplate(transState->fbuf, SFLOW_TID, err)) {
        return FALSE;
    }

    if (!fBufAppend(transState->fbuf, (uint8_t*)sflowrec,
                    sizeof(fbSFlowRecord_t), err))
    {
        /* error appending */
        return FALSE;
    }

    return TRUE;
}

static gboolean sflowAppendOptRec(
    fbCollector_t           *collector,
    fbSFlowCounterRecord_t  *sflowrec,
    GError                  **err)
{
    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;

    /* appending new record */

    if (!fBufSetInternalTemplate(transState->fbuf, SFLOW_OPT_TID, err)) {
        return FALSE;
    }

    if (!fBufSetExportTemplate(transState->fbuf, SFLOW_OPT_TID, err)) {
        return FALSE;
    }

    if (!fBufAppend(transState->fbuf, (uint8_t*)sflowrec,
                    sizeof(fbSFlowCounterRecord_t), err))
    {
        /* error appending */
        return FALSE;
    }

    if (!fBufSetInternalTemplate(transState->fbuf, SFLOW_TID, err)) {
        return FALSE;
    }

    return TRUE;
}



static fbExporter_t *sflowAllocExporter(
    uint8_t      *dataBuf,
    fBuf_t       *fbuf,
    GError       **err)
{
    fbExporter_t *exp = NULL;

    exp = fbExporterAllocBuffer(dataBuf, 65496);

    if (fbuf) {
        fBufSetExporter(fbuf, exp);

        if (!fBufSetInternalTemplate(fbuf, SFLOW_TID, err)) {
            return NULL;
        }

        if (!fBufSetExportTemplate(fbuf, SFLOW_TID, err)) {
            return NULL;
        }
    }

    return exp;

}


static gboolean sflowDecodeRawHeader(
    fbSFlowRecord_t         *sflowrec,
    uint8_t                 *header,
    uint32_t                headerlen,
    uint32_t                protocol,
    GError                  **err)
{
    uint16_t       type = 0;
    size_t         iph_len = 0;
    uint8_t        *data = header;
    uint16_t       datalen = headerlen;
    gboolean       v6 = TRUE;

#if FB_SFLOW_DEBUG
    fprintf(stderr, "PROTOCOL is %u\n", protocol);
#endif

    switch (protocol) {
      case (FB_SFLOW_ETHER) :
        if (headerlen < 14) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Header too small for Ethernet L2 Header");
            return FALSE;
        }

        memcpy(sflowrec->sourceMacAddress, data, 6);
        data += 6;
        memcpy(sflowrec->destinationMacAddress, data, 6);
        data += 6;
        READU16INC(data, type);
        datalen -= 14;
        break;
      case 11:
        /* IP v4 */
        type = FB_SFLOW_IPv4;
        break;
      case 12:
        /* IP v6 */
        type = FB_SFLOW_IPv6;
        break;
      case 13:
        /*MPLS*/
        break;
      default:
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                    "No support for Header protocol %d",
                    protocol);
        return FALSE;
    }

#if FB_SFLOW_DEBUG
    fprintf(stderr, "TYPE is %d\n", type);
#endif

    if (type == FB_SFLOW_8021Q) {
        if (datalen < 4) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Header too small for 802.1q Header");
            return FALSE;
        }
        READU16INC(data, sflowrec->vlanId);
        sflowrec->vlanId = sflowrec->vlanId & 0x0FFF;

#if FB_SFLOW_DEBUG
        fprintf(stderr, "vlan is %d\n", sflowrec->vlanId);
#endif
        READU16INC(data, type);
        datalen -= 4;
    }

    if (type == FB_SFLOW_IPv4) {
        const fbHdrIPv4_t *iph = (const fbHdrIPv4_t *)data;

        if (datalen < 1) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Header too small for IPv4 Header");
            return FALSE;
        }

        iph_len = iph->ip_hl * 4;
        if (datalen < iph_len) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Header too small for Full IPv4 Header");
            return FALSE;
        }

        sflowrec->sourceIPv4Address = g_ntohl(iph->ip_src);
        sflowrec->destinationIPv4Address = g_ntohl(iph->ip_dst);
        sflowrec->ipClassOfService = iph->ip_tos;
        sflowrec->protocolIdentifier = iph->ip_p;
#if FB_SFLOW_DEBUG
        fprintf(stderr, "IPv4 proto %d\n", sflowrec->protocolIdentifier);
#endif
        datalen -= iph_len;
        data += iph_len;

    } else if (type == FB_SFLOW_IPv6) {
        const fbHdrIPv6_t *iph = (const fbHdrIPv6_t *)data;
        uint8_t hdr_next;
        size_t hdr_len = 40;

        if (datalen < hdr_len) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Header too small for IPv6 Header");
            return FALSE;
        }

        memcpy(sflowrec->sourceIPv6Address, &(iph->ip6_src), 16);
        memcpy(sflowrec->destinationIPv6Address, &(iph->ip6_dst), 16);

        sflowrec->ipClassOfService = ((iph->ip6_vcf & 0x0FF00000) >> 20);

        hdr_next = iph->ip6_nxt;

        while (v6) {
            data += hdr_len;
            iph_len += hdr_len;
            datalen -= hdr_len;

            switch (hdr_next) {
              case 56:
                /* No Next Header */
                return TRUE;
              case 44:
                /* Frag */
                hdr_len = 8;
                if (datalen < 8) {
                    return TRUE;
                }
                /* next header identifier */
                hdr_next = *data;
                break;
              case 0:
              case 60:
              case 43:
                if (datalen < 2) {
                    return TRUE;
                }
                hdr_next = *data;
                hdr_len = (*(data + 1) * 8) + 8;
                if (hdr_len > datalen) {
                    return TRUE;
                }
                break;
              default:
                v6 = FALSE;
                sflowrec->protocolIdentifier = hdr_next;
#if FB_SFLOW_DEBUG
                fprintf(stderr,"IPv6 proto %d\n", sflowrec->protocolIdentifier);
#endif
                break;
            }
        }

        datalen -= iph_len;

    } else {
        /* not IP */
        return TRUE;
    }

    /* Layer 4 */

    if (sflowrec->protocolIdentifier == 6) {
        /* TCP */
        if (datalen < 13) {
            return TRUE;
        }

        READU16INC(data, sflowrec->sourceTransportPort);
        READU16INC(data, sflowrec->destinationTransportPort);
        /* skip seq nos*/
        data += 8;
        READU16INC(data, sflowrec->tcpControlBits);
        sflowrec->tcpControlBits = sflowrec->tcpControlBits & 0x0FFF;
#if FB_SFLOW_DEBUG
        fprintf(stderr, "TCP sp %d, dp %d, flags %02x\n", sflowrec->sourceTransportPort,
                sflowrec->destinationTransportPort, sflowrec->tcpControlBits);
#endif
    } else if (sflowrec->protocolIdentifier == 17) {
            /* UDP */
        if (datalen < 8) {
            return TRUE;
        }

        READU16INC(data, sflowrec->sourceTransportPort);
        READU16INC(data, sflowrec->destinationTransportPort);
#if FB_SFLOW_DEBUG
        fprintf(stderr,"UDP sp %d, dp %d\n", sflowrec->sourceTransportPort,
                sflowrec->destinationTransportPort);
#endif
    }

    return TRUE;
}

/*
 * sflowDecodeFlowHeaders
 *
 * this decodes formats 2,3,4.
 *
 *
 */


static void sflowDecodeFlowHeaders(
    fbSFlowRecord_t         *sflowrec,
    uint8_t                 *header,
    uint32_t                headerlen,
    uint16_t                format,
    GError                  **err)
{

    uint8_t *data = header;
    uint32_t sp, dp, proto, flags, tos;

    if (format == 2) {
        /* Ethernet header */
        READU32INC(data, sflowrec->octetTotalCount);
        memcpy(sflowrec->sourceMacAddress, data, 6);
        data += 8;

        memcpy(sflowrec->destinationMacAddress, data, 6);
        data += 8;

    } else if (format == 3) {
        /* IPv4 Data */
        READU32INC(data, sflowrec->octetTotalCount);
        READU32INC(data, proto);

        READU32INC(data, sflowrec->sourceIPv4Address);
        READU32INC(data, sflowrec->destinationIPv4Address);
        READU32INC(data, sp);
        READU32INC(data, dp);
        READU32INC(data, flags);
        READU32INC(data, tos);

        sflowrec->protocolIdentifier = (uint16_t)proto;
        sflowrec->sourceTransportPort = (uint16_t)sp;
        sflowrec->destinationTransportPort = (uint16_t)dp;
        sflowrec->tcpControlBits = (uint16_t)flags;
        sflowrec->ipClassOfService = (uint16_t)tos;
    } else if (format == 4) {
        /* IPv6 Data */

        READU32INC(data, sflowrec->octetTotalCount);
        READU32INC(data, proto);

        memcpy(sflowrec->sourceIPv6Address, data, 16);
        data += 16;
        memcpy(sflowrec->destinationIPv6Address, data, 16);
        data += 16;
        READU32INC(data, sp);
        READU32INC(data, dp);
        READU32INC(data, flags);
        READU32INC(data, tos);

        sflowrec->protocolIdentifier = (uint16_t)proto;
        sflowrec->sourceTransportPort =(uint16_t)sp;
        sflowrec->destinationTransportPort = (uint16_t)dp;
        sflowrec->tcpControlBits = (uint16_t)flags;
        sflowrec->ipClassOfService = (uint16_t)tos;
    }
}

/*#################################################
 *
 * SFlow functions for the collector, used
 * to optionally read
 *
 *#################################################*/

/**
 * fbCollectorDecodeSFlowMsgVL
 *
 * parses the header of a SFlow message and determines
 * how much needs to be read in order to complete
 * the message, (at least in theory)
 *
 * @param collector a pointer to the collector state
 *        structure
 * @param hdr a pointer to the beginning of the buffer
 *        to parse as a message (get converted back
 *        into a uint8_t* and used as such)
 * @param b_len length of the buffer passed in for the
 *        hdr
 * @param m_len length of the message header that still
 *        needs to be read (always set to zero, since
 *        this reads the entire message)
 * @param err a pointer to glib error structure, used
 *        if an error occurs during processing the
 *        stream
 *
 *
 * @return number of octets to read to complete
 *         the message
 */
static gboolean     fbCollectorDecodeSFlowMsgVL(
     fbCollector_t               *collector,
     fbCollectorMsgVL_t          *hdr,
     size_t                      b_len,
     uint16_t                    *m_len,
     GError                      **err)
{
    *m_len = 0;
    return TRUE;
}

/**
 * fbCollectorMessageHeaderSFlow
 *
 * this converts a sFlow header into something every so slightly
 * closer to an IPFIX header; it dumps the up time with a big memcpy
 *
 * @param collector pointer to the collector state structure
 * @param buffer pointer to the message buffer
 * @param b_len length of the buffer passed in
 * @param m_len pointer to the length of the resultant buffer
 * @param err pointer to a GLib error structure
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean    fbCollectorMessageHeaderSFlow (
    fbCollector_t               *collector,
    uint8_t                     *buffer,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err)
{
    uint32_t                    tempRead32;
    uint32_t                    ip_version;
    struct timeval              ct;
    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;


    if (b_len < 28) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                    "Invalid sFlow Header. Buffer Length too short. "
                    "Length: %d", (unsigned int)b_len);
        return FALSE;
    }

    /* first make sure the message seems like a sFlow message */
    READU32(buffer, tempRead32);

#if FB_SFLOW_DEBUG == 1
    fprintf(stderr, "version is %u\n", tempRead32);
#endif  /* FB_SFLOW_DEBUG */

    /* only accept version 5 */
    if (tempRead32 != 5) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                    "invalid version number for sFlow, expecting 5,"
                    " received %u", tempRead32);
        return FALSE;
    }

    READU32((buffer + 4), ip_version);

    if (ip_version != 1 && ip_version != 2) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                    "Invalid IP version number, expecting 1 or 2,"
                    " received %u", ip_version);
        return FALSE;
    }

    gettimeofday(&ct, NULL);

    transState->ptime = ((uint64_t)ct.tv_sec * 1000) +
                        ((uint64_t)ct.tv_usec / 1000);

    collector->time = time(NULL);

    *m_len = b_len;

    return TRUE;
}



/**
 * sflowFlowSampleParse
 *
 *
 * @param collector pointer to the collector state record
 * @param dataBuf pointer to the buffer holding the template def
 *                points <b>after</b> the set ID and set length
 * @param sflowrec pointer to new sflow rec
 * @param err GError pointer to store the error if one occurs
 * @param expanded TRUE if it's an expanded flow sample, FALSE if not
 * @return Number of Templates Parsed
 *
 */
static int sflowFlowSampleParse (
    fbCollector_t   *collector,
    uint8_t         **data,
    size_t          *datalen,
    fbSFlowRecord_t *sflowrec,
    gboolean        expanded,
    GError          **err)
{
    uint32_t        index, type;
    uint32_t        numrecs;
    uint32_t        flows = 0;
    uint32_t        flowformat;
    uint32_t        enterprise;
    uint32_t        flowlength;
    uint32_t        protocol, framelen;
    uint32_t        var32;
    uint16_t        format;
    uint8_t         *dataBuf = *data;

    if (expanded) {
        /* header is 44 but we already read seq num */
        if (*datalen < 40) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Expanded Flow Sample Header");
            return 0;
        }
    } else {
        if (*datalen < 28) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Flow Sample Header");
            return 0;
        }
    }

    if (expanded) {
        READU32INC(dataBuf, type);
        *datalen -= 4;
    }
    READU32INC(dataBuf, index);

    READU32INC(dataBuf, sflowrec->samplingPacketInterval);
    READU32INC(dataBuf, sflowrec->samplingPopulation);
    READU32INC(dataBuf, sflowrec->droppedPacketTotalCount);
    if (expanded) {
        *datalen -= 4;
        dataBuf += 4;
    }
    READU32INC(dataBuf, sflowrec->ingressInterface);
    if (expanded) {
        *datalen -= 4;
        dataBuf += 4;
    }
    READU32INC(dataBuf, sflowrec->egressInterface);
    /* number of flow records */
    READU32INC(dataBuf, numrecs);

#if FB_SFLOW_DEBUG == 1
    fprintf(stderr, "Internal %u, Egress %u, Expanded %d, numrecs %u, datalen %zu\n",
            sflowrec->ingressInterface, sflowrec->egressInterface,
            expanded, numrecs, *datalen);
#endif

    *datalen -= 28;

    while (flows < numrecs) {
        if (*datalen < 4)  {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Flow Record Header.");
            return 0;
        }
        READU32INC(dataBuf, flowformat);
        enterprise = (flowformat & 0xFFFFF000) >> 12;
        format = (flowformat & 0xFFF);
        if (enterprise != 0) {
#if FB_SFLOW_DEBUG
            fprintf(stderr, "INVALID flow: ent %u\n", enterprise);
#endif
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Invalid Flow Enterprise Number (%d)",
                        enterprise);
            return 0;
        }
        READU32INC(dataBuf, flowlength);
        *datalen -= 8;
#if FB_SFLOW_DEBUG
        fprintf(stderr, "Ent %u, Format %u, Length %u, datalen: %zu\n",
                enterprise, format, flowlength, *datalen);
#endif
        if (*datalen < flowlength) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer (%zu) too small for Flow Record (%u)",
                        *datalen, flowlength);
            return 0;
        }

        /* Sampled packets always = 1 */
        sflowrec->packetTotalCount = 1;

        switch (format) {
          case 1:
            READU32(dataBuf, protocol);
            READU32(dataBuf + 4, framelen);
            /* after framelen is removed payload and length of header */
            /* raw packet header */

            if (!sflowDecodeRawHeader(sflowrec, dataBuf+16, flowlength-16, protocol, err)) {
#if FB_SFLOW_DEBUG
                fprintf(stderr, "RAW HEADER DECODE Error: %s\n", (*err)->message);
#endif
                g_clear_error(err);
            }
            sflowrec->octetTotalCount = framelen;
            break;
          case 2:
          case 3:
          case 4:
            sflowDecodeFlowHeaders(sflowrec, dataBuf, flowlength, format, err);
            break;
          case 1001:
            READU32(dataBuf, var32);
            sflowrec->dot1qVlanId = (uint16_t)var32;
            READU32(dataBuf+4, var32);
            sflowrec->dot1qPriority = (uint8_t)var32;
            READU32(dataBuf+8, var32);
            sflowrec->postDot1qVlanId = (uint16_t)var32;
            break;
          case 1002:
            /* read IP version 1=v4 2=v6 */
            READU32(dataBuf, var32);
            if (var32 == 1) {
                READU32(dataBuf+4, sflowrec->nextHopIPv4Address);
                READU32(dataBuf+8, var32);
                sflowrec->sourceIPv4PrefixLength = (uint8_t)var32;
                READU32(dataBuf+12, var32);
                sflowrec->destinationIPv4PrefixLength = (uint8_t)var32;
            } else if (var32 == 2) {
                memcpy(sflowrec->nextHopIPv6Address, dataBuf+4, 16);
                READU32(dataBuf+20, var32);
                sflowrec->sourceIPv4PrefixLength = (uint8_t)var32;
                READU32(dataBuf+24, var32);
                sflowrec->destinationIPv4PrefixLength =(uint8_t)var32;
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                            "malformed extended router data (format 1002). "
                            "Invalid version %d",
                            var32);
                return 0;
            }
            break;
          case 1003:
            READU32(dataBuf, var32);
            if (var32 == 1) {
                READU32(dataBuf+4, sflowrec->bgpNextHopIPv4Address);
                /* router AS */
                READU32(dataBuf+12, sflowrec->bgpSourceAsNumber);
                /* Peer AS */
                READU32(dataBuf+20, var32);
                if (var32) {
                    /* get the first one */
                    READU32(dataBuf+32, sflowrec->bgpDestinationAsNumber);
                }
            } else if (var32 == 2) {
                memcpy(sflowrec->bgpNextHopIPv6Address, dataBuf+4, 16);
                /* router AS */
                READU32(dataBuf+24, sflowrec->bgpSourceAsNumber);
                /* Peer AS */
                READU32(dataBuf+32, var32);
                if (var32) {
                    /* get the first one */
                    READU32(dataBuf+44, sflowrec->bgpDestinationAsNumber);
                }
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                            "malformed extended gateway data (format 1003). "
                            "Invalid version %d",
                            var32);
                return 0;
            }
            break;
          default:
            break;
        }

        dataBuf += flowlength;
        *datalen -= flowlength;
        flows++;
    }

    /* sflowAppendRec */
    if (!sflowAppendRec(collector, sflowrec, err)) {
        return 0;
    }

    *data = dataBuf;
    return numrecs;
}

static int sflowCounterSampleParse (
    fbCollector_t          *collector,
    uint8_t                **data,
    size_t                 *datalen,
    fbSFlowCounterRecord_t *sflowrec,
    gboolean               expanded,
    GError                 **err)
{
    uint32_t        index, type;
    uint32_t        numrecs;
    uint32_t        recs = 0;
    uint32_t        counterformat;
    uint32_t        enterprise;
    uint32_t        counterlength;
    uint16_t        format;
    uint8_t         *dataBuf = *data;
    gboolean        append = FALSE;

    if (expanded) {
        /* header is 16 but we already read seq num */
        if (*datalen < 12) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Expanded Counter Sample Header");
            return 0;
        }

        READU32INC(dataBuf, type);
        *datalen -= 4;

    } else {
        if (*datalen < 8) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Counter Sample Header");
            return 0;
        }
    }

    READU32INC(dataBuf, index);

    /* number of counter records */
    READU32INC(dataBuf, numrecs);

#if FB_SFLOW_DEBUG
    fprintf(stderr, "COUNTER SAMPLE!!!! (%u Records)\n", numrecs);
#endif

    *datalen -= 8;

    while (recs < numrecs) {

        if (*datalen < 8) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Counter Record Header");
            return 0;
        }

        READU32INC(dataBuf, counterformat);
        enterprise = (counterformat & 0xFFFFF000) >> 12;
        format = (counterformat & 0xFFF);
        if (enterprise != 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Invalid Enterprise Number in Counter Record (%d)",
                        enterprise);
            return 0;
        }
        *datalen -= 8;
        READU32INC(dataBuf, counterlength);

        if (*datalen < counterlength) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer (%zu) too small for Counter Data (%u)",
                        *datalen, counterlength);
            return 0;
        }

        if (format == 1) {
            READU32(dataBuf, sflowrec->ingress);
            READU32(dataBuf+4, sflowrec->ingressType);
            memcpy(&sflowrec->inoct, dataBuf+24, 8);
            sflowrec->inoct = fb_ntohll(sflowrec->inoct);
            READU32(dataBuf+32, sflowrec->inpkt);
            READU32(dataBuf+36, sflowrec->inmulti);
            READU32(dataBuf+40, sflowrec->inbroad);
            READU32(dataBuf+44, sflowrec->indiscard);
            READU32(dataBuf+48, sflowrec->inerr);
            READU32(dataBuf+52, sflowrec->inunknown);
            memcpy(&sflowrec->outoct, dataBuf+56, 8);
            sflowrec->outoct = fb_ntohll(sflowrec->outoct);
            READU32(dataBuf+64, sflowrec->outpkt);
            READU32(dataBuf+72, sflowrec->outbroad);
            append = TRUE;
        }

        dataBuf += counterlength;
        *datalen -= counterlength;
        recs++;
    }

    /* sflowAppendRec */
    if (append) {
        if (!sflowAppendOptRec(collector, sflowrec, err)) {
            return 0;
        }
    }

    *data = dataBuf;

    return numrecs;
}




/**
 * fbCollectorPostProcSFlow
 *
 * converts a buffer that was read as sflow
 * into a buffer that "conforms" to IPFIX for the
 * rest of fixbuf to process it
 *
 * @param collector pointer to the collector state structure
 * @param dataBuf pointer to the netflow PDU
 * @param bufLen  the size from UDP of the message
 * @param err     glib error set when FALSE is returned with an
 *                informative message
 *
 * @return TRUE on success FALSE on error
 */
static gboolean     fbCollectorPostProcSFlow(
    fbCollector_t   *collector,
    uint8_t         *dataBuf,
    size_t          *bufLen,
    GError          **err)
{
    int               flows = 0;
    int               counters = 0;
    uint8_t           *msgOsetPtr = dataBuf;
    fbExporter_t      *sfexp = NULL;
    size_t            msgParsed = *bufLen;
    uint32_t          sflowSeqNum;
    uint32_t          innerSeqNum;
    uint32_t          numSamples;
    uint32_t          sampleCount = 0;
    uint32_t          sampleFormat;
    uint32_t          enterprise;
    uint16_t          format;
    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;
    uint32_t          timeStamp;
    uint32_t          obsDomain;
    uint32_t          version;
    uint32_t          sampleLength;
    gboolean          newbuffer = FALSE;
    fbCollectorSFlowSession_t *currentSession = NULL;
    fbSFlowRecord_t   sflowrec;
    fbSFlowCounterRecord_t sflowctr;
    size_t            msglen = 0;

    memset(&sflowrec, 0, sizeof(sflowrec));
    memset(&sflowctr, 0, sizeof(sflowctr));

    pthread_mutex_lock(&transState->ts_lock);

    memset(transState->ipfixBuffer, 0, 65535);

    if (!transState->fbuf) {

        transState->fbuf = fBufAllocForExport(transState->exsession, NULL);

        newbuffer = TRUE;
    }

    sfexp = sflowAllocExporter(transState->ipfixBuffer, transState->fbuf, err);

    if (!sfexp) {
        pthread_mutex_unlock(&transState->ts_lock);
        return FALSE;
    }

    /* we already know this is version 5, so skip */
    msgOsetPtr += 4;
    /* get ip version */
    READU32INC(msgOsetPtr, version);
    if (version == 1) {
        /* ipv4 */
        READU32INC(msgOsetPtr, sflowrec.collectorIPv4Address);
        msgParsed -= 12;
    } else {
        /* ipv6 */
        memcpy(sflowrec.collectorIPv6Address, msgOsetPtr, 16);
        msgOsetPtr+=16;
        msgParsed -= 24;
    }

    READU32INC(msgOsetPtr, obsDomain);
    READU32INC(msgOsetPtr, sflowSeqNum);

#if FB_SFLOW_DEBUG
    fprintf(stderr, "Sequence number %u\n", sflowSeqNum);
#endif

    if (transState->cosession != collector->udp_head->session) {
        /* lookup template Hash Table per Domain */
        transState->session =
            g_hash_table_lookup(transState->domainHash,
                                collector->udp_head->session);
        if (transState->session == NULL) {
            transState->session = g_slice_new0(fbCollectorSFlowSession_t);
            g_hash_table_insert(transState->domainHash,
                                (gpointer)collector->udp_head->session,
                                transState->session);
            newbuffer = TRUE;
        }
        transState->cosession = collector->udp_head->session;
    }

    currentSession = transState->session;
    transState->observation_id = obsDomain;


    if (newbuffer) {

        if (!fbSessionExportTemplates(transState->exsession, err)) {
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        /*fBufSetAutomaticMode(transState->fbuf, FALSE);*/
        fBufEmit(transState->fbuf, err);
        msglen = fbExporterGetMsgLen(sfexp);

#if FB_SFLOW_DEBUG == 1
        fprintf(stderr, "EXPORTED TEMPLATES %u\n", msglen);
#endif
        memcpy(dataBuf, transState->ipfixBuffer, msglen);
        *bufLen = msglen;
        pthread_mutex_unlock(&transState->ts_lock);
        return TRUE;

    }

    /* switch uptime in ms */
    READU32INC(msgOsetPtr, timeStamp);

    /* seq num logic */
    if (currentSession->sflowSeqNum != sflowSeqNum) {
        int seq_diff = sflowSeqNum - currentSession->sflowSeqNum;
#ifndef FB_SUPPRESS_LOGS
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
              "sFlow sequence number mismatch for agent 0x%04x, "
              "expecting 0x%04x received 0x%04x", obsDomain,
              currentSession->sflowSeqNum, sflowSeqNum);
#endif
        if (currentSession->sflowSeqNum) {
            if (seq_diff > 0) {
                if (seq_diff > SF_MAX_SEQ_DIFF) {
                    /* check for reboot */
                    if (timeStamp > SF_REBOOT_SECS) {
                        /* probably not a reboot so account for missed */
                        currentSession->sflowMissed += seq_diff;
                    } /* else - reboot? don't add to missed count */
                } else {
                    currentSession->sflowMissed += seq_diff;
                }
                currentSession->sflowSeqNum = sflowSeqNum;
            } else {
                /* out of order or reboot? */
                if ((currentSession->sflowSeqNum - sflowSeqNum) >
                    SF_OUT_OF_ORDER)
                {
                    /* this may be a reboot - it's pretty out of seq. */
                    currentSession->sflowSeqNum = sflowSeqNum;
                } else {
                    /* this is in accepted range for out of sequence */
                    /* account for not missing. don't reset sequence number */
                    /* But subtract one so when we add one below, it evens out */
                    if (currentSession->sflowMissed) {
                        currentSession->sflowMissed -= 1;
                    }
                    currentSession->sflowSeqNum -= 1;
                }
            }
        } else {
            /* this is the first one we received in this session */
            currentSession->sflowSeqNum = sflowSeqNum;
        }
    }


    /* iterate through the samples */
    READU32INC(msgOsetPtr, numSamples);
    msgParsed -= 16;

    while (sampleCount < numSamples ) {
        if (msgParsed < 8) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for Sample Header");
            currentSession->sflowSeqNum++;
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        READU32INC(msgOsetPtr, sampleFormat);
        /* top 20 bits are enterprise */
        enterprise = (sampleFormat & 0xFFFFF000) >> 12;
        format = (sampleFormat & 0xFFF);

        READU32INC(msgOsetPtr, sampleLength);
        msgParsed -= 8;

#if FB_SFLOW_DEBUG == 1
        fprintf(stderr, "Enterprise %u;  Format %u;  Length %u\n",
                enterprise, format, sampleLength); /* debug */
#endif

        if (enterprise != 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Invalid sFlow enterprise number (%u)",
                        enterprise);
            currentSession->sflowSeqNum++;
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        if (msgParsed < sampleLength) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Buffer too small for sample length (%u)",
                        sampleLength);
            currentSession->sflowSeqNum++;
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        READU32INC(msgOsetPtr, innerSeqNum);
        msgParsed -= 4;

#if FB_SFLOW_DEBUG == 1
        fprintf(stderr, "innerseqnum %u\n", innerSeqNum);
#endif

        if (format == 1 || format == 3) {
            /* flow sample */
            if (innerSeqNum != currentSession->sflowFlowSeqNum) {
#ifndef FB_SUPPRESS_LOGS
                g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                      "sFlow Sample sequence number mismatch for agent 0x%04x, "
                      "expecting 0x%04x received 0x%04x", obsDomain,
                      currentSession->sflowFlowSeqNum, innerSeqNum);
#endif
                currentSession->sflowFlowSeqNum = innerSeqNum;
            }
        } else {
            if (innerSeqNum != currentSession->sflowCounterSeqNum) {
#ifndef FB_SUPPRESS_LOGS
                g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                      "sFlow Counter sequence number mismatch for agent 0x%04x, "
                      "expecting 0x%04x received 0x%04x", obsDomain,
                      currentSession->sflowCounterSeqNum, innerSeqNum);
#endif
                currentSession->sflowCounterSeqNum = innerSeqNum;
            }
        }
        sflowrec.selectorId = obsDomain;
        sflowrec.systemUpTime = (uint64_t)timeStamp;
        sflowrec.collectionTimeMilliseconds = transState->ptime;

        switch (format) {
          case 1:
            /* Flow Sample */
            flows = sflowFlowSampleParse(collector, &msgOsetPtr, &msgParsed,
                                         &sflowrec, FALSE, err);
            currentSession->sflowFlowSeqNum++;
            break;
          case 2:
            sflowctr.agentid = obsDomain;
            sflowctr.sysuptime = (uint64_t)timeStamp;
            sflowctr.ctime = transState->ptime;
            if (version == 1) {
                sflowctr.ipv4 = sflowrec.collectorIPv4Address;
            } else {
                memcpy(sflowctr.ipv6, sflowrec.collectorIPv6Address, 16);
            }
            counters = sflowCounterSampleParse(collector, &msgOsetPtr, &msgParsed,
                                               &sflowctr, FALSE, err);
            currentSession->sflowCounterSeqNum++;
            break;
          case 3:
            flows = sflowFlowSampleParse(collector, &msgOsetPtr, &msgParsed,
                                         &sflowrec, TRUE, err);
            currentSession->sflowFlowSeqNum++;
            break;
          case 4:
            sflowctr.agentid = obsDomain;
            sflowctr.sysuptime = (uint64_t)timeStamp;
            sflowctr.ctime = transState->ptime;
            if (version == 1) {
                sflowctr.ipv4 = sflowrec.collectorIPv4Address;
            } else {
                memcpy(sflowctr.ipv6, sflowrec.collectorIPv6Address, 16);
            }
            counters = sflowCounterSampleParse(collector, &msgOsetPtr, &msgParsed,
                                               &sflowctr, TRUE, err);
            currentSession->sflowCounterSeqNum++;
            break;
          default:
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                        "Invalid sFlow Format (%d)", format);
            currentSession->sflowSeqNum++;
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        if (!flows && !counters) {
            /* error ocurred */
            currentSession->sflowSeqNum++;
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        sampleCount++;

    }


    /* there is possibly extra filling at the end of the packet */
    /* warn and ignore! */

    if (msgParsed) {
#ifndef FB_SUPPRESS_LOGS
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                    "sFlow Record Length Mismatch: (buffer has "
                    "%zu, leftover %zu)", *bufLen, msgParsed);
#endif
    }

    /* increment the sequence number for the netflow side */
    currentSession->sflowSeqNum++;

    fBufEmit(transState->fbuf, err);

    msglen = fbExporterGetMsgLen(sfexp);

    memcpy(dataBuf, transState->ipfixBuffer, msglen);
    *bufLen = msglen;

    fbExporterClose(sfexp);

    pthread_mutex_unlock(&transState->ts_lock);

    return TRUE;
}





/**
 * fbCollectorTransCloseSFlow
 *
 * frees the state included as part of the collector when the
 * SFlow translator is enabled
 *
 * @param collector, pointer to the collector state structure
 *
 */
static void         fbCollectorTransCloseSFlow(
    fbCollector_t   *collector)
{
    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;

    if (transState == NULL) {
        return;
    }

    if (transState->fbuf) {
        fBufFree(transState->fbuf);
    }

    if (transState->model) {
        fbInfoModelFree(transState->model);
    }

    g_slice_free1(65535, transState->ipfixBuffer);

    /* this should destroy each entry in the template */
    g_hash_table_destroy(transState->domainHash);
    transState->domainHash = NULL;

    pthread_mutex_destroy(&transState->ts_lock);

    if (NULL != collector->translatorState) {
        g_slice_free1(sizeof(struct fbCollectorSFlowState_st),
                      collector->translatorState);
    }

    collector->translatorState = NULL;
    return;
}

/**
 * fbCollectorTimeoutSessionSFlow
 *
 * this timeouts sessions when we haven't seen messages for > 30 mins.
 *
 * @param collector pointer to collector state.
 * @param session pointer to session to timeout.
 *
 */
static void fbCollectorTimeOutSessionSFlow(
    fbCollector_t *collector,
    fbSession_t   *session)
{

    struct fbCollectorSFlowState_st     *transState =
        (struct fbCollectorSFlowState_st *)collector->translatorState;
    fbCollectorSFlowSession_t           *sfsession = NULL;

    if (transState == NULL) {
        return;
    }

    pthread_mutex_lock(&transState->ts_lock);

    sfsession = g_hash_table_lookup(transState->domainHash, session);

    if (sfsession == NULL) {
        /* don't need to free! */
        pthread_mutex_unlock(&transState->ts_lock);
        return;
    }

    /* remove this session, free the state */
    g_hash_table_remove(transState->domainHash, session);

    if (session == transState->cosession) {
        transState->cosession = NULL;
        transState->session = NULL;
    }

    pthread_mutex_unlock(&transState->ts_lock);

}



/**
 *fbCollectorSetSFlowTranslator
 *
 * this sets the collector input translator
 * to convert SFlow into IPFIX for the
 * given collector
 *
 * @param collector pointer to the collector state
 *        to perform SFlow conversion on
 * @param err GError structure that holds the error
 *        message if an error occurs
 *
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetSFlowTranslator(
    fbCollector_t               *collector,
    GError                      **err)
{
    struct fbCollectorSFlowState_st *sflowState =
        g_slice_alloc0(sizeof(struct fbCollectorSFlowState_st));
    GHashTable    *hashTable = NULL;
    fbInfoModel_t *model = fbInfoModelAlloc();
    fbTemplate_t  *sftmpl = NULL;
    fbSession_t   *sfsess = NULL;

    if (NULL == sflowState) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TRANSMISC,
                    "Failure to allocate sFlow translator state");
        return FALSE;
    }

    hashTable = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                      NULL, sessionDestroyHelper);

    if (NULL == hashTable) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SFLOW,
                    "Failed to allocate sequence number hash table "
                    "for sFlow translator.");
        return FALSE;
    }

    sflowState->domainHash = hashTable;

    sftmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(sftmpl, sflow_spec, 0xffffffff, err)) {
        return FALSE;
    }

    sfsess = fbSessionAlloc(model);

    if (!fbSessionAddTemplate(sfsess, TRUE, SFLOW_TID, sftmpl, err)) {
        return FALSE;
    }

    if (!fbSessionAddTemplate(sfsess, FALSE, SFLOW_TID, sftmpl, err)) {
        return FALSE;
    }

    /* Options (counter) template */
    sftmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(sftmpl, sflow_ctr_spec, 0xffffffff, err)) {
        return FALSE;
    }

    fbTemplateSetOptionsScope(sftmpl, 1);

    if (!fbSessionAddTemplate(sfsess, TRUE, SFLOW_OPT_TID, sftmpl, err)) {
        return FALSE;
    }

    if (!fbSessionAddTemplate(sfsess, FALSE, SFLOW_OPT_TID, sftmpl, err)) {
        return FALSE;
    }

#if FB_SFLOW_DEBUG == 1
    fprintf(stderr, "Hash table address is %p for collector %p\n",
        hashTable, collector); /* debug */
#endif

    sflowState->session = NULL;
    sflowState->observation_id = 0;
    sflowState->exsession = sfsess;
    sflowState->model = model;
    sflowState->ipfixBuffer = g_slice_alloc0(65535);
    pthread_mutex_init(&sflowState->ts_lock, NULL);

    return fbCollectorSetTranslator(collector, fbCollectorPostProcSFlow,
        fbCollectorDecodeSFlowMsgVL, fbCollectorMessageHeaderSFlow,
        fbCollectorTransCloseSFlow, fbCollectorTimeOutSessionSFlow,
                                    sflowState, err);

}




/**
 * fbCollectorGetSFlowMissed
 *
 * This returns the number of potential missed export packets
 * packets for the ip/obdomain (agentId) of the sFlow exporter.
 * If there is no match, we just return 0.
 *
 * @param collector
 * @param peer address of exporter to lookup
 * @param peerlen sizeof(peer)
 * @param obdomain agentId of peer exporter
 * @return number of missed packets
 *
 */

uint32_t fbCollectorGetSFlowMissed(
    fbCollector_t         *collector,
    struct sockaddr       *peer,
    size_t                 peerlen,
    uint32_t               obdomain)
{
    struct fbCollectorSFlowState_st     *ts = NULL;
    fbUDPConnSpec_t                     *udp = NULL;
    fbSession_t                         *session = NULL;
    fbCollectorSFlowSession_t           *sfsession = NULL;
    uint32_t                            missed = 0;

    if (!collector) {
        return 0;
    }

    if (peer) {
        udp = collector->udp_head;
        while (udp) {
            /* loop through and find the match */
            if (udp->obdomain == obdomain) {
                if (!memcmp(&(udp->peer), peer, (peerlen > udp->peerlen) ?
                            udp->peerlen : peerlen))
                {
                    /* we have a match - set session */
                    session = udp->session;
                    break;
                }
            }
            udp = udp->next;
        }
    } else {
        /* set to most recent */
        session = collector->udp_head->session;
    }

    if (!session) {
        return 0;
    }

    ts = (struct fbCollectorSFlowState_st *)collector->translatorState;


    if (ts == NULL) {
        g_warning("sFlow translator not set on collector.");
        return 0;
    }

    pthread_mutex_lock(&ts->ts_lock);

    if (ts->cosession != session) {
        /* lookup template Hash Table per Domain */
        sfsession = g_hash_table_lookup(ts->domainHash, session);
    } else {
        sfsession = ts->session;
    }

    if (sfsession) {
        missed = sfsession->sflowMissed;
    }

    pthread_mutex_unlock(&ts->ts_lock);

    return missed;
}
