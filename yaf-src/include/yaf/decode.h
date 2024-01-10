/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  decode.h
 *  YAF Layer 2 and Layer 3 decode routines
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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

/**
 * @internal
 *
 * @file decode.h
 *
 * Packet decoding interface for YAF. This file's single function
 * decodes IPv4 and IPv6 packets within loopback, raw, Ethernet, Linux SLL
 * ("cooked"), and C-HDLC frames, encapsulated within MPLS, 802.1q VLAN,
 * and/or GRE. It provides high-performance partial reassembly of IPv4
 * and IPv6 fragments to properly generate flows from fragmented data, and to
 * support the export of the first N bytes of a given flow.
 *
 *
 * The structures filled in by yfDecodePkt() are used within the flow
 * generator,
 * and are suitable for other similar purposes.
 */

#ifndef _YAF_DECODE_H_
#define _YAF_DECODE_H_

#include <yaf/autoinc.h>
#include <yaf/yafcore.h>

/** Fragmentation information structure */
typedef struct yfIPFragInfo_st {
    /** Fragment ID. This is a 32-bit integer to support both IPv4 and IPv6. */
    uint32_t   ipid;
    /** Fragment offset within the reassembled datagram. */
    uint16_t   offset;
    /** IP header length. Used to calculate total fragment length. */
    uint16_t   iphlen;
    /**
     * Decoded header length. Number of bytes at the start of the packet _not_
     * represented in the associated packet data.
     */
    uint16_t   l4hlen;
    /**
     * Fragmented packet flag. Set if the packet is a fragment,
     * clear if it is complete.
     */
    uint8_t    frag;
    /**
     * More fragments flag. Set if this fragment is not the last in the packet.
     */
    uint8_t    more;
} yfIPFragInfo_t;

/** Maximum MPLS label count */
#define YF_MPLS_LABEL_COUNT_MAX     3

/** Datalink layer information structure */
typedef struct yfL2Info_st {
    /** Source MAC address */
    uint8_t    smac[6];
    /** Destination MAC address */
    uint8_t    dmac[6];
    /** Layer 2 Header Length */
    uint16_t   l2hlen;
    /** VLAN tag */
    uint16_t   vlan_tag;
    /** MPLS label count */
    uint32_t   mpls_count;
    /** MPLS label stack */
    uint32_t   mpls_label[YF_MPLS_LABEL_COUNT_MAX];
} yfL2Info_t;

/** MPTCP information structure */
typedef struct yfMPTCPInfo_st {
    /** initial dsn */
    uint64_t   idsn;
    /** token */
    uint32_t   token;
    /** maximum segment size */
    uint16_t   mss;
    /** flags */
    uint8_t    flags;
    /* address id */
    uint8_t    addrid;
} yfMPTCPInfo_t;

/** TCP information structure */
typedef struct yfTCPInfo_st {
    /** TCP sequence number */
    uint32_t        seq;
    /** TCP flags */
    uint8_t         flags;
    /** MPTCP Info **/
    yfMPTCPInfo_t   mptcp;
} yfTCPInfo_t;

/** Full packet information structure. Used in the packet ring buffer. */
typedef struct yfPBuf_st {
    /** Packet timestamp in epoch milliseconds */
    uint64_t             ptime;
    /** Flow key containing decoded IP and transport headers. */
    yfFlowKey_t          key;
    /** Length of all headers, L2, L3, L4 */
    size_t               allHeaderLen;
    /** pcap header */
    struct pcap_pkthdr   pcap_hdr;
    /** pcap struct */
    pcap_t              *pcapt;
    /** offset into pcap */
    uint64_t             pcap_offset;
    /** caplist */
    uint16_t             pcap_caplist;
    /** Packet IP length. */
    uint32_t             iplen;
    /** Interface number packet was decoded from. Currently unused. */
    uint16_t             ifnum;
    /** flag for determining if the packet was fragmented 0-no, 1-yes,
     *  2-not fully assembled*/
    uint8_t              frag;
    /** TCP information structure. */
    yfTCPInfo_t          tcpinfo;
    /** Decoded layer 2 information. */
    yfL2Info_t           l2info;
#if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT)
    /** Length of IP/TCP Headers */
    size_t               headerLen;
    /** contains TCP Headers for export if p0f enabled */
    uint8_t              headerVal[YFP_IPTCPHEADER_SIZE];
#endif /* if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT) */
    /** Length of payload available in captured payload buffer. */
    size_t               paylen;
    /**
     * Captured payload buffer. Note that this in a convenience field;
     * the actual field is larger than one byte. */
    uint8_t              payload[1];
} yfPBuf_t;

/** Size of a packet buffer with payload capture disabled */
#define YF_PBUFLEN_NOL2INFO offsetof(yfPBuf_t, l2info)

/** Size of a packet buffer with payload capture disabled */
#define YF_PBUFLEN_NOPAYLOAD offsetof(yfPBuf_t, paylen)

/** Size of a packet buffer minus payload buffer */
#define YF_PBUFLEN_BASE offsetof(yfPBuf_t, payload)

struct yfDecodeCtx_st;
/** An opaque decode context */
typedef struct yfDecodeCtx_st yfDecodeCtx_t;

/** Ethertype for IP version 4 packets. */
#define YF_TYPE_IPv4    0x0800
/** Ethertype for IP version 6 packets. */
#define YF_TYPE_IPv6    0x86DD
/**
 * Pseudo-ethertype for any IP version packets.
 * Used as the reqtype argument to yfDecodeIP().
 */
#define YF_TYPE_IPANY   0x0000

/** IPv6 Next Header for Hop-by-Hop Options */
#define YF_PROTO_IP6_HOP    0
/** IPv4 Protocol Identifier and IPv6 Next Header for ICMP */
#define YF_PROTO_ICMP       1
/** IPv4 Protocol Identifier and IPv6 Next Header for TCP */
#define YF_PROTO_TCP        6
/** IPv4 Protocol Identifier and IPv6 Next Header for UDP */
#define YF_PROTO_UDP        17
/** IPv6 Next Header for Routing Options */
#define YF_PROTO_IP6_ROUTE  43
/** IPv6 Next Header for Fragment Options */
#define YF_PROTO_IP6_FRAG   44
/** IPv4 Protocol Identifier and IPv6 Next Header for GRE */
#define YF_PROTO_GRE        47
/** IPv4 Protocol Identifier and IPv6 Next Header for ICMP6 */
#define YF_PROTO_ICMP6      58
/** IPv6 No Next Header Option for Extension Header */
#define YF_PROTO_IP6_NONEXT  59
/** IPv6 Next Header for Destination Options */
#define YF_PROTO_IP6_DOPT   60

/** TCP FIN flag. End of connection. */
#define YF_TF_FIN       0x01
/** TCP SYN flag. Start of connection. */
#define YF_TF_SYN       0x02
/** TCP FIN flag. Abnormal end of connection. */
#define YF_TF_RST       0x04
/** TCP PSH flag. */
#define YF_TF_PSH       0x08
/** TCP ACK flag. Acknowledgment number is valid. */
#define YF_TF_ACK       0x10
/** TCP URG flag. Urgent pointer is valid. */
#define YF_TF_URG       0x20
/** TCP ECE flag. Used for explicit congestion notification. */
#define YF_TF_ECE       0x40
/** TCP CWR flag. Used for explicit congestion notification. */
#define YF_TF_CWR       0x80

/** MPTCP FLAG remove priority - set backup */
#define YF_MF_PRIO_CHANGE    0x01
/** MPTCP FLAG priority is set */
#define YF_MF_PRIORITY       0x02
/** MPTCP FLAG FAIL option was seen */
#define YF_MF_FAIL           0x04
/** MPTCP FLAG FASTCLOSE option was seen */
#define YF_MF_FASTCLOSE      0x08

/**
 * Allocate a decode context. Decode contexts are used to store decoder
 * internal state, configuration, and statistics.
 *
 * @param datalink libpcap DLT_ constant describing the layer 2 headers on the
 *                 packet in pkt. Supported datalink types are DLT_EN10MB
 *                 (Ethernet), DLT_CHDLC (Cisco HDLC), DLT_LINUX_SLL (Linux
 *                 "cooked" capture interface), DLT_RAW (raw IP packet, no
 *                 layer 2), DLT_NULL (loopback), and DLT_LOOP (OpenBSD
 *                 loopback).
 * @param reqtype  Required IP packet ethertype. Pass YF_TYPE_IPv4 to decode
 *                 only IPv4 packets, YF_TYPE_IPv6 to decode only IPv6 packets,
 *                 or YP_TYPE_IPANY to decode both IPv4 and IPv6 packets.
 * @param gremode  TRUE to enable GREv1 decoding; otherwise, GRE packets
 *                 will be left encapsulated.
 * @param vxlanports  The ports used to decode VxLAN packets. NULL if
 *                    VxLAN decoding is not enabled.
 * @param geneveports The ports used to decode Geneve packets. NULL if
 *                    Geneve decoding is not enabled.
 * @return a new decode context
 */
yfDecodeCtx_t *
yfDecodeCtxAlloc(
    int        datalink,
    uint16_t   reqtype,
    gboolean   gremode,
    GArray    *vxlanports,
    GArray    *geneveports);

/**
 * Free a decode context.
 *
 * @param ctx A decode context allocated with yfDecodeCtxAlloc()
 */
void
yfDecodeCtxFree(
    yfDecodeCtx_t  *ctx);

/**
 * Decode a packet into a durable packet buffer. It is assumed the packet
 * is encapsulated within a link layer frame described by the datalink
 * parameter. It fills in the pbuf structure, copying payload if necessary.
 *
 * @param ctx      Decode context obtained from yfDecodeCtxAlloc()
 *                 containing decoder configuration and internal state.
 * @param ptime    Packet observation time in epoch milliseconds. Use
 *                 yfDecodeTimeval() or yfDecodeTimeNTP() to get epoch
 *                 milliseconds from a struct timeval or a 64-bit NTP
 *                 timestamp, respectively.
 * @param caplen   Length of the packet to decode pkt.
 * @param pkt      Pointer to packet to decode. Is assumed to start with the
 *                 layer 2 header described by the datalink parameter.
 * @param fraginfo Pointer to IP Fragment information structure which will be
 *                 filled in with fragment id and offset information from the
 *                 decoded IP headers. MAY be NULL if the caller does not
 *                 require fragment information; in this case, all fragmented
 *                 packets will be dropped.
 * @param pbuflen  Total length of the packet buffer pbuf. Use the YF_PBUFLEN_
 *                 macros to set this value. YF_PUBFLEN_NOFRAG disables
 *                 fragment decode, layer 2 decode, and payload capture.
 *                 YF_PBUFLEN_NOL2INFO disables layer 2 decode and payload
 *                 capture. YF_PBUFLEN_NOPAYLOAD disables payload capture only.
 *                 To enable full decode including payload, use YF_PBUFLEN_BASE
 *                 plus the payload length. The buffer at pbuf MUST be able
 *                 to contain pbuflen bytes.
 * @param pbuf     Packet buffer to decode packet into. Will contain copies of
 *                 all packet data and payload; this buffer is durable.
 * @return TRUE on success (a packet of the required type was decoded and
 *         all the decode structures are valid), FALSE otherwise. Failures
 *         are counted in the decode statistics which can be logged with the
 *         yfDecodeDumpStats() call;
 */
gboolean
yfDecodeToPBuf(
    yfDecodeCtx_t   *ctx,
    uint64_t         ptime,
    size_t           caplen,
    const uint8_t   *pkt,
    yfIPFragInfo_t  *fraginfo,
    size_t           pbuflen,
    yfPBuf_t        *pbuf);

/**
 * Utility call to convert a struct timeval (as returned from pcap) into a
 * 64-bit epoch millisecond timestamp suitable for use with yfDecodeToPBuf.
 *
 * @param tv        Pointer to struct timeval to convert
 * @return the corresponding timestamp in epoch milliseconds
 */
uint64_t
yfDecodeTimeval(
    const struct timeval  *tv);

/**
 * Print decoder statistics to the log.
 *
 * @param ctx decode context to print statistics from
 * @param packetTotal total number of packets observed
 */
void
yfDecodeDumpStats(
    yfDecodeCtx_t  *ctx,
    uint64_t        packetTotal);

/**
 * Reset Offset into Pcap if evaluating multiple pcap
 * files
 *
 * @param ctx decode context
 */
void
yfDecodeResetOffset(
    yfDecodeCtx_t  *ctx);

/**
 * Get Stats to Export in Options Records
 *
 * @param ctx decode context to print stats from
 * @return number of packets YAF failed to decode
 */
uint32_t
yfGetDecodeStats(
    yfDecodeCtx_t  *ctx);


/**
 * Fragmentation Reassembly for IP fragments that arrived with
 * a fragment size less than the TCP header length.  We will now pull
 * out TCPInfo and move the offset pointer to after the tcp header
 *
 * @param pkt pointer to payload plus TCP
 * @param caplen size of payload
 * @param key pointer to flow key
 * @param fraginfo pointer to fragmentation info
 * @param tcpinfo pointer to tcpinfo
 * @param payoff pointer to size of frag payload
 * @return TRUE/FALSE depending if the full TCP header is available
 */
gboolean
yfDefragTCP(
    uint8_t         *pkt,
    size_t          *caplen,
    yfFlowKey_t     *key,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo,
    size_t          *payoff);

#endif /* ifndef _YAF_DECODE_H_ */
