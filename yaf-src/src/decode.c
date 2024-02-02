/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  decode.c
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

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/decode.h>
#include <airframe/airutil.h>

/* Definitions of the various headers the decoder understands */

typedef struct yfHdrEn10Mb_st {
    uint8_t    dmac[6];
    uint8_t    smac[6];
    uint16_t   type;
} yfHdrEn10Mb_t;

typedef struct yfHdrChdlc_st {
    uint8_t    address;
    uint8_t    control;
    uint16_t   type;
} yfHdrChdlc_t;

typedef struct yfHdrLinuxSll_st {
    uint16_t   sll_type;
    uint16_t   addr_type;
    uint16_t   addr_len;
    uint8_t    addr[8];
    uint16_t   type;
} yfHdrLinuxSll_t;

typedef struct yfHdrPppOeShim_st {
    uint8_t    vertype;
    uint8_t    code;
    uint16_t   session;
    uint16_t   length;
} yfHdrPppOeShim_t;

typedef struct yfHdr1qShim_st {
    uint16_t   ptt;
    uint16_t   type;
} yfHdr1qShim_t;

typedef struct yfHdrJuniper_st {
    uint8_t    magic[3];
    uint8_t    flags;
    uint16_t   ext_len;
} yfHdrJuniper_t;

typedef struct yfHdrNull_st {
    uint32_t   addr_family;
} yfHdrNull_t;

/** Ethertype for 802.1q VLAN shim header */
#define YF_TYPE_8021Q   0x8100
/** Ethertype for MPLS unicast shim header */
#define YF_TYPE_MPLS    0x8847
/** Ethertype for MPLE multicast shim header */
#define YF_TYPE_MPLSM   0x8848
/** Ethertype for PPPoE shim header */
#define YF_TYPE_PPPOE   0x8864
/** Ethertype for ARP */
#define YF_TYPE_ARP     0x0806
/** Ethertype for LLDP */
#define YF_TYPE_LLDP     0x88CC
/** Ethertype for 802.3 SLOW protocols*/
#define YF_TYPE_SLOW     0x8809

/** Ethernet encoding types:
 * 0x0800  IP v4
 * 0x0806  ARP
 * 0x8035  RARP
 * 0x809b  ApppleTalk
 * 0x80f3  AppleTalk ARP
 * 0x8100  802.1Q tag
 * 0x8137  Novell IPX (alternate)
 * 0x8138  Novell
 * 0x86dd  IP v6
 * 0x8847  MPLS unicast
 * 0x8848  MPLS multicast
 * 0x8863  PPPoE discovery
 * 0x8864  PPPoE session
 */

/** PPP type for IPv4 */
#define YF_PPPTYPE_IPv4 0x0021
/** PPP type for IPv6 */
#define YF_PPPTYPE_IPv6 0x0057
/** PPP type for MPLS unicast shim header */
#define YF_PPPTYPE_MPLS 0x0281
/** PPP type for IPv6 */
#define YF_PPPTYPE_MPLSM 0x0283

/* 802.1q VLAN tag decode macros */

#define YF_VLAN_TAG(_pkt_) (0x0FFF & (g_ntohs(((yfHdr1qShim_t *)(_pkt_))->ptt)))

/* MPLS label decode macros */
#define YF_MPLS_LABEL(_x_) (((_x_) & 0xFFFFF000) >> 12)
#define YF_MPLS_EXP(_x_)   (((_x_) & 0x00000E00) >> 9)
#define YF_MPLS_LAST(_x_)   ((_x_) & 0x00000100)
#define YF_MPLS_TTL(_x_)    ((_x_) & 0x000000FF)

/* Juniper flags */
#define JUNIPER_PKT_OUT        0x00
#define JUNIPER_PKT_IN         0x01
#define JUNIPER_NO_L2          0x02
#define JUNIPER_FLAG_EXT       0x80
#define JUNIPER_MAGIC         "\x4D\x47\x43"
#define JUNIPER_PROTO_IP          2
#define JUNIPER_PROTO_MPLS_IP     3
#define JUNIPER_PROTO_IP_MPLS     4
#define JUNIPER_PROTO_MPLS        5
#define JUNIPER_PROTO_IP6         6
#define JUNIPER_PROTO_MPLS_IP6    7
#define JUNIPER_PROTO_IP6_MPLS    8

/* Cisco ERSPAN Header - found in GRE*/
#define YF_PROTO_ERSPAN   0x88BE

/* TCP Option Codes */
#define YF_MPTCP_OPTION_CODE   30
#define YF_MSS_OPTION_CODE      2

/* MPTCP Subtypes */
#define YF_MPTCP_CAPABLE        0
#define YF_MPTCP_JOIN           1
#define YF_MPTCP_DSS            2
#define YF_MPTCP_ADD_ADDR       3
#define YF_MPTCP_RM_ADDR        4
#define YF_MPTCP_PRIO           5
#define YF_MPTCP_FAIL           6
#define YF_MPTCP_FASTCLOSE      7

/* IP v4/v6 version macros */
#define YF_IP_VERSION(_pkt_)  ((*((uint8_t *)(_pkt_)) & 0xF0) >> 4)

#define YF_IP_VERSION_TO_TYPE(_pkt_, _caplen_, _type_)   \
    {                                                    \
        uint8_t _ipv;                                    \
        /* Check for at least one byte for IP version */ \
        if ((_caplen_) < 1) return NULL;                 \
        /* Fake ethertype based upon IP version */       \
        _ipv = YF_IP_VERSION(_pkt_);                     \
        if (_ipv == 4) {                                 \
            (_type_) = YF_TYPE_IPv4;                     \
        } else if (_ipv == 6) {                          \
            (_type_) = YF_TYPE_IPv6;                     \
        } else {                                         \
            (_type_) = 0;                                \
        }                                                \
    }

/**
 * IPv4 header structure, without options.
 */
typedef struct yfHdrIPv4_st {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    /** IP header length in 32-bit words. */
    unsigned int   ip_hl : 4,
    /** IP version. Always 4 for IPv4 packets.*/
                   ip_v  : 4;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
    /** IP version. Always 4 for IPv4 packets.*/
    unsigned int   ip_v  : 4,
    /** IP header length in 32-bit words. */
                   ip_hl : 4;
#else /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
#error Cannot determine byte order while defining IP header structure.
#endif /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
    /** Type of Service */
    uint8_t        ip_tos;
    /** Total IP datagram length including header in bytes */
    uint16_t       ip_len;
    /** Fragment identifier */
    uint16_t       ip_id;
    /** Fragment offset and flags */
    uint16_t       ip_off;
    /** Time to live in routing hops */
    uint8_t        ip_ttl;
    /** Protocol identifier */
    uint8_t        ip_p;
    /** Header checksum */
    uint16_t       ip_sum;
    /** Source IPv4 address */
    uint32_t       ip_src;
    /** Destination IPv4 address */
    uint32_t       ip_dst;
} yfHdrIPv4_t;

/** IPv4 don't fragment flag. For decoding yfHdrIPv4_t.ip_off. */
#define    YF_IP4_DF 0x4000
/** IPv4 more fragments flag. For decoding yfHdrIPv4_t.ip_off. */
#define    YF_IP4_MF 0x2000
/** IPv4 fragment offset mask. For decoding yfHdrIPv4_t.ip_off. */
#define    YF_IP4_OFFMASK 0x1fff

/**
 * IPv6 header structure.
 */
typedef struct yfHdrIPv6_st {
    /** Version, traffic class, and flow ID. Use YF_VCF6_ macros to access. */
    uint32_t   ip6_vcf;
    /**
     * Payload length. Does NOT include IPv6 header (40 bytes), but does
     * include subsequent extension headers, upper layer headers, and payload.
     */
    uint16_t   ip6_plen;
    /** Next header identifier. Use YF_PROTO_ macros. */
    uint8_t    ip6_nxt;
    /** Hop limit */
    uint8_t    ip6_hlim;
    /** Source IPv6 address */
    uint8_t    ip6_src[16];
    /** Destination IPv6 address */
    uint8_t    ip6_dst[16];
} yfHdrIPv6_t;

/* Version, class, and flow decode macros */
#define YF_VCF6_VERSION(_ip6hdr_)   (((_ip6hdr_)->ip6_vcf & 0xF0000000) >> 28)
#define YF_VCF6_CLASS(_ip6hdr_)     (((_ip6hdr_)->ip6_vcf & 0x0FF00000) >> 20)
#define YF_VCF6_FLOW(_ip6hdr_)       ((_ip6hdr_)->ip6_vcf & 0x000FFFFF)

#define yf_ntohll(x)                                           \
    ((((uint64_t)g_ntohl((uint32_t)((x) & 0xffffffff))) << 32) \
     | g_ntohl((uint32_t)(((x) >> 32) & 0xffffffff)))

/**
 * IPv6 partial extension header structure. Used to decode next and length
 * only.
 */

typedef struct yfHdrIPv6Ext_st {
    /** Next header identifier. Use YF_PROTO_ macros. */
    uint8_t   ip6e_nxt;
    /** Extension header length. */
    uint8_t   ip6e_len;
} yfHdrIPv6Ext_t;

/**
 * IPv6 fragment extension header structure.
 */
typedef struct yfHdrIPv6Frag_st {
    /** Next header identifier. Use YF_PROTO_ macros. */
    uint8_t    ip6f_nxt;
    /** Reserved field. */
    uint8_t    ip6f_reserved;
    /** Fragment offset and flags. */
    uint16_t   ip6f_offlg;
    /** Fragment identifier. */
    uint32_t   ip6f_ident;
} yfHdrIPv6Frag_t;

/* IPv6 Fragmentation decode macros */
#define YF_IP6_MF       0x0001
#define YF_IP6_OFFMASK  0xfff8

/**
 * TCP header structure, without options.
 */
typedef struct yfHdrTcp_st {
    /** Source port */
    uint16_t       th_sport;
    /** Destination port */
    uint16_t       th_dport;
    /** Sequence number */
    uint32_t       th_seq;
    /** Acknowledgment number */
    uint32_t       th_ack;
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    /** Unused. Must be 0. */
    unsigned int   th_x2  : 4,
    /** Data offset. TCP header length in 32-bit words. */
                   th_off : 4;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
    /** Data offset. TCP header length in 32-bit words. */
    unsigned int   th_off : 4,
    /** Unused. Must be 0. */
                   th_x2  : 4;
#else /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
#error Cannot determine byte order while defining TCP header structure.
#endif /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
    /** TCP flags. */
    uint8_t        th_flags;
    /** Congestion window. */
    uint16_t       th_win;
    /** Segment checksum. */
    uint16_t       th_sum;
    /** Urgent pointer. */
    uint16_t       th_urp;
} yfHdrTcp_t;

typedef struct yfHdrTcpOpt_st {
    /** kind */
    uint8_t   op_kind;
    /** length */
    uint8_t   op_len;
} yfHdrTcpOpt_t;

/**
 * UDP header structure.
 */
typedef struct yfHdrUdp_st {
    /** Source port */
    uint16_t   uh_sport;
    /** Destination port */
    uint16_t   uh_dport;
    /** UDP length. Includes header and payload, in octets. */
    uint16_t   uh_ulen;
    /** UDP checksum. Calculated over the entire message. */
    uint16_t   uh_sum;
} yfHdrUdp_t;

/**
 * VxLAN header structure.
 */
typedef struct yfHdrVxlan_st {
    /* Flags and reserved bits */
    uint32_t   flags_r;
    /* Vni and reserved bits */
    uint32_t   vni_r;
} yfHdrVxlan_t;

/* VxLAN VNI decode macro */
#define YF_VXLAN_VNI(_vni_r_)   ((_vni_r_ & 0xFFFFFF00) >> 8)

/**
 * Geneve minimum header structure.
 */
typedef struct yfHdrGeneve_st {
    /* Version, Flags, Option Len, and Type. */
    uint32_t   gv_flags;
    /* VNI. Includes reserved bits */
    uint32_t   gv_vni;
    /* Variable-Length Options. min=8B, max=260B */
    uint8_t    gv_vlo;
} yfHdrGeneve_t;

/* Geneve decode macros */
#define YF_GENEVE_VER(_gv_flags_)    (((_gv_flags_ & 0xC0000000) >> 30))
#define YF_GENEVE_OPLEN(_gv_flags_)  (((_gv_flags_ & 0x3F000000) >> 24) * 4)
#define YF_GENEVE_TYPE(_gv_flags_)   ((_gv_flags_ & 0x0000FFFF))
#define YF_GENEVE_VNI(_gv_vni_)      ((_gv_vni_ & 0xFFFFFF00) >> 8)

/**
 * ICMP/ICMP6 partial header structure. Used to decode type and code only.
 */
typedef struct ydHdrIcmp_st {
    /* ICMP type */
    u_char   icmp_type;
    /* ICMP code */
    u_char   icmp_code;
} yfHdrIcmp_t;

/**
 * GRE partial header structure. Used to decode the first 4 (fixed) bytes
 * of the GRE header only.
 */
typedef struct yfHdrGre_st {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    /** Recursion Control */
    unsigned int   gh_recur   : 3,
    /** Strict Source Routing */
                   gh_f_ssr   : 1,
    /** Sequence Number Present */
                   gh_f_seq   : 1,
    /** Key Present */
                   gh_f_key   : 1,
    /** Routing Present */
                   gh_f_route : 1,
    /** Checksum Present */
                   gh_f_sum   : 1;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
    /** Checksum Present */
    unsigned int   gh_f_sum   : 1,
    /** Routing Present */
                   gh_f_route : 1,
    /** Key Present */
                   gh_f_key   : 1,
    /** Sequence Number Present */
                   gh_f_seq   : 1,
    /** Strict Source Routing */
                   gh_f_ssr   : 1,
    /** Recursion Control */
                   gh_recur   : 3;
#else /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
#error Cannot determine byte order while defining GRE header structure.
#endif /* if G_BYTE_ORDER == G_LITTLE_ENDIAN */
    /** Flags and Version. Reserved, must be zero */
    uint8_t    gh_fv;
    /** Protocol. Ethertype of next header. */
    uint16_t   gh_type;
} yfHdrGre_t;

/* Version, class, and flow decode macros */
#define YF_GHFV_VERSION(_grehdr_)   ((_grehdr_)->gh_fv & 0x07)

/**
 * GRE Source Route Entry partial structure. Used to decode the first 4
 * (fixed) bytes of the SRE only.
 */
typedef struct yfHdrSre_st {
    /** Address family for routing information */
    uint16_t   gh_sre_af;
    /** SRE offset */
    uint8_t    gh_sre_off;
    /** SRE length */
    uint8_t    gh_sre_len;
} yfHdrSre_t;

/* Decode context for configuration and statistics */
struct yfDecodeCtx_st {
    /* State (none) */
    /* Configuration */
    int        datalink;
    uint16_t   pcap_caplist;
    uint16_t   reqtype;
    gboolean   gremode;
    GArray    *vxlanports;
    GArray    *geneveports;
    /* Statistics */
    struct stats_tag {
        uint32_t   fail_l2hdr;
        uint32_t   fail_l2shim;
        uint32_t   fail_l2loop;
        uint32_t   fail_l2type;
        uint32_t   fail_l3type;
        uint32_t   fail_arptype;
        uint32_t   fail_8023type;
        uint32_t   fail_lldptype;
        uint32_t   fail_ip4hdr;
        uint32_t   fail_ip4frag;
        uint32_t   fail_ip6hdr;
        uint32_t   fail_ip6ext;
        uint32_t   fail_ip6frag;
        uint32_t   fail_l4hdr;
        uint32_t   fail_l4frag;
        uint32_t   fail_grevers;
        uint32_t   fail_erspan;
        uint32_t   fail_vxlan;
        uint32_t   fail_geneve;
    } stats;
};

/**
 * @brief Checks if the GArray of ports contains the destination port.
 *
 * @param ports The GArray of ports to search
 * @param dport The dport to search for
 * @return gboolean TRUE if the dport exists in the array, FALSE otherwise.
 */
static gboolean
yfSearchArray(
    const GArray  *ports,
    uint16_t       dport)
{
    uint8_t i = 0;
    do {
        uint16_t port = g_array_index(ports, uint16_t, i);
        if (port == dport) {
            return TRUE;
        }
        i++;
    } while (i < ports->len);
    return FALSE;
}

/**
 * yfDecodeL2Loop
 *
 * Decode loopback packet family
 *
 */
static const uint8_t *
yfDecodeL2Loop(
    yfDecodeCtx_t  *ctx,
    uint32_t        pf,
    const uint8_t  *pkt,
    uint16_t       *type)
{
    if (pf == PF_INET) {
        *type = YF_TYPE_IPv4;
    } else if ((pf == PF_INET6) || (pf == 24) || (pf == 28) ||
               (pf == 30) || (pf == 10) || (pf == 23))
    {
        /* 24 is NetBSD, OpenBSD, BSD/OS */
        /* 28 is FreeBSD, DragonFlyBSD */
        /* 30 is MacOSX */
        /* 10 is Linux */
        /* 23 is Windows (Winsock2.h)*/
        *type = YF_TYPE_IPv6;
    } else {
        ++ctx->stats.fail_l2loop;
        return NULL;
    }

    return pkt;
}


/**
 * yfDecodeL2PPP
 *
 * decode PPP header
 *
 */
static const uint8_t *
yfDecodeL2PPP(
    yfDecodeCtx_t  *ctx,
    size_t         *caplen,
    const uint8_t  *pkt,
    uint16_t       *type)
{
    uint16_t ppptype;

    /* Check for PPP header  */
    if (*caplen < 2) {
        ++ctx->stats.fail_l2hdr;
        return NULL;
    }
    /* Decode PPP type to ethertype */
    ppptype = g_ntohs(*((uint16_t *)pkt));
    switch (ppptype) {
      case YF_PPPTYPE_IPv4:
        *type = YF_TYPE_IPv4;
        break;
      case YF_PPPTYPE_IPv6:
        *type = YF_TYPE_IPv6;
        break;
      case YF_PPPTYPE_MPLS:
        *type = YF_TYPE_MPLS;
        break;
      case YF_PPPTYPE_MPLSM:
        *type = YF_TYPE_MPLSM;
        break;
      default:
        return NULL;
    }
    /* Advance packet pointer */
    pkt += 2;
    *caplen -= 2;
    return pkt;
}


/**
 * yfDecodeL2Shim
 *
 * Decode and remove supported Layer 2 shim headers (802.1q, MPLS)
 *
 *
 */
static const uint8_t *
yfDecodeL2Shim(
    yfDecodeCtx_t  *ctx,
    size_t         *caplen,
    const uint8_t  *pkt,
    uint16_t       *type,
    yfL2Info_t     *l2info)
{
    uint32_t mpls_entry;

    for (;;) {
        switch (*type) {
          case YF_TYPE_8021Q:
            /* Check for full 802.1q shim header */
            if (*caplen < 4) {
                ++ctx->stats.fail_l2shim;
                return NULL;
            }
            /* Get type from 802.1q shim */
            *type = g_ntohs(((yfHdr1qShim_t *)pkt)->type);
            /* Copy out vlan tag if necessary */
            if (l2info) {
                l2info->vlan_tag =  YF_VLAN_TAG(pkt);
            }
            /* Advance packet pointer */
            *caplen -= 4;
            pkt += 4;
            /* And keep going. */
            break;
          case YF_TYPE_MPLS:
          case YF_TYPE_MPLSM:
            /* Check for full MPLS label */
            if (*caplen < 4) {
                ++ctx->stats.fail_l2shim;
                return NULL;
            }
            /* Get label entry */
            mpls_entry = g_ntohl(*((uint32_t *)(pkt)));
            /* Copy out label if necessary */
            if (l2info && l2info->mpls_count < YF_MPLS_LABEL_COUNT_MAX) {
                l2info->mpls_label[l2info->mpls_count++] =
                    YF_MPLS_LABEL(mpls_entry);
            }
            /* Advance packet pointer */
            *caplen -= 4;
            pkt += 4;
            /* Check for end of label stack */
            if (YF_MPLS_LAST(mpls_entry)) {
                YF_IP_VERSION_TO_TYPE(pkt, *caplen, *type);
#if YAF_NONIP
                return pkt;
#endif
                if (*type == 0) {
                    ++ctx->stats.fail_l2type;
                    return NULL;
                }
            }
            break;
          case YF_TYPE_PPPOE:
            /* Check for full PPPoE header */
            if (*caplen < 6) {
                ++ctx->stats.fail_l2shim;
                return NULL;
            }
            /* We don't actually _need_ anything out of the PPPoE header.
             * Just skip it. */
            *caplen -= 6;
            pkt += 6;
            /* now decode ppp */
            pkt = yfDecodeL2PPP(ctx, caplen, pkt, type);
            if (!pkt) {
                return NULL;
            }
            break;
          default:
            /* No more shim headers; type contains real ethertype. Done. */
            return pkt;
        }
    }
}


/**
 * yfDecodeL2
 *
 * Decode and remove supported Layer 2 headers
 *
 *
 */
static const uint8_t *
yfDecodeL2(
    yfDecodeCtx_t  *ctx,
    size_t         *caplen,
    const uint8_t  *pkt,
    uint16_t       *type,
    yfL2Info_t     *l2info)
{
    uint32_t pf;

    if (l2info) {
        memset(l2info, 0, sizeof(*l2info));
    }

    switch (ctx->datalink) {
#ifdef DLT_EN10MB
      case DLT_EN10MB:
#endif
#ifdef DLT_PPP_ETHER
      case DLT_PPP_ETHER:
#endif
#if defined(DLT_EN10MB) || defined(DLT_PPP_ETHER)
        /* Check for full ethernet header */
        if (*caplen < 14) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        /* Copy out ethertype */
        *type = g_ntohs(((yfHdrEn10Mb_t *)pkt)->type);
        /* Copy out MAC addresses if we care */
        if (l2info) {
            memcpy(l2info->smac, ((yfHdrEn10Mb_t *)pkt)->smac, 6);
            memcpy(l2info->dmac, ((yfHdrEn10Mb_t *)pkt)->dmac, 6);
        }
        /* Advance packet pointer */
        pkt += 14;
        *caplen -= 14;
        /* Decode shim headers */
        return yfDecodeL2Shim(ctx, caplen, pkt, type, l2info);
#endif /* if defined(DLT_EN10MB) || defined(DLT_PPP_ETHER) */
#ifdef DLT_C_HDLC
      case DLT_C_HDLC:
        /* Check for full C-HDLC header */
        if (*caplen < 4) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        /* Copy out ethertype */
        *type = g_ntohs(((yfHdrChdlc_t *)pkt)->type);
        /* Advance packet pointer */
        pkt += 4;
        *caplen -= 4;
        /* Decode shim headers */
        return yfDecodeL2Shim(ctx, caplen, pkt, type, l2info);
#endif /* ifdef DLT_C_HDLC */
#ifdef DLT_LINUX_SLL
      case DLT_LINUX_SLL:
        /* Check for full Linux SLL pseudoheader */
        if (*caplen < 16) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        /* Copy out ethertype */
        *type = g_ntohs(((yfHdrLinuxSll_t *)pkt)->type);
        /* Advance packet pointer */
        pkt += 16;
        *caplen -= 16;
        /* Decode shim headers */
        return yfDecodeL2Shim(ctx, caplen, pkt, type, l2info);
#endif /* ifdef DLT_LINUX_SLL */
#ifdef DLT_PPP
      case DLT_PPP:
        /* Check for HDLC framing */
        if (*caplen < 2) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        if ((pkt[0] == 0xff) && (pkt[1] == 0x03)) {
            /* Yep. HDLC framing. Strip it. */
            pkt += 2;
            *caplen -= 2;
        }
        pkt = yfDecodeL2PPP(ctx, caplen, pkt, type);
        return pkt ? yfDecodeL2Shim(ctx, caplen, pkt, type, l2info) : NULL;
#endif /* ifdef DLT_PPP */
#ifdef DLT_RAW
      case DLT_RAW:
        YF_IP_VERSION_TO_TYPE(pkt, *caplen, *type);
        if (*type == 0) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        return pkt;
#endif /* ifdef DLT_RAW */
#ifdef DLT_NULL
      case DLT_NULL:
        /* Check for full NULL header */
        if (*caplen < 4) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        /* Grab packet family */
        pf = *(uint32_t *)pkt;
        /* Advance packet pointer */
        pkt += 4;
        *caplen -= 4;
        /* Decode loopback from packet family */
        return yfDecodeL2Loop(ctx, pf, pkt, type);
#endif /* ifdef DLT_NULL */
#ifdef DLT_LOOP
      case DLT_LOOP:
        /* Check for full LOOP header */
        if (*caplen < 4) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
        /* Grab packet family */
        pf = g_ntohl((*(uint32_t *)pkt));
        /* Advance packet pointer */
        pkt += 4;
        *caplen -= 4;
        /* Decode loopback from packet family */
        return yfDecodeL2Loop(ctx, pf, pkt, type);
#endif /* ifdef DLT_LOOP */
#ifdef DLT_JUNIPER_ETHER
      case DLT_JUNIPER_ETHER:
        {
            uint16_t tot_ext_len = 0;
            uint32_t hdr_len = 4;
            uint32_t proto;

            if (*caplen < 4) {
                ++ctx->stats.fail_l2hdr;
                return NULL;
            }

            /* verify magic header */
            if (memcmp(pkt, JUNIPER_MAGIC, 3) != 0) {
                ++ctx->stats.fail_l2hdr;
                return NULL;
            }

            if ((((yfHdrJuniper_t *)pkt)->flags & JUNIPER_FLAG_EXT) ==
                JUNIPER_FLAG_EXT)
            {
                tot_ext_len = g_ntohs(((yfHdrJuniper_t *)pkt)->ext_len);
                hdr_len = 6 + tot_ext_len;
            }

            if ((((yfHdrJuniper_t *)pkt)->flags & JUNIPER_NO_L2) ==
                JUNIPER_NO_L2)
            {
                pkt += hdr_len;
                *caplen -= hdr_len;
                proto = (*(uint32_t *)pkt);
                switch (proto) {
                  case JUNIPER_PROTO_IP:
                  case JUNIPER_PROTO_MPLS_IP:
                  case JUNIPER_PROTO_IP6:
                  case JUNIPER_PROTO_MPLS_IP6:
                    pkt += 4;
                    *caplen -= 4;
                    YF_IP_VERSION_TO_TYPE(pkt, *caplen, *type);
                    if (*type == 0) {
                        ++ctx->stats.fail_l2type;
                        return NULL;
                    }
                    return pkt;
                  case JUNIPER_PROTO_MPLS:
                  case JUNIPER_PROTO_IP_MPLS:
                  case JUNIPER_PROTO_IP6_MPLS:
                    pkt += 4;
                    *caplen -= 4;
                    *type = YF_TYPE_MPLS;
                    return yfDecodeL2Shim(ctx, caplen, pkt, type, l2info);
                  default:
                    ++ctx->stats.fail_l2hdr;
                    return NULL;
                }
            }

            pkt += hdr_len;
            *caplen -= hdr_len;

            /* Check for full ethernet header */
            if (*caplen < 14) {
                ++ctx->stats.fail_l2hdr;
                return NULL;
            }
            /* Copy out ethertype */
            *type = g_ntohs(((yfHdrEn10Mb_t *)pkt)->type);
            /* Copy out MAC addresses if we care */
            if (l2info) {
                memcpy(l2info->smac, ((yfHdrEn10Mb_t *)pkt)->smac, 6);
                memcpy(l2info->dmac, ((yfHdrEn10Mb_t *)pkt)->dmac, 6);
            }
            /* Advance packet pointer */
            pkt += 14;
            *caplen -= 14;
            /* Decode shim headers */
            return yfDecodeL2Shim(ctx, caplen, pkt, type, l2info);
        }
#endif /* ifdef DLT_JUNIPER_ETHER */
      default:
        g_warning("unknown datalink %u", ctx->datalink);
        return NULL;
    }
}


/**
 * yfDecodeIPv4
 *
 *
 *
 */
static const uint8_t *
yfDecodeIPv4(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo)
{
    const yfHdrIPv4_t *iph = (const yfHdrIPv4_t *)pkt;
    size_t             iph_len;

    /* Verify we have a full IP header */
    if (*caplen < 1) {
        ++ctx->stats.fail_ip4hdr;
        return NULL;
    }

    iph_len = iph->ip_hl * 4;
    if (*caplen < iph_len) {
        ++ctx->stats.fail_ip4hdr;
        return NULL;
    }

    /* Decode source and destination address into key */
    key->version = 4;
    key->addr.v4.sip = g_ntohl(iph->ip_src);
    key->addr.v4.dip = g_ntohl(iph->ip_dst);

    /* Decode protocol into key */
    key->proto = iph->ip_p;
    /* Get IP length */
    *iplen = g_ntohs(iph->ip_len);

    /* Cap capture length to datagram length */
    if (*caplen > *iplen) {
        *caplen = *iplen;
    }

    /* Capture Type of Service */
    key->tos = iph->ip_tos;

    /* Decode fragmentation information */
    if (fraginfo) {
        fraginfo->offset = g_ntohs(iph->ip_off);
        if (fraginfo->offset & (YF_IP4_OFFMASK | YF_IP4_MF)) {
            /* Packet is fragmented */
            fraginfo->frag = 1;
            /* Get ID and offset */
            fraginfo->ipid = g_ntohs(iph->ip_id);
            fraginfo->more = (fraginfo->offset & YF_IP4_MF) ? 1 : 0;
            fraginfo->offset = (fraginfo->offset & YF_IP4_OFFMASK) * 8;
            /* Stash IP header length for fragment length calculation */
            fraginfo->iphlen = iph_len;
            /* Initialize layer 4 header length */
            fraginfo->l4hlen = 0;
        } else {
            /* Packet not fragmented */
            fraginfo->frag = 0;
        }
    } else {
        /* Null fraginfo means we don't want fragments. Drop fragged packets.
         * */
        if (g_ntohs(iph->ip_off) & (YF_IP4_OFFMASK | YF_IP4_MF)) {
            ++ctx->stats.fail_ip4frag;
            return NULL;
        }
    }

    /* Advance packet pointer */
    *caplen -= iph_len;
    return pkt + iph_len;
}


/**
 * yfDecodeIPv6
 *
 *
 *
 */
static const uint8_t *
yfDecodeIPv6(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo)
{
    const yfHdrIPv6_t     *iph = (const yfHdrIPv6_t *)pkt;
    const yfHdrIPv6Ext_t  *ipe;
    const yfHdrIPv6Frag_t *ipf;
    uint16_t               iph_len = 0;     /* total IP header accumulator */
    size_t                 hdr_len = 40;    /* next header length */
    uint8_t                hdr_next;

    /* Verify that we have a full IPv6 header */
    if (*caplen < hdr_len) {
        ++ctx->stats.fail_ip6hdr;
        return NULL;
    }

    /* Decode source and destination address into key */
    memcpy(key->addr.v6.sip, &(iph->ip6_src), 16);
    memcpy(key->addr.v6.dip, &(iph->ip6_dst), 16);
    key->version = 6;

    /* Get IP length */
    *iplen = g_ntohs(iph->ip6_plen) + hdr_len;

    /* Cap capture length to datagram length */
    if (*caplen > *iplen) {
        *caplen = *iplen;
    }

    /* Capture Traffic Class */
    key->tos = YF_VCF6_CLASS(iph);

    /* Decode next header */
    hdr_next = iph->ip6_nxt;

    /* Zero fragment flag */
    if (fraginfo) {
        fraginfo->frag = 0;
    }
    /* Now unwrap extension headers */
    for (;;) {
        /* Advance packet pointer */
        *caplen -= hdr_len;
        pkt += hdr_len;
        iph_len += hdr_len;

        /* Process next extension header */
        switch (hdr_next) {
          case YF_PROTO_IP6_NONEXT:
            return NULL;
          case YF_PROTO_IP6_FRAG:
            /* Verify we have a full fragment header */
            hdr_len = 8;
            if (*caplen < hdr_len) {
                ++ctx->stats.fail_ip6ext;
                return NULL;
            }

            /* Decode fragment header */
            ipf = (const yfHdrIPv6Frag_t *)pkt;
            hdr_next = ipf->ip6f_nxt;
            if (fraginfo) {
                fraginfo->frag = 1;
                fraginfo->ipid = g_ntohl(ipf->ip6f_ident);
                fraginfo->offset = g_ntohs(ipf->ip6f_offlg);
                fraginfo->more = (fraginfo->offset | YF_IP6_MF) ? 1 : 0;
                fraginfo->offset = fraginfo->offset & YF_IP6_OFFMASK;
            } else {
                /* Null fraginfo means we don't want fragments. */
                if (g_ntohs(ipf->ip6f_offlg) & (YF_IP4_OFFMASK | YF_IP4_MF)) {
                    ++ctx->stats.fail_ip6frag;
                    return NULL;
                }
            }
            break;
          case YF_PROTO_IP6_HOP:
          case YF_PROTO_IP6_ROUTE:
          case YF_PROTO_IP6_DOPT:
            /* Verify we have the first two bytes of the extension header */
            if (*caplen < 2) {
                ++ctx->stats.fail_ip6ext;
                return NULL;
            }

            /* Get next header info */
            ipe = (const yfHdrIPv6Ext_t *)pkt;
            hdr_next = ipe->ip6e_nxt;
            hdr_len = ipe->ip6e_len * 8 + 8;
            /* Verify we have the full extension header */
            if (*caplen < hdr_len) {
                ++ctx->stats.fail_ip6ext;
                return NULL;
            }
            break;
          default:
            /* This is not an extension header. We're at layer 4 now. */
            key->proto = hdr_next;
            /*Stash total IPv6 header length for fragment length calculation */
            if (fraginfo && fraginfo->frag) {
                fraginfo->iphlen = iph_len;
                fraginfo->l4hlen = 0;
            }

            return pkt;
        }
    }
}


/**
 * yfDecodeTCPOptions
 *
 *
 */
static void
yfDecodeTCPOptions(
    const uint8_t  *pkt,
    size_t         *caplen,
    yfTCPInfo_t    *tcpinfo,
    size_t          tcph_len)
{
    const yfHdrTcpOpt_t *opth = (const yfHdrTcpOpt_t *)pkt;
    uint8_t              subtype, flags, backup, hash;
    size_t               op_len = tcph_len - sizeof(yfHdrTcp_t);
    size_t               offset = 0;
    size_t               pktlen = *caplen - sizeof(yfHdrTcp_t);

    if (pktlen < op_len) {
        return;
    }

    while ( (offset + 2) < op_len) {
        opth = (const yfHdrTcpOpt_t *)(pkt + offset);

        if (opth->op_kind < 2) {
            /* 0 is end of option list, 1 is no-op */
            offset += 1;
            continue;
        }

        offset += sizeof(yfHdrTcpOpt_t);

        if ((opth->op_len > op_len) || (opth->op_len < sizeof(yfHdrTcpOpt_t))) {
            return;
        }

        if (opth->op_kind == YF_MPTCP_OPTION_CODE) {
            subtype = *(pkt + offset) >> 4;
            backup = *(pkt + offset) & 1;
            offset += 1;
            switch (subtype) {
              case YF_MPTCP_CAPABLE:
                hash = *(pkt + offset) & 0x7;
                /* HMAC_SHA1 is the only assigned handshake algorithm */
                if (hash != 0) {
                    tcpinfo->mptcp.flags = 1;
                }
                break;
              case YF_MPTCP_JOIN:
                /* MP_JOIN */
                /* just the initial syn has the token,
                 * syn/ack is len 16 w/hmac and random #, ack is 24 with hmac*/
                if (opth->op_len == 12) {
                    tcpinfo->mptcp.token = g_ntohl(*(uint32_t *)(pkt +
                                                                 offset + 1));
                    if (backup == 0) {
                        /* this subflow has priority */
                        tcpinfo->mptcp.flags |= YF_MF_PRIORITY;
                    }
                }
                tcpinfo->mptcp.flags |= 0x1;
                /* address id in initial syn is always zero, but will be set
                 * in syn/ack */
                tcpinfo->mptcp.addrid = *(pkt + offset);
                break;
              case YF_MPTCP_DSS:
                {
                    /* DSS */
                    uint8_t len = 0;
                    flags = *(pkt + offset);
                    offset += 1;
                    if (flags & 0x04) {
                        /* if M (0x04): DSN, subflow seq no, data-level length,
                         * and checksum present */
                        if (flags & 0x02) {
                            /* if data ack present and 8 octets */
                            len = 8;
                        } else if (flags & 0x01) {
                            /* data ack but only 4 octets */
                            len = 4;
                        }
                        if (flags & 0x08) {
                            /* data seq no is 8 octets, not 4 */
                            tcpinfo->mptcp.idsn = yf_ntohll(
                                *(uint64_t *)(pkt + offset + len));
                        } else {
                            /* data seq no is 4 octets */
                            tcpinfo->mptcp.idsn = g_ntohl(
                                *(uint32_t *)(pkt + offset + len));
                        }
                    }
                    /* added one so subtract one before length is added*/
                    offset--;
                }
                break;
              case YF_MPTCP_ADD_ADDR:
              case YF_MPTCP_RM_ADDR:
                break;
              case YF_MPTCP_PRIO:
                /* MP_PRIO */
                /* may indicate a change in priority */
                tcpinfo->mptcp.flags |= YF_MF_PRIORITY;
                if (opth->op_len == 4) {
                    /* address is optional */
                    tcpinfo->mptcp.addrid = *(pkt + offset);
                } /* if len=3 then it applies to current subflow only */
                break;
              case YF_MPTCP_FAIL:
                /* MP_FAIL */
                tcpinfo->mptcp.flags |= YF_MF_FAIL;
                break;
              case YF_MPTCP_FASTCLOSE:
                /* MP_FASTCLOSE */
                tcpinfo->mptcp.flags |= YF_MF_FASTCLOSE;
                break;
              default:
                return;
            }
            /* added one so subtract it before we add op_len below */
            offset--;
        } else if (opth->op_kind == YF_MSS_OPTION_CODE) {
            /* maximum segment size */
            tcpinfo->mptcp.mss = g_ntohs(*(uint16_t *)(pkt + offset));
        }

        /* length includes header length */
        offset += (opth->op_len - sizeof(yfHdrTcpOpt_t));
    }
}


/**
 * yfDecodeTCP
 *
 *
 *
 */
static const uint8_t *
yfDecodeTCP(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo)
{
    const yfHdrTcp_t *tcph = (const yfHdrTcp_t *)pkt;
    size_t            tcph_len;

    /* Verify we have a full TCP header */
    if (*caplen < 13) {
        if (fraginfo && fraginfo->frag) {
            /* will have to do TCP stuff later */
            return pkt;
        }
        ++ctx->stats.fail_l4hdr;
        return NULL;
    }

    tcph_len = tcph->th_off * 4;
    if (*caplen < tcph_len) {
        if (fraginfo && fraginfo->frag) {
            /*++ctx->stats.fail_l4frag;*/
            /* will do TCP stuff later */
            return pkt;
        }
        ++ctx->stats.fail_l4hdr;
        return NULL;
    }

    /* Decode source and destination port into key */
    key->sp = g_ntohs(tcph->th_sport);
    key->dp = g_ntohs(tcph->th_dport);

    /* Copy sequence number and flags */
    if (tcpinfo) {
        tcpinfo->seq = g_ntohl(tcph->th_seq);
        tcpinfo->flags = tcph->th_flags;
    }

    if (fraginfo && fraginfo->frag) {
        fraginfo->l4hlen = tcph_len;
    }

    memset(&(tcpinfo->mptcp), 0, sizeof(yfMPTCPInfo_t));

    if (tcph_len > sizeof(yfHdrTcp_t)) {
        /* we have TCP options */
        yfDecodeTCPOptions(pkt + sizeof(yfHdrTcp_t), caplen, tcpinfo, tcph_len);
    }

    /* Advance packet pointer */
    *caplen -= tcph_len;

    return pkt + tcph_len;
}


/**
 * yfDefragTCP
 *
 *
 */
gboolean
yfDefragTCP(
    uint8_t         *pkt,
    size_t          *caplen,
    yfFlowKey_t     *key,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo,
    size_t          *payoff)
{
    const yfHdrTcp_t *tcph = (const yfHdrTcp_t *)pkt;
    size_t            tcph_len;

    /* Verify we have a full TCP header */
    if (*caplen < 13) {
        return FALSE;
    }

    tcph_len = tcph->th_off * 4;
    if (*caplen < tcph_len) {
        return FALSE;
    }

    /* Decode source and destination port into key */
    key->sp = g_ntohs(tcph->th_sport);
    key->dp = g_ntohs(tcph->th_dport);

    /* Copy sequence number and flags */
    if (tcpinfo) {
        tcpinfo->seq = g_ntohl(tcph->th_seq);
        tcpinfo->flags = tcph->th_flags;
    }

    /* Advance packet pointer */
    *payoff += tcph_len;
    fraginfo->l4hlen = tcph_len;

    return TRUE;
}


/**
 * yfDecodeUDP
 *
 *
 *
 */
static const uint8_t *
yfDecodeUDP(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    yfIPFragInfo_t  *fraginfo)
{
    const yfHdrUdp_t *udph = (const yfHdrUdp_t *)pkt;
    const size_t      udph_len = 8;

    /* Verify we have a full UDP header */
    if (*caplen < udph_len) {
        ++ctx->stats.fail_l4hdr;
        if (fraginfo && fraginfo->frag) {
            ++ctx->stats.fail_l4frag;
        }
        return NULL;
    }

    /* Decode source and destination port into key */
    key->sp = g_ntohs(udph->uh_sport);
    key->dp = g_ntohs(udph->uh_dport);

    /* Copy header length if we're the first fragment */
    if (fraginfo && fraginfo->frag) {
        fraginfo->l4hlen = udph_len;
    }

    /* Advance packet pointer */
    *caplen -= udph_len;
    return pkt + udph_len;
}


/**
 * yfDecodeICMP
 *
 *
 *
 */
static const uint8_t *
yfDecodeICMP(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    yfIPFragInfo_t  *fraginfo)
{
    const yfHdrIcmp_t *icmph = (const yfHdrIcmp_t *)pkt;
    const size_t       icmph_len = 8;

    /* Verify we have a full ICMP header */
    if (*caplen < icmph_len) {
        ++ctx->stats.fail_l4hdr;
        if (fraginfo && fraginfo->frag) {
            ++ctx->stats.fail_l4frag;
        }
        return NULL;
    }

    /* Decode source and destination port into key */
    key->sp = 0;
    key->dp = (icmph->icmp_type << 8) + icmph->icmp_code;

    /* Copy header length if we're the first fragment */
    if (fraginfo && fraginfo->frag) {
        fraginfo->l4hlen = icmph_len;
    }

    /* Advance packet pointer */
    *caplen -= icmph_len;
    return pkt + icmph_len;
}


/* prototype needed for GRE recursion */
static const uint8_t *
yfDecodeIP(
    yfDecodeCtx_t   *ctx,
    uint16_t         type,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfTCPInfo_t     *tcpinfo,
    yfIPFragInfo_t  *fraginfo);

/**
 * @brief Decodes a VxLAN header. Assumes the next header is L2.
 * Only runs on UDP packets. There is legitimate non-UDP+VxLAN traffic in AWS,
 * but we are prioritizing being able to decode un-mirrored non-UDP traffic.
 *
 * @param ctx Decode Context
 * @param caplen Capture Length
 * @param pkt Packet Pointer
 * @param key YAF's Flow Key
 * @param iplen Packet IP length.
 * @param fraginfo Fragmentation Info
 * @param tcpinfo TCP Info
 * @return const uint8_t* An updated packet pointer
 */
static const uint8_t *
yfDecodeVxLAN(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo)
{
    const yfHdrVxlan_t *vxlanh   = (const yfHdrVxlan_t *)pkt;
    size_t              vxlanh_len = sizeof(vxlanh);

    if (*caplen < vxlanh_len) {
        /* Could not verify we have a full VxLAN header. */
        ++ctx->stats.fail_vxlan;
        return NULL;
    }
    uint32_t vni_r = g_ntohl(vxlanh->vni_r);
    uint32_t vni = YF_VXLAN_VNI(vni_r);

    /* Set the most significant byte to identify VxLAN overlay type as per
     * IANA IPFIX Information Element 351, layer2SegmentId */
    uint32_t layer2Id = 0x01000000 | vni;
    /* Always export the VxLAN VNI, even if Geneve decoding is enabled. */
    key->layer2Id = layer2Id;

    /* Advance packet pointer, skipping over the VxLAN header */
    *caplen -= vxlanh_len;
    pkt += vxlanh_len;

    /* Decode L2 headers and update the l2info to reflect the encapsulated
     * frame */
    yfL2Info_t l2info;
    uint16_t   type = 0;
    if (!(pkt = yfDecodeL2(ctx, caplen, pkt, &type, &l2info))) {
        ++ctx->stats.fail_l2hdr;
        return NULL;
    }

    /* Now we should have the original IP packet. Decode it. */
    if (!(pkt = yfDecodeIP(ctx, type, caplen, pkt, key, iplen,
                           tcpinfo, fraginfo)))
    {
        return NULL;
    }

    return pkt;
}

/**
 * @brief Decodes a Geneve header.
 *
 * @param ctx Decode Context
 * @param caplen Capture Length
 * @param pkt Packet Pointer
 * @param key YAF's Flow Key
 * @param iplen Packet IP length.
 * @param fraginfo Fragmentation Info
 * @param tcpinfo TCP Info
 * @return const uint8_t* An updated packet pointer
 */
static const uint8_t *
yfDecodeGeneve(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo)
{
    const yfHdrGeneve_t *geneveh = (const yfHdrGeneve_t *)pkt;
    size_t               geneveh_len = sizeof(geneveh);

    if (*caplen < geneveh_len) {
        /* Could not verify we have a full Geneve header. */
        ++ctx->stats.fail_geneve;
        return NULL;
    }

    /* Extract and verify the version number is zero */
    uint32_t gv_flags = g_ntohl(geneveh->gv_flags);
    uint8_t  version = YF_GENEVE_VER(gv_flags);
    if (version != 0) {
        /* Geneve version is unknown. Dropping the packet. */
        ++ctx->stats.fail_geneve;
        return NULL;
    }

    /* Extract the VNI, ethertype, and optlen */
    uint32_t gv_vni = g_ntohl(geneveh->gv_vni);
    uint32_t vni = YF_GENEVE_VNI(gv_vni);
    uint16_t type = YF_GENEVE_TYPE(gv_flags);
    uint8_t oplen = YF_GENEVE_OPLEN(gv_flags);
    geneveh_len += oplen;

    /* Verify we still have a full Geneve header after considering variable
     * options */
    if (*caplen < geneveh_len) {
        ++ctx->stats.fail_geneve;
        return NULL;
    }

    /* Only export the Geneve VNI if VxLAN is not enabled */
    if (!ctx->vxlanports) {
        /* Setting the most significant byte to 0x03 to identify Geneve
         * overlay type */
        uint32_t layer2Id = 0x03000000 | vni;
        key->layer2Id = layer2Id;
    }

    /* Advance packet pointer, skipping over the Geneve header */
    *caplen -= geneveh_len;
    pkt += geneveh_len;

    /* If the next header is ethernet, decode it. */
    if (!(type == YF_TYPE_IPv4 || type == YF_TYPE_IPv6)) {
        yfL2Info_t l2info;
        if (!(pkt = yfDecodeL2(ctx, caplen, pkt, &type, &l2info))) {
            ++ctx->stats.fail_l2hdr;
            return NULL;
        }
    }

    /* Now we should have the next header. Decode it. */
    if (!(pkt = yfDecodeIP(ctx, type, caplen, pkt, key, iplen,
                           tcpinfo, fraginfo)))
    {
        return NULL;
    }

    return pkt;
}

static const uint8_t *
yfDecodeERSPAN(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo)
{
    uint16_t   version;
    uint8_t    hdr_len = 0;
    yfL2Info_t l2info;
    uint16_t   type;

    /* do we have a *valid* ERSPAN header? */
    if (*caplen < 8) {
        ++ctx->stats.fail_erspan;
        return NULL;
    }

    version = ntohs(*((uint16_t *)pkt)) >> 12;

    /* 1 is actually version 2 */
    if (version == 1) {
        *caplen -= 8;
        hdr_len = 8;
    } else {
        /* I think version 3 has a 12 byte header but can't confirm *
         * due to lack of spec */
        ++ctx->stats.fail_erspan;
        return NULL;
    }

    if (!(pkt = yfDecodeL2(ctx, caplen, pkt + hdr_len, &type, &l2info))) {
        ++ctx->stats.fail_erspan;
        return NULL;
    }

    /* We are now at the next layer header.Try to decode it as an IP header.*/
    return yfDecodeIP(ctx, type, caplen, pkt, key, iplen, tcpinfo, fraginfo);
}


/**
 * yfDecodeGRE
 *
 *
 *
 */
static const uint8_t *
yfDecodeGRE(
    yfDecodeCtx_t   *ctx,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfIPFragInfo_t  *fraginfo,
    yfTCPInfo_t     *tcpinfo)
{
    const yfHdrGre_t *greh = (const yfHdrGre_t *)pkt;
    size_t            greh_len = 4;
    const yfHdrSre_t *sreh = NULL;
    size_t            sre_len = 0;

    /* Verify we have a full GRE "mandatory" header */
    /* An IP Frag has to have at least 8 - so we should never
     * enter this IF */
    if (*caplen < greh_len) {
        ++ctx->stats.fail_l4hdr;
        if (fraginfo && fraginfo->frag) {
            ++ctx->stats.fail_l4frag;
        }
        return NULL;
    }

    /* Verify GRE version is 0 */
    if (YF_GHFV_VERSION(greh) != 0) {
        ++ctx->stats.fail_grevers;
        return NULL;
    }

    /* Decode the GRE header. */
    if (greh->gh_f_sum || greh->gh_f_route) {
        /* If this bit is set then the header has to contain 4 more bytes */
        /* Skip checksum and route offset */
        greh_len += 4;
    }

    if (greh->gh_f_key) {
        /* Skip key - if present header contains optional key field*/
        greh_len += 4;
    }

    if (greh->gh_f_seq) {
        /* Skip sequence number - if present header contains opt seq #*/
        greh_len += 4;
    }

    /* Verify we have a full GRE header as extended */
    if (*caplen < greh_len) {
        ++ctx->stats.fail_l4hdr;
        if (fraginfo && fraginfo->frag) {
            ++ctx->stats.fail_l4frag;
        }
        return NULL;
    }

    /* Okay. Now skip the GRE header. */
    pkt += greh_len;
    *caplen -= greh_len;

    /* Parse any SREs if present */
    if (greh->gh_f_route) {
        for (;;) {
            sreh = (const yfHdrSre_t *)pkt;
            sre_len = 4;

            /* Verify we have the SRE header */
            if (*caplen < sre_len) {
                ++ctx->stats.fail_l4hdr;
                if (fraginfo && fraginfo->frag) {
                    ++ctx->stats.fail_l4frag;
                }
                return NULL;
            }

            /* Check for termination */
            if ((sreh->gh_sre_len == 0) && (g_ntohs(sreh->gh_sre_af) == 0)) {
                pkt += sre_len;
                *caplen -= sre_len;
                break;
            }

            /* Get SRE length */
            sre_len += sreh->gh_sre_len;
            /* Verify we have the full SRE*/
            if (*caplen < sre_len) {
                ++ctx->stats.fail_l4hdr;
                if (fraginfo && fraginfo->frag) {
                    ++ctx->stats.fail_l4frag;
                }
                return NULL;
            }

            /* Skip the SRE */
            pkt += sre_len;
            *caplen -= sre_len;
        }
    }

    /* Check to see if we have an ERSPAN Header */
    if (g_ntohs(greh->gh_type) == YF_PROTO_ERSPAN) {
        return yfDecodeERSPAN(ctx, caplen, pkt, key, iplen, fraginfo, tcpinfo);
    }

    /* We are now at the next layer header.Try to decode it as an IP header.*/
    return yfDecodeIP(ctx, g_ntohs(greh->gh_type), caplen, pkt,
                      key, iplen, tcpinfo, fraginfo);
}


/**
 * yfDecodeIP
 *
 *
 *
 */
static const uint8_t *
yfDecodeIP(
    yfDecodeCtx_t   *ctx,
    uint16_t         type,
    size_t          *caplen,
    const uint8_t   *pkt,
    yfFlowKey_t     *key,
    uint32_t        *iplen,
    yfTCPInfo_t     *tcpinfo,
    yfIPFragInfo_t  *fraginfo)
{
#if YAF_NONIP
    if (type == 0) {
        key->version = 4;
        key->sp = 0;
        key->dp = 0;
        /* not really - but best we can do */
        *iplen = *caplen;
        key->proto = 0;
        key->addr.v4.sip = 0;
        key->addr.v4.dip = 0;
        /* Packet not fragmented - as far as we know and care */
        if (fraginfo) {fraginfo->frag = 0;}
        return pkt;
    }
#endif /* if YAF_NONIP */

    /* Check for required IP packet type. */
    if (ctx->reqtype && ctx->reqtype != type) {
        ++ctx->stats.fail_l3type;
        return NULL;
    }

    /* Unwrap and decode IP headers */
    switch (type) {
      case YF_TYPE_IPv4:
        if (!(pkt = yfDecodeIPv4(ctx, caplen, pkt, key, iplen, fraginfo))) {
            return NULL;
        }
        break;
      case YF_TYPE_IPv6:
        if (!(pkt = yfDecodeIPv6(ctx, caplen, pkt, key, iplen, fraginfo))) {
            return NULL;
        }
        break;
      case YF_TYPE_ARP:
        ++ctx->stats.fail_arptype;
        return NULL;
      case YF_TYPE_LLDP:
        ++ctx->stats.fail_lldptype;
        return NULL;
      case YF_TYPE_SLOW:
        ++ctx->stats.fail_8023type;
        return NULL;
      default:
        if (type < 257) {
            ++ctx->stats.fail_8023type;
            return NULL;
        }
        ++ctx->stats.fail_l3type;
        return NULL;
    }

    /* Skip layer 4 decode unless we're the first fragment */
    if (fraginfo && fraginfo->frag && fraginfo->offset) {
        return pkt;
    }

    /* Unwrap and decode layer 4 headers */
    switch (key->proto) {
      case YF_PROTO_TCP:
        if (!(pkt = yfDecodeTCP(ctx, caplen, pkt, key, fraginfo, tcpinfo))) {
            return NULL;
        }
        break;
      case YF_PROTO_UDP:
        if (!(pkt = yfDecodeUDP(ctx, caplen, pkt, key, fraginfo))) {
            return NULL;
        }
        if (ctx->geneveports && yfSearchArray(ctx->geneveports, key->dp)) {
            if (!(pkt = yfDecodeGeneve(ctx, caplen, pkt, key, iplen,
                                       fraginfo, tcpinfo)))
            {
                return NULL;
            }
        }
        if (ctx->vxlanports && yfSearchArray(ctx->vxlanports, key->dp)) {
            if (!(pkt = yfDecodeVxLAN(ctx, caplen, pkt, key, iplen,
                                      fraginfo, tcpinfo)))
            {
                return NULL;
            }
        }
        break;
      case YF_PROTO_ICMP:
      case YF_PROTO_ICMP6:
        if (!(pkt = yfDecodeICMP(ctx, caplen, pkt, key, fraginfo))) {
            return NULL;
        }
        break;
      case YF_PROTO_GRE:
        if (ctx->gremode) {
            if (!(pkt = yfDecodeGRE(ctx, caplen, pkt, key,
                                    iplen, fraginfo, tcpinfo)))
            {
                return NULL;
            }
        } else {
            /* Not decoding GRE. Zero ports. */
            key->sp = 0;
            key->dp = 0;
        }
        break;
      default:
        /* No layer 4 header we understand. Zero ports. */
        key->sp = 0;
        key->dp = 0;
    }

    /* Return what's left of the packet */
    return pkt;
}


/**
 * yfDecodeToPBuf
 *
 *
 *
 */
gboolean
yfDecodeToPBuf(
    yfDecodeCtx_t   *ctx,
    uint64_t         ptime,
    size_t           caplen,
    const uint8_t   *pkt,
    yfIPFragInfo_t  *fraginfo,
    size_t           pbuflen,
    yfPBuf_t        *pbuf)
{
    uint16_t       type;
    yfFlowKey_t   *key = &(pbuf->key);
    uint32_t      *iplen = &(pbuf->iplen);
    yfTCPInfo_t   *tcpinfo = &(pbuf->tcpinfo);
/*    yfL2Info_t              *l2info = (pbuflen >= YF_PBUFLEN_NOPAYLOAD) ?
 *    &(pbuf->l2info) : NULL;*/
    yfL2Info_t    *l2info = &(pbuf->l2info);
    const uint8_t *ipTcpHeaderStart = NULL;
    size_t         capb4l2 = caplen;

    /* Zero packet buffer time (mark it not yet valid) */
    pbuf->ptime = 0;

    /* Keep the start of pcap for pcap output */
    ipTcpHeaderStart = pkt;

    /* keep track of which file we're processing */
    pbuf->pcap_caplist = ctx->pcap_caplist;

    /* Verify enough bytes are available in the buffer. Die hard for now
     * if not; this is not a valid runtime error. */
    if (pbuflen < YF_PBUFLEN_NOL2INFO) {
        g_error("YAF internal error: packet buffer too small (%"
                SIZE_T_FORMAT ", need %"SIZE_T_FORMAT ")",
                (SIZE_T_CAST)pbuflen, (SIZE_T_CAST)YF_PBUFLEN_NOL2INFO);
    }

    /* Unwrap layer 2 headers */
    if (!(pkt = yfDecodeL2(ctx, &caplen, pkt, &type, l2info))) {
        return FALSE;
    }

    key->layer2Id = 0;
    l2info->l2hlen = (uint16_t)(capb4l2 - caplen);
    if (l2info) {
        key->vlanId = l2info->vlan_tag;
    } else {
        key->vlanId = 0;
    }

#if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT)
    /* mark the beginning of the IP/{TCP|UDP} headers */
    memcpy(pbuf->headerVal, pkt,
           sizeof(pbuf->headerVal) < caplen ? sizeof(pbuf->headerVal) - 1 :
           caplen);
    pbuf->headerLen = sizeof(pbuf->headerVal) < caplen ?
        sizeof(pbuf->headerVal) - 1 : caplen;
#endif /* if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT) */
    /* Now we should have an IP packet. Decode it. */
    if (!(pkt = yfDecodeIP(ctx, type, &caplen, pkt, key, iplen,
                           tcpinfo, fraginfo)))
    {
        return FALSE;
    }

    /* Copy ctime into packet buffer */
    pbuf->ptime = ptime;

    /* Keep track of how far we progressed */
    pbuf->allHeaderLen = pkt - ipTcpHeaderStart;

    caplen = caplen + pbuf->allHeaderLen;

    /* Copy payload if available */
    if (pbuflen > YF_PBUFLEN_BASE) {
        pbuf->paylen = pbuflen - YF_PBUFLEN_BASE;
        if (pbuf->paylen > caplen) {
            pbuf->paylen = caplen;
        }
        memcpy(pbuf->payload, ipTcpHeaderStart, pbuf->paylen);
    }

    return TRUE;
}


/**
 * yfDecodeCtxAlloc
 *
 *
 *
 */
yfDecodeCtx_t *
yfDecodeCtxAlloc(
    int        datalink,
    uint16_t   reqtype,
    gboolean   gremode,
    GArray    *vxlanports,
    GArray    *geneveports)
{
    yfDecodeCtx_t *ctx = NULL;

    /* Allocate a flow table */
    ctx = g_slice_new0(yfDecodeCtx_t);

    /* Fill in the configuration */
    ctx->datalink = datalink;
    ctx->reqtype = reqtype;
    ctx->gremode = gremode;
    ctx->vxlanports = vxlanports;
    ctx->geneveports = geneveports;
    ctx->pcap_caplist = 0;

    /* Done */
    return ctx;
}


/**
 * yfDecodeCtxFree
 *
 *
 *
 */
void
yfDecodeCtxFree(
    yfDecodeCtx_t  *ctx)
{
    /* just free the context */
    g_slice_free(yfDecodeCtx_t, ctx);
}


/**
 * yfDecodeTimeval
 *
 *
 *
 */
uint64_t
yfDecodeTimeval(
    const struct timeval  *tv)
{
    return (((uint64_t)tv->tv_sec * 1000) + ((uint64_t)tv->tv_usec / 1000));
}


/**
 * yfGetDecodeStats
 *
 */
uint32_t
yfGetDecodeStats(
    yfDecodeCtx_t  *ctx)
{
    uint32_t fail_snaptotal;
    uint32_t fail_suptotal;
    uint32_t fail_total;

    fail_snaptotal =
        ctx->stats.fail_l2hdr + ctx->stats.fail_l2shim +
        ctx->stats.fail_ip4hdr + ctx->stats.fail_ip6hdr +
        ctx->stats.fail_ip6ext + ctx->stats.fail_l4hdr;

    fail_suptotal =
        ctx->stats.fail_l2loop + ctx->stats.fail_l3type +
        ctx->stats.fail_ip4frag + ctx->stats.fail_ip6frag +
        ctx->stats.fail_grevers + ctx->stats.fail_arptype +
        ctx->stats.fail_l2type + ctx->stats.fail_erspan +
        ctx->stats.fail_8023type + ctx->stats.fail_lldptype;

    fail_total =
        fail_snaptotal + fail_suptotal;

    return fail_total;
}


/**
 * yfDecodeResetOffset
 *
 */
void
yfDecodeResetOffset(
    yfDecodeCtx_t  *ctx)
{
    ctx->pcap_caplist++;
}


/**
 * yfDecodeDumpStats
 *
 *
 *
 */
void
yfDecodeDumpStats(
    yfDecodeCtx_t  *ctx,
    uint64_t        packetTotal)
{
    uint32_t fail_snaptotal;
    uint32_t fail_suptotal;
    uint32_t fail_total;
    /* uint32_t            fail_l3total; */

    fail_snaptotal =
        ctx->stats.fail_l2hdr + ctx->stats.fail_l2shim +
        ctx->stats.fail_ip4hdr + ctx->stats.fail_ip6hdr +
        ctx->stats.fail_ip6ext + ctx->stats.fail_l4hdr;

    fail_suptotal =
        ctx->stats.fail_l2loop + ctx->stats.fail_l3type +
        ctx->stats.fail_ip4frag + ctx->stats.fail_ip6frag +
        ctx->stats.fail_grevers + ctx->stats.fail_arptype +
        ctx->stats.fail_erspan + ctx->stats.fail_l2type +
        ctx->stats.fail_8023type + ctx->stats.fail_lldptype;

    fail_total =
        fail_snaptotal + fail_suptotal;

    /* fail_l3total = ctx->stats.fail_l3type + ctx->stats.fail_arptype + */
    /*                ctx->stats.fail_8023type + ctx->stats.fail_lldptype; */

    if (fail_total) {
        g_debug("Rejected %u packets during decode: (%3.2f%%)",
                fail_total,
                ((double)(fail_total) / (double)(packetTotal) * 100) );

        if (fail_snaptotal) {
            g_debug("  %u due to incomplete headers: (%3.2f%%)",
                    fail_snaptotal,
                    ((double)(fail_snaptotal) / (double)(packetTotal) * 100) );
            if (ctx->stats.fail_l2hdr) {
                g_debug("    %u incomplete layer 2 headers. (%3.2f%%)",
                        ctx->stats.fail_l2hdr,
                        ((double)(ctx->stats.fail_l2hdr) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_l2shim) {
                g_debug("    %u incomplete shim headers. (%3.2f%%)",
                        ctx->stats.fail_l2shim,
                        ((double)(ctx->stats.fail_l2shim) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_ip4hdr) {
                g_debug("    %u incomplete IPv4 headers. (%3.2f%%)",
                        ctx->stats.fail_ip4hdr,
                        ((double)(ctx->stats.fail_ip4hdr) /
                         (double)(packetTotal) * 100) );
            }

            if (ctx->stats.fail_ip6hdr) {
                g_debug("    %u incomplete IPv6 headers. (%3.2f%%)",
                        ctx->stats.fail_ip6hdr,
                        ((double)(ctx->stats.fail_ip6hdr) /
                         (double)(packetTotal) * 100) );
            }

            if (ctx->stats.fail_ip6ext) {
                g_debug("    %u incomplete IPv6 extension headers. (%3.2f%%)",
                        ctx->stats.fail_ip6ext,
                        ((double)(ctx->stats.fail_ip6ext) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_l4hdr) {
                g_debug("    %u incomplete transport headers. (%3.2f%%)",
                        ctx->stats.fail_l4hdr,
                        ((double)(ctx->stats.fail_l4hdr) /
                         (double)(packetTotal) * 100) );
                if (ctx->stats.fail_l4frag) {
                    g_debug("      (%u fragmented.) (%3.2f%%)",
                            ctx->stats.fail_l4frag,
                            ((double)(ctx->stats.fail_l4frag) /
                             (double)(packetTotal) * 100) );
                }
            }
            g_debug("    (Use a larger snaplen to reduce incomplete headers.)");
        }

        if (fail_suptotal) {
            g_debug("  %u due to unsupported/rejected packet type: (%3.2f%%)",
                    fail_suptotal,
                    ((double)(fail_suptotal) / (double)(packetTotal) * 100) );
            if (ctx->stats.fail_l2type) {
                g_debug("      %u unsupported/rejected Layer 2 headers. "
                        "(%3.2f%%)",
                        ctx->stats.fail_l2type,
                        ((double)(ctx->stats.fail_l2type) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_l3type) {
                g_debug("      %u unsupported/rejected Layer 3 headers. "
                        "(%3.2f%%)",
                        ctx->stats.fail_l3type,
                        ((double)(ctx->stats.fail_l3type) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_arptype) {
                g_debug("      %u ARP packets. (%3.2f%%)",
                        ctx->stats.fail_arptype,
                        ((double)(ctx->stats.fail_arptype) /
                         (double)(packetTotal) * 100));
            }
            if (ctx->stats.fail_lldptype) {
                g_debug("      %u LLDP packets. (%3.2f%%)",
                        ctx->stats.fail_lldptype,
                        ((double)(ctx->stats.fail_lldptype) /
                         (double)(packetTotal) * 100));
            }
            if (ctx->stats.fail_8023type) {
                g_debug("      %u 802.3 packets. (%3.2f%%)",
                        ctx->stats.fail_8023type,
                        ((double)(ctx->stats.fail_8023type) /
                         (double)(packetTotal) * 100));
            }
            if (ctx->stats.fail_ip4frag) {
                g_debug("      %u IPv4 fragments. (%3.2f%%)",
                        ctx->stats.fail_ip4frag,
                        ((double)(ctx->stats.fail_ip4frag) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_ip6frag) {
                g_debug("      %u IPv6 fragments. (%3.2f%%)",
                        ctx->stats.fail_ip6frag,
                        ((double)(ctx->stats.fail_ip6frag) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_l2loop) {
                g_debug(
                    "      %u unsupported loopback packet families. (%3.2f%%)",
                    ctx->stats.fail_l2loop,
                    ((double)(ctx->stats.fail_l2loop) /
                     (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_grevers) {
                g_debug("      %u unsupported GRE version headers. (%3.2f%%)",
                        ctx->stats.fail_grevers,
                        ((double)(ctx->stats.fail_grevers) /
                         (double)(packetTotal) * 100) );
            }
            if (ctx->stats.fail_erspan) {
                g_debug("      %u unsupported ERSPAN headers. (%3.2f%%)",
                        ctx->stats.fail_erspan,
                        ((double)(ctx->stats.fail_erspan) /
                         (double)(packetTotal) * 100) );
            }
        }
    }
}
