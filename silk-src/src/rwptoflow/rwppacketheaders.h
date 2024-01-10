/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
#ifndef _RWPPACKETHEADERS_H
#define _RWPPACKETHEADERS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWPMATCH_H, "$SiLK: rwppacketheaders.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#ifdef SK_HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif
#include <silk/utils.h>


/*
**  rwppacketheaders.h
**
**  Headers for ethernet, IP, ICMP, TCP, and UDP packets.
**
*/


/* mask with the IP header flags/fragment offset field to get the
 * fragment offset. */
#ifndef IPHEADER_FO_MASK
#define IPHEADER_FO_MASK 0x1FFF
#endif

/* mask with the IP header flags/fragment offset field to get the
 * 'more fragments' bit */
#ifndef IP_MF
#define IP_MF  0x2000
#endif


typedef struct eth_header_st {
    uint8_t     ether_dhost[6]; /* destination eth addr */
    uint8_t     ether_shost[6]; /* source ether addr    */
    uint16_t    ether_type;     /* packet type ID field */
} eth_header_t;

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

/* IPv4 header */
typedef struct ip_header_st {
    uint8_t     ver_ihl;        /*  0: version:4; header_length_in_words:4; */
    uint8_t     tos;            /*  1: type of service */
    uint16_t    tlen;           /*  2: total length (hdr + payload) */
    uint16_t    ident;          /*  4: identification */
    uint16_t    flags_fo;       /*  6: fragmentation: flags:3;offset:13; */
    uint8_t     ttl;            /*  8: time to live */
    uint8_t     proto;          /*  9: protocol */
    uint16_t    crc;            /* 10: checksum */
    uint32_t    saddr;          /* 12: source address */
    uint32_t    daddr;          /* 16: desitation address */
    /*                             20: variable length options */
} ip_header_t;


/* ICMP header */
typedef struct icmp_header_st {
    uint8_t     type;           /*  0: type of message */
    uint8_t     code;           /*  1: type sub-code */
    uint16_t    checksum;       /*  2: ones complement checksum */
    /*                              4: ICMP Message */
} icmp_header_t;


/* TCP header */
typedef struct tcp_header_st {
    uint16_t    sport;          /*  0: source port */
    uint16_t    dport;          /*  2: destination port */
    uint32_t    seqNum;         /*  4: sequence number */
    uint32_t    ackNum;         /*  8: acknowledgement number */
    uint8_t     offset;         /* 12: offset */
    uint8_t     flags;          /* 13: packet flags */
    uint16_t    window;         /* 14: window */
    uint16_t    checksum;       /* 16: checksum */
    uint16_t    urgentPtr;      /* 18: urgent pointer */
    /*                             20: Variable length options and padding */
} tcp_header_t;


/* UDP header */
typedef struct udp_header_st {
    uint16_t    sport;          /*  0: source port */
    uint16_t    dport;          /*  2: destination port */
    uint16_t    len;            /*  4: udp length */
    uint16_t    crc;            /*  6: udp checksum */
    /*                              8: UDP data */
} udp_header_t;


/* structure used when communicating with plug-ins */
typedef struct sk_pktsrc_st {
    /* the source of the packets */
    pcap_t                     *pcap_src;
    /* the pcap header as returned from pcap_next() */
    const struct pcap_pkthdr   *pcap_hdr;
    /* the packet as returned from pcap_next() */
    const u_char               *pcap_data;
} sk_pktsrc_t;

/*
 * rwptoflow hands the packet to the plugin as an "extra argument".
 * rwptoflow and its plugins must agree on the name of this argument.
 * The extra argument is specified in a NULL-terminated array of
 * argument names.
 */
#define RWP2F_EXTRA_ARGUMENTS {"ptoflow", NULL}


#ifdef __cplusplus
}
#endif
#endif /* _RWPPACKETHEADERS_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
