/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  teredoplugin.c
 *
 *  this is a protocol classifier for the Teredo Tunneling Protocol
 *
 *  Teredo is a tunneling protocol designed to grant IPv6 connectivity to
 *  nodes that are located behind IPv6-unaware NAT devices.  It is a way to
 *  encapsulate IPv6 pkts within IPv4 UDP datagrams.
 *
 *  rfc 4380  href="http://tools.ietf.org/html/rfc4380"
 *
 *  ------------------------------------------------------------------------
 *  Authors: Dan Ruef
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
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <payloadScanner.h>

#include <arpa/inet.h>

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

#define AUTH_HEADER_LEN 13
typedef struct yfIPv6AuthIndicator_st {
    /* indicator type, set to 1 for auth */
    uint16_t   ipv6_indicatorType;
    /* length of the client ID string that follows auth data length */
    uint8_t    ipv6_clientIdLen;
    /* length of the authentication data that follow client id string */
    uint8_t    ipv6_authenticationDataLen;
    /* char * clientId.  There is a char array of variable length next */
    /* uint8_t *authenticationData.  There is a variable array of auth data */
    uint64_t   nonce;
    uint8_t    confirmation;
} yfIPv6AuthIndicator_t;

typedef struct yfIPv6OriginIndicator_st {
    /* indicator type, set to 0 for origin */
    uint16_t   ipv6_indicatorType;
    uint16_t   ipv6_obscuredPortNum;
    uint32_t   ipv6_obscuredOriginAddress;
} yfIPv6OriginIndicator_t;

static uint16_t
lookForIPv6HdrAndTeredoAddrs(
    yfHdrIPv6_t  *ipv6Hdr);

#define TEREDO_PORT_NUMBER 3544

YC_SCANNER_PROTOTYPE(teredoplugin_LTX_ycTeredoScanScan);

/**
 * teredoplugin_LTX_ycTeredoScanScan
 *
 * returns TEREDO_PORT_NUMBER if the passed in payload matches
 * a teredo IPv6 tunneling protocol packet
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * return 0 if no match
 */
uint16_t
teredoplugin_LTX_ycTeredoScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    yfHdrIPv6_t           *ipv6Hdr;
    yfIPv6AuthIndicator_t *authHdr;
    yfIPv6OriginIndicator_t *originHdr;
    int      retval;
    int      authHdrLength = 0;
    uint16_t indicator;

    if (payloadSize < sizeof(yfHdrIPv6_t)) {
        return 0;
    }

    ipv6Hdr = (yfHdrIPv6_t *)payload;

    retval = lookForIPv6HdrAndTeredoAddrs(ipv6Hdr);
    if (retval == TEREDO_PORT_NUMBER) {
        return TEREDO_PORT_NUMBER;
    }

    authHdr = (yfIPv6AuthIndicator_t *)payload;

    indicator = ntohs(authHdr->ipv6_indicatorType);
    if (authHdr->ipv6_indicatorType == 1) {
        authHdrLength = AUTH_HEADER_LEN +
            authHdr->ipv6_clientIdLen +
            authHdr->ipv6_authenticationDataLen;

        if (payloadSize < (authHdrLength + sizeof(yfHdrIPv6_t))) {
            return 0;
        }

        originHdr = (yfIPv6OriginIndicator_t *)(payload + authHdrLength);
        indicator = ntohs(originHdr->ipv6_indicatorType);
        if (indicator == 0) {
            if (payloadSize < (authHdrLength +
                               sizeof(yfHdrIPv6_t) +
                               sizeof(yfIPv6OriginIndicator_t)))
            {
                return 0;
            }
            ipv6Hdr = (yfHdrIPv6_t *)(originHdr + 1);
        } else {
            ipv6Hdr = (yfHdrIPv6_t *)originHdr;
        }
    } else {
        originHdr = (yfIPv6OriginIndicator_t *)payload;
        indicator = ntohs(originHdr->ipv6_indicatorType);
        if (indicator != 0) {
            return 0;
        }

        if (payloadSize < sizeof(yfIPv6OriginIndicator_t) +
            sizeof(yfHdrIPv6_t))
        {
            return 0;
        }

        ipv6Hdr = (yfHdrIPv6_t *)(originHdr + 1);
    }

    return lookForIPv6HdrAndTeredoAddrs(ipv6Hdr);
}


static uint16_t
lookForIPv6HdrAndTeredoAddrs(
    yfHdrIPv6_t  *ipv6Hdr)
{
    uint32_t teredoPrefix = htonl(0x20010000);
    uint32_t vcf = 0;

    vcf = ntohl(ipv6Hdr->ip6_vcf);

    if (((vcf & 0xF0000000) >> 28) != 6) {
        return 0;
    }

    /* try teredo data...prefix...then try icmp for router solicitation */
    if (memcmp(&teredoPrefix, ipv6Hdr->ip6_src, 4) != 0) {
        if (memcmp(&teredoPrefix, ipv6Hdr->ip6_dst, 4) != 0) {
            return 0;
        }
    }

    return TEREDO_PORT_NUMBER;
}
