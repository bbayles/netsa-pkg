/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  dhcpplugin.c
 *
 *
 *  This tries to recognize the DHCP protocol
 *  rfc 2131
 *
 *  The Dynamic Host Configuration Protocol (DHCP) provides a framework
 *  for passing configuration information to hosts on a TCPIP network.
 *  It is based on the Bootstrap Protocol (BOOTP) adding the add'l
 *  capability of automatic allocation of reusable network addresses
 *  and add'l config options.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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

#define DHCP_PORT_NUMBER 67
#define MAGICCOOKIE 0x63825363

YC_SCANNER_PROTOTYPE(dhcpplugin_LTX_ycDhcpScanScan);

/**
 * dhcpplugin_LTX_ycDhcpScanScan
 *
 * the scanner for recognizing DHCP packets
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return dhcp port number
 *         otherwise 0
 */
uint16_t
dhcpplugin_LTX_ycDhcpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t  op, htype;
    uint16_t flags;
    uint32_t offset = 0;
    uint32_t magic_cookie;
    int      loop;

    if (payloadSize < 44) {
        return 0;
    }
    if (flow->key.proto != YF_PROTO_UDP) {
        return 0;
    }

    /* MESSAGE TYPE */
    op = payload[0];
    if (op != 2 && op != 1) {
        return 0;   /* BOOTREPLY = 2, BOOTREQUEST = 1 */
    }
    offset++;

    /* Hardware type */
    htype = *(payload + offset);
    if (htype != 1) {
        return 0;
    }

    /* hardware len is after type */

    offset += 2;

    /* hops should be 0 */
    if (*(payload + offset) != 0) {
        return 0;
    }

    /* transaction ID next & then seconds elapsed */
    offset += 7;

    flags = ntohs(*(uint16_t *)(payload + offset));
    if (flags != 0x8000 && flags != 0) {
        return 0;  /* only 1 (Broadcast flag) bit can be set) */
    }

    /* client addr is after flags - can be different based on type of message
     * */
    offset += 6;

    if (op == 1) {
        /* yiaddr, siaddr, and giaddr should be 0 */
        for (loop = 0; loop < 12; loop++) {
            if (*(payload + offset + loop) != 0) {
                return 0;
            }
        }
    }
    /* 12 for above yiaddr, siaddr, and giaddr, 16 for chaddr */
    offset += 28;
    /* 64 for sname, 128 for file, 4 for magic cookie */
    if ((size_t)offset + 196 <= payloadSize) {
        offset += 192;
    } else {
        /* should be good enough - but magic cookie will secure the decision */
        return DHCP_PORT_NUMBER;
    }

    magic_cookie = ntohl(*(uint32_t *)(payload + offset));
    if (magic_cookie != MAGICCOOKIE) {
        return 0;
    }

    offset += 4;
    if (offset >= payloadSize) {
        /* just enough */
        return DHCP_PORT_NUMBER;
    }

    /* OPTIONS SECTION! */

    return DHCP_PORT_NUMBER;
}
