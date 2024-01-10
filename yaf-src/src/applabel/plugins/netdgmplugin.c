/*
 *  Copyright 2015-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  netdgmplugin.c
 *
 *  This attempts to identify NetBIOS Datagram Service Packets.
 *  Typically UDP Port 138
 *  RFC 1002
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

#define NETDGM_PORT 138
#define NETDGM_DU  0x10
#define NETDGM_DG  0x11
#define NETDGM_BC  0x12
#define NETDGM_ER  0x13
#define NETDGM_QR  0x14
#define NETDGM_QRP 0x15
#define NETDGM_QRN 0x16

YC_SCANNER_PROTOTYPE(netdgmplugin_LTX_ycNetDgmScanScan);

/**
 * netdgmplugin_LTX_ycNetDgmScanScan
 *
 * the scanner for recognizing NetBios Datagram Service Packets
 *
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
 * @return NETDGM_PORT for netbios-dgm packets
 *         otherwise 0
 */
uint16_t
netdgmplugin_LTX_ycNetDgmScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t  msgtype;
    uint8_t  flags;
    uint16_t sp;

    /* Gh0st must have payload in both directions */
    if (payloadSize < 11) {
        return 0;
    }

    /* must be UDP */
    if (flow->key.proto != YF_PROTO_UDP) {
        return 0;
    }

    /* NetBIOS supports IPv4 */
    if (flow->key.version != 4) {
        return 0;
    }
    msgtype = payload[0];
    flags = payload[1] & 0xF0;
    sp = ntohs(*(uint16_t *)(payload + 8));

    if (sp != flow->key.sp) {
        if (sp != NETDGM_PORT) {
            return 0;
        }
    }

    /* Bits 0-3 must be 0 - Reserved */
    if (flags != 0) {
        return 0;
    }

    switch (msgtype) {
      case NETDGM_DU:
      case NETDGM_DG:
      case NETDGM_BC:
        /* 14 for header + 32 srcname, 32 dst name */
        if (payloadSize < 78) {
            return 0;
        }
        break;
      case NETDGM_ER:
        {
            uint8_t errcode = payload[10];
            if (errcode < 0x82 || errcode > 0x84) {
                return 0;
            }
            break;
        }
      case NETDGM_QR:
      case NETDGM_QRP:
      case NETDGM_QRN:
        /* 10 for header + 32 for dst name */
        if (payloadSize < 42) {
            return 0;
        }
        break;
      default:
        return 0;
    }

    return NETDGM_PORT;
}
