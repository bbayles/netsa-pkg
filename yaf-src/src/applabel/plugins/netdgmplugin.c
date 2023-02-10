/**
 * @file netdgmplugin.c
 *
 * This attempts to identify NetBIOS Datagram Service Packets.
 * Typically UDP Port 138
 * RFC 1002
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2015-2023 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 *
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
