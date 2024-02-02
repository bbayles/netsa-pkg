/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  palplugin.c
 *
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


#define PAL1_STARTS 0x18
#define PKT_SIZE 21
#define PAL2_STARTS 0x0A
#define PAL2_ENDS 0xC3E7

YC_SCANNER_PROTOTYPE(palplugin_LTX_ycPalScanScan);

/**
 * palplugin_LTX_ycPalScanScan
 *
 * the scanner for recognizing Palevo.
 * Analysis: http://walisecurity.wordpress.com/
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
 * @return PAL_PORT_NUMBER for Palevo packets,
 *         otherwise 0
 */
uint16_t
palplugin_LTX_ycPalScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint16_t ends;

    /* must be at least 21 bytes */
    if (val->paylen < PKT_SIZE) {
        return 0;
    }

    /* must be UDP */
    if (flow->key.proto != YF_PROTO_UDP) {
        return 0;
    }

    /* first packet must be 21 bytes long */
    if ((val->pkt == 1) && (val->paylen != PKT_SIZE)) {
        return 0;
    } else if ((val->pkt > 1) && (val->paybounds[1] != PKT_SIZE)) {
        return 0;
    }

    if (val->payload[0] == PAL1_STARTS) {
        ends = ntohs(*(uint16_t *)(val->payload + 19));

        if (ends != 0) {
            return 0;
        }

        if (val->payload[8] != val->payload[9]) {
            return 0;
        }

        if (val->payload[12] != val->payload[13]) {
            return 0;
        }

        if (val->payload[16] != val->payload[17]) {
            return 0;
        }

        return 1;
    } else if (val->payload[0] == PAL2_STARTS) {
        ends = ntohs(*(uint16_t *)(val->payload + 19));

        if (ends != PAL2_ENDS) {
            return 0;
        }

        return 1;
    }

    return 0;
}
