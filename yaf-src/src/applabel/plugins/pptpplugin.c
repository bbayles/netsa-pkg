/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  pptpplugin.c
 *
 *  this is a protocol classifier for the point-to-point tunneling
 *  protocol (PPTP)
 *
 *  PPTPis a protocol which allows the Point to Point Protocol (PPP) to be
 *  tunneled through an IP network.  PPTP describes a new vehichle for
 *  carrying PPP.
 *
 *  rfc 2637  href="http://www.ietf.org/rfc/rfc2637.txt"
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Ecoff
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

typedef struct pptpProtoHeader_st {
    uint16_t   length;
    uint16_t   msgType;
    uint32_t   magicCookie;
    uint16_t   controlMsgType;
    uint16_t   reserved;
} pptpProtoHeader_t;

#define PPTP_PORT_NUMBER 1723
#define MAGIC_COOKIE 0x1A2B3C4D

YC_SCANNER_PROTOTYPE(pptpplugin_LTX_ycPPTPScanScan);

/**
 * pptpplugin_LTX_ycPPTPScan
 *
 * returns PPTP_PORT_NUMBER if the passed in payload matches
 * a point to point tunneling protocol packet
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
pptpplugin_LTX_ycPPTPScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    pptpProtoHeader_t *pptpHeader;
    uint16_t           pptpLength;
    uint16_t           pptpMsgType;
    uint32_t           pptpMagicCookie;
    uint16_t           pptpControlType;
    uint16_t           pptpReserved;

    if (0 == payloadSize) {
        return 0;
    }

    if (payloadSize < sizeof(pptpProtoHeader_t)) {
        /*g_debug("PPTP exiting line 100");*/
        return 0;
    }

    pptpHeader = (pptpProtoHeader_t *)payload;

    pptpLength = pptpHeader->length;
    pptpMsgType = pptpHeader->msgType;
    pptpMagicCookie = pptpHeader->magicCookie;
    pptpControlType = pptpHeader->controlMsgType;
    pptpReserved = pptpHeader->reserved;

    pptpLength = ntohs(pptpLength);
    pptpMsgType = ntohs(pptpMsgType);
    pptpMagicCookie = ntohl(pptpMagicCookie);
    pptpControlType = ntohs(pptpControlType);
    pptpReserved = ntohs(pptpReserved);

    /*debug*/
    /*g_debug("PPTP Length: %d", pptpLength);
     * g_debug("PPTP Length: %d", pptpMsgType);
     * g_debug("PPTP Length: %d", pptpMagicCookie);
     * g_debug("PPTP Length: %d", pptpControlType);
     * g_debug("PPTP Length: %d", pptpReserved);
     */

    if (pptpLength <= 0) {
        /*  g_debug("PPTP exiting line 105");*/
        return 0;
    }

    if (pptpReserved != 0) {
        /*g_debug("PPTP exiting line 110");*/
        return 0;
    }

    if (pptpMagicCookie != MAGIC_COOKIE) {
        /*g_debug("PPTP exiting line 115");*/
        return 0;
    }

    if (pptpMsgType != 1 && pptpMsgType != 2) {
        /*g_debug("PPTP exiting line 120");*/
        return 0;
    }

    if (pptpControlType == 0 || pptpControlType > 15) {
        /*printf("PPTP  exiting line 128");*/
        return 0;
    }

    return PPTP_PORT_NUMBER;
}
