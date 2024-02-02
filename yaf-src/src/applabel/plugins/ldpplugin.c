/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ldpplugin.c
 *
 *
 *  This recognizes Label Distribution Protocol (LDP) Packets
 *  see http://www.ietf.org/rfc/rfc3036 for more info
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


#define LDP_PORT_NUMBER  646
#define LDP_VERSION 1

YC_SCANNER_PROTOTYPE(ldpplugin_LTX_ycLdpScanScan);

/**
 * ldpplugin_LTX_ycLdpScanScan
 *
 * the scanner for recognizing LDP packets
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
 * @return LDP_PORT_NUMBER for LDP packets,
 *         otherwise 0
 */
uint16_t
ldpplugin_LTX_ycLdpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0;
    uint16_t     version;
    uint16_t     length;
    uint32_t     id;

    /* Only do decode if MPLS is enabled */
#ifndef YAF_MPLS
    return 0;
#endif

    /* BGP header is fixed - has to be at least 10 */
    if (payloadSize < 10) {
        return 0;
    }

    version = g_ntohs(*(uint16_t *)payload);
    if (version != LDP_VERSION) {
        return 0;
    }

    offset += 2;

    length = g_ntohs(*(uint16_t *)(payload + offset));

    if (length > 4096) {
        return 0;
    }

    if (length < 6) {
        return 0;
    }

    offset += 2;

    id = g_ntohl(*(uint32_t *)(payload + offset));

    /* id should be the same as src ip */

    if (id != flow->key.addr.v4.sip) {
        return 0;
    }

    offset += 4;

    /* Last 2 bytes are 0 */

    if (*(payload + offset) != 0) {
        return 0;
    }

    offset++;

    if (*(payload + offset) != 0) {
        return 0;
    }

    return LDP_PORT_NUMBER;
}
