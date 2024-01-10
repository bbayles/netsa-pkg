/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  bgpplugin.c
 *  This recognizes Border Gateway Protocol (BGP) Packets
 *  BGP is an inter-Autonomous System routing protocol.
 *  It's primary function is to exchange network reachability
 *  infomration with other BGP systems.
 *  see http://www.ietf.org/rfc/rfc4271 for more info
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


#define BGP_PORT_NUMBER  179
#define BGP_MARKER 0xff

YC_SCANNER_PROTOTYPE(bgpplugin_LTX_ycBgpScanScan);

/**
 * bgpplugin_LTX_ycBgpScanScan
 *
 * the scanner for recognizing BGP packets
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
 * @return BGP_PORT_NUMBER for BGP packets,
 *         otherwise 0
 */
uint16_t
bgpplugin_LTX_ycBgpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset;
    uint16_t     bgp_len;
    uint8_t      bgp_type;

    /* BGP header is fixed - has to be at least 19 bytes long... */
    if (payloadSize < 19) {
        return 0;
    }

    for (offset = 0; offset < 16; offset++) {
        if (*(payload + offset) != BGP_MARKER) {
            return 0;
        }
    }

    bgp_len = ntohs(*(uint16_t *)(payload + offset));
    if (bgp_len < 19 || bgp_len > 4096) {
        return 0;
    }

    offset += 2;
    bgp_type = *(payload + offset);

    if (bgp_type == 0 || bgp_type > 4) {
        return 0;
    }

    return BGP_PORT_NUMBER;
}
