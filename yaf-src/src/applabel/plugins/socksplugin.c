/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  tlsplugin.c
 *
 *  This recognizes SOCKS protocol packets
 *  http://en.wikipedia.org/wiki/SOCKS
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

#define SOCKS_PORT_NUMBER  1080

YC_SCANNER_PROTOTYPE(socksplugin_LTX_ycSocksScanScan);


/**
 * socksplugin_LTX_ycSocksScanScan
 *
 * the scanner for recognizing SOCKS packets
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
 * @return socks_port_number
 *         otherwise 0
 */
uint16_t
socksplugin_LTX_ycSocksScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0;
    uint32_t     socks_ip;
    unsigned int num_auth_methods = 0;
    uint8_t      auth_method;
    unsigned int loop;

    if (payloadSize < 2) {
        return 0;
    }

    if (payload[0] == 4) {
        if (payload[1] != 1 && payload[1] != 2) {
            return 0;
        }

        offset += 2;

        if ((size_t)offset + 6 > payloadSize) {
            return 0;
        }

        /*socks_port = ntohs(*(uint16_t *)(payload + offset));*/
        offset += 2;
        socks_ip = ntohl(*(uint32_t *)(payload + offset));

        if (socks_ip != flow->key.addr.v4.dip) {
            if (socks_ip > 0xFF) {
                return 0;
            }
        }
    } else if (payload[0] == 5) {
        num_auth_methods = payload[1];

        if ((num_auth_methods + 2) > payloadSize) {
            return 0;
        }
        offset += 2;
        for (loop = 0; loop < num_auth_methods; loop++) {
            auth_method = *(payload + offset + loop);
            if (auth_method == 4 || auth_method > 9) {
                /* not assigned */
                return 0;
            }
        }
        offset += loop;

        if (offset == payloadSize) {
            return SOCKS_PORT_NUMBER;
        }

        if ((*(payload + offset) != 5)) {
            return 0;
        }
    } else {
        return 0;
    }
    return SOCKS_PORT_NUMBER;
}
