/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  aolplugin.c
 *  This tries to recognize the AOL instant Messenger (OSCAR) protocol
 *  http://en.wikipedia.org/wiki/OSCAR_protocol
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

#define AIM_PORT_NUMBER 5190

YC_SCANNER_PROTOTYPE(aolplugin_LTX_ycAolScanScan);

/* Local Prototypes */

static uint16_t
getTLVID(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t        offset);


/**
 * aolplugin_LTX_ycAolScanScan
 *
 * the scanner for recognizing aol instant messenger/ICQ  packets
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
 * @return aim_port_number
 *         otherwise 0
 */
uint16_t
aolplugin_LTX_ycAolScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    gboolean snac = FALSE;
    uint16_t flap_seq_number = 0;
    uint32_t offset = 0;
    uint16_t flap_data_size = 0;
    uint8_t  class;
    uint16_t tlv_id;

    if (payloadSize < 6) {
        return 0;
    }

    if (*(payload + offset) != 0x2a) {
        return 0;
    }
    offset++;

    class = *(payload + offset);
    if ((class == 0) || (class > 5)) {
        return 0;
    }

    if (class == 2) {
        /* SNAC data */
        snac = TRUE;
    }

    offset++;
    /* seq number */

    flap_seq_number = ntohs(*(uint16_t *)(payload + offset));
    if (flap_seq_number > 0xEFFF) {
        return 0;
    }

    offset += 2;
    /* size of data */
    flap_data_size = ntohs(*(uint16_t *)(payload + offset));
    offset += 2;

    if (snac) {
        uint16_t family;
        uint16_t family_sub_id;

        if ((size_t)offset + 4 > payloadSize) {
            return 0;
        }

        family = ntohs(*(uint16_t *)(payload + offset));
        if (family > 0x17 && family != 0x85) {
            return 0;
        }

        offset += 2;

        family_sub_id = ntohs(*(uint16_t *)(payload + offset));
        /* there are more detailed specifications on what family id and
         * family_sub_id can be paired, but too many to efficiently check
         * so we will generalize */
        if (family_sub_id > 0x21) {
            return 0;
        }

        offset += 8; /* 2 for SNAC flags, 4 for request ID */

        if (offset > payloadSize) {
            return 0;
        }
    }

    if (class == 1) {
        uint32_t protocol;

        /* protocol version */
        if ((size_t)offset + 4 > payloadSize) {
            return 0;
        }

        protocol = ntohl(*(uint32_t *)(payload + offset));

        if (protocol > 1) {
            return 0;
        }

        offset += 4;
        if (flap_data_size != 4) {
            tlv_id = getTLVID(payload, payloadSize, offset);
            if (tlv_id != 6 && tlv_id != 7 && tlv_id != 8 && tlv_id != 3 &&
                tlv_id != 148 && tlv_id != 74)
            {
                return 0;
            }
            offset += 2;
        }
    }

    return AIM_PORT_NUMBER;
}


static uint16_t
getTLVID(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t        offset)
{
    uint16_t tlvid;

    if ((size_t)offset + 2 > payloadSize) {
        return 0;
    }

    tlvid = ntohs(*(uint16_t *)(payload + offset));

    return tlvid;
}
