/**
 * @file aolplugin.c
 *
 *
 * This tries to recognize the AOL instant Messenger (OSCAR) protocol
 * http://en.wikipedia.org/wiki/OSCAR_protocol
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2023 Carnegie Mellon University. All Rights Reserved.
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
