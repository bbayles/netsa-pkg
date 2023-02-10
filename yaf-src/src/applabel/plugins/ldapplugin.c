/**
 * @file ldapplugin.c
 *
 * This tries to recognize the ldap protocol.
 * Decoder based on RFC 4511.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2014-2023 Carnegie Mellon University. All Rights Reserved.
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

#define LDAP_PORT_NUMBER 389

YC_SCANNER_PROTOTYPE(ldapplugin_LTX_ycLdapScanScan);

typedef struct asn_tlv_st {
    uint8_t   class    : 2;
    uint8_t   p_c      : 1;
    uint8_t   tag      : 5;

    uint8_t   longform : 1;
    uint8_t   length   : 7;
} asn_tlv_t;



/* Local Prototypes */
static
void
ldapDecodeTLV(
    const uint8_t  *payload,
    asn_tlv_t      *tlv);

/**
 * ldapplugin_LTX_ycLdapScanScan
 *
 * the scanner for recognizing ldap packets
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
 * @return ldap_port_number
 *         otherwise 0
 */
uint16_t
ldapplugin_LTX_ycLdapScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0;
    uint16_t     min_length = 7;
    unsigned int i;
    uint64_t     num_packets = val->pkt;
    size_t       pkt_length = payloadSize;
    asn_tlv_t    tlv;

    /* must have SEQUENCE Tag, Integer TAG for Message ID, protocol Op Tag */
    if (payloadSize < min_length) {
        return 0;
    }

    if (*payload != 0x30) {
        return 0;
    }

    if (num_packets > YAF_MAX_PKT_BOUNDARY) {
        num_packets = YAF_MAX_PKT_BOUNDARY;
    }

    for (i = 0; i < num_packets; ++i) {
        if (val->paybounds[i]) {
            pkt_length = val->paybounds[i];
            if (pkt_length > payloadSize) {
                pkt_length = payloadSize;
            }
            break;
        }
    }

    ldapDecodeTLV(payload, &tlv);

    offset += 2;

    if (tlv.longform) {
        offset += tlv.length;
        min_length += tlv.length;
        if (pkt_length < min_length) {
            return 0;
        }
    }

    ldapDecodeTLV((payload + offset), &tlv);

    if (tlv.tag != 0x02) {
        return 0;
    }

    if (tlv.length > 4) {
        /* MAX INTEGER is 2^31-1 */
        return 0;
    }

    offset += 2 + tlv.length;

    /* I already count 1 in the minimum length so subtract that */
    min_length += tlv.length - 1;

    if (pkt_length < min_length) {
        return 0;
    }

    ldapDecodeTLV((payload + offset), &tlv);

    if (tlv.class != 1) {
        /* must be Application Class: Bit 8 = 0, Bit 7 = 1 */
        return 0;
    }

    if (tlv.tag > 25) {
        /* valid types are 0-25 */
        return 0;
    }

    if (tlv.longform) {
        /* if this is a long packet, it's close enough */
        return LDAP_PORT_NUMBER;
    }

    offset += 2 + tlv.length;

    min_length += tlv.length;

    if (pkt_length < min_length) {
        return 0;
    }

    /* response should have a resultCode */
    if (tlv.tag % 2) {
        min_length += 2;
        if (pkt_length < min_length) {
            return 0;
        }

        if (*(payload + offset) != 0x02) {
            return 0;
        }
        /* could test resultCode 0-123, 4096 */
    }

    return LDAP_PORT_NUMBER;
}


/**
 * ldapDecodeTLV
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into an ASN.1 structure
 *
 * @param payload a network stream capture
 * @param asn_tlv_t asn.1 tlv struct
 *
 *
 */
static
void
ldapDecodeTLV(
    const uint8_t  *payload,
    asn_tlv_t      *tlv)
{
    uint8_t byte1 = *payload;
    uint8_t byte2 = *(payload + 1);

    tlv->class = (byte1 & 0xD0) >> 6;
    tlv->p_c = (byte1 & 0x20) >> 5;
    tlv->tag = (byte1 & 0x1F);

    tlv->longform = (byte2 & 0x80) >> 7;
    tlv->length = (byte2 & 0x7F);

    /*g_debug("tlv->class: %d, tlv->pc: %d, tlv->tag: %d",
     *      tlv->class, tlv->p_c, tlv->tag);
     *      g_debug("tlv->longform: %d, tlv->length %d", tlv->longform,
     * tlv->length);*/
}
