/**
 * @file modbusplugin.c
 *
 * This tries to recognize the Modbus protocol, a SCADA protocol.
 * Decoder based on reference:
 * http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
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

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define MODBUS_PORT_NUMBER 502
#define MODBUS_OBJECT 285
#define MODBUS_EXCEPTION 0x80

YC_SCANNER_PROTOTYPE(modbusplugin_LTX_ycModbusScanScan);

typedef struct ycMBAPMessageHeader_st {
    uint16_t   trans_id;
    uint16_t   protocol;
    uint16_t   length;
    uint8_t    unit_id;
} ycMBAPMessageHeader_t;


/* Local Prototypes */
static
void
ycMBAPScanRebuildHeader(
    const uint8_t          *payload,
    ycMBAPMessageHeader_t  *header);

/**
 * modbusplugin_LTX_ycModbusScanScan
 *
 * the scanner for recognizing modbus packets
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
 * @return dnp_port_number
 *         otherwise 0
 */
uint16_t
modbusplugin_LTX_ycModbusScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0, total_offset = 0;
    uint64_t     num_packets = val->pkt;
    uint8_t      function, exception;
    unsigned int packets = 0;
    unsigned int i;
    size_t       pkt_length = 0;
    ycMBAPMessageHeader_t header;

    /* must be TCP */
    if (flow->key.proto != 6) {
        return 0;
    }

    /* must have MBAP Header and function and data */
    if (payloadSize < 9) {
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

    if (pkt_length > 260) {
        /* max pkt length of a MODBUS PDU is 260 bytes */
        return 0;
    }

    while (offset < payloadSize) {
        exception = 0;
#ifndef YAF_ENABLE_HOOKS
        if (packets > 0) {
            goto end;
        }
#endif
        offset = total_offset;

        if (((size_t)offset + 9) > payloadSize) {
            goto end;
        }

        /* check for MBAP (Modbus Application Protocol) header */
        ycMBAPScanRebuildHeader((payload + offset), &header);

        if (header.trans_id == pkt_length) {
            /* this is prob Oracle TNS protocol - first 2 bytes are length */
            return 0;
        }

        if (!packets) {
            if ((header.trans_id & 0xFF80) == 0x3080) {
                unsigned int len_octets = header.trans_id & 0x7F;
                /* this might be LDAP (ASN.1 SEQUENCE) long form */
                if ((len_octets + 2) < payloadSize) {
                    if (*(payload + len_octets + 2) == 0x02) {
                        /* INTEGER TAG NUMBER FOR RESPONSE/msgID */
                        return 0;
                    }
                }
            }
        }

        offset += 7;

        /* protocol is always 0 */

        if (header.protocol != 0) {
            goto end;
        }

        if (header.length < 3) {
            goto end;
        }

        if (((size_t)offset + header.length - 1) > payloadSize) {
            goto end;
        }

        if (!packets && (((size_t)header.length + 6) != pkt_length)) {
            /* 6 byte header + length */
            return 0;
        }

        function = *(payload + offset);

        /* 1-65, 72-100, 110-127 are public codes, rest are user-defined */
        if (function > 127) {
            exception = *(payload + offset + 1);
            /* is this is an exception to the query? */
            if (exception == 0 || exception > 12) {
                goto end;
            }
        }

#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, (offset + header.length - 1), NULL,
                          offset, MODBUS_OBJECT, MODBUS_PORT_NUMBER);
#endif
        /* length plus transaction id, protocol id, and length field */
        total_offset += header.length + 6;
        packets++;
    }

  end:

    if (packets) {
        return MODBUS_PORT_NUMBER;
    }

    return 0;
}


/**
 * ycMBAPScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into the MBAP header
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dnp message
 *        header structure
 *
 *
 */
static
void
ycMBAPScanRebuildHeader(
    const uint8_t          *payload,
    ycMBAPMessageHeader_t  *header)
{
    uint16_t offset = 0;

    header->trans_id = ntohs(*((uint16_t *)(payload)));
    offset += 2;
    header->protocol = ntohs(*((uint16_t *)(payload + offset)));
    offset += 2;
    header->length = ntohs(*((uint16_t *)(payload + offset)));
    offset += 2;
    header->unit_id = *(payload + offset);

    /*    g_debug("header->trans_id %d", header->trans_id);
     * g_debug("header->proto_id %d", header->protocol);
     * g_debug("header->length %d", header->length);
     * g_debug("header->unit_id %d", header->unit_id);*/
}
