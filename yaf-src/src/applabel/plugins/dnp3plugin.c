/**
 * @file dnp3plugin.c
 *
 * This tries to recognize the DNP3 protocol, a SCADA protocol.
 * Decoder based on reference:
 * http://www05.abb.com/global/scot/scot229.nsf/veritydisplay/\
 * 65b4a3780db3b3f3c2256e68003dffe6/$file/rec523_dnpprotmanend.pdf
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

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define DNP_PORT_NUMBER 20000
#define DNP_START_BYTES 0x0564
#define DNP3_OBJ_QUAL_INDEX(x) ((x & 0x70) >> 4)
#define DNP3_OBJ_QUAL_CODE(x) (x & 0x0F)
#define DNP3_DLL_FUNCTION(x) (x & 0x0F)
#define DNP_BLOCK_SIZE 16
#define DNP_CLIENT 0
#define DNP_SERVER 1

#define DNP3_NO_INDEX       0x00
#define DNP3_1OCT_INDEX     0x01
#define DNP3_2OCT_INDEX     0x02
#define DNP3_4OCT_INDEX     0x03
#define DNP3_1SZ_INDEX      0x04
#define DNP3_2SZ_INDEX      0x05
#define DNP3_4SZ_INDEX      0x06
#define DNP3_INDEX_RESERVED 0x07

/* Qualifier codes */
#define DNP3_8BIT_IND       0x00
#define DNP3_16BIT_IND      0x01
#define DNP3_32BIT_IND      0x02
#define DNP3_8BIT_ADDRESS   0x03
#define DNP3_16BIT_ADDRESS  0x04
#define DNP3_32BIT_ADDRESS  0x05
#define DNP3_NO_RANGE       0x06
#define DNP3_8BIT_FIELD     0x07
#define DNP3_16BIT_FIELD    0x08
#define DNP3_32BIT_FIELD    0x09
#define DNP3_VARIABLE       0x0B

#define DNP_SRC_ADDRESS     281
#define DNP_DEST_ADDRESS    282
#define DNP_FUNCTION        283
#define DNP_OBJECT          284
#define DNP_PLACEHOLDER     15

YC_SCANNER_PROTOTYPE(dnp3plugin_LTX_ycDnpScanScan);

typedef struct ycDNPMessageHeader_st {
    /* Data Link Layer */
    uint16_t   start_bytes;    /*0x0564*/
    uint8_t    length;
    /* control */
    uint8_t    dir     : 1;
    uint8_t    prm     : 1;
    uint8_t    fcb     : 1;
    uint8_t    fcv     : 1;
    uint8_t    control : 4;
    uint16_t   destination;
    uint16_t   source;
    uint16_t   crc;

    /* Transport Layer */
    uint8_t    transport;
    /* Application Layer */
    uint8_t    app_control;
    uint8_t    app_function;
    /* responses only */
    uint16_t   indications;
} ycDNPMessageHeader_t;



/* Local Prototypes */
static
void
ycDNPScanRebuildHeader(
    const uint8_t         *payload,
    ycDNPMessageHeader_t  *header);


/**
 * dnp3plugin_LTX_ycDnpScanScan
 *
 * the scanner for recognizing DNP3 packets
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
dnp3plugin_LTX_ycDnpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    ycDNPMessageHeader_t header;
    /* int                  direction; */
    uint32_t             offset = 0, function_offset = 0;
    uint32_t             total_offset = 0;
    uint8_t              function = 0;
    /* uint8_t              group, variation, prefix, qual_code; */
    int     app_header_len = 0, packets = 0;
    int     packet_len, packet_rem;
    /*    uint32_t            quantity = 0;*/
#if YAF_ENABLE_HOOKS
    /* The DNP3 length in the header is a single byte but that length does not
     * include the CRCs. However, crc_buf holds the data once the CRCs have
     * been removed, so we can safely use a max of 255. (Actual data max is
     * 250 since the header length includes the link control (1 byte) and
     * destination and source addresses (each 2 bytes)). */
    uint8_t crc_buf[255];
    size_t  crc_buf_len;
#endif  /* #if YAF_ENABLE_HOOKS */

    /* direction is determined by TCP session */
    /* There is a direction and primary bit in the Control flags but
     * it does not determine request vs response */
    if (val == &(flow->val)) {
        /* direction = DNP_CLIENT; */
        app_header_len = 2;
    } else {
        /* direction = DNP_SERVER; */
        app_header_len = 4;
    }

    while (offset < payloadSize) {
        /* only go around once for just applabeling */
#ifndef YAF_ENABLE_HOOKS
        if (packets > 0) {
            goto end;
        }
#endif

        offset = total_offset;

        /*must have start(2),length(1), control(1), dest(2), src(2), crc(2)*/
        if (((size_t)offset + 10) > payloadSize) {
            goto end;
        }

        ycDNPScanRebuildHeader((payload + offset), &header);

        header.start_bytes = ntohs(*((uint16_t *)(payload + offset)));

        /* DNP starts with 0x0564 */
        if (header.start_bytes != DNP_START_BYTES) {
            goto end;
        }

        if (header.prm) {
            if (header.control > 4 && header.control != 9) {
                goto end;
            }
        } else {
            if (header.control > 1) {
                if ((header.control != 11) &&
                    (header.control != 14) && (header.control != 15))
                {
                    goto end;
                }
            }
        }

        /* min length is 5 which indicates there is only a header
         * which includes control, dest, and src. CRC fields are
         * not included in the count */
        if (header.length < 5) {
            goto end;
        }

        /* Length only counts non-CRC octets. Each CRC is 2 octets.
         * There is one after the header and then one for each 16 octets
         * of user data, plus a CRC for the extra */
        packet_len = header.length + 4;

        /* get past the header */
        offset += 10;
        packet_rem = packet_len - 10;

        if (packet_rem <= 0) {
            packets++;
            total_offset += packet_len + 1;
            continue;
        }

        /* have room for transport and application layer headers?
         * if it's the first packet we should and if for some reason we don't,
         * it's not DNP */
        if ( ((size_t)total_offset + offset + packet_rem) > payloadSize) {
            goto end;
        }

        /* transport layer */
        header.transport = *(payload + offset);

        packet_rem--;

        if (packet_rem <= 0) {
            packets++;
            total_offset += packet_len + 1;
            continue;
        }

        /* skip past transport & application control */
        offset += 2;

        function_offset = offset;
        function = *(payload + offset);

        if (function > 23) {
            if (function != 129 && function != 130) {
                goto end;
            }
        } else if (function > 6 && (function < 13)) {
            goto end;
        }

        /* REGULAR EXPRESSIONS START HERE! */

        offset += app_header_len - 1; /* -1 for application control */
        packet_rem -= app_header_len;

        /* now we're at Data Link Layer which contains objects.
         * object is a 2 octet field that identifies the
         * class and variation of object */

        if (packet_rem <= 0) {
            packets++;
            /* 2 for CRC, 1 to move to next packet */
            total_offset += packet_len + 3;
            continue;
        }

        /* group = *(payload + offset); */
        /* variation = *(payload + offset + 1); */

        offset += 2;

        /* The Qualifier field specifies the Range field */
        /* prefix = DNP3_OBJ_QUAL_INDEX(*(payload + offset)); */
        /* qual_code = DNP3_OBJ_QUAL_CODE(*(payload + offset)); */

        offset++;

        /* For a Request, The Index (prefix) bit are only valid when Qualifier
         * Code (qual_code) is 11.  These bits indicate the size, in
         * octets, of each entry in the Range Field. */

        /*
         * if (direction == DNP_CLIENT && qual_code == 11) {
         *
         *  switch (prefix) {
         *    case DNP3_NO_INDEX:
         *      index = 0;
         *      return 0;
         *    case DNP3_1OCT_INDEX:
         *      index = 1;
         *      offset++;
         *      break;
         *    case DNP3_2OCT_INDEX:
         *      index = 2;
         *      offset+=2;
         *      break;
         *    case DNP3_4OCT_INDEX:
         *      index = 4;
         *      offset+=4;
         *      break;
         *    default:
         *      return 0;
         *  }
         *
         * } else {
         *  switch (prefix) {
         *    case DNP3_NO_INDEX:
         *      index = 0;
         *      break;
         *    case DNP3_1OCT_INDEX:
         *    case DNP3_1SZ_INDEX:
         *      index = 1;
         *      offset++;
         *      break;
         *    case DNP3_2OCT_INDEX:
         *    case DNP3_2SZ_INDEX:
         *      index = 2;
         *      offset+=2;
         *      break;
         *    case DNP3_4OCT_INDEX:
         *    case DNP3_4SZ_INDEX:
         *      index = 4;
         *      offset+=4;
         *      break;
         *    default:
         *      return 0;
         *  }
         * }
         *  /* 0 - 5 describes points in sequence */
        /* 7 - 9 describe unrelated points */
        /* 11 describes points that need an object identifier */
        /*
         * switch(qual_code) {
         * case DNP3_8BIT_IND:
         * case DNP3_8BIT_ADDRESS:
         *  offset+=2;
         *  break;
         * case DNP3_16BIT_ADDRESS:
         * case DNP3_16BIT_IND:
         *  offset+=4;
         *  break;
         * case DNP3_32BIT_IND:
         * case DNP3_32BIT_ADDRESS:
         *  offset += 8;
         *  break;
         * case DNP3_NO_RANGE:
         *  break;
         * case DNP3_8BIT_FIELD:
         *  {
         *      quantity = *(payload + offset);
         *      offset += 1 + (index * quantity);
         *      break;
         *  }
         * case DNP3_16BIT_FIELD:
         *  {
         *      quantity = ntohs(*((uint16_t *)(payload + offset)));
         *      offset += 2 + (index * quantity);
         *      break;
         *  }
         * case DNP3_32BIT_FIELD:
         *  {
         *      quantity = ntohl(*((uint32_t *)(payload + offset)));
         *      offset += 4 + (index * quantity);
         *      break;
         *  }
         * case DNP3_VARIABLE:
         *  {
         *      if (index == 1) {
         *          uint8_t size = *(payload + offset + 1);
         *          quantity = *(payload + offset);
         *          offset += 2 + (quantity * size);
         *      } else if (index == 2) {
         *          uint16_t size=ntohs(*((uint16_t *)(payload + offset + 2)));
         *          quantity = ntohs(*((uint16_t *)(payload + offset)));
         *          offset += 4 + (quantity * size);
         *      } else {
         *          uint32_t size=ntohl(*((uint32_t *)(payload + offset + 4)));
         *          quantity = ntohl(*((uint32_t *)(payload + offset)));
         *          offset += 8 + (quantity * size);
         *      }
         *      break;
         *  }
         * default:
         *  return 0;
         * }
         */
        /* Figure out how much to account for CRCs and add it to the total
         * packet length */
        packet_len += ((packet_rem / 16) * 2) + 2;

#if YAF_ENABLE_HOOKS
        /* 3 for DLL header  - is there any user data? */
        if (packet_rem > 3) {
            yfHookScanPayload(flow, payload, 2, NULL, 4,
                              DNP_DEST_ADDRESS, DNP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, 2, NULL, 6,
                              DNP_SRC_ADDRESS, DNP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, 1, NULL, function_offset,
                              DNP_FUNCTION, DNP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, (packet_len - 10), NULL,
                              (total_offset + 10), DNP_PLACEHOLDER,
                              DNP_PORT_NUMBER);
            crc_buf_len = sizeof(crc_buf);
            yfRemoveCRC((payload + total_offset + 10), (packet_len - 10),
                        crc_buf, &crc_buf_len, DNP_BLOCK_SIZE, 2);
            /* offset is 2, past transport & application control */
            yfHookScanPayload(flow, crc_buf, crc_buf_len, NULL,
                              2, DNP_OBJECT, DNP_PORT_NUMBER);
        }
#endif /* if YAF_ENABLE_HOOKS */
        total_offset += packet_len + 1;
        packets++;
    }

  end:
    if (packets) {
        return DNP_PORT_NUMBER;
    }

    return 0;
}


/**
 * ycDNPScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into the DNP structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dnp message
 *        header structure
 *
 *
 */
static
void
ycDNPScanRebuildHeader(
    const uint8_t         *payload,
    ycDNPMessageHeader_t  *header)
{
    uint8_t bitmasks = *(payload + 3);

    header->start_bytes = ntohs(*((uint16_t *)(payload)));
    header->length = *(payload + 2);
    header->dir = (bitmasks & 0xE0) ? 1 : 0;
    header->prm = (bitmasks & 0xD0) ? 1 : 0;
    header->fcb = (bitmasks & 0xB0) ? 1 : 0;
    header->fcv = (bitmasks & 0x70) ? 1 : 0;

    header->control = (bitmasks & 0x0F);

    header->destination = *((uint16_t *)(payload + 4));
    header->source = *((uint16_t *)(payload + 6));

    /*    g_debug("header->start_bytes %d", header->start_bytes);
     * g_debug("header->length %d", header->length);
     * g_debug("header->dir %d", header->dir);
     * g_debug("header->prm %d", header->prm);
     * g_debug("header->fcb %d", header->fcb);
     * g_debug("header->fcv %d", header->fcv);
     * g_debug("header->control %d", header->control);
     * g_debug("header->destination %d", header->destination);
     * g_debug("header->source %d", header->source);*/
}
