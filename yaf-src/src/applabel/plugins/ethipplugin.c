/**
 * @file ethernetipplugin.c
 *
 * This tries to recognize the Ethernet/IP protocol, a protocol often
 * used for SCADA systems.
 * Decoder based on reference:
 * http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf
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

#define ENIP_PORT_NUMBER 44818
#define ENIP_OBJECT 286

YC_SCANNER_PROTOTYPE(ethipplugin_LTX_ycEthIPScanScan);

typedef struct ycEthIPMessageHeader_st {
    uint16_t   command;
    uint16_t   length;
    uint32_t   session;
    uint32_t   status;
    uint64_t   sender;
    uint32_t   options;
} ycEthIPMessageHeader_t;


/* Local Prototypes */
static
void
ycEthIPScanRebuildHeader(
    const uint8_t           *payload,
    ycEthIPMessageHeader_t  *header);

/**
 * ethipplugin_LTX_ycEthIPScanScan
 *
 * the scanner for recognizing Ethernet/IP packets
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
 * @return ethip_port_number
 *         otherwise 0
 */
uint16_t
ethipplugin_LTX_ycEthIPScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t offset = 0, total_offset = 0;
    uint16_t temp16 = 0;
    uint32_t temp32 = 0;
    int      packets = 0;
    gboolean legacy = FALSE;
    ycEthIPMessageHeader_t header;

    while (offset < payloadSize) {
#ifndef YAF_ENABLE_HOOKS
        if (packets > 0) {
            goto end;
        }
#endif
        offset = total_offset;

        if (((size_t)offset + 24) > payloadSize) {
            /* must have MBAP Header and function and data */
            goto end;
        }

        /* check for MBAP (Modbus Application Protocol) header */
        ycEthIPScanRebuildHeader((payload + offset), &header);

        offset += 24;

        if (header.options != 0) {
            goto end;
        }

        switch (header.status) {
          case 0x0000:
          /* success */
          case 0x0001:
          /* invalid or unsupported encapsulation command */
          case 0x0002:
          /* insufficient memory resources */
          case 0x0003:
          /* poorly formed or incorrect data */
          case 0x0064:
          /* invalid session handle */
          case 0x0065:
          /* invalid length */
          case 0x0069:
            /* unspported encapsulation protocol revision */
            break;
          default:
            goto end;
        }

        switch (header.command) {
          case 0x0000:
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            /*NOP*/
            if (header.status != 0) {
                goto end;
            }
            if (header.length == 0 && header.session == 0 &&
                header.sender == 0)
            {
                /* don't allow all 0 packets to go through -
                 * it has to contain something */
                goto end;
            }
            break;
          case 0x0001:
            /* case 0x0002: */
            /* case 0x0003: */
            /* case 0x0005: */
            /* case 0x0071: */
            /* reserved for legacy, don't allow for now - too many fp */
            legacy = TRUE;
            break;
          case 0x0004:
            /*List Services */
            if (header.status != 0) {
                goto end;
            }
            /* check for command specific data in Reply */
            if (header.length) {
                if ((size_t)offset + 4 < payloadSize) {
                    temp16 = *((uint16_t *)(payload + offset));
                    /* should only have 1 item in list */
                    if (temp16 != 1) {
                        goto end;
                    }
                    offset += 2;
                    temp16 = *((uint16_t *)(payload + offset));
                    /* there is only one type for list services */
                    if (temp16 != 0x100) {
                        goto end;
                    }
                }
            }
            break;
          case 0x0063:
          /*List Identity */
          case 0x0064:
            /*List Interfaces */
            if (header.status != 0) {
                goto end;
            }
            if (header.sender != 0) {
                goto end;
            }
            break;
          case 0x0065:
          case 0x0066:
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            /*(un)Register Session */
            if (header.status != 0) {
                goto end;
            }
            if (header.length != 4) {
                /* length of 4 */
                goto end;
            }
            break;
          case 0x006F:
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            if (header.status != 0) {
                goto end;
            }
            /* command specific data */
            if ((size_t)offset + 4 > payloadSize) {
                goto end;
            }
            temp32 = *((uint32_t *)(payload + offset));
            if (temp32 != 0) {
                goto end;
            }
            /*SendRRData*/
            break;
          case 0x0070:
            /*SendUnitData*/
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            if (header.status != 0) {
                goto end;
            }
            /* command specific data */
            if ((size_t)offset + 4 > payloadSize) {
                goto end;
            }
            temp32 = *((uint32_t *)(payload + offset));
            if (temp32 != 0) {
                goto end;
            }
            break;
          case 0x0072:
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            /*Indicate Status*/
            break;
          case 0x0073:
            if (flow->key.proto != 6) {
                /* must be TCP */
                goto end;
            }
            /*Cancel*/
            break;
          default:
            return 0;
        }

#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, (total_offset + header.length + 24),
                          NULL, total_offset, ENIP_OBJECT, ENIP_PORT_NUMBER);
#endif
        /* length plus transaction id, protocol id, and length field */
        total_offset += header.length + 24;
        packets++;
    }

  end:

    if ((packets == 1) && legacy) {
        /* if only 1 packet and it = the legacy command codes, return 0 */
        return 0;
    }

    if (packets) {
        return ENIP_PORT_NUMBER;
    }

    return 0;
}


/**
 * ycEthIPScanRebuildHeader
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
ycEthIPScanRebuildHeader(
    const uint8_t           *payload,
    ycEthIPMessageHeader_t  *header)
{
    uint16_t offset = 0;

    header->command = *((uint16_t *)(payload));
    offset += 2;
    header->length = *((uint16_t *)(payload + offset));
    offset += 2;
    header->session = *((uint32_t *)(payload + offset));
    offset += 4;
    header->status = *((uint32_t *)(payload + offset));
    offset += 4;
    memcpy(&(header->sender), payload + offset, sizeof(uint64_t));
    offset += 8;
    header->options = *((uint32_t *)(payload + offset));
    /*
     * g_debug("header->command %02x", header->command);
     * g_debug("header->length %d", header->length);
     * g_debug("header->session_handle %u", header->session);
     * g_debug("header->status %u", header->status);
     * g_debug("header->sender %llu", header->sender);
     * g_debug("header->options %u", header->options);
     */
}
