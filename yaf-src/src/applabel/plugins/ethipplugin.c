/*
 *  Copyright 2015-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ethernetipplugin.c
 *
 *  This tries to recognize the Ethernet/IP protocol, a protocol often
 *  used for SCADA systems.
 *  Decoder based on reference:
 *  http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf
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
