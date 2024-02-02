/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */

/*
 *  rtpplugin.c
 *
 *  This tries to recognize the Real Time Transport Protocol (RTP)
 *  and associated RTP Control Protocol (RTCP) session.
 *  Based on RFC 3550.
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

#define RTP_PORT_NUMBER 5004
#define RTCP_PORT_NUMBER 5005
#define RTP_PAYTYPE 287

YC_SCANNER_PROTOTYPE(rtpplugin_LTX_ycRtpScanScan);

typedef struct ycRtpScanMessageHeader_st {
    uint16_t   version   : 2;
    uint16_t   padding   : 1;
    uint16_t   extension : 1;
    uint16_t   csrc      : 4;
    uint16_t   marker    : 1;
    uint16_t   paytype   : 7;

    uint16_t   sequence;
    uint32_t   timestamp;
    uint32_t   ssrc;
} ycRtpScanMessageHeader_t;


typedef struct ycRtcpScanMessageHeader_st {
    uint8_t    version : 2;
    uint8_t    padding : 1;
    uint8_t    count   : 5;

    uint8_t    packet_type;
    uint16_t   length;
    uint32_t   ssrc;
} ycRtcpScanMessageHeader_t;



/* Local Prototypes */

static
void
ycRtpScanRebuildHeader(
    const uint8_t             *payload,
    ycRtpScanMessageHeader_t  *header);


static
void
ycRtcpScanRebuildHeader(
    const uint8_t              *payload,
    ycRtcpScanMessageHeader_t  *header);


/**
 * rtpplugin_LTX_ycRtpScanScan
 *
 * the scanner for recognizing RTP/RTCP packets
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
 * @return rtp_port_number
 *         otherwise 0
 */
uint16_t
rtpplugin_LTX_ycRtpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    ycRtpScanMessageHeader_t  header;
    ycRtcpScanMessageHeader_t rtcp_header;
    uint32_t offset = 0;

    if (payloadSize < 12) {
        return 0;
    }

    if (flow->key.proto != 17) {
        /* this only does RTP over UDP */
        return 0;
    }

    ycRtpScanRebuildHeader(payload, &header);

    if (header.version != 2) {
        /* version 2 is standard */
        return 0;
    }

    if (header.paytype > 34) {
        if ((header.paytype > 71) && (header.paytype < 77)) {
            goto rtcp;
        }

        if (header.paytype < 71) {
            return 0;
        }

        if ((header.paytype > 76) && (header.paytype < 96)) {
            return 0;
        }
    }

    offset += 12;

    if (header.csrc > 0) {
        unsigned int csrc_count = (header.csrc > 15) ? 15 : header.csrc;
        unsigned int csrc_length = csrc_count * 4;

        if ((payloadSize - offset) < csrc_length) {
            return 0;
        }

        offset += csrc_length;
    }

    if (header.extension) {
        uint16_t extension_length;

        if ((size_t)offset + 4 > payloadSize) {
            return 0;
        }

        offset += 2;

        extension_length = ntohs(*((uint16_t *)(payload + offset)));

        offset += 2;

        if ((offset + extension_length) > payloadSize) {
            return 0;
        }

        offset += extension_length;
    }

    if (header.sequence == 0) {
        return 0;
    }
    if (header.timestamp == 0) {
        return 0;
    }
    if (header.ssrc == 0) {
        return 0;
    }

#if YAF_ENABLE_HOOKS
    yfHookScanPayload(flow, payload, 1, NULL, header.paytype, RTP_PAYTYPE,
                      RTP_PORT_NUMBER);
#endif

    return RTP_PORT_NUMBER;

  rtcp:

    offset = 0;

    ycRtcpScanRebuildHeader(payload, &rtcp_header);

    if (rtcp_header.count > 0) {
        return 0;
    }

    /* must be a report pkt first */
    if (rtcp_header.packet_type != 201) {
        return 0;
    }
    /* report packets are 1 byte */
    if (rtcp_header.length > 1) {
        return 0;
    }

    offset += 8;

    if ((size_t)offset + 8 > payloadSize) {
        return 0;
    }

    /* get second RTCP */

    ycRtcpScanRebuildHeader((payload + offset), &rtcp_header);

    offset += 8;

    if (rtcp_header.version != 2) {
        return 0;
    }

    if (rtcp_header.packet_type < 191) {
        return 0;
    }

    if (rtcp_header.packet_type > 211) {
        return 0;
    }

    if ((offset + rtcp_header.length) > payloadSize) {
        return 0;
    }

    if (rtcp_header.ssrc == 0) {
        return 0;
    }

    if (rtcp_header.count) {
        uint8_t sdes_type;
        uint8_t sdes_len;

        /* get type */

        sdes_type = *(payload + offset);

        if (sdes_type > 9) {
            return 0;
        }

        offset++;

        sdes_len = *(payload + offset);

        if (sdes_len + offset > payloadSize) {
            return 0;
        }

        /* DPI? */
    }

    return RTCP_PORT_NUMBER;
}


/**
 * ycRtpScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into the RTP structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated rtp message
 *        header structure
 *
 *
 */
static
void
ycRtpScanRebuildHeader(
    const uint8_t             *payload,
    ycRtpScanMessageHeader_t  *header)
{
    uint16_t bitmasks = ntohs(*((uint16_t *)payload));

    header->version = (bitmasks & 0xC000) >> 14;
    header->padding = bitmasks & 0x2000 ? 1 : 0;
    header->extension = bitmasks & 0x1000 ? 1 : 0;
    header->csrc = (bitmasks & 0x0F00) >> 8;
    header->marker = bitmasks & 0x0080 ? 1 : 0;
    header->paytype = bitmasks & 0x007F;

    header->sequence = ntohs(*((uint16_t *)(payload + 2)));

    header->timestamp = ntohl(*((uint32_t *)(payload + 4)));

    header->ssrc = ntohl(*((uint32_t *)(payload + 8)));

    /*
     * g_debug("header->version %d", header->version);
     * g_debug("header->padding %d", header->padding);
     * g_debug("header->extension %d", header->extension);
     * g_debug("header->csrc %d", header->csrc);
     * g_debug("header->marker %d", header->marker);
     * g_debug("header->paytype %d", header->paytype);
     * g_debug("header->sequence %d", header->sequence);
     * g_debug("header->timestamp %d", header->timestamp);
     * g_debug("header->ssrc %d", header->ssrc);
     */
}


static
void
ycRtcpScanRebuildHeader(
    const uint8_t              *payload,
    ycRtcpScanMessageHeader_t  *header)
{
    uint8_t bitmasks = *payload;

    header->version = (bitmasks & 0xC0) >> 6;
    header->padding = bitmasks & 0x20 ? 1 : 0;
    header->count = bitmasks & 0x1F;

    header->packet_type = *(payload + 1);

    header->length = ntohs(*((uint16_t *)(payload + 2)));

    header->ssrc = ntohl(*((uint32_t *)(payload + 4)));

    /*
     * g_debug("header->version %d", header->version);
     * g_debug("header->padding %d", header->padding);
     * g_debug("header->count %d", header->count);
     *
     * g_debug("header_pkt type %d", header->packet_type);
     * g_debug("header->length is %d", header->length);
     */
}
