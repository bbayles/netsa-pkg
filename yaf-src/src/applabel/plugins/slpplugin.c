/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  slpplugin.c
 *
 *  this is a protocol classifier for the service location protocol (SLP)
 *
 *  SLP is a protocol to find well known protocol/services on a local area
 *  network.  It can scale from small scale networks to large lan networks.
 *  For small scale networks, it uses multicasting in order to ask all
 *  machines for a service.  In larger networks it uses Directory Agents
 *  in order to centralize management of service information and increase
 *  scaling by decreasing network load.
 *
 *  rfc 2608  href="http://www.ietf.org/rfc/rfc2608.txt"
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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

#include <arpa/inet.h>


typedef struct srcLocProtoHeader_v1_st {
    uint8_t    version;
    uint8_t    function;
    uint16_t   length;

    uint8_t    overflow    : 1;
    uint8_t    monolingual : 1;
    uint8_t    urlAuth     : 1;
    uint8_t    attribAuth  : 1;
    uint8_t    srvcAck     : 1;
    uint8_t    reserved    : 3;

    uint8_t    dialect;
    uint16_t   langCode;
    uint16_t   charEncoding;
    uint16_t   xid;
} __attribute__ ((packed)) srcLocProtoHeader_v1_t;

/** this structure does not match (bit-for-bit anyway)  the
 *  on the wire protocol.  Machines without native 24-bit
 *  int types (darn near everything except some DSPs & older
 *  video chips maybe) will not be able to pack it correctly
 *  to match the wire */
typedef struct srcLocProtoHeader_v2_st {
    uint8_t    version;
    uint8_t    function;

    /* this is really a 24-bit value */
    uint32_t   length;

    uint8_t    overflow : 1;
    uint8_t    fresh    : 1;
    uint8_t    reqMcast : 1;
    uint16_t   reserved : 13;

    /* this is really a 24-bit value */
    uint32_t   nextExtensionOffset;

    uint16_t   xid;

    uint16_t   langTagLength;
    uint8_t    langCode;                /* there is at least 1 char here, and
                                         * up to 8 */
} srcLocProtoHeader_v2_t;

/* this is the size of the V2 header up to and including the language
 * tag length in uint8_t/octects/bytes */
#define SLP_V2_HEADER_SIZE 14

typedef enum slpFunction_et {
    SrvReq = 1,
    SrvRply = 2,
    SrvReg = 3,
    SrvDereg = 4,
    SrvAck = 5,
    AttrRqst = 6,
    AttrRply = 7,
    DAAdvert = 8,
    SrvTypeRqst = 9,
    SrvTypeReply = 10,
    SAAdvert = 11
} slpFunction_t;


#define SLP_PORT_NUMBER 427

YC_SCANNER_PROTOTYPE(slpplugin_LTX_ycSlpScanScan);


/*
 * File local functions
 *
 */
static unsigned int
ycPopulateSLPV2Header(
    const uint8_t           *payload,
    unsigned int             payloadSize,
    srcLocProtoHeader_v2_t  *header);


/**
 * slpplugin_LTX_ycSlpScanScan
 *
 * returns SLP_PORT_NUMBER if the passed in payload matches a service location
 * protocol packet
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
 * @return 0 if not a match, if it is SLP, returns the version of the protocol
 */
uint16_t
slpplugin_LTX_ycSlpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t      version;
    srcLocProtoHeader_v1_t *slpHeader;
    unsigned int loop;

#if YAF_ENABLE_HOOKS
    gboolean     slpStringFound = FALSE;
    uint16_t     slplength[5];
    uint32_t     slpoffset[5];
    for (loop = 0; loop < 5; loop++) {
        slplength[loop] = 0;
        slpoffset[loop] = 0;
    }
#endif /* if YAF_ENABLE_HOOKS */

    if (payloadSize < 2) {
        return 0;
    }

    /* map the payload into an SLP structure */
    slpHeader = (srcLocProtoHeader_v1_t *)payload;
    version = slpHeader->version;

    if (1 == version) {
        if (payloadSize < sizeof(srcLocProtoHeader_v1_t)) {
            return 0;
        }

        /* check the reserved fields first, they are required to be zero */
        if ((0 != slpHeader->reserved) || (0 != slpHeader->dialect)) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader->function < SrvReq)
            || (slpHeader->function > SrvTypeReply))
        {
            return 0;
        }

#if YAF_ENABLE_HOOKS
        /* version */
        /*yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 0, 90,
         * SLP_PORT_NUMBER);*/
        /* msg type */
        /*yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 1, 91,
         * SLP_PORT_NUMBER);*/

        /*Nothing valuable for now*/
/*    offset = 13;
 *  for (loop = 0; loop < 2; loop++){
 *      yfHookScanPayload(flow, payload, *(payload+offset),
 *                NULL, (offset + sizeof(uint16_t)), 92+loop,
 *                SLP_PORT_NUMBER);
 *      offset += *(payload+offset) + sizeof(uint16_t);
 *      }*/
#endif /* if YAF_ENABLE_HOOKS */

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
        return 1;
    } else if (2 == version) {
        srcLocProtoHeader_v2_t slpHeader2;
        uint32_t offset;

        if (payloadSize < sizeof(srcLocProtoHeader_v2_t)) {
            return 0;
        }

        if (0 == ycPopulateSLPV2Header(payload, payloadSize, &slpHeader2)) {
            return 0;
        }

        /* make sure the reserved field is set to zero, as required */
        if (0 != slpHeader2.reserved) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader2.function < SrvReq) ||
            (slpHeader2.function > SAAdvert))
        {
            return 0;
        }

        /* check the length of the language tag field */
        if (slpHeader2.langTagLength < 1 || slpHeader2.langTagLength > 8) {
            /* this is an invalid language length */
            return 0;
        }

        /* substract the size of the single langCode, but then we need to add
         * the length of the language string */
        offset = SLP_V2_HEADER_SIZE + slpHeader2.langTagLength;

        if (offset > payloadSize) {
            return 0;
        }

        /* five string fields are defined for a request */
        if (slpHeader2.function == SrvReq) {
            uint16_t stringLength;

            for (loop = 0; loop < 5; loop++) {
                if (((size_t)offset + 2) > payloadSize) {
                    return 0;
                }
#if HAVE_ALIGNED_ACCESS_REQUIRED
                stringLength = ((*(payload + offset)) << 8) |
                    ((*(payload + offset + 1)) );
                stringLength = ntohs(stringLength);
#if YAF_ENABLE_HOOKS
                slplength[loop] = stringLength;
#endif
#else /* if HAVE_ALIGNED_ACCESS_REQUIRED */
                stringLength = ntohs(*(uint16_t *)(payload + offset));
#if YAF_ENABLE_HOOKS
                slplength[loop] = stringLength;
#endif
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */
                /* we could get a string out here, but what would we do with
                 * it? */
#if YAF_ENABLE_HOOKS
                slpoffset[loop] = offset + sizeof(uint16_t);
#endif

                offset += sizeof(uint16_t) + stringLength;
            }

            if (offset > payloadSize) {
                return 0;
            }
        }

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
#if YAF_ENABLE_HOOKS
        for (loop = 0; loop < 5; loop++) {
            if ((slplength[loop] > 0) && (slplength[loop] < payloadSize)
                && (slpoffset[loop] < payloadSize))
            {
                slpStringFound = TRUE;
                yfHookScanPayload(flow, payload, slplength[loop], NULL,
                                  slpoffset[loop], 92 + loop, SLP_PORT_NUMBER);
            }
        }
        /* only record version and type if we have some data */
        if (slpStringFound) {
            /* version */
            yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 0, 90,
                              SLP_PORT_NUMBER);
            /* message type */
            yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 1, 91,
                              SLP_PORT_NUMBER);
        }
#endif /* if YAF_ENABLE_HOOKS */

        return 1;
    }

    return 0;
}


/**
 * ycPopulateSLPV2Header
 *
 * reads bytes from a stream (byte-by-byte) to fill in a structure for the V2
 * SLP header
 *
 * @note it doesn't attempt to fill in the langcode field
 *
 * @param payload pointer to the payload bytes as captured from the wire
 * @param payloadSize the size of the payload array
 * @param a pointer to a srcLocProtoHeader_V2_t to populate from parsing the
 * capture array
 *
 *
 * @return 0 on failure, non-zero on success
 */
static
unsigned int
ycPopulateSLPV2Header(
    const uint8_t           *payload,
    unsigned int             payloadSize,
    srcLocProtoHeader_v2_t  *header)
{
    uint32_t     offset = 0;
    uint8_t      readValue;
    uint8_t      readValue2;
    unsigned int loop;

    readValue = *(payload + offset);
    offset++;
    header->version = readValue;

    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->function = readValue;

    header->length = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->length = (header->length << 8) | readValue;
    }

    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->overflow = (readValue & 0x80) >> 7;
    header->fresh = (readValue & 0x40) >> 6;
    header->reqMcast = (readValue & 0x20) >> 5;

    if (offset > payloadSize) {
        return 0;
    }
    readValue2 = *(payload + offset);
    offset++;
    header->reserved = ((readValue & 0x1f) << 8) | (readValue2);

    header->nextExtensionOffset = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->nextExtensionOffset =
            (header->nextExtensionOffset << 8) | readValue;
    }

    header->xid = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->xid = (header->xid << 8) | readValue;
    }

    header->langTagLength = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->langTagLength = (header->langTagLength << 8) | readValue;
    }

    return offset;
}
