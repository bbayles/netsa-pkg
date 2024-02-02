/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  dnsplugin.c
 *
 *  provides a plugin to the ipfix payload classifier to attempt to determine
 *  if a packet payload is a DNS packet (see RFC 1035)
 *
 *  defining PAYLOAD_INSPECTION at compile time will attempt to better
 *  inspection of the packet payload at a cost of deeper inspection;  even with
 *  PAYLOAD_INSPECTION enabled, it is possible that this may not be 100%
 *  correct in ID'ing the packets
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

/*
 * typedef struct ycDnsScanMessageHeader_st {
 *  uint16_t            id;
 *
 *  uint16_t            qr:1;
 *  uint16_t            opcode:4;
 *  uint16_t            aa:1;
 *  uint16_t            tc:1;
 *  uint16_t            rd:1;
 *  uint16_t            ra:1;
 *  uint16_t            z:1;
 *  uint16_t            ad:1;
 *  uint16_t            cd:1;
 *  uint16_t            rcode:4;
 *
 *  uint16_t            qdcount;
 *  uint16_t            ancount;
 *  uint16_t            nscount;
 *  uint16_t            arcount;
 * } ycDnsScanMessageHeader_t;
 */

#define DNS_PORT_NUMBER 53
#define DNS_NAME_COMPRESSION 0xc0
#define DNS_NAME_OFFSET 0x0FFF
#define DNS_MAX_NAME_LENGTH 255
/** this field defines the number of octects we fuzz the size of the
 *  DNS to the IP+TCP+payload size with; we don't record any TCP
 *  options, so it is possible to have a few extra bytes in the
 *  calculation, and we won't say that's bad until that is larger
 *  than the following constant */
#define DNS_TCP_FLAG_SLACK 8

/** Since NETBIOS looks A LOT like DNS, there's no need to create
 *  a separate plugin for it - if we think it's NETBIOS we will
 *  return NETBIOS_PORT */
#define NETBIOS_PORT 137

YC_SCANNER_PROTOTYPE(dnsplugin_LTX_ycDnsScanScan);

#define PAYLOAD_INSPECTION 1



/**
 * local prototypes
 *
 */

#ifdef PAYLOAD_INSPECTION
static uint16_t
ycDnsScanCheckResourceRecord(
    const uint8_t  *payload,
    uint32_t       *offset,
    unsigned int    payloadSize);

#endif /* ifdef PAYLOAD_INSPECTION */


/**
 * dnsScanner_LTX_ycDnsScanScan
 *
 * scans a payload to determine if the payload is a dns request/reply.
 * It checks the structure for self referential integrity, but it can't
 * guarantee that the payload is actually DNS, it could be
 * some degenerate random data
 *
 * name abomination has been achieved by combining multiple naming standards
 * until the prefix to
 * the function name is dnsplugin_LTX_ycDnsScan --- it's a feature
 *
 * @param argc NOT USED
 * @param argv NOT USED
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match DNS_PORT_NUMBER (53) for a match
 *
 */
uint16_t
dnsplugin_LTX_ycDnsScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    uint32_t        payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    unsigned int loop = 0;
    uint16_t     msglen;
    uint32_t     firstpkt = payloadSize;
    ycDnsScanMessageHeader_t header;
    gboolean     netbios = FALSE;
    uint32_t     offset;
    uint16_t     qtype = 0;
#if YAF_ENABLE_HOOKS
    unsigned int recordCount = 0;
    uint16_t     direction;
#endif

    if (payloadSize < sizeof(ycDnsScanMessageHeader_t)) {
        /*fprintf(stderr, " <dns exit 1> ");
         * g_debug("returning at line 118");*/
        return 0;
    }

    if (flow->key.proto == YF_PROTO_TCP) {
        while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
            if (val->paybounds[loop] == 0) {
                loop++;
            } else {
                firstpkt = val->paybounds[loop];
                break;
            }
        }
        msglen = ntohs(*((uint16_t *)(payload)));
        if ((msglen + 2) == firstpkt) {
            /* this is the weird message length in TCP */
            payload += sizeof(uint16_t);
            payloadSize -= sizeof(uint16_t);
        }
    }

    ycDnsScanRebuildHeader(payload, &header);

    if ((header.opcode > 5) || (header.opcode == 3)) {
        if (header.opcode >= 5 && header.opcode < 9) {
            netbios = TRUE;
        } else {
            return 0;
        }
    }

    /* rfc 2136 updates rfc 1035 */
    /* 16-22 are DNSSEC rcodes*/
    if ((header.rcode > 10) && (1 == header.qr)) {
        if ((header.rcode < 16) || (header.rcode > 22)) {
            /*g_debug("returning at line 197 %d", header.rcode);*/
            return 0;
        }
    }

    /* rfc states that Z is reserved for future use and must be zero */
    if (0 != header.z) {
        /*g_debug("returning at line 141");*/
        return 0;
    }

    /* check to make sure resource records are not empty -
     * gets rid of all 0's payloads */
    if (header.qdcount == 0 && header.ancount == 0 && header.nscount == 0
        && header.arcount == 0)
    {
        if (!(header.rcode > 0 && header.qr == 1)) {
            /* DNS responses that are not errors will have something in them*/
            return 0;
        }
    }

    /* query validation */
    if (header.qr == 0) {
        if ((header.rcode > 0 || header.aa != 0 || header.ra != 0 ||
             header.ad != 0))
        {
            /* queries should not have an rcode, an authoritative answer,
             * recursion available, or authenticated data */
            return 0;
        }
        if (!(header.qdcount > 0)) {
            /* queries should have at least one question */
            return 0;
        }
    }

#ifdef PAYLOAD_INSPECTION
    /* parse through the rest of the DNS message, only the header is fixed
     * in size */
    offset = sizeof(ycDnsScanMessageHeader_t);
    /* the the query entries */

    if (offset >= payloadSize) {
        return 0;
    }
    /*fprintf(stderr,"dns qdcount %d, ancount %d, nscount %d, arcount
     * %d\n",header.qdcount,header.ancount,header.nscount, header.arcount);*/

    for (loop = 0; loop < header.qdcount; loop++) {
        uint8_t  sizeOct = *(payload + offset);
        uint16_t qclass;
        uint8_t  comp = 0;            /* turn on if something is compressed */

        while (0 != sizeOct && offset < payloadSize) {
            if (DNS_NAME_COMPRESSION == (sizeOct & DNS_NAME_COMPRESSION)) {
                offset += sizeof(uint16_t);
                /* compression happened so we don't need add 1 later */
                comp = 1;
            } else {
                offset += sizeOct + 1;
            }
            if (offset >= payloadSize) {
                return 0;
            }
            sizeOct = *(payload + offset);
        }

        if (offset >= payloadSize) {
            /* this is either a DNS fragment, or a malformed DNS */
            /*fprintf(stderr, " <dns exit 5> ");*/
            return 0;
        }

        /* get past the terminating 0 length in the name if NO COMPRESSION*/
        if (!comp) {
            offset++;
        }

        if ((offset + 2) > payloadSize) {
            return 0;
        }

        /* check the query type */
#if HAVE_ALIGNED_ACCESS_REQUIRED
        qtype = ((*(payload + offset)) << 8) |
            ((*(payload + offset + 1)) );

        qtype = ntohs(qtype);
#else /* if HAVE_ALIGNED_ACCESS_REQUIRED */
        qtype = ntohs(*((uint16_t *)(payload + offset)));
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */
        if (qtype == 0) {
            return 0;
        } else if (qtype > 52) {
            if ((qtype < 249) || (qtype > 253)) {
                if ((qtype != 32769) && (qtype != 32768) && (qtype != 99)) {
                    return 0;
                }
            }
        }

        if (qtype == 32) {
            netbios = TRUE;
        } else if (qtype == 33 && (flow->key.sp == NETBIOS_PORT ||
                                   flow->key.dp == NETBIOS_PORT))
        {
            netbios = TRUE;
        }

        offset += sizeof(uint16_t);

        if ((offset + 2) > payloadSize) {
            return 0;
        }

        /* check the class code */
#if HAVE_ALIGNED_ACCESS_REQUIRED
        qclass = ((*(payload + offset)) << 8) |
            ((*(payload + offset + 1)) );
        qclass = ntohs(qclass);
#else
        qclass = ntohs(*((uint16_t *)(payload + offset)));
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */

        if (qclass > 4 && qclass != 255) {
            /*fprintf(stderr, " <dns exit 7, qclass = %d> ", qclass);*/
            return 0;
        }

        if (netbios) {
            if (qclass != 1) {
                return 0;
            }
        }

        offset += sizeof(uint16_t);

        if (offset > payloadSize) {
            return 0;
        }
    }

    /* check each record for the answer record count */
    for (loop = 0; loop < header.ancount; loop++) {
        uint16_t rc;

        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return rc;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        } else if (rc == 32) {
            netbios = TRUE;
        } else if (rc == 33 && header.qdcount == 0) {
            netbios = TRUE;
        }

#if YAF_ENABLE_HOOKS
        if (rc != 41) {
            recordCount++;
        }
#endif
    }

    /* check each record for the name server resource record count */
    for (loop = 0; loop < header.nscount; loop++) {
        uint16_t rc;
        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return 0;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        } else if (rc == 2 && header.qdcount == 0) {
            netbios = TRUE;
        }

#if YAF_ENABLE_HOOKS
        if (rc != 41) {
            recordCount++;
        }
#endif
    }
    /* check each record for the additional record count */
    for (loop = 0; loop < header.arcount; loop++) {
        uint16_t rc;
        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return 0;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        }

#if YAF_ENABLE_HOOKS
        if (rc != 41) {
            recordCount++;
        }
#endif
    }

    if (netbios) {
        return NETBIOS_PORT;
    }

#if YAF_ENABLE_HOOKS
    if (val == &(flow->val)) {
        direction = 0;
    } else {
        direction = 1;
    }

#if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN)
    if ((header.aa == 1) || (header.rcode == 3)) {
        if (recordCount + header.qdcount) {
            yfHookScanPayload(flow, payload, 0, NULL,
                              (recordCount + header.qdcount), direction,
                              DNS_PORT_NUMBER);
        }
    }
#elif defined(YAF_ENABLE_DNSAUTH) && !defined(YAF_ENABLE_DNSNXDOMAIN)
    if (header.aa == 1) {
        if (recordCount + header.qdcount) {
            yfHookScanPayload(flow, payload, 0, NULL,
                              (recordCount + header.qdcount),
                              direction, DNS_PORT_NUMBER);
        }
    }
#elif defined(YAF_ENABLE_DNSNXDOMAIN) && !defined(YAF_ENABLE_DNSAUTH)
    if (header.rcode == 3) {
        if (recordCount + header.qdcount) {
            yfHookScanPayload(flow, payload, 0, NULL,
                              (recordCount + header.qdcount), direction,
                              DNS_PORT_NUMBER);
        }
    }
#else /* if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN) */
    if (header.qr && !(header.rcode)) {
        if (recordCount) {
            yfHookScanPayload(flow, payload, 0, NULL, recordCount, direction,
                              DNS_PORT_NUMBER);
        }
    } else {
        if (recordCount + header.qdcount) {
            yfHookScanPayload(flow, payload, 0, NULL,
                              (recordCount + header.qdcount),
                              direction, DNS_PORT_NUMBER);
        }
    }
#endif /* if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN) */
#endif /* if YAF_ENABLE_HOOKS */

#endif /* ifdef PAYLOAD_INSPECTION */

    /* this is the DNS port code */
    /* fprintf(stderr, " <dns exit 11 match> ");*/
    return DNS_PORT_NUMBER;
}


/**
 * ycDnsScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octect stream directly into the DNS structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dns message
 *        header structure
 *
 *
 */
#if 0
static void
ycDnsScanRebuildHeader(
    uint8_t                   *payload,
    ycDnsScanMessageHeader_t  *header)
{
    uint16_t    *tempArray = (uint16_t *)header;
    uint16_t     bitmasks  = ntohs(*((uint16_t *)(payload + 2)));
    unsigned int loop;

    memcpy(tempArray, payload, sizeof(ycDnsScanMessageHeader_t));
    for (loop = 0;
         loop < sizeof(ycDnsScanMessageHeader_t) / sizeof(uint16_t);
         loop++)
    {
    }

    header->qr = bitmasks & 0x8000 ? 1 : 0;
    header->opcode = (bitmasks & 0x7800) >> 11;
    header->aa = bitmasks & 0x0400 ? 1 : 0;
    header->tc = bitmasks & 0x0200 ? 1 : 0;
    header->rd = bitmasks & 0x0100 ? 1 : 0;
    header->ra = bitmasks & 0x0080 ? 1 : 0;
    header->z = bitmasks & 0x0040 ? 1 : 0;
#if 0
    /* don't think we care about these */
    header->ad = bitmasks & 0x0020 ? 1 : 0;
    header->cd = bitmasks & 0x0010 ? 1 : 0;
    header->rcode = bitmasks & 0x000f;

    g_debug("header->qr %d", header->qr);
    g_debug("header->opcode %d", header->opcode);
    g_debug("header->aa %d", header->aa);
    g_debug("header->tc %d", header->tc);
    g_debug("header->rd %d", header->rd);
    g_debug("header->ra %d", header->ra);
    g_debug("header->z %d", header->z);
    g_debug("header->rcode %d", header->rcode);
#endif /* 0 */
}
#endif /* 0 */

#ifdef PAYLOAD_INSPECTION
static
uint16_t
ycDnsScanCheckResourceRecord(
    const uint8_t  *payload,
    uint32_t       *offset,
    unsigned int    payloadSize)
{
    uint16_t nameSize;
    uint16_t rrType;
    uint16_t rrClass;
    uint16_t rdLength;
    gboolean compress_flag = FALSE;

    if (*offset >= payloadSize) {
        return 0;
    }

    nameSize  = *(payload + (*offset));

    while ((0 != nameSize) && (*offset < payloadSize)) {
        if (DNS_NAME_COMPRESSION == (nameSize & DNS_NAME_COMPRESSION)) {
            *offset += sizeof(uint16_t);
            if (!compress_flag) {
                compress_flag = TRUE;
            }
        } else {
            *offset += nameSize + 1;
        }
        if (*offset >= payloadSize) {
            return 0;
        }
        nameSize = *(payload + (*offset));
    }

    if (!compress_flag) {
        *offset += 1;
    }

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* check the type */
#if HAVE_ALIGNED_ACCESS_REQUIRED
    rrType = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rrType = ntohs(rrType);
#else
    rrType = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);

    if (rrType == 0) {
        return 0;
    } else if (rrType > 52) {
        if ((rrType < 249) || (rrType > 253)) {
            if ((rrType != 32769) && (rrType != 32768) && (rrType != 99)) {
                return 0;
            }
        }
    }

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* check the class */
#if HAVE_ALIGNED_ACCESS_REQUIRED
    rrClass = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rrClass = ntohs(rrClass);
#else
    rrClass = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);
    /* OPT Records use class field as UDP payload size */
    if (rrClass > 4 && rrType != 41) {
        /* rfc 2136 */
        if (rrClass != 254) {
            return 0;
        }
    }
    /* skip past the time to live */
    *offset += sizeof(uint32_t);

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* get the record data length, (so we can skip ahead the right amount) */
#if HAVE_ALIGNED_ACCESS_REQUIRED
    rdLength = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rdLength = ntohs(rdLength);
#else
    rdLength = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* if HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);

    /* not going to try to parse the data record, what's in there depends on
     * the class and type fields, but the rdlength field always tells us how
     * many bytes are in it */
    *offset += rdLength;

    if (*offset > payloadSize) {
        return 0;
    }/* the record seems intact enough */
    return rrType;
}


#endif /* ifdef PAYLOAD_INSPECTION */
