/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  gh0stplugin.c
 *
 *  This attempts to identify Gh0st Malware.  The traditional signature is:
 *  ----------------------------------------------------------------------
 *  | FLAG (5 bytes) | Pkt Length (4) | Uncomp. Length (4) | ZLIB Hdr | Data
 *  ----------------------------------------------------------------------
 *
 *  However, many variants do not use this signature.  Often the FLAG will
 *  be at offset 4 or 8 and may contain more than 5 characters.  The Pkt
 *  length may be at offset 0 or much later in the packet.  This decoder
 *  attempts to take those factors into consideration when identifying
 *  Gh0st.
 *  It cannot identify variants that:
 *   - have short flags
 *   - that do not have the packet length in the first 14 bytes AND do not
 *     contain a ZLIB header at some offset in the first 21 bytes
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

#define GHOST_DEBUG 0

#define ZLIB_HEADER 0x789c

YC_SCANNER_PROTOTYPE(gh0stplugin_LTX_ycGh0stScanScan);

static int
findGh0stSignature(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    int             offset);

static int
findGh0stPacketLength(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t        packet_len);



/**
 * gh0stplugin_LTX_ycGh0stScanScan
 *
 * the scanner for recognizing Gh0st
 *
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
 * @return 1 for Gh0st Packets
 *         otherwise 0
 */
uint16_t
gh0stplugin_LTX_ycGh0stScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     pkt_length = 0;
    uint32_t     second_pkt_length = 0;
    uint16_t     zlib_header = 0;
    /* gboolean weird = FALSE; */
    /* gboolean hdr = FALSE; */
    int          offset, name_offset;
    unsigned int loop = 0;

    /* Gh0st must have payload in both directions */
    if (flow->val.payload == NULL || flow->rval.payload == NULL) {
        return 0;
    }

    /* must be TCP */
    if (flow->key.proto != YF_PROTO_TCP) {
        return 0;
    }

    /* 5-13 for signature, 4 for paylen, 4 for uncompressed paylen,
     * 2 for zlib header*/
    if (payloadSize < 23) {
        return 0;
    }

    /* if flow stats were always enabled...
     * if (flow->val.stats && flow->rval.stats) {
     *  if (flow->val.stats->payoct != flow->rval.stats->payoct) {
     *      goto end;
     *  }
     *  if (flow->val.stats->maxpktsize != flow->rval.stats->maxpktsize) {
     *      goto end;
     *  }
     *  if (flow->pktdir != 0x02) {
     *      goto end;
     *  }
     *  init_app = 100;
     *  }*/

    /* Get the first 2 packet lengths */
    while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
        if (val->paybounds[loop] == 0) {
            loop++;
        } else {
            if (pkt_length == 0) {
                pkt_length = val->paybounds[loop];
                loop++;
            } else {
                second_pkt_length = val->paybounds[loop];
                break;
            }
        }
    }

    if (pkt_length == 0) {
        /* only 1 nonempty packet */
        pkt_length = payloadSize;
    }

    /* It is important to get the correct length of the first packet with
     * payload. YAF uses the TCP sequence numbers to calculate the payload
     * length.  In the case of a TCP Keep Alive, the keep alive packet has
     * a sequence number equal to the last byte of data in the previous
     * packet which screws with this calculation, so account for it here.*/
    if (second_pkt_length == pkt_length) {
        /* TCP Keep Alive? */
        pkt_length += 1;
    }

    /* This determines the offset into the payload of the compressed
     * length, if available.  If it can't be found in the first 14 bytes,
     * some variants can be identified by the ZLIB header at offset 16 or 19.
     * If we can't find a length or a ZLIB header, bail out */
    offset = findGh0stPacketLength(payload, payloadSize, pkt_length);
    if (offset < 0) {
        if (payloadSize > 20) {
            offset = 0;
            zlib_header = ntohs(*(uint16_t *)(payload + 19));
            if (zlib_header == ZLIB_HEADER) {
                /* weird = TRUE; */
                /* hdr = TRUE; */
            } else {
                zlib_header = ntohs(*(uint16_t *)(payload + 16));
                if (zlib_header == ZLIB_HEADER) {
                    offset = 6;
                    /* weird = TRUE; */
                    /* hdr = TRUE; */
                } else {
#if GHOST_DEBUG
                    g_debug("returning at pkt length offset check %d %d",
                            pkt_length, second_pkt_length);
#endif
                    return 0;
                }
            }
        }
    }

    /* This determines the offset into the payload of the Flag,
     * traditionally 'Gh0st' but there are hundreds of other known
     * flags.  Look for ASCII characters at a few different offsets */
    name_offset = findGh0stSignature(payload, payloadSize, offset);

    if (name_offset == -1) {
#if GHOST_DEBUG
        g_debug("returning at name offset check");
#endif
        return 0;
    }

    /* The ZLIB header is so rarely present - we only check for it
     * in cases where we can't find a valid length (above) */
    /*if (!hdr) {
     *  zlib_header = ntohs(*(uint16_t *)(payload+offset+13));
     *  if (zlib_header == ZLIB_HEADER) {
     *      hdr = TRUE;
     *  }
     *  }*/

    return 1;
}


/**
 * findGh0stPacketLength
 *
 * Determines if the length of the packet is in the first 14 bytes
 * of the payload
 *
 *
 * @param payload
 * @param payloadSize
 * @param packet_len the length of the first packet w/payload
 *
 * @return offset to the length
 *         otherwise -1
 */
static int
findGh0stPacketLength(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t        packet_len)
{
    int      i = 0;
    uint32_t length;

    while (i < 14) {
        length = ((*(uint32_t *)(payload + i)));
        if (length == packet_len) {
            return i;
        }
        i++;
    }
    return -1;
}


/**
 * findGh0stSignature
 *
 * Determines if their is a signature or "magic word" in the first 13 bytes of
 * payload
 *
 *
 * @param payload
 * @param payloadSize
 * @param offset (typically 5) but if the length of the packet was at
 * offset 0, it might be 4 or 8.  This is the offset of the length
 * in the payload.
 *
 * @return offset to the flag (keyword)
 *         otherwise -1
 */
static int
findGh0stSignature(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    int             offset)
{
    int      i;
    int      noffset = 0;
    gboolean found = TRUE;

    if (offset == 0) {
        noffset = 4;
        /* typical Gh0st */
        for (i = 4; i < 9; i++) {
            if ((payload[i] < 33 || payload[i] > 126)) {
                found = FALSE;
                break;
            }
        }

        if (!found) {
            found = TRUE;
            noffset = 8;
            for (i = 8; i < 13; i++) {
                if ((payload[i] < 33 || payload[i] > 126)) {
                    found = FALSE;
                    break;
                }
            }
        }
    } else {
        /* typical Gh0st */
        for (i = 0; i < 5; i++) {
            if ((payload[i] < 33 || payload[i] > 126)) {
                found = FALSE;
                break;
            }
        }
    }

    if (!found) {
        return -1;
    } else {
        return noffset;
    }
}
