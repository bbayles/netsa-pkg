/**
 * @file gh0stplugin.c
 *
 * This attempts to identify Gh0st Malware.  The traditional signature is:
 * ----------------------------------------------------------------------
 * | FLAG (5 bytes) | Pkt Length (4) | Uncomp. Length (4) | ZLIB Hdr | Data
 * ----------------------------------------------------------------------
 *
 * However, many variants do not use this signature.  Often the FLAG will
 * be at offset 4 or 8 and may contain more than 5 characters.  The Pkt
 * length may be at offset 0 or much later in the packet.  This decoder
 * attempts to take those factors into consideration when identifying
 * Gh0st.
 * It cannot identify variants that:
 *  - have short flags
 *  - that do not have the packet length in the first 14 bytes AND do not
 *    contain a ZLIB header at some offset in the first 21 bytes
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
