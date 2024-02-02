/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafrag.h
 *  YAF Active Fragment Table
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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

/**
 * @file
 *
 * Fragment reassembly interface for YAF. [TODO - new frontmatter]
 *
 * This facility is used by the YAF flow generator.
 */

#ifndef _YAF_FRAG_H_
#define _YAF_FRAG_H_

#include <yaf/autoinc.h>
#include <yaf/decode.h>
#include <yaf/yafcore.h>

struct yfFragTab_st;
/**
 * A fragment table. Opaque. Create with yfFragTabAlloc() and free with
 * yfFragTabFree().
 */
typedef struct yfFragTab_st yfFragTab_t;

/**
 * Allocate a fragment table.
 *
 * @param idle_ms   idle timeout in milliseconds. A fragmented packet for which
 *                  no fragments are received over an idle timeout is dropped.
 *                  Most host IPv4 implementations use 30 seconds (30000); it
 * is
 *                  recommended to use the same here.
 * @param max_frags maximum number of unreassembled fragmented packets.
 *                  Fragmented packets exceeding this limit will be dropped in
 *                  least-recent order. Used to limit resource usage of a
 *                  fragment table. A value of 0 disables fragment count
 * limits.
 * @param max_payload   maximum octets of payload to capture per fragmented
 *                      packet. A value of 0 disables payload reassembly.
 *
 * @return a new fragment table.
 */
yfFragTab_t *
yfFragTabAlloc(
    uint32_t   idle_ms,
    uint32_t   max_frags,
    uint32_t   max_payload);

/**
 * Free a fragment table. Discards any outstanding fragmented packets within.
 *
 * @param fragtab a fragment table.
 */
void
yfFragTabFree(
    yfFragTab_t  *fragtab);

/**
 * Defragment a fragment returned by yfDecodeToPBuf(). This adds the fragment
 * to
 * the given fragment table. If the fragment completes a fragmented packet,
 * copies the assembled packet into the given pbuf, overwriting it, and
 * returns TRUE. If the packet is not fragmented (that is, if fraginfo->frag
 * is 0), has no effect and returns TRUE.
 *
 * @param fragtab   fragment table to add fragment to
 * @param fraginfo  fragment information structure filled in by
 * yfDecodeToPBuf()
 * @param pbuflen   size of the packet buffer pbuf
 * @param pbuf      packet buffer. On call, contains decoded fragmented packet
 *                  to add to the fragment table. If this call returns TRUE,
 *                  on return, contains assembled packet.
 * @param pkt       pkt buffer from libpcap.  We need this to reassemble
 *                  (memcpy) TCP header fragments when payload is not enabled.
 * @param hdr_len   size of the packet buffer pkt
 * @return  TRUE if pbuf is valid and contains an assembled packet,
 *          FALSE otherwise.
 */
gboolean
yfDefragPBuf(
    yfFragTab_t     *fragtab,
    yfIPFragInfo_t  *fraginfo,
    size_t           pbuflen,
    yfPBuf_t        *pbuf,
    const uint8_t   *pkt,
    size_t           hdr_len);

/**
 * Print fragment reassembler statistics to the log.
 *
 * @param fragtab fragment table to dump stats for
 * @param packetTotal total number of packets observed
 */
void
yfFragDumpStats(
    yfFragTab_t  *fragtab,
    uint64_t      packetTotal);

/**
 * Get Frag Stats to yfWriteStatsFlow for Stats Export
 *
 * @param fragtab pointer to fragmentation table
 * @param dropped number of expired fragments
 * @param assembled number of assembled packets
 * @param frags number of fragments
 */
void
yfGetFragTabStats(
    yfFragTab_t  *fragtab,
    uint32_t     *dropped,
    uint32_t     *assembled,
    uint32_t     *frags);

#endif /* ifndef _YAF_FRAG_H_ */
