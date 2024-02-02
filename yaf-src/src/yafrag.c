/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafrag.c
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

#define _YAF_SOURCE_
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <yaf/picq.h>
#include <yaf/yafrag.h>

/* max ip is 60, max tcp is 60, 14 for l2 */
#define YF_FRAG_L4H_MAX 134
#define YF_FRAG_TIMEOUT 30000
#define YF_FRAGPRUNE_DELAY 5000

typedef struct yfFragRec_st {
    uint16_t   off;
    uint16_t   len;
} yfFragRec_t;

typedef struct yfFragKey_st {
    uint32_t      ipid;
    yfFlowKey_t   f;
} yfFragKey_t;

typedef struct yfFragNode_st {
    struct yfFragNode_st  *p;
    struct yfFragNode_st  *n;
    struct yfFragTab_st   *tab;
    uint64_t               last_ctime;
    gboolean               have_first;
    gboolean               have_last;
    gboolean               have_l4hdr;
    yfFragKey_t            key;
    yfTCPInfo_t            tcpinfo;
    yfL2Info_t             l2info;
    uint16_t               iplen;
    GArray                *records;
    size_t                 paylen;
    size_t                 payoff;
    uint8_t               *payload;
} yfFragNode_t;

typedef struct yfFragQueue_st {
    yfFragNode_t  *tail;
    yfFragNode_t  *head;
} yfFragQueue_t;


struct yfFragTabStats_st {
    uint32_t   stat_frags;
    uint32_t   stat_seqrej;
    uint32_t   stat_packets;
    uint32_t   stat_dropped;
    uint32_t   stat_peak;
};

struct yfFragTabStatsDescrip_st {
    const char  *name_frag;
    const char  *descrip_frag;
    const char  *name_seqrej;
    const char  *descrip_seqrej;
    const char  *name_packets;
    const char  *descrip_packets;
    const char  *name_dropped;
    const char  *descrip_dropped;
    const char  *name_peak;
    const char  *descrip_peak;
};

static struct yfFragTabStatsDescrip_st yfFragTabStatsDescrip;

struct yfFragTab_st {
    /* State */
    uint64_t                   ctime;
    uint64_t                   prunetime;
    GHashTable                *table;
    yfFragQueue_t              fraq;
    uint32_t                   count;
    yfFragNode_t              *assembled;
    /* Configuration */
    uint32_t                   idle_ms;
    uint32_t                   max_frags;
    uint32_t                   max_payload;
    /* Stats */
    struct yfFragTabStats_st   stats;
};

static uint32_t
yfFragKeyHash(
    yfFragKey_t  *key)
{
    if (key->f.version == 4) {
        return key->ipid ^ (key->f.proto << 12) ^ (key->f.version << 4) ^
               key->f.addr.v4.sip ^ key->f.addr.v4.dip;
    } else {
        return key->ipid ^ (key->f.proto << 12) ^ (key->f.version << 4) ^
               *((uint32_t *)&(key->f.addr.v6.sip[0])) ^
               *((uint32_t *)&(key->f.addr.v6.sip[4])) ^
               *((uint32_t *)&(key->f.addr.v6.sip[8])) ^
               *((uint32_t *)&(key->f.addr.v6.sip[12])) ^
               *((uint32_t *)&(key->f.addr.v6.dip[0])) ^
               *((uint32_t *)&(key->f.addr.v6.dip[4])) ^
               *((uint32_t *)&(key->f.addr.v6.dip[8])) ^
               *((uint32_t *)&(key->f.addr.v6.dip[12]));
    }
}


static gboolean
yfFragKeyEqual(
    yfFragKey_t  *a,
    yfFragKey_t  *b)
{
    if ((a->f.version == b->f.version) &&
        (a->ipid == b->ipid) &&
        (a->f.proto == b->f.proto))
    {
        if ((a->f.version == 4) &&
            (a->f.addr.v4.sip == b->f.addr.v4.sip) &&
            (a->f.addr.v4.dip == b->f.addr.v4.dip))
        {
            return TRUE;
        } else if ((a->f.version == 6) &&
                   (memcmp(a->f.addr.v6.sip, b->f.addr.v6.sip, 16) == 0) &&
                   (memcmp(a->f.addr.v6.dip, b->f.addr.v6.dip, 16) == 0))
        {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        return FALSE;
    }
}


void
yfGetFragTabStats(
    yfFragTab_t  *fragtab,
    uint32_t     *dropped,
    uint32_t     *assembled,
    uint32_t     *frags)
{
    if (fragtab) {
        *dropped = fragtab->stats.stat_dropped;
        *assembled = fragtab->stats.stat_packets;
        *frags = fragtab->stats.stat_frags;
    } else {
        *dropped = 0;
        *assembled = 0;
        *frags = 0;
    }
}


static int
yfFragSortByOffset(
    yfFragRec_t  *a,
    yfFragRec_t  *b)
{
    return (int)a->off - (int)b->off;
}


static void
yfFragAdd(
    yfFragTab_t     *fragtab,
    yfFragNode_t    *fn,
    yfIPFragInfo_t  *fraginfo,
    uint16_t         iplen,
    const uint8_t   *pkt,
    size_t           caplen,
    const uint8_t   *pkt_hdr,
    size_t           hdr_len)
{
    yfFragRec_t fr;
    ssize_t     frag_payoff = 0;
    ssize_t     frag_paylen, frag_payover;
    ssize_t     pay_offset;

    /* append a fragment record */
    fr.off = fraginfo->offset;
    fr.len = iplen - fraginfo->iphlen;

    g_array_append_vals(fn->records, &fr, 1);
    /* changed this to accomodate rolling pcap so account for it here */
    pay_offset = fraginfo->iphlen + fn->l2info.l2hlen + fraginfo->l4hlen;

    /* we don't want to include headers in caplen  */
    if (caplen >= (size_t)pay_offset) {
        caplen -= pay_offset;
    }

    /* set first and last flag on the fragment node */
    if (fraginfo->offset == 0) {
        fn->have_first = TRUE;
        /* first one needs to copy l2, l3, l4 (if avail) */
        frag_payoff = hdr_len > YF_FRAG_L4H_MAX ? YF_FRAG_L4H_MAX : hdr_len;
        memcpy(fn->payload, pkt_hdr, frag_payoff);
        fn->paylen = frag_payoff;
    } else {
        frag_payoff = fraginfo->offset + pay_offset;
    }

    if (!fraginfo->more) {
        fn->have_last = TRUE;
    }

    /* Short-circuit no payload copy */
    if (!fragtab->max_payload &&
        (fn->have_l4hdr || (fn->paylen >= YF_FRAG_L4H_MAX)))
    {
        /* we don't have max payload & we already have layer 4 headers
         * or captured max fraglen */
        return;
    }

    /* Length of payload is IP length minus headers, capped to caplen */
    frag_paylen = iplen - fraginfo->iphlen - fraginfo->l4hlen;

    /* caplen will be 0 if max-payload is not set */
    if (caplen && frag_paylen > (ssize_t)caplen) {
        frag_paylen = caplen;
    }

    /* Cap payload length to payload buffer length */
    frag_payover = (frag_payoff + frag_paylen) -
        (fragtab->max_payload + YF_FRAG_L4H_MAX);

    if (frag_payover > 0) {
        frag_paylen -= frag_payover;
    }

    /* Short circuit no payload to copy */
    if (frag_paylen <= 0) {
        return;
    }

    /* we already have l2 & l3 & (possibly) l4.  Get the rest here */

    /* Copy payload into buffer */
    if (!caplen) {
        if ((ssize_t)hdr_len >= (frag_paylen + pay_offset)) {
            memcpy(fn->payload + frag_payoff, (pkt_hdr + pay_offset),
                   frag_paylen);
        } else {
            return;
        }
    } else {
        memcpy(fn->payload + frag_payoff, (pkt + pay_offset), frag_paylen);
    }

    /* Track payload buffer length */
    if (frag_payoff + frag_paylen > (ssize_t)fn->paylen) {
        fn->paylen = frag_payoff + frag_paylen;
    }
}


static yfFragNode_t *
yfFragGetNode(
    yfFragTab_t     *fragtab,
    yfFlowKey_t     *flowkey,
    yfIPFragInfo_t  *fraginfo)
{
    yfFragNode_t *fn;
    yfFragKey_t   fragkey;

    /* construct a key to look up the frag node */
    memcpy(&fragkey.f, flowkey, sizeof(*flowkey));
    fragkey.ipid = fraginfo->ipid;

    /* get it out of the fragment table */
    fn = g_hash_table_lookup(fragtab->table, &fragkey);
    if (fn) {
        /* and place it at the head of the fragment queue */
        piqPick(&(fragtab->fraq), fn);
        piqEnQ(&(fragtab->fraq), fn);
        fn->last_ctime = fragtab->ctime;
        return fn;
    }

    /* no fragment node available; create a new one */
    fn = g_slice_new0(yfFragNode_t);

    /* fill in the fragment node */
    memcpy(&fn->key, &fragkey, sizeof(fragkey));

    /* allocate fragment record array */
    fn->records = g_array_sized_new(FALSE, TRUE, sizeof(yfFragRec_t), 4);

    /* create payload buffer, accounting for maximum TCP header size */
    fn->payload = g_slice_alloc0(fragtab->max_payload + YF_FRAG_L4H_MAX);

    /* place it at the head of the fragment queue */
    piqEnQ(&(fragtab->fraq), fn);

    fn->last_ctime = fragtab->ctime;

    /* stick it in the fragment table */
    g_hash_table_insert(fragtab->table, &fn->key, fn);
    ++(fragtab->count);
    if (fragtab->count > fragtab->stats.stat_peak) {
        fragtab->stats.stat_peak = fragtab->count;
    }

    /* return the fragment node */
    return fn;
}


static void
yfFragNodeFree(
    yfFragTab_t   *fragtab,
    yfFragNode_t  *fn)
{
    if (fn->payload) {
        g_slice_free1(fragtab->max_payload + YF_FRAG_L4H_MAX, fn->payload);
    }
    if (fn->records) {
        g_array_free(fn->records, TRUE);
    }

    g_slice_free(yfFragNode_t, fn);
}


static void
yfFragRemoveNode(
    yfFragTab_t   *fragtab,
    yfFragNode_t  *fn,
    gboolean       drop)
{
    g_hash_table_remove(fragtab->table, &(fn->key));
    piqPick(&(fragtab->fraq), fn);
    --(fragtab->count);

    if (drop) {
        ++(fragtab->stats.stat_dropped);
        yfFragNodeFree(fragtab, fn);
    } else {
        ++(fragtab->stats.stat_packets);
        g_assert(fragtab->assembled == NULL);
        fragtab->assembled = fn;
    }
}


static gboolean
yfFragComplete(
    yfFragTab_t     *fragtab,
    yfFragNode_t    *fn,
    yfIPFragInfo_t  *fraginfo)
{
    yfFragRec_t *frag = NULL;
    uint32_t     i, next_off;

    /* Short circuit unless we have both the first and last fragment */
    if (!fn->have_first || !fn->have_last) {
        return FALSE;
    }

    /* Sort the fragment array by offset */
    g_array_sort(fn->records, (GCompareFunc)yfFragSortByOffset);

    /* Traverse the fragment array to see if the fragments fit */
    for (i = 0, next_off = 0; i < fn->records->len; i++) {
        frag = &g_array_index(fn->records, yfFragRec_t, i);
        if (frag->off <= next_off) {
            next_off = frag->off + frag->len;
        } else {
            /* Fragment gap. Stop. */
            return FALSE;
        }
    }

    /* If we have a short first fragment - need to do Layer 4 decode */
    if (!fn->have_l4hdr) {
        if (fn->key.f.proto == YF_PROTO_TCP) {
            if (!yfDefragTCP(fn->payload + fraginfo->iphlen + fn->l2info.l2hlen,
                             &(fn->paylen), &(fn->key.f),
                             fraginfo, &(fn->tcpinfo), &(fn->payoff)))
            {
                /* we have all fragments but still can't decode it - seeya */
                yfFragRemoveNode(fragtab, fn, TRUE);
                return FALSE;
            }
        }
    }

    /*
     * If we're here, the fragments fit. Calculate total IP length.
     * This is the total of the offsets plus the IP header.
     */
    fn->iplen = next_off + fraginfo->iphlen;

    /* Stuff the fragment in the assembled buffer. */
    yfFragRemoveNode(fragtab, fn, FALSE);

    /* we've assembled a fragment */
    return TRUE;
}


static void
yfFragQueuePrune(
    yfFragTab_t  *fragtab,
    gboolean      prune_all)
{
    /* Limit prune rate */
    if (fragtab->prunetime &&
        (fragtab->ctime < fragtab->prunetime + YF_FRAGPRUNE_DELAY))
    {
        return;
    }
    fragtab->prunetime = fragtab->ctime;

    /* remove limited fragments */
    while (fragtab->max_frags &&
           fragtab->fraq.tail &&
           fragtab->count >= fragtab->max_frags)
    {
        yfFragRemoveNode(fragtab, fragtab->fraq.tail, TRUE);
    }

    /* remove expired fragments */
    while (fragtab->fraq.tail &&
           (fragtab->ctime - fragtab->fraq.tail->last_ctime > YF_FRAG_TIMEOUT))
    {
        yfFragRemoveNode(fragtab, fragtab->fraq.tail, TRUE);
    }

    /* remove all fragments */
    while (prune_all && fragtab->fraq.tail) {
        yfFragRemoveNode(fragtab, fragtab->fraq.tail, TRUE);
    }
}


yfFragTab_t *
yfFragTabAlloc(
    uint32_t   idle_ms,
    uint32_t   max_frags,
    uint32_t   max_payload)
{
    yfFragTab_t *fragtab = NULL;

    /* Allocate a fragment table */
    fragtab = g_slice_new0(yfFragTab_t);

    /* Fill in the configuration */
    fragtab->idle_ms = idle_ms;
    fragtab->max_frags = max_frags;
    fragtab->max_payload = max_payload;

    /* Allocate key index table */
    fragtab->table = g_hash_table_new((GHashFunc)yfFragKeyHash,
                                      (GEqualFunc)yfFragKeyEqual);

    /* initialize the stats meta information */
    yfFragTabStatsDescrip.name_frag = "frag";
    yfFragTabStatsDescrip.descrip_frag = "frag";
    yfFragTabStatsDescrip.name_seqrej = "seqrej";
    yfFragTabStatsDescrip.descrip_seqrej = "seqrej";
    yfFragTabStatsDescrip.name_packets = "packets";
    yfFragTabStatsDescrip.descrip_packets = "packets";
    yfFragTabStatsDescrip.name_dropped = "dropped";
    yfFragTabStatsDescrip.descrip_dropped = "dropped";
    yfFragTabStatsDescrip.name_peak = "peak";
    yfFragTabStatsDescrip.descrip_peak = "peak";

    /* Done */
    return fragtab;
}


void
yfFragTabFree(
    yfFragTab_t  *fragtab)
{
    while (fragtab->fraq.tail) {
        yfFragRemoveNode(fragtab, fragtab->fraq.tail, TRUE);
    }

    /* free the key index table */
    g_hash_table_destroy(fragtab->table);

    /* now free the flow table */
    g_slice_free(yfFragTab_t, fragtab);
}


gboolean
yfDefragPBuf(
    yfFragTab_t     *fragtab,
    yfIPFragInfo_t  *fraginfo,
    size_t           pbuflen,
    yfPBuf_t        *pbuf,
    const uint8_t   *pkt,
    size_t           hdrlen)
{
    yfFragNode_t *fn;
    yfTCPInfo_t  *tcpinfo = &(pbuf->tcpinfo);
    yfL2Info_t   *l2info = (pbuflen >= YF_PBUFLEN_NOPAYLOAD) ?
        &(pbuf->l2info) : NULL;
    uint8_t      *payload = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->payload : NULL;
    size_t        paylen = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->paylen : 0;
    size_t        calc_l4;

    /* short-circuit unfragmented packets */
    if (!fraginfo || !fraginfo->frag) {
        return TRUE;
    }

    /* reject out-of-sequence fragments and mark them invalid */
    if (pbuf->ptime < fragtab->ctime) {
        ++(fragtab->stats.stat_seqrej);
        pbuf->ptime = 0;
        return FALSE;
    }

    /* set fragment table packet clock */
    fragtab->ctime = pbuf->ptime;

    /* get a fragment node and place it at the head of the queue */
    fn = yfFragGetNode(fragtab, &(pbuf->key), fraginfo);

    /* stash information from first fragment */
    if (fraginfo->offset == 0) {
        if (fraginfo->l4hlen) {
            /* ports */
            fn->key.f.sp = pbuf->key.sp;
            fn->key.f.dp = pbuf->key.dp;

            /* Layer 4 info */
            fn->payoff = fraginfo->l4hlen;
            if (tcpinfo && fn->key.f.proto == YF_PROTO_TCP) {
                memcpy(&(fn->tcpinfo), tcpinfo, sizeof(yfTCPInfo_t));
            }
            fn->have_l4hdr = 1;
        }

        /* Layer 2 info */
        if (l2info) {
            memcpy(&(fn->l2info), l2info, sizeof(*l2info));
        }
    }

    if (l2info) {
        /* this needs to be right for putting together fragmented header
         * info in yfFragAdd (not sure why it would change) */
        fn->l2info.l2hlen = l2info->l2hlen;
    }

    /* add the fragment to the fragment node */
    yfFragAdd(fragtab, fn, fraginfo, pbuf->iplen, payload, paylen,
              pkt, hdrlen);
    ++(fragtab->stats.stat_frags);

    calc_l4 = fn->payoff;
    /* move completed fragments to the assembled buffer */
    if (yfFragComplete(fragtab, fn, fraginfo)) {
        if (calc_l4 != fn->payoff) {
            /* defragtcp will add the tcphlen -
             *  add l4hlen to pbuf->allheaderlen */
            pbuf->allHeaderLen += fraginfo->l4hlen;
            fn->payoff -= fraginfo->l4hlen;
        }
    }

    /* drop expired and limited fragments off the end of the queue */
    yfFragQueuePrune(fragtab, FALSE);

    /* return and mark packet invalid if no assembled packet available */
    if (!fragtab->assembled) {
        pbuf->ptime = 0;
        return FALSE;
    }

    /* copy assembled packet into packet buffer */
    fn = fragtab->assembled;
    fragtab->assembled = NULL;

    /* Copy out pointers to stored fragment information */
    if (pbuflen >= YF_PBUFLEN_BASE && fn->payload) {
        /* Payload is stored at an offset into the payload buffer */
        paylen = fn->paylen - fn->payoff;
        payload = fn->payload + fn->payoff;
        /* Cap payload length to space available in pbuf */
        if (paylen > pbuflen - YF_PBUFLEN_BASE) {
            paylen = pbuflen - YF_PBUFLEN_BASE;
        }
        /* Now stuff it in the packet buffer. */
        pbuf->paylen = paylen;
        memcpy(pbuf->payload, payload, paylen);
    }

    /* Copy other values from fragment node to packet buffer */
    memcpy(&(pbuf->key), &(fn->key.f), sizeof(yfFlowKey_t));
    pbuf->iplen = fn->iplen;
    memcpy(tcpinfo, &(fn->tcpinfo), sizeof(yfTCPInfo_t));
    if (l2info) {
        memcpy(l2info, &(fn->l2info), sizeof(yfL2Info_t));
    }

    /* Mark that the flow contained fragmented pkts */
    pbuf->frag = TRUE;

    /* Free the fragment node */
    yfFragNodeFree(fragtab, fn);

    /* All done. Packet buffer is valid. */
    return TRUE;
}


void
yfFragDumpStats(
    yfFragTab_t  *fragtab,
    uint64_t      packetTotal)
{
    if (!fragtab) {
        return;
    }

    g_debug("Assembled %u fragments into %u packets:",
            fragtab->stats.stat_frags, fragtab->stats.stat_packets);
    g_debug("  Expired %u incomplete fragmented packets. (%3.2f%%)",
            fragtab->stats.stat_dropped,
            ((double)(fragtab->stats.stat_dropped) / (double)(packetTotal) *
             100) );
    g_debug("  Maximum fragment table size %u.",
            fragtab->stats.stat_peak);
    if (fragtab->stats.stat_seqrej) {
        g_warning("Rejected %u out-of-sequence fragments. (%3.2f%%)",
                  fragtab->stats.stat_seqrej,
                  ((double)(fragtab->stats.stat_seqrej) /
                   (double)(packetTotal) * 100) );
    }
}
