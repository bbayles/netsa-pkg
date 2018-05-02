/**
 ** yafpfring.c
 ** YAF PFRING live input support
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2016 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
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
 */

#define _YAF_SOURCE_
#include <yaf/autoinc.h>

#if YAF_ENABLE_PFRING
#include "yafout.h"
#include "yafpfring.h"
#include "yaftab.h"
#include "yafstat.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/privconfig.h>
#include <airframe/airlock.h>
#include <pfring.h>
#include <pcap.h>
#include "yaflush.h"
#if YAF_ENABLE_PFRINGZC
#include <pfring_zc.h>
#endif


#define YAF_CAP_COUNT 64
#define MAX_SLOTS 32768
#define BUFF 256

/* Statistics */
static uint32_t     yaf_stats_out = 0;
static uint64_t     yaf_drop = 0;
GTimer *stimer = NULL;  /* to export stats */

/* Quit flag support */
extern int yaf_quit;

static pfring *gpf = NULL;

#if YAF_ENABLE_PFRINGZC
static pfring_zc_queue *pfzc = NULL;

struct yfPfRingZCSource_st {
    pfring_zc_queue          *queue;
    pfring_zc_stat           stat;
    pfring_zc_buffer_pool    *pool;
    pfring_zc_pkt_buff       *buffer;
    gboolean                 zc_open;
};
#endif

struct yfPfRingSource_st {
    pfring                   *pf;
    pfring_stat              stat;
    gboolean                 pf_open;
};

#if YAF_ENABLE_PFRINGZC
uint64_t yfPfRingZCTimespec(
     pfring_zc_timespec    *ts)
{
    return (((uint64_t)ts->tv_sec * 1000000000) +
            ((uint64_t)ts->tv_nsec)) / 1000000;
}
#endif


yfPfRingSource_t *yfPfRingOpenLive(
    const char              *ifname,
    int                     snaplen,
    int                     *datalink,
    GError                  **err)
{
    yfPfRingSource_t        *pf = NULL;
    uint32_t                flags = PF_RING_LONG_HEADER | PF_RING_TIMESTAMP | PF_RING_PROMISC;
    uint32_t                ring_version;

    /* Allocate a new PF_RING context */
    pf = g_new0(yfPfRingSource_t, 1);

    /* open the PF_RING socket */
    pf->pf = pfring_open(ifname, snaplen, flags);

    if (!pf->pf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't open %s", ifname);
        return NULL;
    }

    pf->pf_open = TRUE;

    pfring_set_application_name(pf->pf, "yaf");

    pfring_version(pf->pf, &ring_version);

    g_debug("Opened PF_RING version v.%d.%d.%d",
            (ring_version & 0xFFFF0000) >> 16,
           (ring_version & 0x0000FF00) >> 8, ring_version & 0x000000FF);
    g_debug("Device RX channels: %d", pfring_get_num_rx_channels(pf->pf));

    *datalink = DLT_EN10MB;

    /* return PF_RING context */
    return pf;
}

#if YAF_ENABLE_PFRINGZC

yfPfRingZCSource_t *yfPfRingZCOpenLive(
    const char              *ifname,
    int                     snaplen,
    int                     *datalink,
    GError                  **err)
{
    yfPfRingZCSource_t        *zc = NULL;
    gchar                     **name_split = NULL;
    char                      *ring_version;
    int                       i = 0;
    int                       cluster_id = 0;
    int                       queue_id = 0;

    name_split = g_strsplit(ifname, ":", -1);

    while (name_split[i] && *name_split[i]) {
        i++;
    }

    /* one for null char */
    if (i != 2) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid Input Name. "
                    " Valid Form: -i [cluster_id]:[queue_id]");
        return NULL;
    }

    cluster_id = atoi(name_split[0]);
    queue_id = atoi(name_split[1]);

    if (cluster_id < 0 || queue_id < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid cluster ID or queue ID.");
        return NULL;
    }

    /* Allocate a new PF_RING context */
    zc = g_new0(yfPfRingZCSource_t, 1);

    /* open the PF_RING socket */
    zc->queue = pfring_zc_ipc_attach_queue(cluster_id, queue_id, rx_only);

    if (!zc->queue) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error attaching queue: %s.  Please check that cluster %d"
                    " is running.", strerror(errno), cluster_id);
        return NULL;
    }

    zc->pool = pfring_zc_ipc_attach_buffer_pool(cluster_id, queue_id);

    if (zc->pool == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error attaching to buffer pool: %s. Please check that "
                    "cluster %d id is running.", strerror(errno), cluster_id);
        return NULL;
    }

    zc->buffer = pfring_zc_get_packet_handle_from_pool(zc->pool);

    if (zc->buffer == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error retrieving packet handle from pool");
        return NULL;
    }

    zc->zc_open = TRUE;

    ring_version = pfring_zc_version();

    g_debug("YAF attached to cluster ID %d, queue ID %d", cluster_id,queue_id);
    g_debug("Opened PF_RING ZC version v %s", ring_version);

    *datalink = DLT_EN10MB;

    pfzc = zc->queue;

    /* return PF_RING context */
    return zc;
}


void yfPfRingZCClose(
    yfPfRingZCSource_t       *zc)
{
    if (zc->zc_open) {
        pfring_zc_release_packet_handle_to_pool(zc->pool, zc->buffer);
        pfring_zc_ipc_detach_queue(zc->queue);
        pfring_zc_ipc_detach_buffer_pool(zc->pool);
    }

    g_free(zc);
}
#endif

void yfPfRingClose(
    yfPfRingSource_t          *pf)
{

    if (pf->pf_open) {
        pfring_close(pf->pf);
    }

    g_free(pf);
}

void yfPfRingBreakLoop(
    yfContext_t                *ctx)
{

#if YAF_ENABLE_PFRINGZC
    if (pfzc) {
        pfring_zc_queue_breakloop(pfzc);
    }
#endif
    if (gpf) {
        pfring_breakloop(gpf);
    }

}

void yfPfRingHandle(
    const struct pfring_pkthdr  *hdr,
    const u_char                *pkt,
    yfContext_t                 *ctx)
{

    yfPBuf_t                   *pbuf;
    yfIPFragInfo_t             fraginfo_buf;
    yfIPFragInfo_t             *fraginfo = ctx->fragtab ? &fraginfo_buf : NULL;
    static int                 pkts = 0;

    /* get next spot in ring buffer */
    pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring);
    g_assert(pbuf);

#if YAF_ENABLE_SEPARATE_INTERFACES
    pbuf->key.netIf = hdr->extended_hdr.if_index;
#endif

    pkts++;

    /* Decode packet into packet buffer */
    if (!yfDecodeToPBuf(ctx->dectx,
                        yfDecodeTimeval(&(hdr->ts)),
                        hdr->caplen, pkt,
                        fraginfo, ctx->pbuflen, pbuf))
    {
        /* Couldn't decode packet; counted in dectx. Skip. */
        goto end;
    }


    /* Handle fragmentation if necessary */
    if (fraginfo && fraginfo->frag) {
        if (!yfDefragPBuf(ctx->fragtab, fraginfo,
                          ctx->pbuflen, pbuf, pkt, hdr->caplen))
        {
            /* No complete defragmented packet available. Skip. */
            goto end;
        }
    }

  end:

    if (pkts > YAF_CAP_COUNT) {
        pkts = 0;
        yfPfRingBreakLoop(ctx);
    }
}



gboolean yfPfRingMain(
    yfContext_t             *ctx)
{
    gboolean                ok = TRUE;
    yfPfRingSource_t        *pf = (yfPfRingSource_t *)ctx->pktsrc;

    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    if (pfring_enable_ring(pf->pf) != 0) {
        g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to enable ring.");
        yfPfRingClose(pf);
        return FALSE;
    }

    gpf = pf->pf;

    /* process input until we're done */
    while (!yaf_quit) {

        pfring_loop(pf->pf, (pfringProcesssPacket)yfPfRingHandle, (u_char *)ctx, 1);

        /* Process the packet buffer */
        if (!yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
            break;
        }

        if (pfring_stats(pf->pf, &(pf->stat)) < 0) {
            g_debug("Error retrieving PF_RING stats");
        }

        if (!ctx->cfg->nostats) {
            if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {
                if (!yfWriteOptionsDataFlows(ctx, pf->stat.drop, yfStatGetTimer(),
                                      &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                g_timer_start(stimer);
                yaf_stats_out++;
                yaf_drop = pf->stat.drop;
            }
        }
    }

    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) yaf_stats_out++;
        /* free timer */
        g_timer_destroy(stimer);
    }

    /* Handle final flush */
    return yfFinalFlush(ctx, ok, pf->stat.drop, yfStatGetTimer(),
                        &(ctx->err));
}

#if YAF_ENABLE_PFRINGZC
gboolean yfPfRingZCMain(
    yfContext_t             *ctx)
{
    gboolean                ok = TRUE;
    yfPfRingZCSource_t      *zc = (yfPfRingZCSource_t *)ctx->pktsrc;
    yfPBuf_t                *pbuf;
    yfIPFragInfo_t          fraginfo_buf;
    yfIPFragInfo_t          *fraginfo = ctx->fragtab ? &fraginfo_buf : NULL;
    uint64_t                initial_drop = 0;
    uint8_t                 *data;
    static int              pkts = 0;

    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    pfzc = zc->queue;

    if (pfring_zc_stats(zc->queue, &(zc->stat)) < 0) {
        g_debug("Error retrieving PF_RING stats");
    }

    initial_drop = zc->stat.drop;

    /* process input until we're done */
    while (!yaf_quit) {

      while (pfring_zc_recv_pkt(zc->queue, &zc->buffer, 1)) {

        /* get next spot in ring buffer */
        pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring);

        g_assert(pbuf);

        pkts++;

        fraginfo = &fraginfo_buf;

#if YAF_ENABLE_SEPARATE_INTERFACES
        pbuf->key.netIf = zc->buffer->hash;
#endif
        data = pfring_zc_pkt_buff_data(zc->buffer, zc->queue);

        /* Decode packet into packet buffer */
        if (!yfDecodeToPBuf(ctx->dectx,
                            yfPfRingZCTimespec(&(zc->buffer->ts)),
                            zc->buffer->len+24, data,
                            fraginfo, ctx->pbuflen, pbuf))
        {
            /* Couldn't decode packet; counted in dectx. Skip. */
            goto end;
        }


        /* Handle fragmentation if necessary */
        if (fraginfo && fraginfo->frag) {
            if (!yfDefragPBuf(ctx->fragtab, fraginfo, ctx->pbuflen,
                              pbuf, data, zc->buffer->len+24))
            {
                /* No complete defragmented packet available. Skip. */
                goto end;
            }
        }
        end:
        if (pkts > YAF_CAP_COUNT) {
            pkts = 0;
            break;
        }
      }

      /* Process the packet buffer */
      if (!yfProcessPBufRing(ctx, &(ctx->err))) {
          ok = FALSE;
          break;
      }

      if (pfring_zc_stats(zc->queue, &(zc->stat)) < 0) {
          g_debug("Error retrieving PF_RING stats");
      }

      if (!ctx->cfg->nostats) {
          if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {

              if (!yfWriteOptionsDataFlows(ctx, zc->stat.drop, yfStatGetTimer(),
                                    &(ctx->err)))
              {
                  ok = FALSE;
                  break;
              }
              g_timer_start(stimer);
              yaf_stats_out++;
              yaf_drop = zc->stat.drop;
          }
      }
    }

    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) yaf_stats_out++;
        /* free timer */
        g_timer_destroy(stimer);
    }

    /* Handle final flush */
    return yfFinalFlush(ctx, ok, zc->stat.drop, yfStatGetTimer(),
                        &(ctx->err));
}
#endif

void yfPfRingDumpStats() {

    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }

    if (yaf_drop) {
        g_warning("Live capture device dropped %"PRIu64" packets.", yaf_drop);
    }
}

#endif
