/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafnfe.c
 *  YAF Netronome support
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

#if YAF_ENABLE_NETRONOME
#include "yafout.h"
#include "yafnfe.h"
#include "yaftab.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/privconfig.h>
#include <airframe/airlock.h>
#include "yafstat.h"
#include "yaflush.h"
#include "nfe_packetcap.h"

/* Statistics */
static uint64_t yaf_nfe_captured = 0;
static uint64_t yaf_nfe_dropped = 0;
static uint32_t yaf_stats_out = 0;

struct yfNFESource_st {
    char          *nfe_ring;
    unsigned int   device;
    unsigned int   ring;
};

#define YAF_NFE_TIMEOUT 1000

yfNFESource_t *
yfNFEOpenLive(
    const char  *ifname,
    int          snaplen,
    int         *datalink,
    GError     **err)
{
    yfNFESource_t *ps = NULL;

    if (ifname[1] != '.') {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid interface %s.\n  Inteface should be "
                    "in the form [device].[ring]. ex. 0.0", ifname);
        return NULL;
    }

    ps = g_new0(yfNFESource_t, 1);

    ps->device = atoi(ifname);

    if (ps->device > 3) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid Device Number.  Must be 0-3.");
        return NULL;
    }

    ps->ring = atoi(ifname + 2);
    if (ps->ring > 63) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid Ring Number.  Must be 0-63.");
        return NULL;
    }

    /* to be able to receive traffic on separate card/ring combos, use
     * nfe_pc_multi_init and nfe_pc_multi_add */
    if (!(ps->nfe_ring = nfe_pc_init(ps->device, ps->ring))) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Initializing Netronome API");
        return NULL;
    }

    g_debug("Detected Netronome Device. Reading from card %d, ring %d.",
            ps->device, ps->ring);

    nfe_pc_set_snaplen(ps->nfe_ring, snaplen);

    *datalink = DLT_EN10MB;

    /* return context */
    return ps;
}


void
yfNFEClose(
    yfNFESource_t  *ps)
{
    nfe_pc_close(ps->nfe_ring);
}


gboolean
yfNFEMain(
    yfContext_t  *ctx)
{
    gboolean         ok = TRUE;
    yfNFESource_t   *ps = (yfNFESource_t *)ctx->pktsrc;
    yfPBuf_t        *pbuf = NULL;
    struct timeval   ts;
    struct nfe_pc_descriptor *nfe_header;
    GTimer          *stimer = NULL;
    yfIPFragInfo_t   fraginfo_buf;
    yfIPFragInfo_t  *fraginfo = ctx->fragtab ? &fraginfo_buf : NULL;
    uint8_t         *frame = NULL;
    int              wait_status;

    /* create stats timer if starts are turned on */
    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    /* Start capture on the device */
    nfe_pc_start(ps->nfe_ring);

    /* process input until we're done */
    while (!yaf_quit) {
        frame = (uint8_t *)nfe_pc_next_packet(ps->nfe_ring, &nfe_header);
        if (frame == (uint8_t *)NFE_PC_ERROR) {
            g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Error reading Netronome feed: %s\n",
                        nfe_pc_get_error(ps->nfe_ring));
            ok = FALSE;
            break;
        } else if (frame == NULL) {
            /* Live, no packet processed (timeout). Flush buffer */
            if (!yfTimeOutFlush(ctx, (uint32_t)yaf_nfe_dropped,
                                &yaf_stats_out, yfStatGetTimer(),
                                stimer, &(ctx->err)))
            {
                ok = FALSE;
                break;
            }
            wait_status = nfe_pc_wait_packet(ps->nfe_ring, YAF_NFE_TIMEOUT);
            if (wait_status < 0 && errno != EINTR) {
                g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                            "Error reading Netronome feed: %s\n",
                            nfe_pc_get_error(ps->nfe_ring));
                ok = FALSE;
                break;
            }
            continue;
        }
        /* Grab a packet buffer from ring head */
        if (!(pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring))) {
            break;
        }

        pbuf->ptime = 0;

        nfe_pc_get_timestamp_us(ps->nfe_ring, nfe_header, &ts);

#if YAF_ENABLE_SEPARATE_INTERFACES
        /* if enabled, record the Netronome interface */
        pbuf->key.netIf = nfe_header->ingress_port;
#endif
        yaf_nfe_captured++;

        /* Decode packet into packet buffer */
        if (!yfDecodeToPBuf(ctx->dectx,
                            yfDecodeTimeval(&ts),
                            nfe_header->capture_length, frame,
                            fraginfo, ctx->pbuflen, pbuf))
        {
            /* No packet available. Skip. */
            goto process;
        }

        /* Handle fragmentation if necessary */
        if (fraginfo && fraginfo->frag) {
            if (!yfDefragPBuf(ctx->fragtab, fraginfo, ctx->pbuflen,
                              pbuf, frame, nfe_header->capture_length))
            {
                /* No complete defragmented packet available. Skip. */
                goto process;
            }
        }

      process:
        if (yaf_nfe_captured % 64) {
            /* Process the packet buffer */
            if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
                ok = FALSE;
                break;
            }

            if (!ctx->cfg->nostats) {
                if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {
                    yaf_nfe_dropped = nfe_pc_get_drop(ps->nfe_ring);
                    if (!yfWriteOptionsDataFlows(ctx, (uint32_t)yaf_nfe_dropped,
                                                 yfStatGetTimer(), &(ctx->err)))
                    {
                        ok = FALSE;
                        break;
                    }
                    g_timer_start(stimer);
                    yaf_stats_out++;
                }
            }
        }
    }

    /* Stop Capture */
    nfe_pc_stop(ps->nfe_ring);

    /* Update packet drop statistics for live capture */
    if (ok) {
        yaf_nfe_dropped = nfe_pc_get_drop(ps->nfe_ring);
    }

    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) {yaf_stats_out++;}
        g_timer_destroy(stimer);
    }
    /* Handle final flush */
    return yfFinalFlush(ctx, ok, (uint32_t)yaf_nfe_dropped,
                        yfStatGetTimer(), &(ctx->err));
}


void
yfNFEDumpStats(
    void)
{
    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }
    if (yaf_nfe_dropped) {
        g_warning("Live capture device: captured %lu, dropped %lu",
                  yaf_nfe_captured,
                  yaf_nfe_dropped);
    }
}


#endif /* if YAF_ENABLE_NETRONOME */
