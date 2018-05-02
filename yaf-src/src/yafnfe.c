/*
** yafnfe.c
** YAF Netronome support
**
** ------------------------------------------------------------------------
** Copyright (C) 2006-2016 Carnegie Mellon University. All Rights Reserved.
** ------------------------------------------------------------------------
** Authors: Emily Sarneso <ecoff@cert.org>
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
static uint64_t     yaf_nfe_captured = 0;
static uint64_t     yaf_nfe_dropped = 0;
static uint32_t     yaf_stats_out = 0;

GTimer *stimer = NULL;

/* Quit flag support */
extern int yaf_quit;

struct yfNFESource_st {
    char * nfe_ring;
    unsigned int device;
    unsigned int ring;
};

#define YAF_NFE_TIMEOUT 1000

yfNFESource_t *yfNFEOpenLive(
    const char              *ifname,
    int                     snaplen,
    int                     *datalink,
    GError                  **err)
{
    yfNFESource_t            *ps = NULL;

    if ( ifname[1] != '.' ) {
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
       nfe_pc_multi_init and nfe_pc_multi_add */
    if (!(ps->nfe_ring = nfe_pc_init(ps->device, ps->ring))) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Initializing Netronome API");
        return NULL;
    };

    g_debug("Detected Netronome Device. Reading from card %d, ring %d.",
            ps->device, ps->ring);

    nfe_pc_set_snaplen(ps->nfe_ring, snaplen);

    *datalink = DLT_EN10MB;

    /* return context */
    return ps;

}

void yfNFEClose(
    yfNFESource_t          *ps)
{
    nfe_pc_close(ps->nfe_ring);
}

gboolean yfNFEMain(
    yfContext_t             *ctx)
{
    gboolean                ok = TRUE;
    yfNFESource_t           *ps = (yfNFESource_t *)ctx->pktsrc;
    yfPBuf_t                *pbuf = NULL;
    struct timeval          ts;
    struct nfe_pc_descriptor *nfe_header;
    yfIPFragInfo_t          fraginfo_buf,
                            *fraginfo = ctx->fragtab ?
                            &fraginfo_buf : NULL;
    uint8_t                 *frame = NULL;
    int                     wait_status;

    /* create stats timer if starts are turned on */
    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    /* Start capture on the device */
    nfe_pc_start(ps->nfe_ring);

    /* process input until we're done */
    while (!yaf_quit) {

        frame = (uint8_t *)nfe_pc_next_packet(ps->nfe_ring, &nfe_header);
        if (frame == (uint8_t*)NFE_PC_ERROR) {
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
        if (ok) yaf_stats_out++;
        g_timer_destroy(stimer);
    }
    /* Handle final flush */
    return yfFinalFlush(ctx, ok, (uint32_t)yaf_nfe_dropped,
                        yfStatGetTimer(), &(ctx->err));
}



void yfNFEDumpStats() {

    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }
    if (yaf_nfe_dropped) {
        g_warning("Live capture device: captured %lu, dropped %lu",
                  yaf_nfe_captured,
                  yaf_nfe_dropped);
    }
}

#endif
