/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafdag.c
 *  YAF Endace DAG live input support
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
#include <yaf/autoinc.h>

#if YAF_ENABLE_DAG
#include "yafout.h"
#include "yafdag.h"
#include "yaftab.h"
#include "yafstat.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/privconfig.h>
#include <airframe/airlock.h>
#include <dagapi.h>
#include <pcap.h>
#include "yaflush.h"

/* Statistics */
static uint32_t yaf_dag_drop = 0;
static uint32_t yaf_stats_out = 0;

struct yfDagSource_st {
    char       name[DAGNAME_BUFSIZE];
    int        stream;
    int        fd;
    int        datalink;
    gboolean   fd_opened;
    gboolean   stream_attached;
    gboolean   stream_started;
};

/**
 *  Returns the number of milliseconds since the UNIX epoch given a ERF
 *  timestamp.
 *
 *  An ERF timestamp is like an NTP timestamp but uses the UNIX epoch.
 *
 *  Background:
 *
 *  From the "Extensible Record Format Timestamps" section of the Endace "ERF
 *  Types Reference Guide", EDM11-01 Version 21, retrieved 2023-05-31
 *
 *  https://www.endace.com/erf-extensible-record-format-types.pdf
 *
 *      The Extensible Record Format (ERF) incorporates a hardware generated
 *      timestamp of the packet’s arrival.
 *
 *      The format of this timestamp is a single little-endian 64-bit fixed
 *      point number, representing whole and fractional seconds since
 *      midnight on the first of January 1970.
 *
 *      The high 32-bits contain the integer number of seconds, while the
 *      lower 32-bits contain the binary fraction of the second. This allows
 *      an ultimate resolution of 2 -32 seconds, or approximately 233
 *      picoseconds.
 *
 *      Another advantage of the ERF timestamp format is that a difference
 *      between two timestamps can be found with a single 64-bit
 *      subtraction.
 *
 */
static uint64_t
yaf_dag_timestamp(
    uint64_t         dts)
{
    uint64_t ms;

    /* Mask the lower 32 bits of dts to get the fractional second part.
     * Divide by 2^32 to get a floating point number that is a fraction of a
     * second and multiply by 1000 to get milliseconds, but do those in
     * reverse order and use shift for the division.  Before the shift, round
     * up if needed by checking the highest bit that is about to get chopped
     * off. */
    ms = (dts & 0xffffffffULL) * 1000;
    ms = (ms + ((ms & 0x80000000ULL) << 1)) >> 32;

    /* Right shift dts by 32 to get the whole seconds part.  Multiply by 1000
     * to get milliseconds. */
    ms += (dts >> 32) * 1000;

    return ms;
}


yfDagSource_t *
yfDagOpenLive(
    const char  *ifname,
    int          snaplen,
    int         *datalink,
    GError     **err)
{
    yfDagSource_t *ds = NULL;
    struct timeval timeout, poll;

    /* Allocate a new DAG context */
    ds = g_new0(yfDagSource_t, 1);

    /* parse the device name to get the stream */
    if (dag_parse_name(ifname, ds->name,
                       DAGNAME_BUFSIZE, &ds->stream) < 0)
    {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't parse device name %s: %s",
                    ifname, strerror(errno));
        goto err;
    }

    /* open the DAG fd */
    if ((ds->fd = dag_open(ds->name)) < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't open %s: %s",
                    ds->name, strerror(errno));
        goto err;
    }
    ds->fd_opened = TRUE;

    /* configure the fd options */
    /* FIXME do we care about these? what are they? */
    if (dag_configure(ds->fd, "") < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't configure %s: %s",
                    ds->name, strerror(errno));
        goto err;
    }

    /* attach the stream */
    if (dag_attach_stream(ds->fd, ds->stream, 0, 0) < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't attach stream %u on %s: %s",
                    ds->stream, ds->name, strerror(errno));
        goto err;
    }
    ds->stream_attached = TRUE;

    /* start the stream */
    if (dag_start_stream(ds->fd, ds->stream) < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Couldn't start stream %u on %s: %s",
                    ds->stream, ds->name, strerror(errno));
        goto err;
    }
    ds->stream_started = TRUE;

    /* set polling parameters, 100ms timeout with 10ms polling interval. */
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    poll.tv_sec = 0;
    poll.tv_usec = 10000;
    dag_set_stream_poll(ds->fd, ds->stream, 32 * 1024, &timeout, &poll);

    /* set DAG linktype */
    switch (dag_linktype(ds->fd)) {
      case TYPE_ETH:
        ds->datalink = DLT_EN10MB;
        g_debug("Detected Ethernet DAG device %s (TYPE_ETH, DLT_EN10MB)",
                ds->name);
        break;
      case TYPE_MC_HDLC:
        ds->datalink = DLT_RAW;
        g_debug("Detected HDLC DAG device %s (TYPE_MC_HDLC, DLT_RAW)",
                ds->name);
        break;
      case TYPE_HDLC_POS:
        ds->datalink = DLT_RAW;
        g_debug("Detected HDLC DAG device %s (TYPE_HDLC_POS, DLT_RAW)",
                ds->name);
        break;
      default:
        ds->datalink = DLT_RAW;
        g_warning("Detected unsupported DAG device %s linktype %d; "
                  "no packets will be processed.",
                  ds->name, dag_linktype(ds->fd));
    }
    *datalink = ds->datalink;

    /* return dag context */
    return ds;

  err:
    /* tear down the dag context */
    yfDagClose(ds);
    return NULL;
}


void
yfDagClose(
    yfDagSource_t  *ds)
{
    if (ds->fd_opened) {
        if (ds->stream_attached) {
            if (ds->stream_started) {
                dag_stop_stream(ds->fd, ds->stream);
            }
            dag_detach_stream(ds->fd, ds->stream);
        }
        dag_close(ds->fd);
    }

    g_free(ds);
}


gboolean
yfDagMain(
    yfContext_t  *ctx)
{
    gboolean         ok = TRUE;
    yfDagSource_t   *ds = (yfDagSource_t *)ctx->pktsrc;
    yfPBuf_t        *pbuf = NULL;
    GTimer          *stimer = NULL;
    yfIPFragInfo_t   fraginfo_buf;
    yfIPFragInfo_t  *fraginfo = ctx->fragtab ? &fraginfo_buf : NULL;
    uint8_t         *cp = NULL, *ep = NULL, *fpp = NULL;
    dag_record_t    *rec;
    size_t           caplen, reclen;

    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    /* process input until we're done */
    while (!yaf_quit) {
        /* advance the stream if necessary */
        if ((cp >= ep) &&
            !(ep = dag_advance_stream(ds->fd, ds->stream, &cp)))
        {
            g_warning("Couldn't advance stream %u on %s: %s",
                      ds->stream, ds->name, strerror(errno));
            ok = FALSE;
            break;
        }

        /* Process packets, defragmenting them */
        while (cp < ep) {
            /* Grab a packet buffer from ring head */
            if (!(pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring))) {
                break;
            }

            /* mark it skippable to start */
            pbuf->ptime = 0;

            /* get the DAG record */
            rec = (dag_record_t *)cp;

            /* account for lost packets since last record */
            if (rec->lctr) {
                yaf_dag_drop += g_ntohs(rec->lctr);
            }

            /* get length of captured data */
            reclen = g_ntohs(rec->rlen);

            /* advance pointer */
            cp += reclen;

            /* only process dag records matching the declared datalink */
            if (rec->type == TYPE_ETH &&
                ds->datalink == DLT_EN10MB)
            {
                /* skip pad to start of ethernet header */
                fpp = &(rec->rec.eth.dst[0]);
            } else if (rec->type == TYPE_MC_HDLC &&
                       ds->datalink == DLT_RAW)
            {
                /* skip to payload and treat as raw */
                fpp = &(rec->rec.mc_hdlc.pload[0]);
            } else if (rec->type == TYPE_HDLC_POS &&
                       ds->datalink == DLT_RAW)
            {
                fpp = &(rec->rec.pos.pload[0]);
            } else {
                continue;
            }

            /* remove dag and unused layer 2 headers from caplen */
            caplen = (((uint8_t *)rec + reclen) - fpp);

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
            /* if enabled, record the DAG interface */
            pbuf->key.netIf = rec->flags.iface;
#endif

            /* Decode packet into packet buffer */
            if (!yfDecodeToPBuf(ctx->dectx,
                                yaf_dag_timestamp(rec->ts),
                                caplen, fpp,
                                fraginfo, ctx->pbuflen, pbuf))
            {
                /* No packet available. Skip. */
                continue;
            }

            /* Handle fragmentation if necessary */
            if (fraginfo && fraginfo->frag) {
                if (!yfDefragPBuf(ctx->fragtab, fraginfo,
                                  ctx->pbuflen, pbuf, fpp, caplen))
                {
                    /* No complete defragmented packet available. Skip. */
                    continue;
                }
            }
        }

        /* Process the packet buffer */
        if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
            break;
        }

        if (!ctx->cfg->nostats) {
            if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {
                if (!yfWriteOptionsDataFlows(ctx, yaf_dag_drop,
                                             yfStatGetTimer(),
                                             &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                g_timer_start(stimer);
                yaf_stats_out++;
            }
        }
    }

    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) {yaf_stats_out++;}
        /* free timer */
        g_timer_destroy(stimer);
    }

    /* Handle final flush */
    return yfFinalFlush(ctx, ok, yaf_dag_drop, yfStatGetTimer(),
                        &(ctx->err));
}


void
yfDagDumpStats(
    void)
{
    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }

    if (yaf_dag_drop) {
        g_warning("Live capture device dropped %u packets.", yaf_dag_drop);
    }
}


#endif /* if YAF_ENABLE_DAG */
