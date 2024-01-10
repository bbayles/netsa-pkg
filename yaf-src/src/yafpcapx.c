/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafpcapx.c
 *  YAF Napatech support
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

#if YAF_ENABLE_NAPATECH
#include "yafout.h"
#include "yafpcapx.h"
#include "yaftab.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/privconfig.h>
#include <airframe/airlock.h>
#include "yafstat.h"
#include "yaflush.h"

/* Statistics */
static uint64_t yaf_nt_dropped = 0;
static uint32_t yaf_stats_out = 0;
static uint64_t yaf_nt_dev_drop = 0;

struct yfNTSource_st {
    NtNetStreamRx_t   *netStream;
    NtConfigStream_t  *cfgStream;
    NtStatStream_t    *statStream;
    uint32_t           streamId;
    uint32_t           ntplId;
    int                filter_init;
};

yfNTSource_t *
yfPcapxOpenLive(
    const char  *ifname,
    int          snaplen,
    int         *datalink,
    GError     **err)
{
    yfNTSource_t  *nt = NULL;
    NtInfoStream_t infoStream;
    NtInfo_t       info;
    NtNtplInfo_t   ntplInfo;
    char           errBuf[100];
    char           filterBuf[200];
    char          *portstr = NULL;
    int            status;

    /* device name should be "nt3g<s>[:<p>]" */
    if (!(((ifname[0] == 'n') || (ifname[0] == 'N')) &&
          ((ifname[1] == 't') || (ifname[1] == 'T')) &&
          (ifname[2] == '3') &&
          ((ifname[3] == 'g') || (ifname[3] == 'G'))))
    {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Invalid interface %s. Interface should be in the "
                    "form nt3g[<s>:<p>] where <s> is the stream ID"
                    "and <p> is a comma-separated list of ports.", ifname);
        return NULL;
    }

    nt = g_new0(yfNTSource_t, 1);

    if (strlen(ifname) > 4) {
        nt->streamId = atoi(&ifname[4]);
    }

    if (strlen(ifname) > 5) {
        portstr = strchr(ifname, ':');
    }

    /* Initialize the NTAPI library */
    status = NT_Init(NTAPI_VERSION);

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Initalize Napatech API: %s\n", errBuf);
        goto err;
    }

    nt->cfgStream = g_new0(NtConfigStream_t, 1);

    status = NT_ConfigOpen(nt->cfgStream, "yafCfg");

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Config Stream: %s\n", errBuf);
        goto err;
    }

    status = NT_InfoOpen(&infoStream, "yafInfo");

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Info Stream: %s\n", errBuf);
        goto err;
    }

    info.cmd = NT_INFO_CMD_READ_SYSTEM;
    status = NT_InfoRead(infoStream, &info);
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Read Info Stream: %s\n", errBuf);
        goto err;
    }

    g_debug("Identified Napatech card: System contains %d adapters, "
            "%d ports, and %d NUMA nodes.",
            info.u.system.data.numAdapters, info.u.system.data.numPorts,
            info.u.system.data.numNumaNodes);

    status = NT_InfoClose(infoStream);

    if (portstr) {
        sprintf(filterBuf, "Assign[StreamId=%d] = port == %s", nt->streamId,
                portstr + 1);
    } else {
        sprintf(filterBuf, "Assign[StreamId=%d] = All", nt->streamId);
    }

    g_debug("Napatech Traffic Filter: %s", filterBuf);

    /* what does streamid need to be? */
    status = NT_NTPL(*(nt->cfgStream), filterBuf,
                     &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Assign Traffic to Stream: %s\n", errBuf);
        goto err;
    }

    nt->ntplId = ntplInfo.ntplId;

    nt->filter_init = 1;

    nt->netStream = g_new0(NtNetStreamRx_t, 1);

    /* use NT_NET_INTERFACE_PACKET to get 1 pkt at a time */
    status = NT_NetRxOpen(nt->netStream, "yafStream",
                          NT_NET_INTERFACE_SEGMENT, nt->streamId, -1);

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Rx Stream: %s\n", errBuf);
        goto err;
    }

    nt->statStream = g_new0(NtStatStream_t, 1);
    status = NT_StatOpen(nt->statStream, "yafStat");
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Stat Stream: %s\n", errBuf);
        goto err;
    }

    /* set datalink to Ethernet - this doesn't get returned until
     * buffer comes back with first packet, so if it's not - we'll
     * error then */
    *datalink = DLT_EN10MB;

    /* return context */
    return nt;

  err:
    /* tear down the Napatech/PcapExpress context */
    yfPcapxClose(nt);
    return NULL;
}


void
yfPcapxClose(
    yfNTSource_t  *nt)
{
    int          status;
    NtNtplInfo_t ntplInfo;
    char         errBuf[100];
    char         tempBuffer[20];

    snprintf(tempBuffer, 20, "delete=%d", nt->ntplId);
    if (nt->filter_init) {
        status = NT_NTPL(*(nt->cfgStream), tempBuffer, &ntplInfo,
                         NT_NTPL_PARSER_VALIDATE_NORMAL);
        if (status != NT_SUCCESS) {
            NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
            g_warning("Failure to Free Resources: %s\n", errBuf);
        }
    }

    status = NT_NetRxClose(*(nt->netStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_warning("Failure to Close Rx Stream: %s\n", errBuf);
    }

    status = NT_ConfigClose(*(nt->cfgStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_warning("Failure to Close Config Stream: %s\n", errBuf);
    }

    status = NT_StatClose(*(nt->statStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_warning("Failure to Close Stat Stream: %s\n", errBuf);
    }
}


gboolean
yfPcapxMain(
    yfContext_t  *ctx)
{
    gboolean          ok = TRUE;
    yfNTSource_t     *nt = (yfNTSource_t *)ctx->pktsrc;
    yfPBuf_t         *pbuf = NULL;
    NtNetBuf_t        netBuf;
    struct NtNetBuf_s pktNetBuf;
    int               yaf_nt_captured;
    NtNetRx_t         rxRd;
    NtStatistics_t    stat;
    GTimer           *stimer = NULL;
    yfIPFragInfo_t    fraginfo_buf;
    yfIPFragInfo_t   *fraginfo = ctx->fragtab ? &fraginfo_buf : NULL;
    int32_t           status = 0;
    uint8_t          *pkt;
    size_t            caplen;
    char              errBuf[100];

    /* create stats timer if starts are turned on */
    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
    /* Read the stats counter to clear the stats */
    stat.u.query_v2.poll = 0;
    stat.u.query_v2.clear = 1;
    if ((status = NT_StatRead(*(nt->statStream), &stat)) != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
        g_warning("Unable to Read & Clear Stats: %s", errBuf);
    }

    /* process input until we're done */
    while (!yaf_quit) {
        status = NT_NetRxGet(*(nt->netStream), &netBuf, 1000);
        if (status != NT_SUCCESS) {
            if (status == NT_STATUS_TRYAGAIN) {
                continue;
            } else if (status == NT_STATUS_TIMEOUT) {
                /* Live, no packet processed (timeout). Flush buffer */
                if (!yfTimeOutFlush(ctx,
                                    (uint32_t)(yaf_nt_dropped +
                                               yaf_nt_dev_drop),
                                    &yaf_stats_out, yfStatGetTimer(),
                                    stimer, &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                continue;
            }

            NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
            g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Error Retrieving Pkts: %s\n", errBuf);
            ok = FALSE;
            break;
        }

        _nt_net_build_pkt_netbuf(netBuf, &pktNetBuf);

        do {
            /* use the following if doing PACKET interface */
            /*caplen = NT_NET_GET_PKT_CAP_LENGTH(netBuf) -
             * NT_NET_GET_PKT_DESCR_LENGTH(netBuf);*/

            caplen = NT_NET_GET_PKT_CAP_LENGTH((&pktNetBuf));

            /* not sure why NT_NetRxGet returns NT_SUCCESS with 0 pkts */
            if (!caplen) {
                break;
            }

            /* Grab a packet buffer from ring head */
            if (!(pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring))) {
                break;
            }

            pbuf->ptime = 0;

#if YAF_ENABLE_SEPARATE_INTERFACES
            /* if enabled, record the Napatech interface */
            pbuf->key.netIf = NT_NET_GET_PKT_RXPORT(netBuf);
#endif
            /* PACKET INTERFACE - use following */
            /*pkt = NT_NET_GET_PKT_L2_PTR(netBuf);*/

            pkt = (uint8_t *)pktNetBuf.hPkt;

            yaf_nt_captured++;

            /* Decode packet into packet buffer */
            /** Timestamp is in 10 ns resolution timer from 1970 EPOCH*/
            if (!yfDecodeToPBuf(ctx->dectx,
                                NT_NET_GET_PKT_TIMESTAMP(&pktNetBuf) / 100000,
                                caplen, pkt,
                                fraginfo, ctx->pbuflen, pbuf))
            {
                /* No packet available. Skip. */
                continue;
                /* if PACKET INTERFACE - make sure to release */
            }

            /* Handle fragmentation if necessary */
            if (fraginfo && fraginfo->frag) {
                if (!yfDefragPBuf(ctx->fragtab, fraginfo, ctx->pbuflen,
                                  pbuf, pkt, caplen))
                {
                    /* No complete defragmented packet available. Skip. */
                    continue;
                }
            }

            if (yaf_nt_captured > 64) {
                if (!yfProcessPBufRing(ctx, &(ctx->err))) {
                    ok = FALSE;
                    break;
                }
                yaf_nt_captured = 0;
            }
        } while ((_nt_net_get_next_packet(netBuf, NT_NET_GET_SEGMENT_LENGTH(
                                              netBuf), &pktNetBuf) > 0));

        yaf_nt_captured = 0;

        /* Process the packet buffer */
        if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
            break;
        }

        if (!ctx->cfg->nostats) {
            if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {
                if (!yfWriteOptionsDataFlows(ctx,
                                             (uint32_t)(yaf_nt_dropped +
                                                        yaf_nt_dev_drop),
                                             yfStatGetTimer(), &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                g_timer_start(stimer);
                yaf_stats_out++;
            }
        }

        rxRd.cmd = NT_NETRX_READ_CMD_STREAM_DROP;

        if (NT_NetRxRead(*(nt->netStream), &rxRd) == NT_SUCCESS) {
            yaf_nt_dropped = rxRd.u.streamDrop.pktsDropped;
        } else {
            NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
            g_warning("Unable to Read Interface Stats: %s", errBuf);
        }

        stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
        stat.u.query_v2.poll = 1; /* get the current counters - don't wait */
        stat.u.query_v2.clear = 0; /* don't clear */
        if ((status = NT_StatRead(*(nt->statStream), &stat)) == NT_SUCCESS) {
            yaf_nt_dev_drop =
                stat.u.query_v2.data.stream.streamid[nt->streamId].drop.pkts;
        } else {
            NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
            g_warning("Unable to Read Interface Stats: %s", errBuf);
        }

        status = NT_NetRxRelease(*(nt->netStream), netBuf);
        if (status != NT_SUCCESS) {
            NT_ExplainError(status, errBuf, sizeof(errBuf) - 1);
            g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Error Releasing Pkt: %s\n", errBuf);
            ok = FALSE;
            break;
        }

        if (!ok) {
            break;
        }
    }

    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) {yaf_stats_out++;}
        g_timer_destroy(stimer);
    }

    /* Handle final flush */
    return yfFinalFlush(ctx, ok, (uint32_t)(yaf_nt_dropped + yaf_nt_dev_drop),
                        yfStatGetTimer(), &(ctx->err));
}


void
yfPcapxDumpStats(
    void)
{
    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }
    if (yaf_nt_dropped) {
        g_warning("Live capture device dropped %lu", yaf_nt_dropped);
    }
    if (yaf_nt_dev_drop) {
        g_warning("Network Interface dropped %lu", yaf_nt_dev_drop);
    }
}


#endif /* if YAF_ENABLE_NAPATECH */
