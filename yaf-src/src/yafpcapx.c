/*
 ** yafpcapx.c
 ** YAF Napatech support
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
static uint64_t     yaf_nt_dropped = 0;
static uint32_t     yaf_stats_out = 0;
static uint64_t     yaf_nt_dev_drop = 0;

GTimer *stimer = NULL;

/* Quit flag support */
extern int yaf_quit;

struct yfNTSource_st {
    NtNetStreamRx_t      *netStream;
    NtConfigStream_t     *cfgStream;
    NtStatStream_t       *statStream;
    uint32_t             streamId;
    uint32_t             ntplId;
    int                  filter_init;
};

yfNTSource_t *yfPcapxOpenLive(
    const char              *ifname,
    int                     snaplen,
    int                     *datalink,
    GError                  **err)
{
    yfNTSource_t             *nt = NULL;
    NtInfoStream_t           infoStream;
    NtInfo_t                 info;
    NtNtplInfo_t             ntplInfo;
    char                     errBuf[100];
    char                     filterBuf[200];
    char                     *portstr = NULL;
    int                      status;


    /* device name should be "nt3g<s>[:<p>]" */
    if ( !(((ifname[0] == 'n') || (ifname[0] == 'N')) &&
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
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Initalize Napatech API: %s\n", errBuf);
        goto err;
    }

    nt->cfgStream = g_new0(NtConfigStream_t, 1);

    status = NT_ConfigOpen(nt->cfgStream, "yafCfg");

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Config Stream: %s\n", errBuf);
        goto err;
    }

    status = NT_InfoOpen(&infoStream, "yafInfo");

    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Info Stream: %s\n", errBuf);
        goto err;
    }

    info.cmd = NT_INFO_CMD_READ_SYSTEM;
    status = NT_InfoRead(infoStream, &info);
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
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
                portstr+1);
    } else {
        sprintf(filterBuf, "Assign[StreamId=%d] = All", nt->streamId);
    }

    g_debug("Napatech Traffic Filter: %s", filterBuf);

    /* what does streamid need to be? */
    status = NT_NTPL(*(nt->cfgStream), filterBuf,
                     &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
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
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Rx Stream: %s\n", errBuf);
        goto err;
    }

    nt->statStream = g_new0(NtStatStream_t, 1);
    status = NT_StatOpen(nt->statStream, "yafStat");
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Failure to Open Stat Stream: %s\n", errBuf);
        goto err;
    }

    /* set datalink to Ethernet - this doesn't get returned until
       buffer comes back with first packet, so if it's not - we'll
       error then */
    *datalink = DLT_EN10MB;

    /* return context */
    return nt;

err:
    /* tear down the Napatech/PcapExpress context */
    yfPcapxClose(nt);
    return NULL;
}

void yfPcapxClose(
    yfNTSource_t          *nt)
{
    int                   status;
    NtNtplInfo_t          ntplInfo;
    char                  errBuf[100];
    char                  tempBuffer[20];

    snprintf(tempBuffer, 20, "delete=%d", nt->ntplId);
    if (nt->filter_init) {
        status = NT_NTPL(*(nt->cfgStream), tempBuffer, &ntplInfo,
                         NT_NTPL_PARSER_VALIDATE_NORMAL);
        if (status != NT_SUCCESS) {
            NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
            g_warning("Failure to Free Resources: %s\n", errBuf);
        }
    }

    status = NT_NetRxClose(*(nt->netStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_warning("Failure to Close Rx Stream: %s\n", errBuf);
    }

    status = NT_ConfigClose(*(nt->cfgStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_warning("Failure to Close Config Stream: %s\n", errBuf);
    }

    status = NT_StatClose(*(nt->statStream));
    if (status != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
        g_warning("Failure to Close Stat Stream: %s\n", errBuf);
    }
}


gboolean yfPcapxMain(
    yfContext_t             *ctx)
{
    gboolean                ok = TRUE;
    yfNTSource_t            *nt = (yfNTSource_t *)ctx->pktsrc;
    yfPBuf_t                *pbuf = NULL;
    NtNetBuf_t              netBuf;
    struct NtNetBuf_s       pktNetBuf;
    int                     yaf_nt_captured;
    NtNetRx_t               rxRd;
    NtStatistics_t          stat;
    yfIPFragInfo_t          fraginfo_buf,
                            *fraginfo = ctx->fragtab ?
                                        &fraginfo_buf : NULL;
    int32_t                 status = 0;
    uint8_t                 *pkt;
    size_t                  caplen;
    char                    errBuf[100];

    /* create stats timer if starts are turned on */
    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
    /* Read the stats counter to clear the stats */
    stat.u.query_v2.poll = 0;
    stat.u.query_v2.clear = 1;
    if ((status = NT_StatRead(*(nt->statStream), &stat)) != NT_SUCCESS) {
        NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
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
                                    (uint32_t)(yaf_nt_dropped+yaf_nt_dev_drop),
                                    &yaf_stats_out, yfStatGetTimer(),
                                    stimer, &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                continue;
            }

            NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
            g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Error Retrieving Pkts: %s\n", errBuf);
            ok = FALSE;
            break;
        }

        _nt_net_build_pkt_netbuf(netBuf, &pktNetBuf);

        do {

            /* use the following if doing PACKET interface */
            /*caplen = NT_NET_GET_PKT_CAP_LENGTH(netBuf) -
              NT_NET_GET_PKT_DESCR_LENGTH(netBuf);*/

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
                                NT_NET_GET_PKT_TIMESTAMP(&pktNetBuf) /100000,
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

        } while ((_nt_net_get_next_packet(netBuf, NT_NET_GET_SEGMENT_LENGTH(netBuf), &pktNetBuf) > 0));

        yaf_nt_captured = 0;

        /* Process the packet buffer */
        if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
            break;
        }

        if (!ctx->cfg->nostats) {
            if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats) {
                if (!yfWriteOptionsDataFlows(ctx,
                                    (uint32_t)(yaf_nt_dropped+yaf_nt_dev_drop),
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
            NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
            g_warning("Unable to Read Interface Stats: %s", errBuf);
        }

        stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
        stat.u.query_v2.poll = 1; /* get the current counters - don't wait */
        stat.u.query_v2.clear = 0; /* don't clear */
        if ((status = NT_StatRead(*(nt->statStream), &stat)) == NT_SUCCESS) {
            yaf_nt_dev_drop = stat.u.query_v2.data.stream.streamid[nt->streamId].drop.pkts;
        } else {
            NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
            g_warning("Unable to Read Interface Stats: %s", errBuf);
        }


        status = NT_NetRxRelease(*(nt->netStream), netBuf);
        if (status != NT_SUCCESS) {
            NT_ExplainError(status, errBuf, sizeof(errBuf)-1);
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
        if (ok) yaf_stats_out++;
        g_timer_destroy(stimer);
    }

    /* Handle final flush */
    return yfFinalFlush(ctx, ok, (uint32_t)(yaf_nt_dropped + yaf_nt_dev_drop),
                        yfStatGetTimer(), &(ctx->err));
}



void yfPcapxDumpStats() {

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

#endif
