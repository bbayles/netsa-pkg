/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafstat.c
 *  YAF Statistics Signal Handler
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell, Chris Inacio
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
#include "yafstat.h"
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include <yaf/decode.h>
#include "yafcap.h"

#if YAF_ENABLE_NETRONOME
#include "yafnfe.h"
#endif

#if YAF_ENABLE_NAPATECH
#include "yafpcapx.h"
#endif

#if YAF_ENABLE_DAG
#include "yafdag.h"
#endif

static uint32_t     yaf_do_stat = 0;
static GTimer      *yaf_fft = NULL;
static yfContext_t *statctx = NULL;

static void
yfSigUsr1(
    int   s)
{
    (void)s;
    ++yaf_do_stat;
}


void
yfStatInit(
    yfContext_t  *ctx)
{
    struct sigaction sa, osa;

    /* install usr1 handler */
    sa.sa_handler = yfSigUsr1;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, &osa)) {
        g_error("sigaction(SIGUSR1) failed: %s", strerror(errno));
    }

    /* stash statistics context */
    statctx = ctx;

    /* start the timer */
    yaf_fft = g_timer_new();
    g_timer_start(yaf_fft);
}


static void
yfStatDump(
    void)
{
    uint64_t numPackets;
    uint32_t dropped, assembled, frags;

    numPackets = yfFlowDumpStats(statctx->flowtab, yaf_fft);
    numPackets += yfGetDecodeStats(statctx->dectx);
    yfGetFragTabStats(statctx->fragtab, &dropped, &assembled, &frags);
    numPackets += (frags - assembled);
    g_debug("YAF read %" PRIu64 " total packets", numPackets);
    yfFragDumpStats(statctx->fragtab, numPackets);
    yfDecodeDumpStats(statctx->dectx, numPackets);
    yfCapDumpStats();

#if YAF_ENABLE_NETRONOME
    yfNFEDumpStats();
#endif
#if YAF_ENABLE_DAG
    yfDagDumpStats();
#endif
#if YAF_ENABLE_NAPATECH
    yfPcapxDumpStats();
#endif
#if YAF_ENABLE_PFRING
    yfPfRingDumpStats();
#endif
}


void
yfStatDumpLoop(
    void)
{
    if (yaf_do_stat) {
        --yaf_do_stat;
        yfStatDump();
    }
}


void
yfStatComplete(
    void)
{
    g_timer_stop(yaf_fft);
    yfStatDump();
}


GTimer *
yfStatGetTimer(
    void)
{
    return yaf_fft;
}
