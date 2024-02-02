/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwscan_tcp.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwscan.h"


void
add_count(
    uint32_t           *counts,
    uint32_t            value,
    uint32_t            max)
{
    if (value >= max - 1) {
        counts[max - 1]++;
    } else {
        counts[value]++;
    }
}

void
increment_tcp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics)
{
    if (!(rwRecGetFlags(rwrec) & ACK_FLAG)) {
        metrics->flows_noack++;
    }

    if (rwRecGetPkts(rwrec) < SMALL_PKT_CUTOFF) {
        metrics->flows_small++;
    }

    if ((rwRecGetBytes(rwrec) / rwRecGetPkts(rwrec)) > PACKET_PAYLOAD_CUTOFF) {
        metrics->flows_with_payload++;
    }

    if (rwRecGetFlags(rwrec) == RST_FLAG
        || rwRecGetFlags(rwrec) == (SYN_FLAG | ACK_FLAG)
        || rwRecGetFlags(rwrec) == (RST_FLAG | ACK_FLAG))
    {
        metrics->flows_backscatter++;
    }
    add_count(metrics->tcp_flag_counts,
              rwRecGetFlags(rwrec),
              RWSCAN_MAX_FLAGS);

}

void
calculate_tcp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics)
{
    calculate_shared_metrics(event_flows, metrics);

    metrics->proto.tcp.noack_ratio =
        ((double) metrics->flows_noack / metrics->event_size);
    metrics->proto.tcp.small_ratio =
        ((double) metrics->flows_small / metrics->event_size);
    metrics->proto.tcp.sp_dip_ratio =
        ((double) metrics->sp_count / metrics->unique_dips);
    metrics->proto.tcp.payload_ratio =
        ((double) metrics->flows_with_payload / metrics->event_size);
    metrics->proto.tcp.unique_dip_ratio =
        ((double) metrics->unique_dips / metrics->event_size);
    metrics->proto.tcp.backscatter_ratio =
        ((double) metrics->flows_backscatter / metrics->event_size);

    print_verbose_results((RWSCAN_VERBOSE_FH,
                           "\ttcp (%.3f, %.3f, %.3f, %.3f, %.3f, %.3f)",
                           metrics->proto.tcp.noack_ratio,
                           metrics->proto.tcp.small_ratio,
                           metrics->proto.tcp.sp_dip_ratio,
                           metrics->proto.tcp.payload_ratio,
                           metrics->proto.tcp.unique_dip_ratio,
                           metrics->proto.tcp.backscatter_ratio));
}

void
calculate_tcp_scan_probability(
    event_metrics_t    *metrics)
{
    double y = 0;

    y = TCP_BETA0
        + TCP_BETA2 * metrics->proto.tcp.noack_ratio
        + TCP_BETA4 * metrics->proto.tcp.small_ratio
        + TCP_BETA13 * metrics->proto.tcp.sp_dip_ratio
        + TCP_BETA15 * metrics->proto.tcp.payload_ratio
        + TCP_BETA19 * metrics->proto.tcp.unique_dip_ratio
        + TCP_BETA21 * metrics->proto.tcp.backscatter_ratio;
    metrics->scan_probability = exp(y) / (1.0 + exp(y));

    if (metrics->scan_probability > 0.5) {
        metrics->event_class = EVENT_SCAN;
    }

}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
