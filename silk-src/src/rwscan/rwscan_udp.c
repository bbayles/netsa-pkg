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

RCSIDENT("$SiLK: rwscan_udp.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwscan.h"


void
increment_udp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics)
{
    if (rwRecGetPkts(rwrec) < SMALL_PKT_CUTOFF) {
        metrics->flows_small++;
    }

    if ((rwRecGetBytes(rwrec) / rwRecGetPkts(rwrec)) > PACKET_PAYLOAD_CUTOFF) {
        metrics->flows_with_payload++;
    }

}

void
calculate_udp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics)
{
    uint32_t     i;
    uint32_t     class_c_next = 0, class_c_curr = 0;
    uint32_t     dip_next     = 0, dip_curr = 0;
    sk_bitmap_t *low_dp_bitmap;
    uint32_t     low_dp_hit = 0;

    sk_bitmap_t *sp_bitmap;

    uint32_t subnet_run = 1, max_subnet_run = 1;
    rwRec   *rwcurr     = NULL;
    rwRec   *rwnext     = NULL;

    skBitmapCreate(&low_dp_bitmap, 1024);
    skBitmapCreate(&sp_bitmap, UINT16_MAX);
    if (!low_dp_bitmap || !sp_bitmap) {
        skAppPrintOutOfMemory("bitmap");
        skBitmapDestroy(&low_dp_bitmap);
        skBitmapDestroy(&sp_bitmap);
        return;
    }

    calculate_shared_metrics(event_flows, metrics);

    rwcurr = event_flows;
    rwnext = event_flows;

    skBitmapSetBit(low_dp_bitmap, rwRecGetDPort(rwcurr));
    dip_next     = rwRecGetDIPv4(rwnext);
    class_c_next = dip_next & 0xFFFFFF00;

    for (i = 0; i < metrics->event_size; ++i, ++rwcurr) {
        skBitmapSetBit(sp_bitmap, rwRecGetSPort(rwcurr));

        dip_curr     = dip_next;
        class_c_curr = class_c_next;

        if (i + 1 == metrics->event_size) {
            rwnext = NULL;
            dip_next = dip_curr - 1;
            class_c_next = class_c_curr - 0x100;

            if (subnet_run > max_subnet_run) {
                max_subnet_run = subnet_run;
            }
        } else {
            ++rwnext;

            dip_next     = rwRecGetDIPv4(rwnext);
            class_c_next = dip_next & 0xFFFFFF00;

            if (dip_curr == dip_next) {
                skBitmapSetBit(low_dp_bitmap, rwRecGetDPort(rwnext));
            } else if (class_c_curr == class_c_next) {
                if (dip_next - dip_curr == 1) {
                    ++subnet_run;
                } else if (subnet_run > max_subnet_run) {
                    max_subnet_run = subnet_run;
                    subnet_run = 1;
                }
            }
        }

        if (dip_curr != dip_next) {
            uint32_t j;
            uint32_t port_run = 0;

            /* determine longest consecutive run of low ports */
            for (j = 0; j < 1024; j++) {
                if (skBitmapGetBit(low_dp_bitmap, j)) {
                    ++port_run;
                } else if (port_run) {
                    if (port_run > metrics->proto.udp.max_low_port_run_length){
                        metrics->proto.udp.max_low_port_run_length = port_run;
                    }
                    port_run = 0;
                }
            }

            /* determine number of hits on low ports */
            low_dp_hit = skBitmapGetHighCount(low_dp_bitmap);
            if (low_dp_hit > metrics->proto.udp.max_low_dp_hit) {
                metrics->proto.udp.max_low_dp_hit = low_dp_hit;
            }

            /* reset */
            skBitmapClearAllBits(low_dp_bitmap);
            skBitmapSetBit(low_dp_bitmap, rwRecGetDPort(rwcurr));
        }

        if (class_c_curr != class_c_next) {
            if (max_subnet_run > metrics->proto.udp.max_class_c_dip_run_length)
            {
                metrics->proto.udp.max_class_c_dip_run_length = max_subnet_run;
            }
            max_subnet_run = 1;
        }
    }

    metrics->unique_sp_count = skBitmapGetHighCount(sp_bitmap);

    metrics->proto.udp.sp_dip_ratio =
        ((double) metrics->sp_count / metrics->unique_dsts);
    metrics->proto.udp.payload_ratio =
        ((double) metrics->flows_with_payload / metrics->event_size);
    metrics->proto.udp.unique_sp_ratio =
        ((double) metrics->unique_sp_count / metrics->event_size);
    metrics->proto.udp.small_ratio =
        ((double) metrics->flows_small / metrics->event_size);

    print_verbose_results((RWSCAN_VERBOSE_FH,
                           "\tudp (%.3f, %u, %u, %u, %.3f, %.3f, %.3f)",
                           metrics->proto.udp.small_ratio,
                           metrics->proto.udp.max_class_c_dip_run_length,
                           metrics->proto.udp.max_low_dp_hit,
                           metrics->proto.udp.max_low_port_run_length,
                           metrics->proto.udp.sp_dip_ratio,
                           metrics->proto.udp.payload_ratio,
                           metrics->proto.udp.unique_sp_ratio));

    skBitmapDestroy(&low_dp_bitmap);
    skBitmapDestroy(&sp_bitmap);
}

void
calculate_udp_scan_probability(
    event_metrics_t    *metrics)
{
    double y = 0;

    y = UDP_BETA0
        + UDP_BETA4 * metrics->proto.udp.small_ratio
        + UDP_BETA5 * metrics->proto.udp.max_class_c_dip_run_length
        + UDP_BETA8 * metrics->proto.udp.max_low_dp_hit
        + UDP_BETA10 * metrics->proto.udp.max_low_port_run_length
        + UDP_BETA13 * metrics->proto.udp.sp_dip_ratio
        + UDP_BETA15 * metrics->proto.udp.payload_ratio
        + UDP_BETA20 * metrics->proto.udp.unique_sp_ratio;

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
