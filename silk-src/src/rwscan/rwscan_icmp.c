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

RCSIDENT("$SiLK: rwscan_icmp.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwscan.h"


void
increment_icmp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics)
{
    uint8_t type = 0, code = 0;

    type = rwRecGetIcmpType(rwrec);
    code = rwRecGetIcmpCode(rwrec);

    if ((type == 8 || type == 13 || type == 15 || type == 17)
        && (code == 0))
    {
        metrics->flows_icmp_echo++;
    }
}


void
calculate_icmp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics)
{
    uint32_t i;
    uint32_t class_c_next = 0, class_c_curr = 0;
    uint32_t dip_next     = 0, dip_curr = 0;

    uint8_t  run               = 1, max_run_curr = 1;
    uint32_t class_c_run       = 1, max_class_c_run = 1;
    uint8_t  class_c_dip_count = 1, max_class_c_dip_count = 1;

    rwRec *rwcurr = NULL;
    rwRec *rwnext = NULL;

    calculate_shared_metrics(event_flows, metrics);

    for (i = 0; i < metrics->event_size; i++) {
        rwcurr = &(event_flows[i]);
        rwnext =
            (i + 1 < (metrics->event_size)) ? &(event_flows[i + 1]) : NULL;

        dip_curr     = rwRecGetDIPv4(rwcurr);
        class_c_curr = dip_curr & 0xFFFFFF00;

        if (rwnext != NULL) {
            dip_next     = rwRecGetDIPv4(rwnext);
            class_c_next = dip_next & 0xFFFFFF00;
        }

        if ((rwnext != NULL) && (class_c_curr == class_c_next)) {
            if (dip_curr != dip_next) {
                class_c_dip_count++;
                if (dip_next - dip_curr == 1) {
                    run++;
                } else {
                    if (run > max_run_curr) {
                        max_run_curr = run;
                    }
                    run = 1;
                }
            }
        } else {
            if (((class_c_next - class_c_curr) >> 8) == 1) {
                class_c_run++;
            } else {
                if (class_c_run > max_class_c_run) {
                    max_class_c_run = class_c_run;
                }
                class_c_run = 1;
            }

            if (max_run_curr >
                metrics->proto.icmp.max_class_c_dip_run_length)
            {
                metrics->proto.icmp.max_class_c_dip_run_length = max_run_curr;
            }

            if (class_c_dip_count > max_class_c_dip_count) {
                max_class_c_dip_count = class_c_dip_count;
            }
            class_c_dip_count = 1;
        }
    }

    metrics->proto.icmp.max_class_c_subnet_run_length = max_class_c_run;

    metrics->proto.icmp.echo_ratio =
        ((double) metrics->flows_icmp_echo / metrics->event_size);
    metrics->proto.icmp.max_class_c_dip_count = max_class_c_dip_count;
    metrics->proto.icmp.total_dip_count       = metrics->unique_dsts;

    print_verbose_results((RWSCAN_VERBOSE_FH, "\ticmp (%u, %u, %u, %u, %.3f)",
                           metrics->proto.icmp.max_class_c_subnet_run_length,
                           metrics->proto.icmp.max_class_c_dip_run_length,
                           metrics->proto.icmp.max_class_c_dip_count,
                           metrics->proto.icmp.total_dip_count,
                           metrics->proto.icmp.echo_ratio));
}


void
calculate_icmp_scan_probability(
    event_metrics_t    *metrics)
{
    double y = 0;

    y = ICMP_BETA0
        + ICMP_BETA1 * metrics->proto.icmp.max_class_c_subnet_run_length
        + ICMP_BETA5 * metrics->proto.icmp.max_class_c_dip_run_length
        + ICMP_BETA6 * metrics->proto.icmp.max_class_c_dip_count
        + ICMP_BETA11 * metrics->proto.icmp.total_dip_count
        + ICMP_BETA22 * metrics->proto.icmp.echo_ratio;

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
