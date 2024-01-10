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
#ifndef _RWSCAN_H
#define _RWSCAN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWSCAN_H, "$SiLK: rwscan.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/iptree.h>
#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include "rwscan_workqueue.h"

/* bound on false positives */
#define TRW_ALPHA   0.01
/* detection probability */
#define TRW_BETA    0.99

/* lower bound */
#define TRW_ETA0    ( (1-TRW_BETA)/(1-TRW_ALPHA) )
/* upper bound */
#define TRW_ETA1    (TRW_BETA/TRW_ALPHA)

/*
 *  The values used here require 10 success destination IPs to be valid, with
 *  no invalid ones, before the hypothesis is that the source is benign.
 *  Conversely, 6 invalid destination IPs must be chosen, with no valid ones,
 *  before the accepted hypothesis is that the source is malicious.
 */

/*
 *  Probability that connection is a success given the hypothesis that the
 *  remote source is benign.
 */
#define TRW_DEFAULT_THETA0  0.8

/*
 *  Probability that connection is a success given the hypothesis that the
 *  remote source is malicious.
 */
#define TRW_DEFAULT_THETA1 0.2

/*
 *  Conversely, the probability that the connection is a failure given
 *  the hypothesis that the remote source is benign is 1.0 - THETA0, and
 *  the probability that the connection is a failure given the hypothesis
 *  that the remote source is malicious is 1.0 - THETA1
 */

#define EVENT_GAP 300
#define EVENT_FLOW_THRESHOLD 32

#define ICMP_BETA0   -4.307079
#define ICMP_BETA1   -0.08245704
#define ICMP_BETA5   -0.02800612
#define ICMP_BETA6   0.04877852
#define ICMP_BETA11  -0.000006398878
#define ICMP_BETA22  4.016751

#define TCP_BETA0    -2.838353611
#define TCP_BETA2    3.309023427
#define TCP_BETA4    -0.157047027
#define TCP_BETA13   -0.002319304
#define TCP_BETA15   -1.047413699
#define TCP_BETA19   3.163018548
#define TCP_BETA21   -3.260270447

#define UDP_BETA0     -1.887907966
#define UDP_BETA4     0.543683505
#define UDP_BETA5     0.025150994
#define UDP_BETA8     0.529094801
#define UDP_BETA10    -1.244182168
#define UDP_BETA13    -0.001841634
#define UDP_BETA15    -0.224548546
#define UDP_BETA20    -0.697943155

#define SMALL_PKT_CUTOFF 3
#define PACKET_PAYLOAD_CUTOFF 60

/* TRW will give up after hitting this number of flows */
#define RWSCAN_FLOW_CUTOFF 100000

#define RWSCAN_ALLOC_SIZE 65536

#define RWSCAN_MAX_FLAGS 64
#define RWSCAN_MAX_PORTS 65536

#define RWSCAN_MAX_FIELD_DEFS 256

#define RWSCAN_VERBOSE_FH stderr

#define print_verbose_results(args)                                  \
    if (options.verbose_results &&                                   \
        (metrics->event_size >= options.verbose_results))            \
    {                                                                \
        flockfile(RWSCAN_VERBOSE_FH);                                \
        fprintf args;                                                \
        funlockfile(RWSCAN_VERBOSE_FH);                              \
    }                                                                \


#define TCP_FLAGS_STATE (FIN_FLAG | SYN_FLAG | RST_FLAG | ACK_FLAG)


enum EventClassification
{
    EVENT_UNKNOWN = 0,
    EVENT_BENIGN,
    EVENT_BACKSCATTER,
    EVENT_FLOOD,
    EVENT_SCAN
};

enum ScanModel
{
    RWSCAN_MODEL_HYBRID = 0,
    RWSCAN_MODEL_TRW,
    RWSCAN_MODEL_BLR
};

typedef enum field_id {
    RWSCAN_FIELD_SIP = 1,
    RWSCAN_FIELD_PROTO,
    RWSCAN_FIELD_STIME,
    RWSCAN_FIELD_ETIME,
    RWSCAN_FIELD_FLOWS,
    RWSCAN_FIELD_PKTS,
    RWSCAN_FIELD_BYTES,
    RWSCAN_FIELD_MODEL,
    RWSCAN_FIELD_SCAN_PROB
} field_id_t;

struct field_def_st {
    field_id_t  id;
    const char *label;
    uint8_t     width;
};

typedef struct field_def_st field_def_t;

/* User options */
typedef struct options_st {
    uint32_t     scan_model;
    const char  *trw_internal_set_file;
    double       trw_theta0;
    double       trw_theta1;
    const char  *output_file;
    uint8_t      integer_ips;
    uint8_t      model_fields;
    uint8_t      no_titles;
    uint8_t      no_columns;
    uint8_t      verbose_flows;
    uint32_t     verbose_results;
    char         delimiter;
    uint8_t      no_final_delimiter;
    uint32_t     verbose_progress;
    uint32_t     worker_threads;
    uint32_t     work_queue_depth;
} options_t;

typedef struct summary_metrics_st {
    pthread_mutex_t mutex;
    uint32_t        total_flows;
    uint32_t        total_flows_processed;
    uint32_t        ignored_flows;
    uint32_t        scanners;
    uint32_t        benign;
    uint32_t        backscatter;
    uint32_t        flooders;
    uint32_t        unknown;
} summary_metrics_t;

typedef struct top_ten_st {
    uint32_t value[10];
    double   percent[10];
    uint32_t occurrences[10];
    uint32_t uniq;
} top_ten_t;

typedef struct top_list_st {
    uint32_t value;
    uint32_t count;
    struct top_list_st *next;
    struct top_list_st *prev;
} top_list_t;

typedef struct event_metrics_st {
    uint8_t   protocol;
    uint32_t  sip;
    uint32_t  event_size;

    uint32_t  stime;
    uint32_t  etime;

    uint32_t  sp_count;
    uint32_t  unique_dsts;
    uint32_t  unique_dips;
    uint32_t  unique_ports;

    uint32_t  bytes;
    uint32_t  pkts;

    uint32_t  unique_sp_count;

    uint32_t  flows_noack;
    uint32_t  flows_small;
    uint32_t  flows_with_payload;
    uint32_t  flows_backscatter;

    uint32_t  flows_icmp_echo;

    uint32_t  tcp_flag_counts[RWSCAN_MAX_FLAGS];
    top_ten_t top_tcp_flags;

    union {
        struct {
            uint32_t max_class_c_subnet_run_length;
            uint32_t max_class_c_dip_run_length;
            uint32_t max_class_c_dip_count;
            uint32_t total_dip_count;
            double   echo_ratio;
        } icmp;
        struct {
            double noack_ratio;
            double small_ratio;
            double sp_dip_ratio;
            double payload_ratio;
            double unique_dip_ratio;
            double backscatter_ratio;
        } tcp;
        struct {
            double   small_ratio;
            uint32_t max_class_c_dip_run_length;
            uint32_t max_low_dp_hit;
            uint32_t max_low_port_run_length;
            double   sp_dip_ratio;
            double   payload_ratio;
            double   unique_sp_ratio;
        } udp;
    } proto;

    enum EventClassification event_class;
    double scan_probability;
    enum ScanModel model;
} event_metrics_t;

typedef struct trw_counters_st {
    uint32_t flows;
    uint32_t dips;
    uint32_t hits;              /* holds number of hits */
    uint32_t misses;            /* holds number of misses */
    uint32_t syns;              /* number of SYNs */
    uint32_t bs;                /* number of backscatter flows */
    uint32_t floodresponse;
    double   likelihood;        /* used in hypothesis testing */
} trw_counters_t;

typedef struct trw_data_st {
    pthread_mutex_t mutex;
    skipset_t      *existing;
    skIPTree_t     *benign;     /* holds benign sources */
    skIPTree_t     *scanners;   /* holds scanning sources */
} trw_data_t;

typedef struct scan_info_st {
    uint32_t ip;
    char     country[3];
    uint32_t stime;
    uint32_t etime;
    uint32_t uniq_dsts;
    uint32_t flows;
    uint32_t pkts;
    uint32_t bytes;
    uint8_t  proto;
    double   scan_prob;
    enum ScanModel model;
} scan_info_t;


typedef struct cleanup_node_st {
    work_queue_node_t node;
    int               threadnum;
    pthread_t         tid;
} cleanup_node_t;

typedef struct worker_thread_data_st {
    work_queue_node_t node;
    rwRec            *flows;
    event_metrics_t  *metrics;
    trw_counters_t   *counters;
} worker_thread_data_t;


extern options_t         options;
extern trw_data_t        trw_data;
extern summary_metrics_t summary_metrics;

extern sk_options_ctx_t     *optctx;
extern sk_fileptr_t          out_scans;

extern work_queue_t *stats_queue;

extern int update_stats;

/* utility functions */

void
appSetup(
    int                 argc,
    char              **argv);

void
appTeardown(
    void);

void *
worker_thread(
    void               *myarg);
int
create_worker_threads(
    void);
void
join_threads(
    void);

void
print_flow(
    const rwRec        *rwcurr);

/* sort function for the TRW model */
int
rwrec_compare_dip(
    const void         *a,
    const void         *b);

/* sort function for the first stage of BLR model */
int
rwrec_compare_proto_stime(
    const void         *a,
    const void         *b);

/* sort function for the second stage of BLR model */
int
rwrec_compare_dip_sport(
    const void         *a,
    const void         *b);


void
calculate_shared_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics);


/* helper functions for TCP events */
void
add_count(
    uint32_t           *counts,
    uint32_t            value,
    uint32_t            max);
void
analyze_tcp_event(
    event_metrics_t    *metrics);
top_ten_t
build_top_ten(
    uint32_t           *,
    uint32_t);

void
increment_tcp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics);

void
calculate_tcp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics);

void
calculate_tcp_scan_probability(
    event_metrics_t    *metrics);


/* helper functions for UDP events */
void
increment_udp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics);

void
calculate_udp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics);

void
calculate_udp_scan_probability(
    event_metrics_t    *metrics);


/* helper functions for ICMP events */
void
increment_icmp_counters(
    rwRec              *rwrec,
    event_metrics_t    *metrics);

void
calculate_icmp_metrics(
    rwRec              *event_flows,
    event_metrics_t    *metrics);

void
calculate_icmp_scan_probability(
    event_metrics_t    *metrics);

#ifdef __cplusplus
}
#endif
#endif /* _RWSCAN_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
