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

RCSIDENT("$SiLK: rwscan.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwscan.h"
#include "rwscan_db.h"


/* EXTERNAL VARIABLE DEFINITIONS */

/* program options structure */
options_t options;

/* structure for reporting totals for each run */
summary_metrics_t summary_metrics;

/* input files */
sk_options_ctx_t *optctx = NULL;

/* output file */
sk_fileptr_t out_scans;

trw_data_t trw_data;


/* LOCAL VARIABLE DEFINITIONS */

static int numthreads = 0;

static work_queue_t *work_queue;
static work_queue_t *cleanup_queue;

/* Lock to prevent interleaved output from threads */
static pthread_mutex_t output_mutex;


/* LOCAL FUNCTION PROTOTYPES */

static int
process_file(
    const char         *infile);
static int
invoke_trw_model(
    worker_thread_data_t   *work);
static int
invoke_blr_model(
    worker_thread_data_t   *work);


/* FUNCTION DEFINITONS */

int
invoke_trw_model(
    worker_thread_data_t   *work)
{
    rwRec           *flows    = NULL;
    event_metrics_t *metrics  = NULL;
    trw_counters_t  *counters = NULL;

    rwRec   *rwcurr = NULL;
    uint32_t i;
    uint32_t dip_prev = 0xffffffff, dip_curr = 0;

    flows    = work->flows;
    metrics  = work->metrics;
    counters = work->counters;

    metrics->model = RWSCAN_MODEL_TRW;

    for (i = 0; i < metrics->event_size; i++) {
        uint32_t j;

        rwcurr   = &(flows[i]);
        dip_curr = rwRecGetDIPv4(rwcurr);
        if (options.verbose_flows) {
            fprintf(RWSCAN_VERBOSE_FH, "%4u/%4u  ", i + 1,
                    metrics->event_size);
            print_flow(rwcurr);
        }
        counters->flows++;

        if (dip_curr != dip_prev) {
            pthread_mutex_lock(&trw_data.mutex);
            if (skIPSetCheckRecordDIP(trw_data.existing, rwcurr)) {
                counters->hits++;
            } else {
                if ((rwRecGetFlags(rwcurr) & TCP_FLAGS_STATE) == SYN_FLAG) {
                    counters->misses++;
                } else {
                    counters->hits++;
                }
            }
            pthread_mutex_unlock(&trw_data.mutex);
            counters->dips++;
        }
        if ((rwRecGetFlags(rwcurr) & TCP_FLAGS_STATE) == SYN_FLAG) {
            counters->syns++;
        }

        if (rwRecGetFlags(rwcurr) == RST_FLAG
            || rwRecGetFlags(rwcurr) == (SYN_FLAG | ACK_FLAG)
            || rwRecGetFlags(rwcurr) == (RST_FLAG | ACK_FLAG))
        {
            counters->bs++;
        }
        if (rwRecGetFlags(rwcurr) == RST_FLAG
            || rwRecGetFlags(rwcurr)  == (SYN_FLAG | RST_FLAG)
            || rwRecGetFlags(rwcurr)  == (RST_FLAG | ACK_FLAG))
        {
            counters->floodresponse++;
        }
        if (dip_curr != dip_prev) {
            for (j = 0, counters->likelihood = 1.0;
                 j < counters->hits;
                 j++)
            {
                counters->likelihood = counters->likelihood
                                       * (options.trw_theta1 /
                                          options.trw_theta0);
            }
            for (j = 0; j < counters->misses; j++) {
                counters->likelihood =
                    counters->likelihood * ((1.0 - options.trw_theta1) /
                                            (1.0 - options.trw_theta0));
            }
        }
        if (i > RWSCAN_FLOW_CUTOFF) {
            if (options.verbose_progress) {
                fprintf(RWSCAN_VERBOSE_FH,
                        "warning:  TRW giving up after %d flows\n",
                        RWSCAN_FLOW_CUTOFF);
            }
            break;
        }
        if (counters->syns == counters->flows) {
            if (counters->likelihood > TRW_ETA1) {
                /* add to scanners iptree */
                pthread_mutex_lock(&trw_data.mutex);
                skIPTreeAddAddress(trw_data.scanners, rwRecGetSIPv4(rwcurr));
                pthread_mutex_unlock(&trw_data.mutex);
                metrics->scan_probability = counters->likelihood;
                calculate_shared_metrics(flows, metrics);

                print_verbose_results((RWSCAN_VERBOSE_FH, "\ttrw: scan (%f)",
                                       counters->likelihood));
                return (metrics->event_class = EVENT_SCAN);
            } else if (counters->likelihood < TRW_ETA0) {
                /* add to benign iptree */
                pthread_mutex_lock(&trw_data.mutex);
                skIPTreeAddAddress(trw_data.benign, rwRecGetSIPv4(rwcurr));
                pthread_mutex_unlock(&trw_data.mutex);
                metrics->scan_probability = counters->likelihood;
                print_verbose_results((RWSCAN_VERBOSE_FH,
                                       "\ttrw: benign (%f)",
                                       counters->likelihood));
                return (metrics->event_class = EVENT_BENIGN);
            }
        }
        dip_prev = dip_curr;
    }

    if (counters->bs == counters->flows
        && counters->dips > 3 && counters->flows > 100)
    {
        print_verbose_results((RWSCAN_VERBOSE_FH, "\ttrw: backscatter"));
        return (metrics->event_class = EVENT_BACKSCATTER);
    }
    if (counters->dips == 1 && (counters->syns >= (counters->flows * 0.5))
        && ((counters->syns + counters->floodresponse) == counters->flows)
        && counters->flows > 10)
    {
        print_verbose_results((RWSCAN_VERBOSE_FH, "\ttrw: flood"));
        return (metrics->event_class = EVENT_FLOOD);
    }
    print_verbose_results((RWSCAN_VERBOSE_FH, "\ttrw: unknown (%f)",
                           counters->likelihood));
    return (metrics->event_class = EVENT_UNKNOWN);
}

int
invoke_blr_model(
    worker_thread_data_t   *work)
{
    uint32_t         i;
    rwRec           *flows;
    event_metrics_t *metrics;

    flows   = work->flows;
    metrics = work->metrics;

    metrics->model = RWSCAN_MODEL_BLR;
    if (metrics->event_size >= EVENT_FLOW_THRESHOLD) {
        rwRec *rwcurr = NULL;

        /* Loop through each RW record in the event, incrementing various
         * counters which will be used later. */
        for (i = 0; i < metrics->event_size; i++) {
            rwcurr = &(flows[i]);
            if (options.verbose_flows) {
                fprintf(RWSCAN_VERBOSE_FH, "%4u/%4u  ", i + 1,
                        metrics->event_size);
                print_flow(rwcurr);
            }
            switch (rwRecGetProto(rwcurr)) {
              case IPPROTO_ICMP:
                increment_icmp_counters(rwcurr, metrics);
                break;
              case IPPROTO_TCP:
                increment_tcp_counters(rwcurr, metrics);
                break;
              case IPPROTO_UDP:
                increment_udp_counters(rwcurr, metrics);
                break;
              default:
                /* we only detect scans in ICMP, TCP, and UDP protocols */
                skAbortBadCase(rwRecGetProto(rwcurr));
            }
        }

        /* Now that we know we have a scan, we sort by dest IP and source
         * port (or for ICMP, just dest IP) to get further metrics-> */
        qsort(flows, metrics->event_size, sizeof(rwRec),
              rwrec_compare_dip_sport);

        switch (metrics->protocol) {
          case IPPROTO_ICMP:
            calculate_icmp_metrics(flows, metrics);
            calculate_icmp_scan_probability(metrics);
            break;
          case IPPROTO_TCP:
            calculate_tcp_metrics(flows, metrics);
            calculate_tcp_scan_probability(metrics);
            break;
          case IPPROTO_UDP:
            calculate_udp_metrics(flows, metrics);
            calculate_udp_scan_probability(metrics);
            break;
          default:
            skAppPrintErr("%s:%d: invalid protocol", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }

    } else {
        print_verbose_results((RWSCAN_VERBOSE_FH, "\tmissile: small"));
    }
    return metrics->event_class;
}


#ifndef SKTHREAD_UNKNOWN_ID
/* Create a local copy of the function from libsilk-thrd. */
/*
 *    Tell the current thread to ignore all signals except those
 *    indicating a failure (e.g., SIGBUS and SIGSEGV).
 */
static void
skthread_ignore_signals(
    void)
{
    sigset_t sigs;

    sigfillset(&sigs);
    sigdelset(&sigs, SIGABRT);
    sigdelset(&sigs, SIGBUS);
    sigdelset(&sigs, SIGILL);
    sigdelset(&sigs, SIGSEGV);

#ifdef SIGEMT
    sigdelset(&sigs, SIGEMT);
#endif
#ifdef SIGIOT
    sigdelset(&sigs, SIGIOT);
#endif
#ifdef SIGSYS
    sigdelset(&sigs, SIGSYS);
#endif

    pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}
#endif  /* #ifndef SKTHREAD_UNKNOWN_ID */


/*  THREAD ENTRY POINT  */
void *
worker_thread(
    void               *myarg)
{
    work_queue_node_t    *mynode;
    worker_thread_data_t *mywork;
    cleanup_node_t       *cleanup_node;

    rwRec           *flows;
    event_metrics_t *metrics;
    skipaddr_t       ipaddr;
    char             ipstr[SKIPADDR_STRLEN];

    /* ignore all signals */
    skthread_ignore_signals();

    cleanup_node = (cleanup_node_t *) myarg;
    pthread_mutex_lock(&work_queue->mutex);

    while (work_queue->active) {
        while (workqueue_depth(work_queue) == 0 && work_queue->active) {
            pthread_cond_wait(&work_queue->cond_posted, &work_queue->mutex);
        }
        if (!work_queue->active) {
            if (options.verbose_progress) {
                fprintf(RWSCAN_VERBOSE_FH, "work queue no longer active\n");
            }
            break;
        }
        workqueue_get(work_queue, &mynode);
        mywork = (worker_thread_data_t *) mynode;

        flows   = mywork->flows;
        metrics = mywork->metrics;

        pthread_mutex_unlock(&work_queue->mutex);

        skipaddrSetV4(&ipaddr, &metrics->sip);
        skipaddrString(ipstr, &ipaddr, 0);
        print_verbose_results((RWSCAN_VERBOSE_FH, "%d. %s [%d] (%u) ",
                               cleanup_node->threadnum, ipstr,
                               metrics->protocol, metrics->event_size));

        if ((metrics->protocol == IPPROTO_TCP)
            && (options.scan_model == RWSCAN_MODEL_HYBRID
                || options.scan_model == RWSCAN_MODEL_TRW))
        {
            mywork->counters
                = (trw_counters_t*)calloc(1, sizeof(trw_counters_t));
            if (mywork->counters == NULL) {
                skAppPrintOutOfMemory("TRW counters");
                return NULL;
            }
            memset(mywork->counters, 0, sizeof(trw_counters_t));
            invoke_trw_model(mywork);
        }
        if ((metrics->event_class != EVENT_SCAN
             && metrics->event_class != EVENT_FLOOD
             && metrics->event_class != EVENT_BACKSCATTER)
            && (options.scan_model == RWSCAN_MODEL_HYBRID
                || options.scan_model == RWSCAN_MODEL_BLR))
        {
            qsort(flows, metrics->event_size, sizeof(rwRec),
                  rwrec_compare_proto_stime);
            invoke_blr_model(mywork);
        }
        switch (metrics->event_class) {
          case EVENT_SCAN:
          {
              scan_info_t *scan = (scan_info_t*)malloc(sizeof(scan_info_t));

              print_verbose_results((RWSCAN_VERBOSE_FH, "\tscan (%.3f)\n",
                                     metrics->scan_probability));

              if (scan == NULL) {
                  skAppPrintOutOfMemory("scan data");
                  return NULL;
              }

              /* yup, it's a scan */
              pthread_mutex_lock(&summary_metrics.mutex);
              summary_metrics.scanners++;
              pthread_mutex_unlock(&summary_metrics.mutex);
              memset(scan, 0, sizeof(scan_info_t));
              scan->ip        = metrics->sip;
              scan->model     = metrics->model;
              scan->stime     = metrics->stime;
              scan->etime     = metrics->etime;
              scan->flows     = metrics->event_size;
              scan->pkts      = metrics->pkts;
              scan->bytes     = metrics->bytes;
              scan->proto     = metrics->protocol;
              scan->scan_prob = metrics->scan_probability;

              assert(scan->scan_prob > 0);

              pthread_mutex_lock(&output_mutex);
              write_scan_record(scan, out_scans.of_fp, options.no_columns,
                                options.delimiter,
                                options.model_fields);
              pthread_mutex_unlock(&output_mutex);
              free(scan);
          }
            break;
          case EVENT_BENIGN:
            print_verbose_results((RWSCAN_VERBOSE_FH, "\tbenign (%.3f)\n",
                                   metrics->scan_probability));
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.benign++;
            pthread_mutex_unlock(&summary_metrics.mutex);
            break;
          case EVENT_BACKSCATTER:
            print_verbose_results((RWSCAN_VERBOSE_FH, "\tbackscatter\n"));
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.backscatter++;
            pthread_mutex_unlock(&summary_metrics.mutex);
            break;
          case EVENT_FLOOD:
            print_verbose_results((RWSCAN_VERBOSE_FH, "\tflood\n"));
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.flooders++;
            pthread_mutex_unlock(&summary_metrics.mutex);
            break;
          case EVENT_UNKNOWN:
            print_verbose_results((RWSCAN_VERBOSE_FH, "\tunknown (%.3f)\n",
                                   metrics->scan_probability));
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.unknown++;
            pthread_mutex_unlock(&summary_metrics.mutex);
            break;
        }

        if (mywork->flows) {
            free(mywork->flows);
        }
        if (mywork->metrics) {
            free(mywork->metrics);
        }
        if (mywork->counters) {
            free(mywork->counters);
        }
        free(mywork);
        pthread_mutex_lock(&work_queue->mutex);
        work_queue->pending--;
        pthread_cond_signal(&work_queue->cond_avail);
    }
    if (options.verbose_progress) {
        fprintf(RWSCAN_VERBOSE_FH, "work queue deactivated\n");
    }

    pthread_mutex_unlock(&work_queue->mutex);
    workqueue_put(cleanup_queue, &(cleanup_node->node));
    pthread_cond_signal(&cleanup_queue->cond_posted);

    if (options.verbose_progress) {
        fprintf(RWSCAN_VERBOSE_FH, "thread %d shutting down...\n",
                cleanup_node->threadnum);
    }
    return NULL;
}


int
process_file(
    const char         *infile)
{
    skstream_t      *in;
    rwRec           *event_flows = NULL; /* all flows for a given sip/proto */
    rwRec            rwrec;              /* holds each record read */
    uint32_t         last_sip   = 0;
    uint32_t         last_proto = 0;
    int              done       = 0;
    event_metrics_t *metrics    = NULL;
    int              retval     = -1;
    int              rv;

    metrics = (event_metrics_t*)calloc(1, sizeof(event_metrics_t));
    if (metrics == NULL) {
        skAppPrintOutOfMemory("metrics data");
        return -1;
    }

    RWREC_CLEAR(&rwrec);
    /* open the input file */

    rv = skStreamOpenSilkFlow(&in, infile, SK_IO_READ);
    if (rv) {
        skStreamPrintLastErr(in, rv, &skAppPrintErr);
        goto END;
    }
    skStreamSetIPv6Policy(in, SK_IPV6POLICY_ASV4);

    /* The main program runloop. */
    while (!done) {
        /* Read in a single RW record. */
        if (!skStreamReadRecord(in, &rwrec)) {
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.total_flows++;
            pthread_mutex_unlock(&summary_metrics.mutex);
        } else {
            done = 1;
        }

        /* If the proto is one we don't care about, read the next record. */
        if ((rwRecGetProto(&rwrec) != IPPROTO_ICMP)
            && (rwRecGetProto(&rwrec) != IPPROTO_TCP)
            && (rwRecGetProto(&rwrec) != IPPROTO_UDP))
        {
            pthread_mutex_lock(&summary_metrics.mutex);
            summary_metrics.ignored_flows++;
            pthread_mutex_unlock(&summary_metrics.mutex);
            continue;
        }
        /* These are the conditions under which we process the current event
         * (if applicable) and begin a new one. */
        if (rwRecGetSIPv4(&rwrec)!= last_sip
            || rwRecGetProto(&rwrec) != last_proto || done)
        {
            /* If we have flows to examine, do so. */
            if (metrics->event_size > 0) {
                worker_thread_data_t *mywork = NULL;
                uint32_t prog_ip;

                prog_ip = rwRecGetSIPv4(&rwrec) & options.verbose_progress;
                if ((last_sip & options.verbose_progress) != prog_ip) {
                    char ipstr[SKIPADDR_STRLEN];
                    skipaddr_t ipaddr;
                    skipaddrSetV4(&ipaddr, &prog_ip);
                    fprintf(RWSCAN_VERBOSE_FH, "progress: %s\n",
                            skipaddrString(ipstr, &ipaddr, 0));
                }
                mywork = ((worker_thread_data_t*)
                          calloc(1, sizeof(worker_thread_data_t)));
                if (mywork == NULL) {
                    skAppPrintOutOfMemory("worker thread data");
                    goto END;
                }
                mywork->flows   = event_flows;
                mywork->metrics = metrics;
                workqueue_put(work_queue, &(mywork->node));

                metrics     = NULL;
                event_flows = NULL;
                mywork      = NULL;

            }

            /* begin new event */
            if (event_flows == NULL) {
                event_flows = (rwRec*)malloc(RWSCAN_ALLOC_SIZE *sizeof(rwRec));
                if (event_flows == NULL) {
                    skAppPrintOutOfMemory("event flow data");
                    goto END;
                }
            } else {
                rwRec *old_event_flows = event_flows;
                event_flows = (rwRec*)realloc(event_flows,
                                              (RWSCAN_ALLOC_SIZE
                                               * sizeof(rwRec)));
                if (event_flows == NULL) {
                    skAppPrintOutOfMemory("event flow data");
                    event_flows = old_event_flows;
                    goto END;
                }
            }

            if (metrics == NULL) {
                metrics = (event_metrics_t*)malloc(sizeof(event_metrics_t));
                if (metrics == NULL) {
                    skAppPrintOutOfMemory("metrics data");
                    goto END;
                }
            }

            memset(metrics, 0, sizeof(event_metrics_t));
            metrics->protocol = rwRecGetProto(&rwrec) ;
            metrics->sip      = rwRecGetSIPv4(&rwrec);
            metrics->stime    = rwRecGetStartSeconds(&rwrec);
            metrics->etime    = rwRecGetEndSeconds(&rwrec);

        } else {
            /* No new event, so keep adding flows to the current event. */
            if (rwRecGetStartSeconds(&rwrec) < metrics->stime) {
                metrics->stime = rwRecGetStartSeconds(&rwrec);
            }
            if (rwRecGetStartSeconds(&rwrec) > metrics->etime) {
                metrics->etime = rwRecGetEndSeconds(&rwrec);
            }
        }

        if (!(metrics->event_size % RWSCAN_ALLOC_SIZE)
            && (metrics->event_size != 0))
        {
            rwRec *old_event_flows = event_flows;
            event_flows
                = (rwRec*)realloc(event_flows,
                                  ((metrics->event_size + RWSCAN_ALLOC_SIZE)
                                   * sizeof(rwRec)));
            if (event_flows == NULL) {
                skAppPrintOutOfMemory("event flow data");
                event_flows = old_event_flows;
                goto END;
            }
        }
        metrics->event_size++;
        memcpy(&(event_flows[metrics->event_size - 1]), &rwrec,
               sizeof(rwRec));

        last_sip   = rwRecGetSIPv4(&rwrec);
        last_proto = rwRecGetProto(&rwrec);
    }

    retval = 0;

  END:
    skStreamDestroy(&in);
    if (event_flows != NULL) {
        free(event_flows);
    }
    if (metrics != NULL) {
        free(metrics);
    }
    return retval;
}

int
create_worker_threads(
    void)
{
    uint32_t        x;
    cleanup_node_t *curnode;

    for (x = 1; x <= options.worker_threads; x++) {
        curnode = (cleanup_node_t*)malloc(sizeof(cleanup_node_t));
        if (!curnode) {
            return 1;
        }
        memset(curnode, 0, sizeof(cleanup_node_t));
        curnode->threadnum = x;
        if (pthread_create(&curnode->tid, NULL, worker_thread, (void*)curnode))
        {
            return 1;
        }
        if (options.verbose_progress) {
            fprintf(RWSCAN_VERBOSE_FH, "created worker thread %u\n", x);
        }
        numthreads++;
    }
    return 0;
}

void
join_threads(
    void)
{
    cleanup_node_t    *curnode;
    work_queue_node_t *mynode;

    if (options.verbose_progress) {
        fprintf(RWSCAN_VERBOSE_FH, "joining threads...\n");
    }

    while (numthreads) {
        pthread_mutex_lock(&cleanup_queue->mutex);

        while (workqueue_depth(cleanup_queue) == 0) {
            pthread_cond_wait(&cleanup_queue->cond_posted,
                              &cleanup_queue->mutex);
        }

        workqueue_get(cleanup_queue, &mynode);
        curnode = (cleanup_node_t *) mynode;

        pthread_mutex_unlock(&cleanup_queue->mutex);
        pthread_join(curnode->tid, NULL);
        if (options.verbose_progress) {
            fprintf(RWSCAN_VERBOSE_FH, "joined with thread %d\n",
                    curnode->threadnum);
        }
        free(curnode);
        numthreads--;
    }
}



int main(
    int    argc,
    char **argv)
{
    char *input_file;
    int count;
    int rv = 0;

    /* set up for application */
    appSetup(argc, argv);
    pthread_mutex_init(&output_mutex, NULL);

    pthread_mutex_init(&summary_metrics.mutex, NULL);

    cleanup_queue = workqueue_create(options.worker_threads);

    work_queue = workqueue_create(options.work_queue_depth);

    if (!options.no_titles) {
        write_scan_header(out_scans.of_fp, options.no_columns,
                          options.delimiter, options.model_fields);
    }

    if (create_worker_threads()) {
        fprintf(RWSCAN_VERBOSE_FH, "Error starting worker threads!\n");
        skAbort();
    }
    while (skOptionsCtxNextArgument(optctx, &input_file) == 0) {
        if (options.verbose_progress) {
            fprintf(RWSCAN_VERBOSE_FH, "processing: %s\n", input_file);
        }
        process_file(input_file);
    }

    pthread_mutex_lock(&work_queue->mutex);
    while ((count = workqueue_depth(work_queue)) > 0) {
        if (options.verbose_progress) {
            fprintf(RWSCAN_VERBOSE_FH,
                    "waiting for %d worker thread%s to finish...\n",
                    count, ((count > 1) ? "s" : ""));
        }
        pthread_cond_wait(&work_queue->cond_avail, &work_queue->mutex);
    }
    pthread_mutex_unlock(&work_queue->mutex);

    workqueue_deactivate(work_queue);
    join_threads();

    workqueue_destroy(work_queue);
    workqueue_destroy(cleanup_queue);

    if (options.verbose_progress) {
        fprintf(RWSCAN_VERBOSE_FH, "Read %u flows\n",
                summary_metrics.total_flows);
        fprintf(RWSCAN_VERBOSE_FH, "\t%u scanners\n",
                summary_metrics.scanners);
        fprintf(RWSCAN_VERBOSE_FH, "\t%u benign\n", summary_metrics.benign);
        fprintf(RWSCAN_VERBOSE_FH, "\t%u unknown\n", summary_metrics.unknown);
        fprintf(RWSCAN_VERBOSE_FH, "\t\t%u backscatter\n",
                summary_metrics.backscatter);
        fprintf(RWSCAN_VERBOSE_FH, "\t\t%u SYN flooders\n",
                summary_metrics.flooders);
    }

    /* done */
    appTeardown();

    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
