/*
 *  Copyright 2015-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafzcbalance.c
 *  Performs load balancing required to run yaf with PFRING ZC.
 *
 *  ------------------------------------------------------------------------
 *  Author: Emily Sarneso
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

/**
 *  @file yafzcbalance.c
 *
 *  @brief This file performs the load balancing required to run yaf with
 *  PFRING ZC
 */

#define _GNU_SOURCE
#define _YAF_SOURCE_

#include <yaf/autoinc.h>
#include <airframe/privconfig.h>
#include <airframe/logconfig.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <glib.h>
#include "pfring.h"
#include "pfring_zc.h"
#include "pfring_mod_sysdig.h"


#define MAX_CARD_SLOTS     32768
#define POOL_SIZE          16
#define QUEUE_LEN          8192
#define CACHE_LINE_LEn     64
#define STATS_TIMEOUT      10

static char    *inspec = NULL;
static int      numout = 1;
static int      cluster = 99;
static int      core = -1;
static int      time_core = -1;
static gboolean yz_daemon = FALSE;
static int      stats_timeout = 0;
static char    *pidfile = NULL;
static int      sleep_time = STATS_TIMEOUT;
static int      yzstat = 0;
static pfring_zc_worker *zw;
static pfring_zc_queue **inzqs;
static pfring_zc_queue **outzqs;

static int yzquit = 0;
volatile u_int64_t      *pulse_timestamp_ns;
static struct timeval    start_time;

#define SET_TS_FROM_PULSE(p, t)     \
    {                               \
        u_int64_t __pts = t;        \
        p->ts.tv_sec = __pts >> 32; \
        p->ts.tv_nsec = __pts & 0xffffffff; }

static AirOptionEntry yz_core_option[] = {
    AF_OPTION("in", 'i', 0, AF_OPT_TYPE_STRING, &inspec,
              "Device (comma-separated list)", "device"),
    AF_OPTION("cluster", 'c', 0, AF_OPT_TYPE_INT, &cluster,
              "Cluster ID [99]", "cluster id"),
    AF_OPTION("num", 'n', 0, AF_OPT_TYPE_INT, &numout,
              "Number of application instances [1]", "num inst"),
    AF_OPTION("core", 'g', 0, AF_OPT_TYPE_INT, &core,
              "Bind this application to core", "core_id"),
    AF_OPTION("time", 't', 0, AF_OPT_TYPE_INT, &time_core,
              "Bind the time pulse thread to core", "core_id"),
    AF_OPTION( "pidfile", 'p', 0, AF_OPT_TYPE_STRING, &pidfile,
               "Write pid to the specified file", "pid file"),
    AF_OPTION("daemon", 'd', 0, AF_OPT_TYPE_NONE, &yz_daemon,
              "Daemon mode", NULL),
    AF_OPTION("stats", 's', 0, AF_OPT_TYPE_INT, &stats_timeout,
              "Seconds between statistics logging [0 for none]", "seconds"),
    AF_OPTION_END
};


static GString *
yzPrintVersion(
    void)
{
    GString *versString;

    versString = g_string_new(NULL);

    g_string_append_printf(versString,
                           "yafzcbalance version %s"
                           " (c) 2016-2023 Carnegie Mellon University.\n",
                           VERSION);
    g_string_append(versString, "GNU General Public License (GPL) Rights "
                    "pursuant to Version 2, June 1991\n");
    g_string_append(versString,
                    "Some included library code covered by LGPL 2.1; "
                    "see source for details.\n");
    g_string_append(versString,
                    "Send bug reports, feature requests, and comments to "
                    "netsa-help@cert.org.\n");

    return versString;
}


int
bind2core(
    int   core_id)
{
    cpu_set_t cpuset;
    int       s;

    if (core_id < 0) {
        return -1;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(),
                                    sizeof(cpu_set_t), &cpuset)) != 0)
    {
        fprintf(stderr, "Error while binding to core %u: errno=%i\n",
                core_id, s);
        return -1;
    } else {
        return 0;
    }
}


double
delta_time(
    struct timeval  *now,
    struct timeval  *before)
{
    time_t delta_seconds;
    time_t delta_microseconds;

    delta_seconds      = now->tv_sec - before->tv_sec;
    delta_microseconds = now->tv_usec - before->tv_usec;

    if (delta_microseconds < 0) {
        delta_microseconds += 1000000;  /* 1e6 */
        --delta_seconds;
    }

    return ((double)(delta_seconds * 1000) + (double)delta_microseconds / 1000);
}


void
print_stats(
    pfring_zc_cluster  *zc,
    char              **devices,
    int                 num_devices)
{
    static u_int8_t           print_all = 0;
    static struct timeval     last_time;
    static unsigned long long last_tot_recv = 0, last_tot_slave_recv = 0;
    static unsigned long long last_tot_drop = 0, last_tot_slave_drop = 0;
    unsigned long long        tot_recv = 0, tot_drop = 0, tot_slave_recv = 0,
                              tot_slave_drop = 0;
    struct timeval            end_time;
    char buf1[64], buf2[64], buf3[64], buf4[64];
    pfring_zc_stat            stats;
    char      stats_buf[1024];
    /* double    duration; */
    int       i;
    u_int64_t tot_if_recv = 0, tot_if_drop = 0;

    if (start_time.tv_sec == 0) {
        gettimeofday(&start_time, NULL);
    } else {
        print_all = 1;
    }

    gettimeofday(&end_time, NULL);

    /* mthomas.2020.11.05: duration is never read. commenting out. */
    /* duration = delta_time(&end_time, &start_time); */

    for (i = 0; i < num_devices; i++) {
        if (pfring_zc_stats(inzqs[i], &stats) == 0) {
            tot_recv += stats.recv, tot_drop += stats.drop;
        }
    }

    for (i = 0; i < numout; i++) {
        if (pfring_zc_stats(outzqs[i], &stats) == 0) {
            tot_slave_recv += stats.recv, tot_slave_drop += stats.drop;
        }
    }

    g_warning("=========================\n"
              "Absolute Stats: Recv %s pkts (%s drops) - "
              "Forwarded %s pkts (%s drops)",
              pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
              pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0),
              pfring_format_numbers((double)tot_slave_recv, buf3, sizeof(buf3),
                                    0),
              pfring_format_numbers((double)tot_slave_drop, buf4, sizeof(buf4),
                                    0));

    snprintf(stats_buf, sizeof(stats_buf),
             "ClusterId:         %d\n"
             "TotQueues:         %d\n"
             "Applications:      %d\n",
             cluster, numout, numout);

    for (i = 0; i < num_devices; i++) {
        if (pfring_zc_stats(inzqs[i], &stats) == 0) {
            tot_if_recv += stats.recv;
            tot_if_drop += stats.drop;
            g_message("                %s RX %lu pkts Dropped "
                      "%lu pkts (%.1f %%)",
                      devices[i], stats.recv, stats.drop,
                      ((stats.recv == 0)
                       ? 0
                       : ((double)(stats.drop * 100) /
                          (double)(stats.recv + stats.drop))));
        }
    }

    snprintf(&stats_buf[strlen(stats_buf)],
             sizeof(stats_buf) - strlen(stats_buf),
             "IFPackets:         %lu\n"
             "IFDropped:         %lu\n",
             (long unsigned int)tot_if_recv,
             (long unsigned int)tot_if_drop);
    for (i = 0; i < numout; i++) {
        if (pfring_zc_stats(outzqs[i], &stats) == 0) {
            g_message("                Q %u RX %lu pkts "
                      "Dropped %lu pkts (%.1f %%)",
                      i, stats.recv, stats.drop,
                      ((stats.recv == 0)
                       ? 0
                       : ((double)(stats.drop * 100) /
                          (double)(stats.recv + stats.drop))));
        }
    }

    pfring_zc_set_proc_stats(zc, stats_buf);
    if (print_all && last_time.tv_sec > 0) {
        double delta_msec = delta_time(&end_time, &last_time);
        unsigned long long diff_recv = tot_recv - last_tot_recv;
        unsigned long long diff_drop = tot_drop - last_tot_drop;
        unsigned long long diff_slave_recv = tot_slave_recv -
            last_tot_slave_recv;
        unsigned long long diff_slave_drop = tot_slave_drop -
            last_tot_slave_drop;

        g_message("Actual Stats: Recv %s pps (%s drops) - Forwarded %s pps"
                  " (%s drops)",
                  pfring_format_numbers(((double)diff_recv /
                                         (double)(delta_msec / 1000)),  buf1,
                                        sizeof(buf1), 1),
                  pfring_format_numbers(((double)diff_drop /
                                         (double)(delta_msec / 1000)),  buf2,
                                        sizeof(buf2), 1),
                  pfring_format_numbers(((double)diff_slave_recv /
                                         (double)(delta_msec / 1000)),  buf3,
                                        sizeof(buf3), 1),
                  pfring_format_numbers(((double)diff_slave_drop /
                                         (double)(delta_msec / 1000)),  buf4,
                                        sizeof(buf4), 1)
                  );
    }

    g_warning("=========================");

    last_tot_recv = tot_recv, last_tot_slave_recv = tot_slave_recv;
    last_tot_drop = tot_drop, last_tot_slave_drop = tot_slave_drop;
    last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}


void
yzExit(
    void)
{
    if (pidfile) {
        unlink(pidfile);
    }
}


void
sigproc(
    int   sig)
{
    static int called = 0;

    g_debug("Exiting...");

    if (called) {return;} else {called = 1;}

    pfring_zc_kill_worker(zw);

    yzquit = 1;
}


static void
yzSigStat(
    int sig)
{
    (void)sig;
    ++yzstat;
}


void *
time_pulse_thread(
    void  *data)
{
    u_int64_t       ns;
    struct timespec tn;
    u_int64_t       pulse_clone = 0;

    bind2core(time_core);

    /* mthomas.2021.08.17. The condition used to be "while(likely(!yzquit))" */
    for (;;) {
        if (yzquit) {
            return NULL;
        }
        /* clock_gettime takes up to 30 nsec to get the time */
        clock_gettime(CLOCK_REALTIME, &tn);

        ns = ((u_int64_t)((u_int64_t)tn.tv_sec * 1000000000) + (tn.tv_nsec));

        if (ns >= pulse_clone +
            100 /* nsec precision (avoid updating each cycle) */)
        {
            *pulse_timestamp_ns = ((u_int64_t)((u_int64_t)tn.tv_sec << 32) |
                                   tn.tv_nsec);
            pulse_clone = ns;
        }
    }
}


/* the pfring_zc_distribution_func.  return type of the function's typedef may
 * by int32_t or int64_t depending an PFRING version */
int32_t
yz_multiapp_hash_func(
    pfring_zc_pkt_buff  *pkt_handle,
    pfring_zc_queue     *in_queue,
    void                *user)
{
#ifdef PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_GTPC
    /* PF_RING 7.8.0 adds output flags parameter, which we ignore */
    uint32_t flags = 0;
#endif
    int32_t  app_instance,  hash;
    uint32_t id  = pfring_zc_get_queue_id(in_queue);

    SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);

    pkt_handle->hash = QUEUEID_TO_IFINDEX(id);

    hash = pfring_zc_builtin_gtp_hash(pkt_handle, in_queue
#ifdef PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_GTPC
                                      , &flags
#endif
                                     );

    app_instance = hash % numout;

    return app_instance;
}


/**
 * yzDaemonize
 *
 * daemonize yaf.  An alternative to using airdaemon which has
 * it's issues.
 *
 */
static void
yzDaemonize(
    void)
{
    pid_t pid;
    int   rv = -1;
    char  str[256];
    int   fp;

    if (chdir("/") == -1) {
        rv = errno;
        fprintf(stderr, "Cannot change directory: %s\n", strerror(rv));
        exit(-1);
    }

    if ((pid = fork()) == -1) {
        rv = errno;
        fprintf(stderr, "Cannot fork for daemon: %s\n", strerror(rv));
        exit(-1);
    } else if (pid != 0) {
        g_message("Forked child %ld.  Parent exiting", (long)pid);
        _exit(EXIT_SUCCESS);
    }

    setsid();

    umask(0022);

    rv = atexit(yzExit);
    if (rv == -1) {
        fprintf(stderr, "Unable to register function with atexit(): %s\n",
                strerror(rv));
        exit(-1);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);

    if (pidfile) {
        fp = open(pidfile, O_RDWR | O_CREAT, 0640);
        if (fp < 0) {
            fprintf(stderr, "Unable to open pid file %s\n", pidfile);
            exit(1);
        }
        sprintf(str, "%d\n", getpid());
        if (!write(fp, str, strlen(str))) {
            fprintf(stderr, "Unable to write pid to file\n");
        }
    } else {
        g_message("pid: %d", getpid());
    }
}


static void
idParseOptions(
    int   *argc,
    char **argv[])
{
    AirOptionCtx *aoctx = NULL;
    GError       *err = NULL;
    GString      *versionString;

    aoctx = air_option_context_new("", argc, argv, yz_core_option);

    privc_add_option_group(aoctx);

    air_option_context_set_help_enabled(aoctx);

    versionString = yzPrintVersion();

    logc_add_option_group(aoctx, "yafzcbalance", versionString->str);

    air_option_context_parse(aoctx);

    /* set up logging and privilege drop */
    if (!logc_setup(&err)) {
        fprintf(stderr, "%s\n", err->message);
    }

    if (!privc_setup(&err)) {
        fprintf(stderr, "%s\n", err->message);
    }

    if (inspec == NULL) {
        fprintf(stderr, "Must provide input device\n");
        exit(1);
    }

    if (stats_timeout) {
        sleep_time = stats_timeout;
    }

    if (yz_daemon) {
        yzDaemonize();
    }

    if (numout < 1) {
        fprintf(stderr, "Error: Must have at least one application.\n");
        exit(1);
    }

    g_string_free(versionString, TRUE);

    air_option_context_free(aoctx);
}


int
max_packet_len(
    char  *device)
{
    pfring *ring;
    pfring_card_settings settings;

    ring = pfring_open(device, 1536, PF_RING_PROMISC);

    if (ring == NULL) {
        return 1536;
    }

    pfring_get_card_settings(ring, &settings);

    pfring_close(ring);

    return settings.max_packet_size;
}


int
main(
    int    argc,
    char  *argv[])
{
    char    **devices = NULL;
    char     *dev;
    int       i, off, n = 0;
    pfring_zc_cluster *zc;
    pfring_zc_buffer_pool *wsp;
    pthread_t time_thread;
    struct sigaction sa, osa;
    GError   *err = NULL;

    idParseOptions(&argc, &argv);

    signal(SIGINT,  sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGINT,  sigproc);

    /* install sigusr1 handler */
    sa.sa_handler = yzSigStat;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, &osa)) {
        fprintf(stderr, "Failed to set sigaction(SIGUSR1): %s\n",
                strerror(errno));
        exit(1);
    }

    dev = strtok(inspec, ",");
    while (dev != NULL) {
        devices = realloc(devices, sizeof(char *) * (n + 1));
        devices[n] = strdup(dev);
        n++;
        dev = strtok(NULL, ",");
    }

    zc = pfring_zc_create_cluster(cluster, max_packet_len(devices[0]),
                                  0, ((n * MAX_CARD_SLOTS) +
                                      (numout * (QUEUE_LEN + POOL_SIZE))),
                                  pfring_zc_numa_get_cpu_node(core), NULL
#if RING_VERSION_NUM >= 0x070600
                                  ,0
#endif
                                 );
    if (zc == NULL) {
        fprintf(stderr, "pfring_zc_create_cluster error [%s]"
                "Please check your hugetlb configuration\n",
                strerror(errno));
        return -1;
    }

    inzqs = calloc(n, sizeof(pfring_zc_queue *));
    outzqs = calloc(numout, sizeof(pfring_zc_queue *));

    for (i = 0; i < n; i++) {
        inzqs[i] = pfring_zc_open_device(zc, devices[i], rx_only, 0);
        if (inzqs[i] == NULL) {
            fprintf(stderr, "pfring_zc_open_device error [%s] "
                    "Please check that %s is up and not already used\n",
                    strerror(errno), devices[i]);
            return -1;
        }
    }

    for (i = 0; i < numout; i++) {
        outzqs[i] = pfring_zc_create_queue(zc, QUEUE_LEN);
        if (outzqs[i] == NULL) {
            fprintf(stderr, "pfring_zc_create_queue error [%s]\n",
                    strerror(errno));
            return -1;
        }
    }

    for (i = 0; i < numout; i++) {
        if (pfring_zc_create_buffer_pool(zc, POOL_SIZE) == NULL) {
            fprintf(stderr, "pfring_zc_create_buffer pool error\n");
            return -1;
        }
    }

    wsp = pfring_zc_create_buffer_pool(zc, 8);

    if (wsp == NULL) {
        fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
        return -1;
    }

    pulse_timestamp_ns = calloc(64 / sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);

    while (!*pulse_timestamp_ns && !yzquit) {} /* wait for ts */
    off = 0;

    g_debug("Run your yaf instances as follows:");
    for (i = 0; i < n; i++) {
        if (n > 1) {g_debug("yaf %d", i);}
        g_debug("\tyaf -i %d:%d --live zc", cluster, off++);
    }

    zw = pfring_zc_run_balancer(inzqs, outzqs, n, numout, wsp,
                                round_robin_bursts_policy,
                                NULL,
                                ((pfring_zc_distribution_func)
                                 yz_multiapp_hash_func),
                                (void *)((long)numout), 0, core);

    if (zw == NULL) {
        fprintf(stderr, "pfring_zc_run_balancer error [%s]\n", strerror(errno));
        return -1;
    }

    if (!privc_become(&err)) {
        if (g_error_matches(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_NODROP)) {
            g_message("running as root in --live mode, "
                      "but not dropping privilege");
            g_clear_error(&err);
        } else {
            fprintf(stderr, "Cannot drop privilege: %s\n", err->message);
            exit(1);
        }
    }

    while (!yzquit) {
        sleep(sleep_time);
        if (stats_timeout || yzstat) {
            print_stats(zc, devices, n);
            yzstat = 0;
        }
    }

    pthread_join(time_thread, NULL);

    pfring_zc_destroy_cluster(zc);

    if (pidfile) {
        unlink(pidfile);
    }

    return 0;
}
