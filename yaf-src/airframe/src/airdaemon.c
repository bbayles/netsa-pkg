/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airdaemon.c
 *  Keeps a child process running.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Tony Cebzanov
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

#define _AIRFRAME_SOURCE_
#include <airframe/autoinc.h>
#include <airframe/airopt.h>
#include <airframe/logconfig.h>

static uint32_t       ad_retry_min        = 30;
static uint32_t       ad_retry_max        = 0;
static gboolean       ad_nodaemon         = FALSE;
static pid_t          ad_pid              = 0;
static char          *ad_pidfile          = NULL;
static char          *ad_cpidfile         = NULL;


static AirOptionEntry ad_options[]  = {
    AF_OPTION( "retry", 'r', 0, AF_OPT_TYPE_INT, &ad_retry_min,
               "Retry delay in seconds", "sec" ),
    AF_OPTION( "retry-max", 'R', 0, AF_OPT_TYPE_INT, &ad_retry_max,
               "Retry delay maximum in seconds", NULL ),
    AF_OPTION( "pidfile", 'P', 0, AF_OPT_TYPE_STRING, &ad_cpidfile,
               "A filename to write the child process pid to", NULL ),
    AF_OPTION( "airdaemon-pidfile", 'A', 0, AF_OPT_TYPE_STRING, &ad_pidfile,
               "A filename to write airdaemon's pid to", NULL ),
    AF_OPTION( "no-daemon", (char)0, 0, AF_OPT_TYPE_NONE, &ad_nodaemon,
               "do not daemonize", NULL ),
    AF_OPTION_END
};

typedef struct _ad_child_data {
    GMainLoop  *loop;
    gboolean   *done;
} ad_child_data_t;

static void
parse_options(
    int   *argc,
    char **argv[])
{
    AirOptionCtx *aoctx = NULL;

    aoctx = air_option_context_new("", argc, argv, ad_options);
    logc_add_option_group(aoctx, "airdaemon", VERSION);

    air_option_context_set_help_enabled(aoctx);

    air_option_context_parse(aoctx);
}


static void
on_child_exit(
    GPid       child_pid,
    gint       status,
    gpointer   data)
{
    GMainLoop *loop = ((ad_child_data_t *)data)->loop;
    gboolean  *done = ((ad_child_data_t *)data)->done;

    g_message("pid %lu exited with status %d", (gulong)child_pid, status);

#ifdef G_OS_UNIX
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == EXIT_SUCCESS) {
            g_debug("pid %lu returned success", (gulong)child_pid);
            *done = TRUE;
        } else {
            g_warning("pid %lu returned error status %d", (gulong)child_pid,
                      WEXITSTATUS(status));
        }
    } else if (WIFSIGNALED(status)) {
        g_critical("pid %lu terminated with signal %d\n",
                   (gulong)child_pid, WTERMSIG(status));
    } else {
        g_critical("pid %lu terminated", (gulong)child_pid);
    }
#endif /* G_OS_UNIX */
    g_spawn_close_pid(child_pid);
    g_main_loop_quit(loop);
}


static gboolean
daemonize(
    void)
{
    /* fork */
    if (fork()) {exit(0);}

    /* dissociate from controlling terminal */
    if (setsid() < 0) {
        g_critical("setsid() failed: %s", strerror(errno));
        return FALSE;
    }

    /* redirect stdio */
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);

    ad_pid = getpid();
    if (ad_pidfile) {
        FILE *pidfile = fopen(ad_pidfile, "w");
        if (!pidfile) {
            g_critical("could not write pidfile");
            goto end;
        }
        fprintf(pidfile, "%d\n", ad_pid);
        fclose(pidfile);
    }
  end:

    return TRUE;
}


int
main(
    int    argc,
    char  *argv[])
{
    int        i;
    gboolean   done = FALSE;
    GError    *err = NULL;
    uint32_t   delay;
    GTimer    *uptimer  = NULL;
    gdouble    elapsed_time;

    GMainLoop *loop;

    GPtrArray *child_args     = NULL;

    /* parse options */
    parse_options(&argc, &argv);

    /* set up logging */
    if (!logc_setup(&err)) {
        air_opterr("%s", err->message);
    }

    if (ad_retry_max && (ad_retry_min > ad_retry_max) ) {
        air_opterr("--retry value (%d) cannot exceed --retry-max value (%d) ",
                   ad_retry_min,
                   ad_retry_max);
    }
    delay = ad_retry_min;

    child_args = g_ptr_array_sized_new(64);
    for (i = 1; i < argc; i++) {
        /* Double dash indicates end of airdaemon's arguments */
        if (!strncmp(argv[i], "--", strlen(argv[i])) ) {
            continue;
        }
        g_ptr_array_add(child_args, g_strdup(argv[i]));
    }
    g_ptr_array_add(child_args, NULL);

    loop = g_main_loop_new(NULL, FALSE);

    /* Options check out; daemonize */
    if (!ad_nodaemon) {
        if (!daemonize()) {
            goto end;
        }
    }

    uptimer = g_timer_new();

    while (!done) {
        GPid            child_pid;
        char          **child_envp            = {NULL};
        GError         *child_err             = NULL;
        ad_child_data_t child_data;

        if (!g_spawn_async_with_pipes(".",
                                      (gchar **)child_args->pdata,
                                      child_envp,
                                      G_SPAWN_SEARCH_PATH |
                                      G_SPAWN_DO_NOT_REAP_CHILD,
                                      NULL,
                                      NULL,
                                      &child_pid,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &child_err))
        {
            g_error("error spawning process: %s",
                    (child_err && child_err->message ? child_err->
                     message : "unknown error"));
        }

        g_timer_start(uptimer);

        /* Write child pid if requested */
        if (ad_cpidfile) {
            FILE *cpidfile = fopen(ad_cpidfile, "w");
            if (!cpidfile) {
                g_critical("could not write pidfile");
                goto end;
            }
            fprintf(cpidfile, "%d\n", child_pid);
            fclose(cpidfile);
        }

        /* Watch for process exit status */
        child_data.loop = loop;
        child_data.done = &done;

        g_child_watch_add(child_pid, on_child_exit, &child_data);
        g_main_loop_run(loop);

        g_timer_stop(uptimer);
        elapsed_time = g_timer_elapsed(uptimer, NULL);

        if (done) {
            g_debug("done");
        } else {
            if (ad_retry_max && (elapsed_time >= ad_retry_min) ) {
                g_debug("child survived for %fs, resetting delay",
                        elapsed_time);
                delay = ad_retry_min;
            }
            g_debug("child exited abnormally, sleeping for %d seconds", delay);
            sleep(delay);
            if (ad_retry_max) {
                if (2 * delay <= ad_retry_max) {
                    delay *= 2;
                } else {
                    delay = ad_retry_max;
                }
            }
        }
    }

  end:

    return 0;
}
