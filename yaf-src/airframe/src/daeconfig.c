/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  daeconfig.c
 *  Generic daemon configuration support
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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
#include <airframe/daeconfig.h>
#include <airframe/airopt.h>

static gboolean opt_daemon = FALSE;
static gboolean opt_fg = FALSE;

static gboolean did_fork = FALSE;

static gboolean daemon_quit = FALSE;

static AirOptionEntry  daec_optentries[] = {
    AF_OPTION( "daemon", 'd', 0, AF_OPT_TYPE_NONE, &opt_daemon,
               "Become daemon", NULL ),
    AF_OPTION( "foreground", (char)0, 0, AF_OPT_TYPE_NONE, &opt_fg,
               "Do not fork to background in daemon mode", NULL ),
    AF_OPTION_END
};

gboolean
daec_add_option_group(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);

    air_option_context_add_group(aoctx, "daemon", "Daemon options:",
                                 "Show help for daemon options",
                                 daec_optentries);

    return TRUE;
}


gboolean
daec_is_daemon(
    void)
{
    return opt_daemon;
}


gboolean
daec_did_fork(
    void)
{
    return did_fork;
}


gboolean
daec_will_fork(
    void)
{
    return opt_daemon ? (opt_fg ? 0 : 1) : 0;
}


void
daec_quit(
    void)
{
    ++daemon_quit;
}

static void
sighandler_daec_quit(
    int   sig)
{
    (void)sig;
    daec_quit();
}

gboolean
daec_did_quit(
    void)
{
    return daemon_quit;
}


gboolean
daec_setup(
    GError **err)
{
    struct sigaction sa, osa;

    /* fork if necessary */
    if (daec_will_fork()) {
        /* fork */
        if (fork()) {exit(0);}

        /* dissociate from controlling terminal */
        if (setsid() < 0) {
            g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                        "setsid() failed: %s", strerror(errno));
            return FALSE;
        }

        /* redirect stdio */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        /* we forked */
        did_fork = TRUE;
    }

    /* install quit flag handlers */
    sa.sa_handler = sighandler_daec_quit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, &osa)) {
        g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                    "sigaction(SIGINT) failed: %s", strerror(errno));
        return FALSE;
    }

    sa.sa_handler = sighandler_daec_quit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, &osa)) {
        g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                    "sigaction(SIGTERM) failed: %s", strerror(errno));
        return FALSE;
    }

    return TRUE;
}
