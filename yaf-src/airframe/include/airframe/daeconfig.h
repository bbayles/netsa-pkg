/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  daeconfig.h
 *  Generic daemon configuration support
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *           Tony Cebzanov
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
 * @file
 *
 * Airframe Daemon Configuration Support. Supplies automatic daemonization
 * and the command line option processing necessary to use it. Use this when
 * your application can run as a daemon and you want to give your users control
 * over whether it does via the command line.
 */

/* idem hack */
#ifndef _AIR_DAECONFIG_H_
#define _AIR_DAECONFIG_H_

#include <airframe/autoinc.h>
#include <airframe/airopt.h>

/** GError domain for daeconfig errors */
#define DAEC_ERROR_DOMAIN g_quark_from_string("airframeDaemonError")
/**
 * Daeconfig setup error. Signifies that daemonization failed due to an
 * underlying operating system error.
 */
#define DAEC_ERROR_SETUP  1

/**
 * Set up daemon configuration. Call this after parsing an options context
 * including a GOptionGroup returned from daec_option_group(). This sets
 * up internal state used by the other daeconfig calls and daemonizes the
 * application, if necessary.
 *
 * @param err an error description
 * @return TRUE on success, FALSE otherwise
 */
gboolean
daec_setup(
    GError **err);

/**
 * Add an option group for daemon configuration to the given optoin context.
 * This option group defines two options: --daemon (-d) to become a daemon, and
 * --foreground to run in daemon mode without forking.
 *
 * @param aoctx airframe option context
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
daec_add_option_group(
    AirOptionCtx  *aoctx);

/**
 * Return daemon mode state. Returns true if --daemon was passed in on the
 * command line, regardless of whether --foreground was also present. If an
 * application's logic is different for daemon and non-daemon mode, the
 * application should use this call to determine which mode to run in.
 *
 * @return TRUE if in daemon mode, FALSE otherwise.
 */
gboolean
daec_is_daemon(
    void);

/**
 * Return future fork state. Returns true if --daemon and not --foreground. Use
 * this call to determine whether a call to daec_setup() will cause the
 * application for fork to the background. This is primarily designed for
 * interoperation with logconfig, which must know whether daeconfig will
 * fork without requiring said fork to occur before logging is set up.
 *
 * @return TRUE if subsequent call to daec_setup() will fork, FALSE otherwise.
 */
gboolean
daec_will_fork(
    void);

/**
 * Return forked state. Returns true if a prior call to daec_setup() caused
 * the application to fork to the background.
 *
 * @return TRUE if the daemon has forked, FALSE otherwise
 */
gboolean
daec_did_fork(
    void);

/**
 * Return quit flag state. Returns FALSE until daec_quit() has been called,
 * then returns TRUE. Provided as a convenience, so applications don't have
 * to track their own quit flag.
 *
 * @return TRUE if daec_quit() has been called.
 */
gboolean
daec_did_quit(
    void);

/**
 * Set the quit flag.
 */
void
daec_quit(
    void);

#endif /* ifndef _AIR_DAECONFIG_H_ */
