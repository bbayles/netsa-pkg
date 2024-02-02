/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  logconfig.h
 *  Generic glib-based logging configuration support
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
 * Airframe Logging Configuration Support. Supplies glib log routing to
 * standard error, file output, and the UNIX syslog facility, and the command
 * line option processing necessary to use it. Integrates with daeconfig to
 * ensure proper use of standard error, and to default to standard error or
 * syslog as appropriate. Use this when your application uses glib logging and
 * you want to give your users control over where to route logging information
 * via the command line.
 */

/* idem hack */
#ifndef _AIR_LOGCONFIG_H_
#define _AIR_LOGCONFIG_H_

#include <airframe/autoinc.h>
#include <airframe/airopt.h>

/** GError domain for logconfig errors */
#define LOGC_ERROR_DOMAIN (g_quark_from_string("airframeLogError"))
/**
 * Logconfig argument error. The user passed in an illegal command-line
 * argument.
 */
#define LOGC_ERROR_ARGUMENT 1

/**
 * Add an option group for logging configuration to the given option context.
 * This option group defines four options: --log (-l) to specify a logging
 * destination, --loglevel (-L)  to specify the minimum severity of logged
 * messages, --verbose (-v) which is a shortcut for --loglevel debug, and
 * --version (-V) which will print version information and exit the
 * application.
 *
 * @param aoctx airframe option context
 * @param appname application name to display
 * @param version application version string
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
logc_add_option_group(
    AirOptionCtx  *aoctx,
    const char    *appname,
    const char    *version);

/**
 * Set up log routing. Call this after parsing an options context including a
 * GOptionGroup returned from logc_option_group(). This sets up log routing
 * using logconfig; subsequent glib logging calls will be routed as specified
 * by the user.
 *
 * By default, if the application will fork to the background logging is
 * routed to standard error; otherwise, it is routed to the "user" syslog
 * facility. In either case, the default loglevel is warning.
 *
 * @param err an error description
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
logc_setup(
    GError **err);


void
logc_set(
    char  *spec,
    char  *level);

#endif /* ifndef _AIR_LOGCONFIG_H_ */
