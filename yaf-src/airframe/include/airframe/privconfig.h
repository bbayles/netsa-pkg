/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  privconfig.c
 *  Generic privilege configuration support.
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
 * Airframe Privilege Configuration Support. Supplies privilege dropping
 * for post-root initialization reduction of privileges (e.g. for live packet
 * capture applications) and the command line option processing necessary to
 * use it. Use this when you want to drop privileges after doing one-time
 * setup as root.
 */

/* idem hack */
#ifndef _AIR_PRIVCONFIG_H_
#define _AIR_PRIVCONFIG_H_

#include <airframe/autoinc.h>
#include <airframe/airopt.h>

/** GError domain for privconfig errors */
#define PRIVC_ERROR_DOMAIN g_quark_from_string("airframePrivilegeError")
/**
 * Privconfig setup error. Signifies that setup failed because of bad command
 * line options.
 */
#define PRIVC_ERROR_SETUP  1
/**
 * Privilege drop error.
 */
#define PRIVC_ERROR_FAILED 2
/**
 * Couldn't drop privilege because privilege already dropped.
 */
#define PRIVC_ERROR_ALREADY 3
/**
 * Won't drop privilege because not running as root.
 */
#define PRIVC_ERROR_NODROP  4

/**
 * Return an option group for privilege configuration. This option group
 * defines
 * two options: --become-user (-U) to become a specified user by name,
 * and --become-group to additionally specify a group to become (otherwise,
 * drops privileges to the given user's default group.)
 *
 * @param aoctx airframe option context
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
privc_add_option_group(
    AirOptionCtx  *aoctx);

/**
 * Set up privilege configuration. Call this after parsing an options context
 * including a GOptionGroup returned from privc_option_group(). This sets
 * up internal state used by the other privconfig calls.
 *
 * @param err an error description
 * @return TRUE on success, FALSE otherwise
 */
gboolean
privc_setup(
    GError **err);

/**
 * Determine if the user wants to drop privileges. Use this to determine
 * whether warn the user if the application will not call priv_become() due
 * to some application-specific state.
 *
 * @return TRUE if --become-user supplied on command line.
 */
gboolean
privc_configured(
    void);

/**
 * Drop privileges if necessary. Returns TRUE if not running as root. Returns
 * FALSE if running as root with no --become-user option with
 * PRIVC_ERROR_NODROP, or if privc_become() was already called succsssfully
 * with PRIVC_ERROR_ALREADY. If for some reason a required privilege drop
 * fails, returns FALSE with PRIVC_ERROR_FAILED.
 *
 * @param err an error description
 * @return TRUE on success, FALSE otherwise
 */
gboolean
privc_become(
    GError **err);

#endif /* ifndef _AIR_PRIVCONFIG_H_ */
