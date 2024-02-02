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

/*
**  skdaemon.h
**
**    Setup logging, create a pid file, install a signal handler and
**    fork an application in order to run it as a daemon.
**
*/
#ifndef _SKDAEMON_H
#define _SKDAEMON_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKDAEMON_H, "$SiLK: skdaemon.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/**
 *  @file
 *
 *    Functions for daemonizing a SiLK application.
 *
 *    This file is part of libsilk.
 */


/**
 *    By default, skdaemonize() will cause the application to fork,
 *    though the user's --no-daemon option can override that behavior.
 *    When this function is called, the application will not fork,
 *    regardless of the user's --no-daemon option.
 */
void
skdaemonDontFork(
    void);


/**
 *    Write the usage strings for options that skdaemonSetup() added
 *    to the global list of options.
 */
void
skdaemonOptionsUsage(
    FILE               *fh);


/**
 *    Verify that all the required options were specified and that
 *    their values are valid.
 */
int
skdaemonOptionsVerify(
    void);


/**
 *    Register the options used when running as a daemon.  The
 *    'log_features' value will be passed to sklogSetup().
 *
 *    The 'argc' and 'argv' contain the commmand line used to start
 *    the program.  They will be written to the log.
 */
int
skdaemonSetup(
    int                 log_features,
    int                 argc,
    char   * const     *argv);


/**
 *    Stop logging and remove the PID file.
 */
void
skdaemonTeardown(
    void);


/**
 *    In the general case: start the logger, fork the application,
 *    register the specified 'exit_handler', create a pid file, and
 *    install a signal handler in order to run an application as a
 *    daemon.  When the signal handler is called, it will set
 *    'shutdown_flag' to a non-zero value.
 *
 *    The application will not fork if the user requested --no-daemon.
 *
 *    Returns 0 if the application forked and everything succeeds.
 *    Returns 1 if everything succeeds but the application did not
 *    fork.  Returns -1 to indicate an error.
 */
int
skdaemonize(
    volatile int       *shutdown_flag,
    void                (*exit_handler)(void));

#ifdef __cplusplus
}
#endif
#endif /* _SKDAEMON_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
