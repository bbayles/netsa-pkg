/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airlock.c
 *  Airframe lockfile interface
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
#include <airframe/airlock.h>

gboolean
air_lock_acquire(
    AirLock     *lock,
    const char  *path,
    GError     **err)
{
    /* Lazily create scratch path */
    if (!lock->lpath) {
        lock->lpath = g_string_new(NULL);
    }

    /* Generate lock path */
    g_string_printf(lock->lpath, "%s.lock", path);

    /* Open lock file */
    lock->lfd = open(lock->lpath->str, O_WRONLY | O_CREAT | O_EXCL, 0664);
    if (lock->lfd < 0) {
        g_set_error(err, LOCK_ERROR_DOMAIN, LOCK_ERROR_LOCK,
                    "Cannot lock file %s: %s",
                    path, strerror(errno));
        unlink(lock->lpath->str);
        return FALSE;
    }

    /* Note lock held */
    lock->held = TRUE;

    return TRUE;
}


void
air_lock_release(
    AirLock  *lock)
{
    /* Lock release is no-op if lock not held */
    if (!lock->held) {
        return;
    }

    /* Verify lockfile still exists */
    if (!g_file_test(lock->lpath->str, G_FILE_TEST_IS_REGULAR)) {
        g_warning("Lock collision warning: %s missing",
                  lock->lpath->str);
    }

    /* Close and unlink lockfile */
    close(lock->lfd);
    unlink(lock->lpath->str);

    /* clean up the lock */
    lock->held = FALSE;
}


void
air_lock_cleanup(
    AirLock  *lock)
{
    if (lock->lpath) {
        g_string_free(lock->lpath, TRUE);
    }
}
