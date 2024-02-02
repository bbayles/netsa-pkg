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

/**
 * @file
 *
 * Airframe lockfile interface. Used to acquire lockfiles compatible with
 * the Airframe filedaemon.
 */

/* idem hack */
#ifndef _AIR_AIRLOCK_H_
#define _AIR_AIRLOCK_H_

#include <airframe/autoinc.h>

/** GError domain for lock errors */
#define LOCK_ERROR_DOMAIN g_quark_from_string("airframeLockError")
/**
 * A lock could not be acquired.
 */
#define LOCK_ERROR_LOCK  1

/**
 * A lock structure. Must be maintained by a caller from lock acquisition
 * to release. Should be initialized by AIR_LOCK_INIT or memset(0) or bzero().
 */
typedef struct _AirLock {
    /** Path to .lock file */
    GString   *lpath;
    /** File descriptor of open .lock file */
    int        lfd;
    /** TRUE if this lock is held, and lpath and lfd are valid. */
    gboolean   held;
} AirLock;

/** Convenience initializer for AirLock structures */
#define AIR_LOCK_INIT { NULL, 0, FALSE }

/**
 * Acquire a lock. Creates a lockfile and returns TRUE if the lockfile was
 * created (and is now held).
 *
 * @param lock AirLock structure to store lockfile information in.
 * @param path path of file to lock (without .lock extension).
 * @param err an error descriptor
 * @return TRUE if lockfile created, FALSE if lock not available
 */
gboolean
air_lock_acquire(
    AirLock     *lock,
    const char  *path,
    GError     **err);

/**
 * Release an acquired lock.
 *
 * @param lock AirLock structure filled in by air_lock_acquire()
 */
void
air_lock_release(
    AirLock  *lock);

/**
 * Free storage used by an AirLock structure. Does not free the structure
 * itself.
 *
 * @param lock AirLock to free
 */
void
air_lock_cleanup(
    AirLock  *lock);

#endif /* ifndef _AIR_AIRLOCK_H_ */
