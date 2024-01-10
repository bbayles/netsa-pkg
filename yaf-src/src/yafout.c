/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafout.c
 *  YAF IPFIX file and session output support
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

#define _YAF_SOURCE_
#include "yafout.h"
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <airframe/airutil.h>

fBuf_t *
yfOutputOpen(
    yfConfig_t  *cfg,
    AirLock     *lock,
    GError     **err)
{
    GString        *namebuf = NULL;
    fBuf_t         *fbuf = NULL;
    static uint32_t serial = 0;

    /* Short-circuit IPFIX output over the wire.
     * Get a writer for the given connection specifier. */
    if (cfg->ipfixNetTrans) {
#ifdef HAVE_SPREAD
        if (cfg->ipfixSpreadTrans) {
            return yfWriterForSpread( &(cfg->spreadparams), cfg->odid,
                                      cfg->spreadGroupIndex,
                                      cfg->tmpl_metadata, err);
        }
#endif /* ifdef HAVE_SPREAD */
        return yfWriterForSpec(&(cfg->connspec), cfg->odid, cfg->tmpl_metadata,
                               err);
    }

    /* create a buffer for the output filename */
    namebuf = g_string_new(NULL);

    if (cfg->rotate_ms) {
        /* Output file rotation.
         * Generate a filename by adding a timestamp and serial number
         * to the end of the output specifier. */
        g_string_append_printf(namebuf, "%s-", cfg->outspec);
        air_time_g_string_append(namebuf, time(NULL), AIR_TIME_SQUISHED);
        g_string_append_printf(namebuf, "-%05u.yaf", serial++);
    } else {
        /* No output file rotation. Write to the file named by the output
         * specifier. */
        g_string_append_printf(namebuf, "%s", cfg->outspec);
    }

    /* lock, but not stdout */
    if (lock) {
        if (!(((strlen(cfg->outspec) == 1) && cfg->outspec[0] != '-'))) {
            if (!air_lock_acquire(lock, namebuf->str, err)) {
                goto err;
            }
        }
    }
    /* start a writer on the file */

    if (!(fbuf = yfWriterForFile(namebuf->str, cfg->odid, cfg->tmpl_metadata,
                                 err)))
    {
        goto err;
    }

    /* all done */
    goto end;

  err:
    if (lock) {
        air_lock_release(lock);
    }

  end:
    g_string_free(namebuf, TRUE);
    return fbuf;
}


void
yfOutputClose(
    fBuf_t    *fbuf,
    AirLock   *lock,
    gboolean   flush)
{
    gboolean rv;
    GError  *err = NULL;

    /* Close writer (this frees the buffer) */
    rv = yfWriterClose(fbuf, flush, &err);

    if (!rv) {
        g_critical("Error: %s", err->message);
    }

    /* Release lock */
    if (lock) {
        air_lock_release(lock);
    }
}
