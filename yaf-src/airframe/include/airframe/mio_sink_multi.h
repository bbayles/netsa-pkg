/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_sink_multi.h
 *  Multiple I/O multisink, for output fanout.
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
 * MIO multisink initializer and utilities.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_SINK_MULTI_H_
#define _AIRFRAME_MIO_SINK_MULTI_H_
#include <airframe/mio.h>

/**
 * Initialize a multisink for writing to multiple subordinate sinks. A
 * multisink simply distributes its operations (next, close, free) among
 * its subordinates. This function creates a multisink with all of its
 * subordinate sinks zeroed - after initializing, each subordinate sink must
 * in turn be initialized by a specific sink initializer.
 *
 *
 * @param sink      pointer to MIOSink to initialize. This MIOSink will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Ignored; may be NULL.
 * @param vsp_type  requested sink pointer type, or MIO_T_ANY for default.
 *                  Must be ANY or MULTISINK.
 * @param cfg       Number of subordinate sinks to allocate
 *                  cast to a void pointer using GUINT_TO_POINTER.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSink was successfully initialized.
 */
gboolean
mio_sink_init_multi(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

/**
 * Convenience macro to retrieve the subordinate sink count for a
 * given multisink.
 */
#define mio_smc(_s_) (GPOINTER_TO_UINT((_s_)->cfg))

/**
 * Convenience macro to access a given subordinate sink by index for a
 * given multisink. Evaluates to a structure; use the address operator to
 * get a pointer to the subordinate sink.
 */
#define mio_smn(_s_, _n_) (((MIOSink *)(_s_)->vsp)[(_n_)])

#endif /* ifndef _AIRFRAME_MIO_SINK_MULTI_H_ */
