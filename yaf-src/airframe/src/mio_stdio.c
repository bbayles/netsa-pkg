/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_stdio.c
 *  Multiple I/O standard in source / standard out sink
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
#include <airframe/mio_stdio.h>
#include "mio_internal.h"

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


gboolean
mio_source_check_stdin(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    /* terminate the application if standard input has been closed. */
    if (!source->name) {
        *flags |= MIO_F_CTL_TERMINATE;
        return FALSE;
    }

    return TRUE;
}


gboolean
mio_source_close_stdin(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    source->name = NULL;
    return TRUE;
}


gboolean
mio_source_init_stdin(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* match spec */
    if (strcmp(spec, "-")) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open stdin source: spec mismatch");
        return FALSE;
    }

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_FP;}

    /* initialize source */
    source->spec = C("-");
    source->name = C("-");
    source->vsp_type = vsp_type;
    source->cfg = NULL;
    source->ctx = NULL;
    source->next_source = mio_source_check_stdin;
    source->close_source = mio_source_close_stdin;
    source->free_source = NULL;
    source->opened = FALSE;
    source->active = FALSE;

    /* set up source pointer as appropriate */
    switch (vsp_type) {
      case MIO_T_NULL:
        source->vsp = NULL;
        break;
      case MIO_T_FD:
        source->vsp = GINT_TO_POINTER(0);
        break;
      case MIO_T_FP:
        source->vsp = stdin;
        break;
      default:
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open stdin source: type mismatch");
        return FALSE;
    }

    return TRUE;
}


gboolean
mio_sink_init_stdout(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* match spec */
    if (strcmp(spec, "-")) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open stdout sink: spec mismatch");
        return FALSE;
    }

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_FP;}

    /* initialize sink */
    sink->spec = C("-");
    sink->name = C("-");
    sink->vsp_type = vsp_type;
    sink->cfg = NULL;
    sink->ctx = NULL;
    sink->next_sink = NULL;
    sink->close_sink = NULL;
    sink->free_sink = NULL;
    sink->opened = FALSE;
    sink->active = FALSE;
    sink->iterative = FALSE;

    /* set up sink pointer as appropriate */
    switch (vsp_type) {
      case MIO_T_NULL:
        sink->vsp = NULL;
        break;
      case MIO_T_FD:
        sink->vsp = GINT_TO_POINTER(1);
        break;
      case MIO_T_FP:
        sink->vsp = stdout;
        break;
      default:
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open stdout sink: type mismatch");
        return FALSE;
    }

    return TRUE;
}
