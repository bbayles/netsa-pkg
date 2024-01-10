/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_sink_multi.c
 *  Multiple I/O compound sink, for output fanout case
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
#include <airframe/mio_sink_multi.h>

static gboolean
mio_sink_next_multi(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    MIOSink *ms = NULL, *cs = NULL;
    GError  *err2 = NULL;
    uint32_t i, j;

    for (i = 0; i < mio_smc(sink); i++) {
        ms = &mio_smn(sink, i);
        if (!ms->next_sink(source, ms, flags, err)) {
            /* on error, close all sinks that already went next. */
            for (j = 0; j < i; j++) {
                cs = &mio_smn(sink, j);
                if (!cs->close_sink(source, cs, flags, &err2)) {
                    /* error closing an opened sink... bail for now */
                    g_error("panic on multiple sink next: "
                            "couldn't close sink %s: %s on error "
                            "while opening sink %s: %s",
                            cs->spec, err2->message,
                            ms->spec, (*err)->message);
                }
            }

            /* all sinks opened by this operation closed. */
            return FALSE;
        }
    }

    /* done. */
    return TRUE;
}


static gboolean
mio_sink_close_multi(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    GString *errstr = NULL;
    GError  *err2 = NULL;
    uint32_t errcount = 0;
    MIOSink *ms = NULL;
    uint32_t i;

    /* close subordinate sinks */
    for (i = 0; i < mio_smc(sink); i++) {
        ms = &mio_smn(sink, i);
        if (!ms->close_sink(source, ms, flags, &err2)) {
            if (!errstr) {errstr = g_string_new(NULL);}
            g_string_append_printf(errstr, "%s\n", err2->message);
            errcount++;
            g_clear_error(&err2);
        }
    }

    /* report errors */
    if (errcount) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_MULTIPLE,
                    "%u error(s) closing sink: %s", errcount, errstr->str);
        g_string_free(errstr, TRUE);
        return FALSE;
    }

    /* done */
    return TRUE;
}


static void
mio_sink_free_multi(
    MIOSink  *sink)
{
    MIOSink *ms = NULL;
    uint32_t i;

    for (i = 0; i < mio_smc(sink); i++) {
        ms = &mio_smn(sink, i);
        ms->free_sink(ms);
    }

    if (sink->spec) {g_free(sink->spec);}
    if (sink->vsp) {g_free(sink->vsp);}
}


gboolean
mio_sink_init_multi(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    uint32_t vsp_count = GPOINTER_TO_UINT(cfg);

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_SINKARRAY;}

    /* Ensure type is valid */
    if (vsp_type != MIO_T_SINKARRAY) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create multiple sink: type mismatch");
        return FALSE;
    }

    /* Ensure array length is valid */
    if (!vsp_count) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create multiple sink: zero sinks");
        return FALSE;
    }

    /* initialize multi sink */
    if (spec) {
        sink->spec = g_strdup(spec);
    } else {
        sink->spec = NULL;
    }
    sink->name = NULL;
    sink->vsp_type = vsp_type;
    sink->vsp = g_new0(MIOSink, vsp_count);
    sink->ctx = NULL;
    sink->cfg = cfg;
    sink->next_sink = mio_sink_next_multi;
    sink->close_sink = mio_sink_close_multi;
    sink->free_sink = mio_sink_free_multi;
    sink->opened = FALSE;
    sink->active = FALSE;
    sink->iterative = TRUE;

    return TRUE;
}
