/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio.c
 *  Multiple I/O configuration and routing support for file and network daemons
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
#include <airframe/mio.h>
#include <airframe/daeconfig.h>

#define MIOD_ERR1       \
    {                   \
        ok = FALSE;     \
        goto afterproc; \
    }

#define MIOD_ERR2                                                          \
    {                                                                      \
        ok = FALSE;                                                        \
        if (err && *err) {                                                 \
            xem = g_string_new(*err ? (*err)->message : "[null error]");   \
            g_clear_error(err);                                            \
            g_string_append_printf(xem, "%s\n",                            \
                                   ierr ? ierr->message : "[null error]"); \
            g_clear_error(&ierr);                                          \
        } else if (!xem) {                                                 \
            g_propagate_error(err, ierr);                                  \
            g_clear_error(&ierr);                                          \
        } else {                                                           \
            g_string_append_printf(xem, "%s\n",                            \
                                   ierr ? ierr->message : "[null error]"); \
            g_clear_error(&ierr);                                          \
        }                                                                  \
    }

#define MIOD_ERR3                                                               \
    {                                                                           \
        g_warning("%s", (err && err->message) ? err->message : "[null error]"); \
        g_clear_error(&err);                                                    \
    }

gboolean
mio_dispatch(
    MIOSource     *source,
    MIOSink       *sink,
    MIOAppDriver  *app_drv,
    void          *vctx,
    uint32_t      *flags,
    GError       **err)
{
    gboolean ok   = TRUE;
    GString *xem  = NULL;
    GError  *ierr = NULL;

    /* clear MIO control flags */
    *flags &= ~MIO_F_CTL_MASK;

    /* check for termination */
    if (daec_did_quit()) {
        *flags |= MIO_F_CTL_TERMINATE;
        goto afterproc;
    }

    /* ensure available active source */
    if (!source->active) {
        /* get next source */
        if (source->next_source
            && !source->next_source(source, flags, err))
        {
            MIOD_ERR1;
        }
        source->opened = TRUE;
        if (app_drv->app_open_source
            && !app_drv->app_open_source(source, vctx, flags, err))
        {
            MIOD_ERR1;
        }
        source->active = TRUE;
    }

    /* ensure available active sink */
    if (!sink->active) {
        if (sink->next_sink
            && !sink->next_sink(source, sink, flags, err))
        {
            MIOD_ERR1;
        }
        sink->opened = TRUE;
        if (app_drv->app_open_sink
            && !app_drv->app_open_sink(source, sink, vctx, flags, err))
        {
            MIOD_ERR1;
        }
        sink->active = TRUE;
    }

    /* process an item */
    if (!app_drv->app_process(source, sink, vctx, flags, err)) {
        MIOD_ERR1;
    }

  afterproc:
    /* promote poll to terminate if we're not a daemon. */
    if (*flags & MIO_F_CTL_POLL && !(*flags & MIO_F_OPT_DAEMON)) {
        *flags &= ~MIO_F_CTL_POLL;
        *flags |= MIO_F_CTL_TERMINATE;
    }

    /* close sink if closing source and source and sink are linked. */
    if (*flags & MIO_F_CTL_SOURCECLOSE && *flags & MIO_F_OPT_SINKLINK) {
        *flags |= MIO_F_CTL_SINKCLOSE;
    }

    /* close everything if quitting */
    if (*flags & MIO_F_CTL_TERMINATE) {
        *flags |= (MIO_F_CTL_SOURCECLOSE | MIO_F_CTL_SINKCLOSE);
    }

    /* close sink if necessary */
    if (*flags & MIO_F_CTL_SINKCLOSE) {
        if (sink->active) {
            sink->active = FALSE;
            if (app_drv->app_close_sink
                && !app_drv->app_close_sink(source, sink, vctx, flags, &ierr))
            {
                MIOD_ERR2;
            }
        }
        if (sink->opened) {
            sink->opened = FALSE;
            if (sink->close_sink
                && !sink->close_sink(source, sink, flags, &ierr))
            {
                MIOD_ERR2;
            }
        }
    }

    /* close source if necessary */
    if (*flags & MIO_F_CTL_SOURCECLOSE) {
        if (source->active) {
            source->active = FALSE;
            if (app_drv->app_close_source
                && !app_drv->app_close_source(source, vctx, flags, &ierr))
            {
                MIOD_ERR2;
            }
        }
        if (source->opened) {
            source->opened = FALSE;
            if (source->close_source
                && !source->close_source(source, flags, &ierr))
            {
                MIOD_ERR2;
            }
        }
    }

    /* done with this guy... */
    if (xem) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_MULTIPLE,
                    "Multiple errors in MIO dispatch: %s", xem->str);
        g_string_free(xem, TRUE);
    }
    return ok;
}


gboolean
mio_dispatch_loop(
    MIOSource     *source,
    MIOSink       *sink,
    MIOAppDriver  *app_drv,
    void          *vctx,
    uint32_t       flags,
    uint32_t       polltime,
    uint32_t       retrybase,
    uint32_t       retrymax)
{
    uint32_t retrytime = retrybase;
    GError  *err       = NULL;
    gboolean rv        = TRUE;

    while (1) {
        /* process a record */
        if (mio_dispatch(source, sink, app_drv, vctx, &flags, &err)) {
            /* success. reset retry delay. */
            retrytime = retrybase;
        } else {
            /* processing error. display error message if necessary. */
            if (flags & (MIO_F_CTL_ERROR | MIO_F_CTL_TRANSIENT)) {
                MIOD_ERR3;
                rv = FALSE;
            } else {
                g_clear_error(&err);
            }

            /* sleep if necessary */
            if (flags & MIO_F_CTL_TRANSIENT) {
                /* Transient error. Set retry delay. */
                sleep(retrytime);
                retrytime *= 2;
                if (retrytime > retrymax) {retrytime = retrymax;}
            } else if (flags & MIO_F_CTL_POLL) {
                /* No input. Set poll delay. */
                if (polltime) {sleep(polltime);}
            }
        }

        /* check for termination flag no matter what */
        if (flags & MIO_F_CTL_TERMINATE) {break;}
    }
    return rv;
}


void
mio_source_free(
    MIOSource  *source)
{
    source->free_source(source);
}


void
mio_sink_free(
    MIOSink  *sink)
{
    sink->free_sink(sink);
}


static void
mio_source_free_app(
    MIOSource  *source)
{
    if (source->spec) {g_free(source->spec);}
}


gboolean
mio_source_init_app(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_APP;}
    if (vsp_type != MIO_T_APP) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open application-specific source: type mismatch");
        return FALSE;
    }

    /* initialize source */
    source->spec         = g_strdup(spec);
    source->name         = source->spec;
    source->vsp_type     = vsp_type;
    source->cfg          = cfg;
    source->ctx          = NULL;
    source->next_source  = NULL;
    source->close_source = NULL;
    source->free_source  = mio_source_free_app;
    source->opened       = FALSE;
    source->active       = FALSE;

    return TRUE;
}


static void
mio_sink_free_app(
    MIOSink  *sink)
{
    if (sink->spec) {g_free(sink->spec);}
}


gboolean
mio_sink_init_app(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_APP;}
    if (vsp_type != MIO_T_APP) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open application-specific sink: type mismatch");
        return FALSE;
    }

    /* initialize sink */
    sink->spec       = g_strdup(spec);
    sink->name       = sink->spec;
    sink->vsp_type   = vsp_type;
    sink->cfg        = cfg;
    sink->ctx        = NULL;
    sink->next_sink  = NULL;
    sink->close_sink = NULL;
    sink->free_sink  = mio_sink_free_app;
    sink->opened     = FALSE;
    sink->active     = FALSE;
    sink->iterative  = FALSE;

    return TRUE;
}
