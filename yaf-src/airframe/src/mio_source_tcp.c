/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_tcp.c
 *  Multiple I/O passive TCP single-client stream source
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
#include <airframe/mio_source_tcp.h>
#include "mio_common_net.h"

typedef struct _MIOSourceTCPContext {
    struct addrinfo  *ai;
    union {
        struct sockaddr_in    in4;
#if HAVE_GETADDRINFO
        struct sockaddr_in6   in6;
#endif
    } sa;
    uint32_t          sa_len;
    int               lsock;
} MIOSourceTCPContext;

static gboolean
mio_source_next_tcp(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceTCPContext *tcpx = (MIOSourceTCPContext *)source->ctx;
    MIOSourceTCPConfig  *tcpc = (MIOSourceTCPConfig *)source->cfg;
    struct addrinfo     *ai = NULL;
    int    sock, srv;
    fd_set lfdset;

    /* Create listening socket if necessary */
    if (tcpx->lsock < 0) {
        ai = tcpx->ai;
        do {
            tcpx->lsock = socket(ai->ai_family, ai->ai_socktype,
                                 ai->ai_protocol);
            if (tcpx->lsock < 0) {continue;}
            if (bind(tcpx->lsock, ai->ai_addr, ai->ai_addrlen) < 0) {
                close(tcpx->lsock); tcpx->lsock = -1; continue;
            }
            if (listen(tcpx->lsock, 1) < 0) {
                close(tcpx->lsock); tcpx->lsock = -1; continue;
            }
            break;
        } while ((ai = ai->ai_next));

        /* check for no listenable socket */
        if (ai == NULL) {
            *flags |= MIO_F_CTL_ERROR;
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_CONN,
                        "couldn't create TCP socket listening to %s: %s",
                        source->spec ? source->spec : "default",
                        strerror(errno));
            return FALSE;
        }
    }

    /* accept connection without blocking */
    FD_ZERO(&lfdset);
    FD_SET(tcpx->lsock, &lfdset);
    srv = select(tcpx->lsock + 1, &lfdset, NULL, NULL, &(tcpc->timeout));
    if (srv < 0) {
        if (errno == EINTR) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_NOINPUT,
                        "Interrupted select");
            return FALSE;
        } else {
            *flags |= MIO_F_CTL_ERROR;
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                        "error waiting for a TCP connection on %s: %s",
                        source->spec ? source->spec : "default",
                        strerror(errno));
            return FALSE;
        }
    } else if (srv == 0) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_NOINPUT,
                    "No connections waiting");
        return FALSE;
    }

    /* Kickass. We have an acceptable socket. */
    g_assert(FD_ISSET(tcpx->lsock, &lfdset));
    tcpx->sa_len = sizeof(tcpx->sa);
    sock = accept(tcpx->lsock, (struct sockaddr *)&(tcpx->sa), &(tcpx->sa_len));
    if (sock < 0) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                    "error accepting a TCP connection on %s: %s",
                    source->spec ? source->spec : "default", strerror(errno));
        return FALSE;
    }

    /* Store file descriptor */
    source->vsp = GINT_TO_POINTER(sock);

    return TRUE;
}


static gboolean
mio_source_close_tcp(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    close(GPOINTER_TO_INT(source->vsp));
    source->vsp = GINT_TO_POINTER(-1);
    return TRUE;
}


static void
mio_source_free_tcp(
    MIOSource  *source)
{
    MIOSourceTCPContext *tcpx = (MIOSourceTCPContext *)source->ctx;

    if (source->spec) {g_free(source->spec);}
    if (source->name) {g_free(source->name);}
    if (tcpx) {
        mio_freeaddrinfo((struct addrinfo *)tcpx->ai);
        close(GPOINTER_TO_UINT(tcpx->lsock));
        g_free(tcpx);
    }
}


gboolean
mio_source_init_tcp(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    MIOSourceTCPContext *tcpx = NULL;
    MIOSourceTCPConfig  *tcpc = (MIOSourceTCPConfig *)cfg;
    gboolean             ok = TRUE;
    char *splitspec = NULL, *hostaddr = NULL, *svcaddr = NULL;

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_SOCK_STREAM;}

    /* initialize TCP source */
    source->spec = spec ? g_strdup(spec) : NULL;
    source->name = NULL;
    source->vsp_type = vsp_type;
    source->vsp = NULL;
    source->ctx = NULL;
    source->cfg = cfg;
    source->next_source = mio_source_next_tcp;
    source->close_source = mio_source_close_tcp;
    source->free_source = mio_source_free_tcp;
    source->opened = FALSE;
    source->active = FALSE;

    /* Ensure type is valid */
    if (vsp_type != MIO_T_SOCK_STREAM) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create TCP source: type mismatch");
        ok = FALSE;
        goto end;
    }

    /* Parse specifier */
    splitspec = spec ? g_strdup(spec) : NULL;
    mio_init_ip_splitspec(splitspec, TRUE, tcpc->default_port,
                          &hostaddr, &svcaddr, &source->name);

    /* Create context */
    tcpx = g_new0(MIOSourceTCPContext, 1);

    /* Do lookup */
    if (!(tcpx->ai = mio_init_ip_lookup(hostaddr, svcaddr,
                                        SOCK_STREAM, IPPROTO_TCP, TRUE, err)))
    {
        ok = FALSE;
        goto end;
    }

    /* force listening socket creation */
    tcpx->lsock = -1;

    /* stash the context */
    source->ctx = tcpx;

  end:
    if (!ok && tcpx) {
        if (tcpx->ai) {mio_freeaddrinfo(tcpx->ai);}
        g_free(tcpx);
    }
    if (splitspec) {g_free(splitspec);}

    return ok;
}
