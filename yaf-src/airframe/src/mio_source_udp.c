/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_udp.c
 *  Multiple I/O passive UDP datagram source
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
#include <airframe/mio_source_udp.h>
#include "mio_common_net.h"

static gboolean
mio_source_next_udp(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    struct addrinfo *ai = (struct addrinfo *)source->ctx;
    int              sock;

    /* open a socket */
    do {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {continue;}
        if (bind(sock, ai->ai_addr, ai->ai_addrlen) == 0) {break;}
        close(sock);
    } while ((ai = ai->ai_next));

    /* check for no openable socket */
    if (ai == NULL) {
        *flags |= MIO_F_CTL_ERROR;
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_CONN,
                    "couldn't create bound UDP socket to %s: %s",
                    source->spec ? source->spec : "default", strerror(errno));
        return FALSE;
    }

    /* store file descriptor */
    source->vsp = GINT_TO_POINTER(sock);

    return TRUE;
}


static gboolean
mio_source_close_udp(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    /* Close socket */
    close(GPOINTER_TO_INT(source->vsp));
    source->vsp = GINT_TO_POINTER(-1);

    /* All done */
    return TRUE;
}


static void
mio_source_free_udp(
    MIOSource  *source)
{
    if (source->spec) {g_free(source->spec);}
    if (source->name) {g_free(source->name);}
    mio_freeaddrinfo((struct addrinfo *)source->ctx);
}


gboolean
mio_source_init_udp(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    char *splitspec = NULL, *hostaddr = NULL, *svcaddr = NULL;

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_SOCK_DGRAM;}

    /* initialize UDP source */
    source->spec = spec ? g_strdup(spec) : NULL;
    source->name = NULL;
    source->vsp_type = vsp_type;
    source->vsp = NULL;
    source->ctx = NULL;
    source->cfg = cfg;
    source->next_source = mio_source_next_udp;
    source->close_source = mio_source_close_udp;
    source->free_source = mio_source_free_udp;
    source->opened = FALSE;
    source->active = FALSE;

    /* Ensure type is valid */
    if (vsp_type != MIO_T_SOCK_DGRAM) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create UDP source: type mismatch");
        return FALSE;
    }

    /* Parse specifier */
    splitspec = spec ? g_strdup(spec) : NULL;
    mio_init_ip_splitspec(splitspec, TRUE, (char *)cfg,
                          &hostaddr, &svcaddr, &source->name);

    /* Do lookup and create context */
    source->ctx = mio_init_ip_lookup(hostaddr, svcaddr,
                                     SOCK_DGRAM, IPPROTO_UDP, TRUE, err);

    if (splitspec) {g_free(splitspec);}

    return source->ctx ? TRUE : FALSE;
}
