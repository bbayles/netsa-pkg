/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_common_net.c
 *  Multiple I/O network source/sink common support and addrinfo glue
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
#include "mio_common_net.h"

#if HAVE_GETADDRINFO
void
mio_freeaddrinfo(
    struct addrinfo  *ai)
{
    freeaddrinfo(ai);
}


struct addrinfo *
mio_init_ip_lookup(
    char      *hostaddr,
    char      *svcaddr,
    int        socktype,
    int        protocol,
    gboolean   passive,
    GError   **err)
{
    struct addrinfo *ai = NULL, hints;
    int              ai_err;

    /* set up hints */
    memset(&hints, 0, sizeof(hints));
    /* some ancient linuxen won't let you specify this */
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif
    if (passive) {hints.ai_flags |= AI_PASSIVE;}
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;

    /* get addrinfo for host/port */
    if ((ai_err = getaddrinfo(hostaddr, svcaddr, &hints, &ai))) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "error looking up UDP address %s:%s: %s",
                    hostaddr ? hostaddr : "*", svcaddr, gai_strerror(ai_err));
        return NULL;
    }

    /* lookup succeeded. return addrinfo. */
    return ai;
}


#else /* if HAVE_GETADDRINFO */

void
mio_freeaddrinfo(
    struct addrinfo  *ai)
{
    g_free(ai->ai_addr);
    g_free(ai);
}


struct addrinfo *
mio_init_ip_lookup(
    char      *hostaddr,
    char      *svcaddr,
    int        socktype,
    int        protocol,
    gboolean   passive,
    GError   **err)
{
    struct addrinfo    *ai = NULL;
    struct sockaddr_in *sa = NULL;
    struct hostent     *he = NULL;
    struct servent     *se = NULL;
    unsigned long       svcaddrlong;
    char *svcaddrend;

    /* create a sockaddr */
    sa = g_new0(struct sockaddr_in, 1);

    /* get service address */
    svcaddrlong = strtoul(svcaddr, &svcaddrend, 10);
    if (svcaddrend != svcaddr) {
        /* Convert long to net-order uint16_t */
        sa->sin_port = g_htons((uint16_t)svcaddrlong);
    } else {
        struct servent *se;
        /* Do service lookup */
        if (!(se = getservbyname(svcaddr, "udp"))) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "error looking up service %s", svcaddr);
            g_free(sa);
            return NULL;
        }
        sa->sin_port = se->s_port;
    }

    /* get host address */
    if (hostaddr) {
        if (!(he = gethostbyname(hostaddr))) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "error looking up host %s: %s",
                        hostaddr, hstrerror(h_errno));
            g_free(sa);
            return NULL;
        }
        sa->sin_addr.s_addr = *(he->h_addr);
    } else {
        if (passive) {
            sa->sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "cannot connect() without host address");
            g_free(sa);
            return NULL;
        }
    }

    /* fake up a struct addrinfo */
    ai = g_new0(struct addrinfo, 1);
    ai->ai_family = AF_INET;
    ai->ai_socktype = socktype;
    ai->ai_protocol = protocol;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = sa;
    return ai;
}


#endif /* if HAVE_GETADDRINFO */

void
mio_init_ip_splitspec(
    char      *spec,
    gboolean   passive,
    char      *default_port,
    char     **hostaddr,
    char     **svcaddr,
    char     **srcname)
{
    GString *gsrcname = NULL;

    /* Split specifier */
    if (!spec || !strlen(spec)) {
        /* No specifier at all. Use default port. */
        *hostaddr = NULL;
        *svcaddr = default_port;
    } else if ((*svcaddr = strchr(spec, ','))) {
        /* Contains colon; bind to host and port */
        if (*hostaddr && (strcmp(*hostaddr, "*") == 0)) {
            /* Special case - * is explicit bind-to-all */
            *hostaddr = NULL;
        } else {
            *hostaddr = spec;
        }
        *((*svcaddr)++) = (char)0;
    } else {
        if (passive) {
            /* No colon. Assume whole address is port/service. */
            *hostaddr = NULL;
            *svcaddr = spec;
        } else {
            /* No colon. Assume whole address is host. */
            *hostaddr = spec;
            *svcaddr = default_port;
        }
    }

    /* then build a name out of the parts */
    gsrcname = g_string_new(NULL);
    g_string_printf(gsrcname, "%s-%s", *hostaddr ? *hostaddr : "any", *svcaddr);
    *srcname = gsrcname->str;
    g_string_free(gsrcname, FALSE);
}


gboolean
mio_sink_next_common_net(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    struct addrinfo *ai = (struct addrinfo *)sink->ctx;
    int              sock;

    do {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {continue;}
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {break;}
        close(sock);
    } while ((ai = ai->ai_next));

    /* check for no openable socket */
    if (ai == NULL) {
        *flags |= MIO_F_CTL_TRANSIENT;
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_CONN,
                    "couldn't create connected socket to %s: %s",
                    sink->spec, strerror(errno));
        return FALSE;
    }

    /* store file descriptor */
    sink->vsp = GINT_TO_POINTER(sock);

    return TRUE;
}


gboolean
mio_sink_close_common_net(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    /* Close socket */
    close(GPOINTER_TO_INT(sink->vsp));
    sink->vsp = GINT_TO_POINTER(-1);

    /* All done */
    return TRUE;
}


void
mio_sink_free_common_net(
    MIOSink  *sink)
{
    mio_freeaddrinfo((struct addrinfo *)sink->ctx);
}
