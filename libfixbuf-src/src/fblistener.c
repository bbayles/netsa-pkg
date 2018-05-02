/*@internal
 *
 * fblistener.c
 * IPFIX Collecting Process connection listener implementation
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2006-2018 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Brian Trammell
 * ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of the libfixbuf system and related source code is subject to the terms
 * of the following licenses:
 *
 * Copyright 2018 Carnegie Mellon University. All Rights Reserved.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 * ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 * BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 * LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 * EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 * MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 * ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 * COPYRIGHT INFRINGEMENT.
 *
 * Released under a GNU-Lesser GPL 3.0-style license, please see
 * License.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for
 * public release and unlimited distribution.  Please see Copyright
 * notice for non-US Government use and distribution.
 *
 * Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 * Trademark Office by Carnegie Mellon University.
 *
 * @OPENSOURCE_HEADER_END@
 * ------------------------------------------------------------------------
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>
#include <poll.h>



/**
 *
 * Understanding socket handling and collector construction within the
 * fixbuf listener:
 *
 * Error handling on connections in fixbuf is very different between
 * TCP and UDP connections.  The reasons behind this are partial
 * tied up within the IPFIX standard and its handling of UDP.
 * But within fixbuf, this needs to be understood in terms of how
 * collector's are created with respect to listener's.
 *
 * For both TCP and UDP, when a listener is created, a listening
 * socket is created with the listener.  (lsock)
 *
 * For UDP, the listener sock (lsock) is the socket used to create
 * the collector.  The collector gets created immediately, and the
 * collector is the structure that is associated with the fBuf
 * structure which actually handles PDU's.
 *
 * For TCP, the case is different.  The listening socket is used
 * primarily for the listenerWait call.  It is used as a socket
 * passed to select waiting for connection establishment.  Then
 * an accept call is made which creates a new socket handle.
 * That socket handle is used is to create the collector, and the
 * lsock handle is left only within the listener.
 *
 * When an error occurs, the normal usage of the API would be
 * to call fBufFree and call listenerWait again.  In the case
 * of TCP this works.  The library will wait for a new connection
 * to the listener lsock and create a new collector from a new
 * socket from the accept call.  For UDP, this will not work, and
 * the library will simply hang.  (Each lsock also has a
 * corresponding set of pipes to detect interrupts) and the select
 * call will simply wait on the read pipe handle.
 *
 *
 */

#define MAX_BUFFER_FREE 100

/* Maximum number of connections allowed by fixbuf */
#define MAX_CONNECTIONS 25

struct fbListener_st {
    /** Connection specifier for passive socket. */
    fbConnSpec_t                *spec;
    /** Base session. Used for internal templates. */
    fbSession_t                 *session;
    /** UDP Base Session.  Only set for UDP listeners.
     * Since UDP sessions are created at connection time,
     * this holds the first one so we can free it. */
    fbSession_t                 *udp_session;
    /** Last buffer returned by fbListenerWait(). */
    fBuf_t                      *lastbuf;
    /** The set of file descriptors to be monitored */
    struct pollfd               *pfd_array;
    /** size of array */
    nfds_t                      pfd_len;
    /** Holds last file descriptor used */
    int                         lsock;
    /** mode (-1 for udp) */
    int                         mode;
    /**
     * Interrupt pipe read end file descriptor.
     * Used to unblock a call to fbListenerWait().
     */
    int                         rip;
    /**
     * Interrupt pipe write end file descriptor.
     * Used to unblock a call to fbListenerWait().
     */
    int                         wip;
    /**
     * used to hold the handle to the collector for
     * this listener
     */
    fbCollector_t               *collectorHandle;
    /**
     * File descriptor table.
     * Maps file descriptors to active listener-managed buffer instances.
     */
    GHashTable                  *fdtab;
    /**
     * Application initialization function. Allows the application
     * to bind internal context to a collector, and to reject connections
     * after accept() but before session setup.
     */
    fbListenerAppInit_fn        appinit;
    /** Application free function. Frees storage allocated by appinit. */
    fbListenerAppFree_fn        appfree;
};

typedef struct fbListenerWaitFDSet_st {
    fd_set                      fds;
    int                         maxfd;
    fBuf_t                      *fbuf;
} fbListenerWaitFDSet_t;

/**
 * Structure that holds the listeners that are added to the group.
 */
struct fbListenerGroup_st
{
    /** pointer to the head of the listener group result list */
    fbListenerEntry_t   *head;
    /** pointer to the last fbListener */
    fbListenerEntry_t   *lastlist;
    /** pointer to a generic structure for future use */
    struct pollfd       *group_pfd;
    /** length of usable fds */
    nfds_t               pfd_len;
};


/**
 * fbListenerTeardownSocket
 *
 *
 *
 *
 */
static void fbListenerTeardownSocket(
    fbListener_t                *listener)
{
    unsigned int i;

    if (listener->pfd_len) {
        for (i = 0; i < listener->pfd_len; i++) {
            if (listener->pfd_array[i].fd >= 0) {
                close(listener->pfd_array[i].fd);
                listener->pfd_array[i].fd = -1;
            }
        }
        g_slice_free1((MAX_CONNECTIONS * sizeof(struct pollfd)),
                      listener->pfd_array);
        listener->pfd_len = 0;
    }

}

/**
 *fbListenerInitSocket
 *
 *
 *
 *
 */
static gboolean fbListenerInitSocket(
    fbListener_t                *listener,
    GError                      **err)
{
    int                         pfd[2];
    int                         i = 0;
    int                         count = 0;
    struct pollfd               *cpfd = NULL;
    struct addrinfo             *ai = NULL;
    struct addrinfo             *current = NULL;

    /* Create interrupt pipe */
    if (pipe(pfd)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "fbListener error creating interrupt pipe: %s",
                    strerror(errno));
        return FALSE;
    }


    /* Look up the passive socket address */
    if (!fbConnSpecLookupAI(listener->spec, TRUE, err)) {
        fbListenerTeardownSocket(listener);
        return FALSE;
    }

    ai = (struct addrinfo *)listener->spec->vai;

    current = ai;

    /* figure out how many addresses there are */
    while (current) {
        i++;
        current = current->ai_next;
    }

    listener->pfd_array = (struct pollfd*)g_slice_alloc0(MAX_CONNECTIONS *
                                                        sizeof(struct pollfd));

    if (listener->pfd_array == NULL) {
        return FALSE;
    }

    listener->pfd_len = i+2;

    /* read interrupt pipe */
    listener->pfd_array[0].fd = pfd[0];
    listener->pfd_array[0].events = POLLIN;
    /* write interrupt pipe */
    listener->pfd_array[1].fd = pfd[1];

    i = 2;
    /* Create the passive socket */
    do {

        cpfd = &listener->pfd_array[i];
        /*
         * Kludge for SCTP. addrinfo doesn't accept SCTP hints.
         */
#if FB_ENABLE_SCTP
        if ((listener->spec->transport == FB_SCTP) ||
            (listener->spec->transport == FB_DTLS_SCTP)) {
            ai->ai_socktype = SOCK_STREAM;
            ai->ai_protocol = IPPROTO_SCTP;
        }
#endif
        /* Create socket and bind it to the passive address */
        cpfd->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (cpfd->fd < 0) {
            i++; continue;
        }
        if (bind(cpfd->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            close(cpfd->fd); cpfd->fd = -1; i++; continue;
        }
        cpfd->events = POLLIN;

        /* Listen only on socket and sequenced packet sockets */
        if ((ai->ai_socktype == SOCK_STREAM)
#ifdef SOCK_SEQPACKET
            || (ai->ai_socktype == SOCK_SEQPACKET)
#endif
            ) {
            if (listen(cpfd->fd, 1) < 0) {
                close(cpfd->fd); cpfd->fd = -1; i++; continue;
            }
        }
        i++;
        /* Socket successfully bound for listening */
        count++;
    } while ((ai = ai->ai_next));

    /* check for no listenable socket */
    if (!count) {
        fbListenerTeardownSocket(listener);
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't create socket listening to %s:%s: %s",
                    listener->spec->host ? listener->spec->host : "*",
                    listener->spec->svc, strerror(errno));
        return FALSE;
    }


    /* All done. */
    return TRUE;
}

/**
 *fbListenerInitUDPSocket
 *
 *
 *
 *
 */
static gboolean fbListenerInitUDPSocket(
    fbListener_t                *listener,
    GError                      **err)
{
    void                        *ctx = NULL;
    fbCollector_t               *collector = NULL;
    fBuf_t                      *fbuf = NULL;
    unsigned int                i;

    /* Simulate accept on UDP socket */

    /* Ask application for context */
    if (listener->appinit) {
        if (!listener->appinit(listener, &ctx, listener->lsock, NULL, 0, err)){
            return FALSE;
        }
    }

    /* Create collector on UDP socket */
    switch (listener->spec->transport) {
    case FB_UDP:
        collector = fbCollectorAllocSocket(listener, ctx,
                                           listener->lsock, NULL, 0);
        break;
#if HAVE_OPENSSL_DTLS
    case FB_DTLS_UDP:
        collector = fbCollectorAllocTLS(listener, ctx,
                                        listener->lsock, NULL, 0, err);
        break;
#endif
    default:
        g_assert_not_reached();
    }

    /* Check for collector alloc error */
    if (!collector) return FALSE;

    /* Create a buffer with a cloned session around the collector */
    fbuf = fBufAllocForCollection(fbSessionClone(listener->session),collector);

    /* add this fbuf for all file descriptors */
    for (i = 2; i < listener->pfd_len; i++) {
        g_hash_table_insert(listener->fdtab,
                            GINT_TO_POINTER(listener->pfd_array[i].fd), fbuf);
    }


    /* Add collector to the file descriptor table */
    /*g_hash_table_insert(listener->fdtab,
      GINT_TO_POINTER(listener->lsock), fbuf);*/

    /* No more passive socket */
    /*listener->lsock = -1;*/
    /* set mode to UDP */
    listener->mode = -1;

    /* store this session so we can free it later */
    listener->udp_session = fBufGetSession(fbuf);

    /* store the handle to the collector */
    listener->collectorHandle = collector;

    /* All done. */
    return TRUE;
}

/**
 *fbListenerAlloc
 *
 *
 *
 *
 */
fbListener_t *fbListenerAlloc(
    fbConnSpec_t                *spec,
    fbSession_t                 *session,
    fbListenerAppInit_fn        appinit,
    fbListenerAppFree_fn        appfree,
    GError                      **err)
{
    fbListener_t                *listener = NULL;
    gboolean                    ownSocket;

    if (spec) {
        ownSocket = FALSE;
    } else {
        ownSocket = TRUE;
    }

    /* Allocate a new listener */
    listener = g_slice_new0(fbListener_t);

    /* -1 for file descriptors means no fd */
    listener->lsock = -1;
    listener->rip = -1;
    listener->wip = -1;

    if (ownSocket) { /* user handling own socket creation and connections */
        listener->spec = NULL;
    } else {
        listener->spec = fbConnSpecCopy(spec);
    }
    /* Fill in what we can */
    listener->session = session;
    listener->appinit = appinit;
    listener->appfree = appfree;

    /* allocate file descriptor table */
    listener->fdtab = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!ownSocket) {
        /* Do transport-specific initialization */
        switch (spec->transport) {
#if FB_ENABLE_SCTP
          case FB_SCTP:
#if HAVE_OPENSSL_DTLS_SCTP
          case FB_DTLS_SCTP:
#endif
#endif
          case FB_TCP:
#if HAVE_OPENSSL
          case FB_TLS_TCP:
#endif
            if (!fbListenerInitSocket(listener, err)) {
                goto err;
            }
            break;
          case FB_UDP:
#if HAVE_OPENSSL_DTLS
          case FB_DTLS_UDP:
#endif
            /* FIXME this may leak on socket setup error for UDP. */
            if (fbListenerInitSocket(listener, err)) {
                if (!fbListenerInitUDPSocket(listener, err)) {
                    fbListenerTeardownSocket(listener);
                    goto err;
                }
            } else {
                goto err;
            }
            break;
          default:
#ifndef FB_ENABLE_SCTP
            if (spec->transport == FB_SCTP || spec->transport == FB_DTLS_SCTP){
                g_error("Libfixbuf not enabled for SCTP Transport. "
                        " Run configure with --with-sctp");
            }
#endif
            if (spec->transport == FB_TLS_TCP ||
                spec->transport == FB_DTLS_SCTP ||
                spec->transport == FB_DTLS_UDP)
            {
                g_error("Libfixbuf not enabled for this mode of transport. "
                        " Run configure with --with-openssl");
            }
        }
    }

    /* Return the initialized listener */
    return listener;

err:
    if (listener) {
        if (listener->fdtab) {
            g_hash_table_destroy(listener->fdtab);
        }

        g_slice_free(fbListener_t, listener);
    }

    /* No listener */
    return NULL;
}


/**
 * fbListenerFreeBuffer
 *
 *
 *
 *
 */
static void   fbListenerFreeBuffer(
    void                        *vfd __attribute__((unused)),
    fBuf_t                      *fbuf,
    /*    void                        *vignore __attribute__((unused)) )*/
    fBuf_t                      **lfbuf)
{
    /* free the buffer; this will close the socket. */
    /*    fBufFree(fbuf);*/
    /* we can't change the hash table while we are looping through it */
    *lfbuf = fbuf;
    lfbuf++;
}

/**
 * fbListenerAppFree
 *
 *
 */

void fbListenerAppFree(
    fbListener_t               *listener,
    void                       *ctx)
{
    if (listener) {
        if (listener->appfree) {
            (listener->appfree)(ctx);
        }
    }
}


/**
 *fbListenerFree
 *
 *
 *
 *
 */
void            fbListenerFree(
    fbListener_t                *listener)
{
    fBuf_t                     *tfbuf[MAX_BUFFER_FREE+1];
    fBuf_t                     *lfbuf = NULL;
    fbSession_t                *session = NULL;
    unsigned int               loop = 0;

    while (loop < MAX_BUFFER_FREE) {
        tfbuf[loop] = NULL;
        loop++;
    }

    /* shut down passive socket */
    fbListenerTeardownSocket(listener);

    /* free any open buffers we may have */
    g_hash_table_foreach(listener->fdtab,
                        (GHFunc)fbListenerFreeBuffer, tfbuf);

    loop = 0;
    lfbuf = tfbuf[0];
    /* free first session */
    if (listener->udp_session) {
        /* we need to get the session set on the fBuf - it should be the
           same as udp_session in the case that we haven't received anything*/
        session = fBufGetSession(lfbuf);
        if (listener->udp_session != session) {
            fbSessionFree(listener->udp_session);
        }
    }

    if (listener->mode == -1) {
        /* for UDP there can be multiple FDs with the same fBuf */
        /* And there should only be 1 fBuf for this listener */
        fBufFree(lfbuf);
    } else {
        while (lfbuf && loop < MAX_BUFFER_FREE) {
            fBufFree(lfbuf);
            loop++;
            lfbuf = tfbuf[loop];
        }
    }
    /* free the listener table */
    g_hash_table_destroy(listener->fdtab);

    /* free the connection specifier */
    fbConnSpecFree(listener->spec);

    /* free the listener itself */
    g_slice_free(fbListener_t, listener);
}

/**
 *fbListenerWaitAddFD
 *
 *
 *
 *
 */
/*static void   fbListenerWaitAddFD(
    void                        *vfd,
    void                        *vignore __attribute__((unused)),
    fbListenerWaitFDSet_t       *lfdset)
{
    int                         fd = GPOINTER_TO_INT(vfd);

    FD_SET(fd,&(lfdset->fds));
    if (fd > lfdset->maxfd) lfdset->maxfd = fd;
}
*/

/**
 * fbListenerWaitSearch
 *
 *
 *
 *
 */
 /*static void   fbListenerWaitSearch(
    void                        *vfd,
    void                        *fbuf,
    fbListenerWaitFDSet_t       *lfdset)
{
    int                         fd = GPOINTER_TO_INT(vfd);

    if (FD_ISSET(fd,&(lfdset->fds))) {
        lfdset->fbuf = fbuf;
    }
    }*/

/**
 * fbListenerAddPollFD
 *
 *
 */
static void fbListenerAddPollFD(
    struct pollfd              *fd_array,
    nfds_t                     *array_len,
    int                        fd)
{
    nfds_t i;
    nfds_t num_fds = *array_len;
    gboolean added = FALSE;

    /* use an old entry for this new entry */
    for (i = 0; i < num_fds; i++) {
        if (fd_array[i].fd < 0) {
            fd_array[i].fd = fd;
            fd_array[i].events = POLLIN;
            added = TRUE;
            break;
        }
    }

    /* no free entries in the array, add a new one */
    if (!added) {
        fd_array[num_fds].fd = fd;
        fd_array[num_fds].events = POLLIN;
        num_fds++;
        *array_len = num_fds;
    }
}

/**
 * fbListenerWaitAccept
 *
 *
 *
 *
 */
static fBuf_t *fbListenerWaitAccept(
    fbListener_t                *listener,
    GError                      **err)
{
    int                         asock;
    union {
        struct sockaddr         so;
        struct sockaddr_in      ip4;
        struct sockaddr_in6     ip6;
    }                           peer;
    socklen_t                   peerlen;
    void                        *ctx = NULL;
    fbCollector_t               *collector = NULL;
    fBuf_t                      *fbuf = NULL;

    /* Accept the connection */
    peerlen = sizeof(peer);
    asock = accept(listener->lsock, &(peer.so), &peerlen);
    if (asock < 0) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "listener accept error: %s",
                    strerror(errno));
        return NULL;
    }

    /* Okay, we have a socket. Ask the application for context. */
    if (listener->appinit) {

        if (!listener->appinit(listener, &ctx, asock,
                               &(peer.so), peerlen, err)) {
            close(asock);
            return NULL;
        }
    }

    /* Create a collector as appropriate */
    switch (listener->spec->transport) {
#if FB_ENABLE_SCTP
    case FB_SCTP:
#endif
    case FB_TCP:
        collector = fbCollectorAllocSocket(listener, ctx, asock,
                                           &(peer.so), peerlen);
        break;
#if HAVE_OPENSSL
#if HAVE_OPENSSL_DTLS_SCTP
    case FB_DTLS_SCTP:
#endif
    case FB_TLS_TCP:
        collector = fbCollectorAllocTLS(listener, ctx, asock,
                                        &(peer.so), peerlen, err);
        break;
#endif
    default:
        g_assert_not_reached();
    }

    /* Check for collector creation error */
    if (!collector) return NULL;

    /* Create a buffer with a cloned session around the collector */
    fbuf = fBufAllocForCollection(fbSessionClone(listener->session),collector);

    /* Make the buffer automatic */
    fBufSetAutomaticMode(fbuf, TRUE);

    /* Add buffer to the file descriptor table */
    g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(asock), fbuf);

    /* don't add to array if fbListenerWaitNoCollectors was called */
    if (listener->mode < 1) {
        /* add to poll array */
        if (listener->pfd_len < MAX_CONNECTIONS) {
            fbListenerAddPollFD(listener->pfd_array, &listener->pfd_len,asock);
        } else {
            g_warning("Max connections %d reached.", MAX_CONNECTIONS);
        }
    }

    listener->lsock = asock;

    /* store the collector handle */
    listener->collectorHandle = collector;

    /* All done. */
    return fbuf;
}

/**
 * fbListenerRemove
 *
 *
 *
 *
 */
void fbListenerRemove(
    fbListener_t        *listener,
    int                 fd)
{
    unsigned int i;

    /* remove from hash table */
    g_hash_table_remove(listener->fdtab, GINT_TO_POINTER(fd));

    /* remove from poll array */
    for (i = 0; i < listener->pfd_len; i++) {
        if (listener->pfd_array[i].fd == fd) {
            if (listener->lsock == fd) {
                /* unset lsock */
                listener->lsock = 0;
            }
            close(listener->pfd_array[i].fd);
            listener->pfd_array[i].fd = -1;
            break;
        }
    }
}

/**
 * fbListenerWait
 *
 *
 *
 *
 */
fBuf_t *fbListenerWait(
    fbListener_t                *listener,
    GError                      **err)
{
    fBuf_t                      *fbuf = NULL;
    uint8_t                     byte;
    int                         got_sock = -1;
    int                         rc;
    unsigned int                i;

    /* wait for data available on one of our file descriptors */
    rc = poll(listener->pfd_array, listener->pfd_len, -1);

    if (rc < 0) {
        if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Interrupted listener wait");
                return NULL;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: %s",
                        strerror(errno));
            return NULL;
        }
    }

    /* Loop through file descriptors */
    for (i = 0; i < listener->pfd_len; i++) {
        struct pollfd *pfd = &listener->pfd_array[i];

        if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
            /* hang up or error */
            got_sock = pfd->fd;
            break;
        }

        if (!(pfd->revents & POLLIN)) {
            continue;
        }

        if (i == 0) {
            /* read or write interrupt */
            /* consume and ignore return */
            read(pfd->fd, &byte, sizeof(byte));
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "External interrupt on pipe");
            return NULL;
        }

        got_sock = pfd->fd;
        break;
    }

    /* quick solution - check if the fd is the same as last time */
    if ((listener->lsock == got_sock) && listener->lastbuf) {
        return listener->lastbuf;
    }

    listener->lsock = got_sock;

    /* different than last time -> check to see if it's been seen before */
    if ((fbuf =g_hash_table_lookup(listener->fdtab,GINT_TO_POINTER(got_sock))))
    {
        listener->lastbuf = fbuf;
        if (listener->mode < 0) {
            /* if UDP set FD on collector for reading */
            fbCollectorSetFD(fBufGetCollector(fbuf), got_sock);
        }
        return fbuf;
    } else {
        if (listener->mode >= 0) {
            /* new connection */
            fbuf = fbListenerWaitAccept(listener, err);
            if (!fbuf) return NULL;
            listener->lastbuf = fbuf;
            return fbuf;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: invalid FD");
            /* this is strange bc UDP fbufs are set in fblisteneralloc */
            return NULL;
        }
    }
}

fBuf_t *fbListenerWaitNoCollectors(
    fbListener_t                *listener,
    GError                      **err)
{
    fBuf_t                      *fbuf = NULL;
    uint8_t                     byte;
    int                         rc;
    unsigned int                i;


    /* set the mode to 1 so fbListenerWaitAccept doesn't add fd */
    listener->mode = 1;
    /* wait for data available on one of our file descriptors */
    rc = poll(listener->pfd_array, listener->pfd_len, -1);

    if (rc < 0) {
        if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Interrupted listener wait");
            return NULL;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: %s",
                        strerror(errno));
            return NULL;
        }
    }

    /* Loop file descriptors */
    for (i = 0; i < listener->pfd_len; i++) {
        struct pollfd *pfd = &listener->pfd_array[i];

        if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
            listener->lsock = pfd->fd;
            break;
        }

        if (!(pfd->revents & POLLIN)) {
            continue;
        }

        if (i == 0) {
            /* read or write interrupt */
            /* consume and ignore return */
            read(pfd->fd, &byte, sizeof(byte));
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "External interrupt on pipe");
            return NULL;
        }

        listener->lsock = pfd->fd;
        break;
    }

    /* handle any pending accept, return the accepted buffer immediately. */
    if (listener->mode >= 0) {
        return fbListenerWaitAccept(listener, err);
    } else {
        /* For UDP this doesn't really work, just return the data */
        if ((fbuf = g_hash_table_lookup(listener->fdtab,
                                        GINT_TO_POINTER(listener->lsock))))
        {
            fbCollectorSetFD(fBufGetCollector(fbuf), listener->lsock);
            return fbuf;
        }
    }

    /* this should never happen */
    return NULL;
}


static void   fbListenerInterruptCollectors(
    void                        *vfd __attribute__((unused)),
    void                        *fbuf,
    fbListenerWaitFDSet_t       *lfdset __attribute__((unused)))
{
    fBufInterruptSocket(fbuf);
}


/**
 * fbListenerInterrupt
 *
 *
 *
 *
 */
void fbListenerInterrupt(
    fbListener_t        *listener)
{
    uint8_t             byte = 0xe7;

    /* send interrrupts to the collectors, then to the listener */
    g_hash_table_foreach(listener->fdtab,
                         (GHFunc)fbListenerInterruptCollectors,
                         NULL);

    /* write and ignore return */
    /*write(listener->wip, &byte, sizeof(byte));
      write(listener->rip, &byte, sizeof(byte));*/
    write(listener->pfd_array[0].fd, &byte, sizeof(byte));
    write(listener->pfd_array[1].fd, &byte, sizeof(byte));


}

/**
 * fbListenerGetConnSpec
 *
 *
 *
 *
 */
fbConnSpec_t        *fbListenerGetConnSpec(
    fbListener_t        *listener)
{
    return listener->spec;
}


/**
 *fbListenerGetCollector
 *
 * gets the collector allocated to the listener
 *
 */
gboolean            fbListenerGetCollector(
    fbListener_t        *listener,
    fbCollector_t       **collector,
    GError              **err)
{
    if (NULL == listener->collectorHandle) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "no collector available to be retrieved");
        return FALSE;
    }

    *collector = listener->collectorHandle;

    return TRUE;
}

/* returns NULL or pointer to allocated group structure */

fbListenerGroup_t* fbListenerGroupAlloc(
    void)
{
    fbListenerGroup_t   *group = NULL;

    group = g_slice_new0( fbListenerGroup_t );

    if (!group) {
        return NULL;
    }

    group->group_pfd = (struct pollfd*)g_slice_alloc0(MAX_CONNECTIONS* 5 *sizeof(struct pollfd));

    group->head = NULL;

    return group;
}


/**
 * fbListenerGroupFree
 *
 * frees a listener group
 *
 */
void fbListenerGroupFree(
    fbListenerGroup_t *group)
{

    if (group->group_pfd) {
        g_slice_free1((MAX_CONNECTIONS * 5 * sizeof(struct pollfd)),
                      group->group_pfd);
    }

    g_slice_free(fbListenerGroup_t, group);
}

/**
 * fbListenerGroupAddListener
 *
 * @return 0 upon success.  "1" if entry couldn't get created
 *         maybe "2" if either of the incoming pointers is NULL
 */
int fbListenerGroupAddListener(
    fbListenerGroup_t  *group,
    const fbListener_t *listener)
{
    fbListenerEntry_t   *entry = NULL;
    unsigned int        i;

    if (!group || !listener) {
        return 2;
    }

    entry = g_slice_new0( fbListenerEntry_t );

    if (!entry) {
        /* needs to be something like ERR_NO_MEM */
        return 1;
    }

    entry->prev = NULL;
    entry->next = group->head;
    entry->listener = (fbListener_t*)listener;

    if (group->head) {
        group->head->prev = entry;
    }

    group->head = entry;

    /* add FDs */
    for (i = 0; i < entry->listener->pfd_len; i++) {
        group->group_pfd[group->pfd_len].fd = entry->listener->pfd_array[i].fd;
        group->group_pfd[group->pfd_len].events = POLLIN;
        group->pfd_len++;
    }

    group->lastlist = entry;

    return 0;
}

/**
 * fbListenerGroupDeleteListener
 *
 * @return 0 on success.  "1" if not found. "2" if a pointer is NULL
*/
int fbListenerGroupDeleteListener(
    fbListenerGroup_t   *group,
    const fbListener_t  *listener)
{
    fbListenerEntry_t   *entry = NULL;
    unsigned int i, k;

    if (!group || !listener) {
        return 2;
    }

    for (entry = group->head; entry; entry = entry->next) {
        if (entry->listener == listener) {
            if (entry->prev) {
                entry->prev->next = entry->next;
            }

            if (entry->next) {
                entry->next->prev = entry->prev;
            }

            /* remove FDs (close will happen later) */
            for (i = 0; i < entry->listener->pfd_len; i++) {
                for (k = 0; k < group->pfd_len; k++) {
                    if (entry->listener->pfd_array[i].fd ==
                        group->group_pfd[k].fd)
                    {
                        group->group_pfd[k].fd = -1;
                        break;
                    }
                }
            }

            if (entry == group->lastlist) {
                group->lastlist = group->head;
            }

            g_slice_free(fbListenerEntry_t, entry);

            return 0;
        }
    }

    return 1;
}

fbListenerGroupResult_t *fbListenerNewResult(
    fbListenerGroupResult_t **resultList,
    fbListener_t            *listener)
{
    fbListenerGroupResult_t *result = NULL;

    /* allocate new one */
    result = g_slice_new0( fbListenerGroupResult_t );
    /* set buffer to last one */
    result->fbuf = listener->lastbuf;
    /* set listener */
    result->listener = listener;
    /* put it on the list */
    result->next = *resultList;

    *resultList = result;

    return result;
}


void fbListenerFreeGroupResult(
    fbListenerGroupResult_t *result)
{
    fbListenerGroupResult_t *cr, *nr;

    for (cr = result; cr; cr = nr) {
        nr = cr->next;
        g_slice_free(fbListenerGroupResult_t, cr);
    }
}




fbListenerGroupResult_t* fbListenerGroupWait(
    fbListenerGroup_t   *group,
    GError             **err)
{
    gboolean                    found;
    uint8_t                     byte;
    unsigned int                i, k;
    int                         rc;
    int                         new_fd = -1;
    fBuf_t                      *fbuf = NULL;
    fbListenerEntry_t           *entry       = NULL;
    fbListenerGroupResult_t     *resultHead  = NULL;
    fbListenerGroupResult_t     *result      = NULL;

    g_assert(group);

    /* wait for data available on one of our file descriptors */

    while (!resultHead) {
        rc = poll(group->group_pfd, group->pfd_len, -1);

        if (rc < 0) {
            if (errno == EINTR) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                            "Interrupted listener wait");
                return NULL;
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "listener wait error: %s",
                            strerror(errno));
                return NULL;
            }
        }

        /* Loop file descriptors */
        for (i = 0; i < group->pfd_len; i++) {

            struct pollfd *pfd = &group->group_pfd[i];

            found = FALSE;

            if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
                /* hang up or error */
                new_fd = pfd->fd;
            } else if (!(pfd->revents & POLLIN)) {
                continue;
            }

            new_fd = pfd->fd;

            /* check to see if this belongs to the last listener */
            if (new_fd == group->lastlist->listener->lsock) {
                result = fbListenerNewResult(&resultHead,
                                             group->lastlist->listener);
                continue;
            }

            /* find out which listener this belongs to */
            for (entry = group->head; entry; entry = entry->next) {
                /* handle interrupt pipe read end */

                for (k = 0; k < entry->listener->pfd_len; k++) {
                    struct pollfd *cpfd = &entry->listener->pfd_array[k];

                    if (new_fd == cpfd->fd) {

                        if (k == 0) {
                            /* read or write interrupt */
                            /* consume and ignore return */
                            read(cpfd->fd, &byte, sizeof(byte));
                            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                                        "External interrupt on pipe");
                            return NULL;
                        }

                        if ((entry->listener->lsock == new_fd) &&
                            entry->listener->lastbuf)
                        {
                            result = fbListenerNewResult(&resultHead,
                                                         entry->listener);
                            found = TRUE;
                            group->lastlist = entry;
                            break;
                        }

                        entry->listener->lsock = new_fd;
                        /* Look it up */
                        if ((fbuf = g_hash_table_lookup(entry->listener->fdtab,
                                                GINT_TO_POINTER(new_fd))))
                        {
                            if (entry->listener->mode < 0) {
                                fbCollectorSetFD(fBufGetCollector(fbuf),
                                                 new_fd);
                            }
                            entry->listener->lastbuf = fbuf;
                            result = fbListenerNewResult(&resultHead,
                                                         entry->listener);
                            group->lastlist = entry;
                            found = TRUE;
                            break;
                        } else {
                            if (entry->listener->mode >= 0) {
                                /* TCP - call accept */
                                fbuf = fbListenerWaitAccept(entry->listener,
                                                            err);
                                entry->listener->lastbuf = fbuf;
                                result = fbListenerNewResult(&resultHead,
                                                             entry->listener);
                                if (group->pfd_len < (MAX_CONNECTIONS * 5)) {
                                    fbListenerAddPollFD(group->group_pfd,
                                                        &group->pfd_len,
                                                       entry->listener->lsock);
                                } else {
                                    g_warning("Maximum connections reached "
                                              "for Listener Group (%d)",
                                              group->pfd_len);
                                }
                                found = TRUE;
                                group->lastlist = entry;
                                break;
                            } else {
                                /* shouldn't happen */
                                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                                            "listener wait error: invalid FD");
                                return NULL;
                            }
                        }

                    } /* new_fd == cpfd->fd */
                } /* listener->pfd_array for loop */

                if (found) {
                    break;
                }

            } /* listenergroup for loop */

            if (!found) {
                /* close the old one, it doesn't belong to any listeners
                 it most likely was closed on the listener */
                close(pfd->fd);
                pfd->fd = -1;
            }

        } /* loop through fd's */

    } /* !resultHead */
    return resultHead;

}

/*  Given a socket descriptor with an existing connection, return an fbuf
 *  fBufNext can be called on it
 *  Interrupting the accepting of new connections on this socket is the
 *  responsibility of the caller, it cannot be done with
 *  fbListenerInterrupt().  However, the collectors attached to this listener
 *  can be interrupted by this call, which short circuits fBufNext().
 *  Call fbListenerInterrupt to stop the collectors, then stop the listener
 *  socket on your own.
 */
fBuf_t  *fbListenerOwnSocketCollectorTCP(
    fbListener_t   *listener,
    int             sock,
    GError        **err)
{
    fbCollector_t   *collector  = NULL;
    fBuf_t          *fbuf       = NULL;
    fbConnSpec_t     connSpec;
    g_assert(listener);

    if (sock <= 2) {
        /* invalid socket */
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
            "Invalid socket descriptor");
        return NULL;
    }

    connSpec.transport = FB_TCP;
    listener->spec = &connSpec;

    collector = fbCollectorAllocSocket(listener, NULL, sock, NULL, 0);

    fbuf = fBufAllocForCollection(fbSessionClone(listener->session),collector);

    fBufSetAutomaticMode(fbuf, FALSE);

    /* Add buffer to the file descriptor table */
    /* g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(sock), fbuf);*/

    listener->lsock = sock;

    /* store the collector handle */
    listener->collectorHandle = collector;

    listener->spec = NULL;

    /* All done. */
    return fbuf;
}

/* not even remotely tested yet */
fBuf_t  *fbListenerOwnSocketCollectorTLS(
    fbListener_t   *listener,
    int             sock,
    GError        **err)
{
    fbCollector_t   *collector  = NULL;
    fBuf_t          *fbuf       = NULL;

    g_assert(listener);

    if (sock <= 2) {
        /* invalid socket */
        return NULL;
    }

    listener->spec->transport = FB_TLS_TCP;

/*    collector = fbCollectorAllocTLS(listener, NULL, sock, NULL, 0, err);*/

    fbuf = fBufAllocForCollection(fbSessionClone(listener->session),collector);

    fBufSetAutomaticMode(fbuf, FALSE);

    /* Add buffer to the file descriptor table */
    /*g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(sock), fbuf);*/

    /* store the collector handle */
    listener->collectorHandle = collector;

    listener->lsock = sock;

    (void)err;

    /* All done. */
    return fbuf;
}

void fbListenerRemoveLastBuf(
    fBuf_t         *fbuf,
    fbListener_t   *listener)
{
    if (listener->lastbuf == fbuf) {
        listener->lastbuf = NULL;
    }
}

gboolean fbListenerCallAppInit(
    fbListener_t       *listener,
    fbUDPConnSpec_t    *spec,
    GError             **err)
{

    if (listener->appinit) {
        if (!listener->appinit(listener, &(spec->ctx), listener->lsock,
                               &(spec->peer.so), spec->peerlen, err)) {
            return FALSE;
        }
    }

    return TRUE;

}

fbSession_t *fbListenerSetPeerSession(
    fbListener_t        *listener,
    fbSession_t         *session)
{

    fbSession_t *new_session = session;

    if (!new_session) {
        new_session = fbSessionClone(listener->session);
    }

    listener->session = new_session;

    fBufSetSession(listener->lastbuf, new_session);

    fbSessionSetTemplateBuffer(new_session, listener->lastbuf);

    return new_session;

}
