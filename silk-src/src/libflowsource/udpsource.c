/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

/*
**  Functions to create and read from a UDP socket.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: udpsource.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#if SK_ENABLE_ZLIB
#include <zlib.h>
#endif
#include <poll.h>
#include <silk/libflowsource.h>
#include <silk/redblack.h>
#include <silk/skdllist.h>
#include <silk/sklog.h>
#include <silk/skthread.h>
#include "udpsource.h"
#include "circbuf.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* Timeout to pass to the poll(2) system class, in milliseconds. */
#define POLL_TIMEOUT 500

/* Whether to compile in code to help debug accept-from-host */
#ifndef DEBUG_ACCEPT_FROM
#define DEBUG_ACCEPT_FROM 0
#endif


/* forward declarations */
struct skUDPSourceBase_st;
typedef struct skUDPSourceBase_st skUDPSourceBase_t;
struct peeraddr_source_st;
typedef struct peeraddr_source_st peeraddr_source_t;


/*
 *    There is one skUDPSource_t for every skpc_probe_t that accepts
 *    data on a UDP port.  The skUDPSource_t contains data collected
 *    for that particular probe.
 *
 *    For each source/probe, the pair (listen_address, accept_from)
 *    must be unique.  That is, either the source is only thing
 *    listening on this address/port, or the sources are distinguished
 *    by the address the packets are coming from (i.e., the peer
 *    address).
 *
 *    Under the 'skUDPSource_t' there is a 'skUDPSourceBase_t' object,
 *    which handles the collection of data from the network.  When
 *    multiple 'skUDPSource_t's listen on the same address, they share
 *    the same 'skUDPSourceBase_t'.  The 'skUDPSourceBase_t' has an
 *    red-black tree (the 'addr_to_source' member) that maps back to
 *    all the 'skUDPSource_t objects' that share that base.  The key
 *    in the red-black tree is the 'from-address'.
 */
struct skUDPSource_st {
    /* callback function invoked for each received packet to determine
     * whether the packet should be rejected, and the data to pass as
     * a parameter to that function. */
    udp_source_reject_fn        reject_pkt_fn;
    void                       *fn_callback_data;

    /* network collector */
    skUDPSourceBase_t          *base;

    /* probe associated with this source */
    const skpc_probe_t         *probe;

    /* 'data_buffer' holds packets collected for this probe but not
     * yet requested.  'pkt_buffer' is the current location in the
     * 'data_buffer' */
    sk_circbuf_t               *data_buffer;
    void                       *pkt_buffer;

    unsigned                    stopped : 1;
};


/* typedef struct skUDPSourceBase_st skUDPSourceBase_t; */
struct skUDPSourceBase_st {
    /* when a probe does not have an accept-from-host clause, any peer
     * may connect, and there is a one-to-one mapping between a source
     * object and a base object.  The 'any' member points to the
     * source, and the 'addr_to_source' member must be NULL. */
    skUDPSource_t          *any;

    /* if there is an accept-from clause, the 'addr_to_source'
     * red-black tree maps the address of the peer to a particular
     * source object (via 'peeraddr_source_t' objects), and the 'any'
     * member must be NULL. */
    struct rbtree          *addr_to_source;

    /* addresses to bind() to */
    const sk_sockaddr_array_t *listen_address;

    /* Thread data */
    pthread_t               thread;
    pthread_mutex_t         mutex;
    pthread_cond_t          cond;

    /* Sockets to listen to */
    struct pollfd          *pfd;
    nfds_t                  pfd_len;   /* Size of array */
    nfds_t                  pfd_valid; /* Number of valid entries in array */

    /* Used with file-based sources */
    uint8_t                *file_buffer;
#if SK_ENABLE_ZLIB
    gzFile                  udpfile;
#else
    FILE                   *udpfile;
#endif

    char                    name[PATH_MAX];

    /* 'data_size' is the maximum size of an individual packet. */
    size_t                  data_size;

    /* number of 'sources' that use this 'base' */
    uint32_t                refcount;
    /* number of 'sources' that are running */
    uint32_t                active_sources;

    /* Is this a file source? */
    unsigned                file       : 1;
    /* Was the udp_reader thread started? */
    unsigned                started    : 1;
    /* Is the udp_reader thread running? */
    unsigned                running    : 1;

    /* Set to 1 to signal the udp_reader thread to stop running */
    unsigned                stop       : 1;
    /* Was the previous packet from an unknown host? */
    unsigned                unknown_host:1;
};


/*
 *    The 'addr_to_source' member of 'skUDPSourceBase_t' is a
 *    red-black tree whose data members are 'peeraddr_source_t'
 *    objects.  They are used when multiple sources have
 *    accept-from-host clauses and listen on the same port so that the
 *    base can choose the source based on the peer address.
 *
 *    The 'addr_to_source' tree uses the peeraddr_compare() comparison
 *    function.
 */
/* typedef struct peeraddr_source_st peeraddr_source_t; */
struct peeraddr_source_st {
    const sk_sockaddr_t *addr;
    skUDPSource_t       *source;
};


/* LOCAL VARIABLE DEFINITIONS */

/* The 'source_bases' list contains pointers to all existing
 * skUDPSourceBase_t objects.  When creating a new skUDPSource_t, the
 * list is checked for existing sources listening on the same port. */
static sk_dllist_t *source_bases = NULL;
static pthread_mutex_t source_bases_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t source_bases_count = 0;

/* The 'sockets_count' variable maintains the number of open sockets;
 * used when setting the socket buffer size. */
static uint32_t sockets_count = 0;

/* FUNCTION DEFINITIONS */

/*
 *     The peeraddr_compare() function is used as the comparison
 *     function for the skUDPSourceBase_t's red-black tree,
 *     addr_to_source.
 *
 *     The tree stores peeraddr_source_t objects, keyed by
 *     sk_sockaddr_t address of the accepted peers.
 */
static int
peeraddr_compare(
    const void         *va,
    const void         *vb,
    const void         *ctx)
{
    const sk_sockaddr_t *a = ((const peeraddr_source_t *)va)->addr;
    const sk_sockaddr_t *b = ((const peeraddr_source_t *)vb)->addr;
    SK_UNUSED_PARAM(ctx);

    return skSockaddrCompare(a, b, SK_SOCKADDRCOMP_NOPORT);
}


/*
 *    THREAD ENTRY POINT
 *
 *    The udp_reader() function is the thread for listening to data on
 *    a single UDP port.  The skUDPSourceBase_t object containing
 *    information about the port is passed into this function.  This
 *    thread is started from the udpSourceCreateBase() function.
 */
static void *
udp_reader(
    void               *vbase)
{
    skUDPSourceBase_t *base = (skUDPSourceBase_t*)vbase;
    sk_sockaddr_t addr;
    void *data;
    peeraddr_source_t target;
    socklen_t len;
    skUDPSource_t *source = NULL;
    const peeraddr_source_t *match_address;

    assert(base != NULL);

    /* ignore all signals */
    skthread_ignore_signals();

    DEBUGMSG("UDP listener started for %s", base->name);

    /* Lock for initialization */
    pthread_mutex_lock(&base->mutex);

    /* Note run state */
    base->started = 1;
    base->running = 1;

    /* Allocate a space to read data into */
    data = (void *)malloc(base->data_size);
    if (NULL == data) {
        NOTICEMSG("Unable to create UDP listener data buffer for %s: %s",
                  base->name, strerror(errno));
        base->running = 0;
        pthread_cond_signal(&base->cond);
        pthread_mutex_unlock(&base->mutex);
        return NULL;
    }

    /* Signal completion of initialization */
    pthread_cond_broadcast(&base->cond);

    /* Wait for initial source to be connected to this base*/
    while (!base->stop && !base->active_sources) {
        pthread_cond_wait(&base->cond, &base->mutex);
    }
    pthread_mutex_unlock(&base->mutex);

    /* Main loop */
    while (!base->stop && base->active_sources && base->pfd_valid) {
        nfds_t i;
        ssize_t rv;

        /* Wait for data */
        rv = poll(base->pfd, base->pfd_len, POLL_TIMEOUT);
        if (rv == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                /* Interrupted by a signal, or internal alloc failed,
                 * try again. */
                continue;
            }
            /* Error */
            ERRMSG("Poll error for %s (%d) [%s]",
                   base->name, errno, strerror(errno));
            break;
        }

        /* See if we timed out.  We time out every now and then in
         * order to see if we need to shut down. */
        if (rv == 0) {
            continue;
        }

        /* Loop around file descriptors */
        for (i = 0; i < base->pfd_len; i++) {
            struct pollfd *pfd = &base->pfd[i];

            if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (!(pfd->revents & POLLNVAL)) {
                    close(pfd->fd);
                }
                pfd->fd = -1;
                base->pfd_valid--;
                DEBUGMSG("Poll for %s encountered a (%s,%s,%s) condition",
                         base->name, (pfd->revents & POLLERR) ? "ERR": "",
                         (pfd->revents & POLLHUP) ? "HUP": "",
                         (pfd->revents & POLLNVAL) ? "NVAL": "");
                DEBUGMSG("Closing file handle, %d remaining",
                         (int)base->pfd_valid);
                continue;
            }

            if (!(pfd->revents & POLLIN)) {
                continue;
            }

            /* Read the data */
            len = sizeof(addr);
            rv = recvfrom(pfd->fd, data, base->data_size, 0,
                          (struct sockaddr *)&addr, &len);

            /* Check for error or recv from wrong address */
            if (rv == -1) {
                switch (errno) {
                  case EINTR:
                    /* Interrupted by a signal: ignore now, try again
                     * later. */
                    continue;
                  case EAGAIN:
                    /* We should not be getting this, but have seen them
                     * in the field nonetheless.  Note and ignore them. */
                    NOTICEMSG(("Ignoring spurious EAGAIN from recvfrom() "
                               "call on %s"), base->name);
                    continue;
                  default:
                    ERRMSG("recvfrom error from %s (%d) [%s]",
                           base->name, errno, strerror(errno));
                    goto BREAK_WHILE;
                }
            }

            pthread_mutex_lock(&base->mutex);

            if (base->any) {
                /* When there is no accept-from address on the probe,
                 * there is a one-to-one mapping between source and
                 * base, and all connections are permitted. */
                assert(NULL == base->addr_to_source);
                source = base->any;
            } else {
                /* Using the address of the incoming connection,
                 * search for the source object associated with this
                 * address. */
                assert(NULL != base->addr_to_source);
                target.addr = &addr;
                match_address = ((const peeraddr_source_t*)
                                 rbfind(&target, base->addr_to_source));
                if (match_address) {
                    /* we recognize the sender */
                    source = match_address->source;
                    base->unknown_host = 0;
#if  !DEBUG_ACCEPT_FROM
                } else if (!base->unknown_host) {
                    /* additional packets seen from one or more
                     * distinct unknown senders; ignore */
                    pthread_mutex_unlock(&base->mutex);
                    continue;
#endif
                } else {
                    /* first packet seen from unknown sender after
                     * receiving packet from valid sensder; log */
                    char addr_buf[2 * SKIPADDR_STRLEN];
                    base->unknown_host = 1;
                    pthread_mutex_unlock(&base->mutex);
                    skSockaddrString(addr_buf, sizeof(addr_buf), &addr);
                    INFOMSG("Ignoring packets from host %s", addr_buf);
                    continue;
                }
            }

            if (source->stopped) {
                pthread_mutex_unlock(&base->mutex);
                continue;
            }

            /* Copy the data onto the source */
            memcpy(source->pkt_buffer, data, rv);
            pthread_mutex_unlock(&base->mutex);

            if (source->reject_pkt_fn
                && source->reject_pkt_fn(rv, source->pkt_buffer,
                                         source->fn_callback_data))
            {
                /* reject the packet; do not advance to next location */
                continue;
            }

            /* Acquire the next location */

            if (skCircBufGetWriterBlock(
                    source->data_buffer, &source->pkt_buffer, NULL))
            {
                NOTICEMSG("Non-existent data buffer for %s", base->name);
                break;
            }
        } /* for (i = 0; i < base->nfds_t; i++) */
    } /* while (!base->stop && base->pfd_valid) */

  BREAK_WHILE:

    free(data);

    /* Set running to zero, and notify waiters of our exit */
    pthread_mutex_lock(&base->mutex);
    base->running = 0;
    pthread_cond_broadcast(&base->cond);
    pthread_mutex_unlock(&base->mutex);

    DEBUGMSG("UDP listener stopped for %s", base->name);

    return NULL;
}

/* Adjust socket buffer sizes */
static void
adjust_socketbuffers(
    void)
{
    static int sbufmin = SOCKETBUFFER_MINIMUM;
    static int sbufnominaltotal = SOCKETBUFFER_NOMINAL_TOTAL;
    static int env_calculated = 0;
    int sbufsize;
    const skUDPSourceBase_t *base;
    sk_dll_iter_t iter;

    assert(pthread_mutex_trylock(&source_bases_mutex) == EBUSY);

    if (!env_calculated) {
        const char *env;
        char *end;

        env = getenv(SOCKETBUFFER_NOMINAL_TOTAL_ENV);
        if (env) {
            long int val = strtol(env, &end, 0);
            if (end != env && *end == '\0') {
                if (val > INT_MAX) {
                    val = INT_MAX;
                }
                sbufnominaltotal = val;
            }
        }
        env = getenv(SOCKETBUFFER_MINIMUM_ENV);
        if (env) {
            long int val = strtol(env, &end, 0);
            if (end != env && *end == '\0') {
                if (val > INT_MAX) {
                    val = INT_MAX;
                }
                sbufmin = val;
            }
        }
        env_calculated = 1;
    }

    if (sockets_count) {
        assert(source_bases);
        sbufsize = sbufnominaltotal / sockets_count;
        if (sbufsize < sbufmin) {
            sbufsize = sbufmin;
        }

        skDLLAssignIter(&iter, source_bases);
        while (skDLLIterForward(&iter, (void **)&base) == 0) {
            nfds_t i;
            for (i = 0; i < base->pfd_len; i++) {
                if (base->pfd[i].fd >= 0) {
                    skGrowSocketBuffer(base->pfd[i].fd, SO_RCVBUF, sbufsize);
                }
            }
        }
    }
}


/* Destroy a base object and its associated thread */
static void
udpSourceDestroyBase(
    skUDPSourceBase_t  *base)
{
    nfds_t i;

    assert(base);

    pthread_mutex_lock(&base->mutex);

    assert(base->refcount == 0);

    if (base->file) {
        /* Close file */
        if (base->udpfile) {
#if SK_ENABLE_ZLIB
            gzclose(base->udpfile);
#else
            fclose(base->udpfile);
#endif
        }

        /* Free data structures */
        if (base->file_buffer) {
            free(base->file_buffer);
        }
    } else {
        /* If running, notify thread to stop, and then wait for exit */
        if (base->running) {
            base->stop = 1;
            while (base->running) {
                pthread_cond_wait(&base->cond, &base->mutex);
            }
        }
        /* Reap thread */
        pthread_join(base->thread, NULL);

        /* Close sockets */
        for (i = 0; i < base->pfd_len; i++) {
            if (base->pfd[i].fd >= 0) {
                pthread_mutex_lock(&source_bases_mutex);
                close(base->pfd[i].fd);
                base->pfd[i].fd = -1;
                --base->pfd_valid;
                --sockets_count;
                pthread_mutex_unlock(&source_bases_mutex);
            }
        }
        free(base->pfd);
        base->pfd = NULL;

        /* Free addr_to_source tree */
        if (base->addr_to_source) {
            assert(rblookup(RB_LUFIRST, NULL, base->addr_to_source) == NULL);
            rbdestroy(base->addr_to_source);
        }

        /* Remove from source_bases list */
        if (base->listen_address) {
            sk_dll_iter_t iter;
            skUDPSourceBase_t *b;

            pthread_mutex_lock(&source_bases_mutex);
            assert(source_bases);
            skDLLAssignIter(&iter, source_bases);
            while (skDLLIterForward(&iter, (void **)&b) == 0) {
                if (b == base) {
                    skDLLIterDel(&iter);
                    --source_bases_count;
                    if (source_bases_count == 0) {
                        skDLListDestroy(source_bases);
                        source_bases = NULL;
                    } else {
                        adjust_socketbuffers();
                    }
                    break;
                }
            }
            pthread_mutex_unlock(&source_bases_mutex);
        }
    }

    pthread_mutex_unlock(&base->mutex);
    pthread_mutex_destroy(&base->mutex);
    if (!base->file) {
        pthread_cond_destroy(&base->cond);
    }

    free(base);
}


/*
 *    Create a base object and its associated thread.  The file
 *    descriptors for the base to monitor are in the 'pfd_array'.  If
 *    an error occurs, close the descriptors and return NULL.
 */
static skUDPSourceBase_t *
udpSourceCreateBase(
    const char         *name,
    uint16_t            port,
    struct pollfd      *pfd_array,
    nfds_t              pfd_len,
    nfds_t              pfd_valid,
    uint32_t            itemsize)
{
    skUDPSourceBase_t *base;
    int rv;

    /* Create base structure */
    base = (skUDPSourceBase_t*)calloc(1, sizeof(skUDPSourceBase_t));
    if (base == NULL) {
        nfds_t i;

        for (i = 0; i < pfd_len; i++) {
            if (pfd_array[i].fd >= 0) {
                close(pfd_array[i].fd);
                pfd_array[i].fd = -1;
            }
        }
        return NULL;
    }

    /* Fill the data structure */
    base->pfd = pfd_array;
    base->pfd_len = pfd_len;
    base->pfd_valid = pfd_valid;
    base->data_size = itemsize;
    pthread_mutex_init(&base->mutex, NULL);
    pthread_cond_init(&base->cond, NULL);
    if (port) {
        snprintf(base->name, sizeof(base->name), "%s:%d", name, port);
    } else {
        snprintf(base->name, sizeof(base->name), "%s", name);
    }

    /* Start the collection thread */
    pthread_mutex_lock(&base->mutex);
    rv = skthread_create(base->name, &base->thread, udp_reader, (void*)base);
    if (rv != 0) {
        pthread_mutex_unlock(&base->mutex);
        WARNINGMSG("Unable to spawn new thread for '%s': %s",
                   base->name, strerror(rv));
        udpSourceDestroyBase(base);
        return NULL;
    }

    /* Wait for the thread to finish initializing before returning. */
    do {
        pthread_cond_wait(&base->cond, &base->mutex);
    } while (!base->started);
    pthread_mutex_unlock(&base->mutex);

    return base;
}


/*
 *    Add the 'source' object to the 'base' object (or for an
 *    alternate view, have the 'source' wrap the 'base').  Return 0 on
 *    success, or -1 on failure.
 */
static int
updSourceBaseAddUDPSource(
    skUDPSourceBase_t  *base,
    skUDPSource_t      *source)
{
    const sk_sockaddr_array_t **accept_from;
    peeraddr_source_t *peeraddr;
    const peeraddr_source_t *found;
    uint32_t accept_from_count;
    uint32_t i;
    uint32_t j;

    assert(base);
    assert(source);
    assert(source->probe);
    assert(NULL == source->base);

    accept_from_count = skpcProbeGetAcceptFromHost(source->probe,&accept_from);

    /* Lock the base */
    pthread_mutex_lock(&base->mutex);

    /* Base must not be file-based nor currently configured to accept
     * packets from any host. */
    if (base->file || base->any) {
        goto ERROR;
    }

    if (NULL == accept_from) {
        /* When no accept-from-host is specified, this source accepts
         * packets from any address and there should be a one-to-one
         * mapping between source and base */
        if (base->addr_to_source) {
            /* The base already references another source. */
            goto ERROR;
        }
        base->any = source;
        source->base = base;
        ++base->refcount;

    } else {
        /* Otherwise, we need to update the base so that it knows
         * packets coming from the 'accept_from' host should be
         * processed by this source */
        if (base->addr_to_source == NULL) {
            base->addr_to_source = rbinit(peeraddr_compare, NULL);
            if (base->addr_to_source == NULL) {
                goto ERROR;
            }
        }

        for (j = 0; j < accept_from_count; ++j) {
            for (i = 0; i < skSockaddrArrayGetSize(accept_from[j]); ++i) {
                peeraddr = ((peeraddr_source_t*)
                            calloc(1, sizeof(peeraddr_source_t)));
                if (peeraddr == NULL) {
                    goto ERROR;
                }
                peeraddr->source = source;
                peeraddr->addr = skSockaddrArrayGet(accept_from[j], i);
                found = ((const peeraddr_source_t*)
                         rbsearch(peeraddr, base->addr_to_source));
                if (found != peeraddr) {
                    if (found && (found->source == peeraddr->source)) {
                        /* Duplicate address, same connection */
                        free(peeraddr);
                        continue;
                    }
                    /* Memory error adding to tree */
                    free(peeraddr);
                    goto ERROR;
                }
            }
        }

#if DEBUG_ACCEPT_FROM
        {
            char addr_buf[2 * SKIPADDR_STRLEN];
            RBLIST *iter;
            peeraddr_source_t *addr;

            iter = rbopenlist(base->addr_to_source);
            while ((addr = (peeraddr_source_t *)rbreadlist(iter)) != NULL) {
                skSockaddrString(addr_buf, sizeof(addr_buf), addr->addr);
                DEBUGMSG("Base '%s' accepts packets from '%s'",
                         base->name, addr_buf);
            }
            rbcloselist(iter);
        }
#endif  /* DEBUG_ACCEPT_FROM */

        source->base = base;
        ++base->refcount;
    }

    /* Increase the number of active sources and signal the
     * udp_reader() thread to continue */
    ++base->active_sources;
    pthread_cond_broadcast(&base->cond);

    pthread_mutex_unlock(&base->mutex);

    return 0;

  ERROR:
    pthread_mutex_unlock(&base->mutex);
    return -1;
}


/*
 *    Completes the creatation a UDP source representing a Berkeley
 *    socket.
 */
static int
udpSourceCreateFromSockaddr(
    skUDPSource_t      *source,
    uint32_t            itemsize)
{
    const sk_sockaddr_array_t  *listen_address;
    const sk_sockaddr_t *addr;
    skUDPSourceBase_t *base;
    skUDPSourceBase_t *cleanup_base = NULL;
    struct pollfd *pfd_array = NULL;
    nfds_t pfd_valid;
    uint32_t i;
    int rv;
    uint16_t arrayport;
    int retval = -1;

    assert(source);
    assert(source->probe);

    if (skpcProbeGetListenOnSockaddr(source->probe, &listen_address)) {
        return -1;
    }

    /* If base objects already exists, look for one that has been
     * bound to this source's port.  If a base is found, have this
     * source object use it and jump to the end of this function. */
    pthread_mutex_lock(&source_bases_mutex);
    if (source_bases) {
        sk_dll_iter_t iter;
        skDLLAssignIter(&iter, source_bases);
        while (skDLLIterForward(&iter, (void **)&base) == 0) {
            if (skSockaddrArrayEqual(listen_address, base->listen_address,
                                     SK_SOCKADDRCOMP_NOT_V4_AS_V6))
            {
                if ((base->data_size != itemsize)
                    || (!skSockaddrArrayEqual(listen_address,
                                              base->listen_address,
                                              SK_SOCKADDRCOMP_NOT_V4_AS_V6)))
                {
                    /* errror: all sources that listen on this address
                     * must accept the same size packets.  Also, sources
                     * that listen to the same address must listen to
                     * *all* the same addresses. */
                    goto END;
                }
                /* found one.  Add the skUDPSource_t to the
                 * skUDPSourceBase_t */
                retval = updSourceBaseAddUDPSource(base, source);
                goto END;
            }
            if (skSockaddrArrayMatches(listen_address, base->listen_address,
                                       SK_SOCKADDRCOMP_NOT_V4_AS_V6))
            {
                /* If two arrays match imperfectly, bail out */
                goto END;
            }
        }
    }

    /* If not, attempt to bind the address/port pairs */
    pfd_array = (struct pollfd*)calloc(skSockaddrArrayGetSize(listen_address),
                                       sizeof(struct pollfd));
    if (pfd_array == NULL) {
        goto END;
    }
    pfd_valid = 0;

    /* arrayport holds the port of the listen_address array (0 ==
     * undecided) */
    arrayport = 0;

    DEBUGMSG(("Attempting to bind %" PRIu32 " addresses for %s"),
             skSockaddrArrayGetSize(listen_address),
             skSockaddrArrayGetHostPortPair(listen_address));
    for (i = 0; i < skSockaddrArrayGetSize(listen_address); i++) {
        char addr_name[PATH_MAX];
        struct pollfd *pfd = &pfd_array[i];
        uint16_t port;

        addr = skSockaddrArrayGet(listen_address, i);

        skSockaddrString(addr_name, sizeof(addr_name), addr);

        /* Get a socket */
        pfd->fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
        if (pfd->fd == -1) {
            DEBUGMSG("Skipping %s: Unable to create dgram socket: %s",
                     addr_name, strerror(errno));
            continue;
        }
        /* Bind socket to port */
        if (bind(pfd->fd, &addr->sa, skSockaddrGetLen(addr)) == -1) {
            DEBUGMSG("Skipping %s: Unable to bind: %s",
                     addr_name, strerror(errno));
            close(pfd->fd);
            pfd->fd = -1;
            continue;
        }
        DEBUGMSG("Bound %s for listening", addr_name);
        pfd_valid++;
        pfd->events = POLLIN;

        port = skSockaddrGetPort(addr);
        if (0 == arrayport) {
            arrayport = port;
        } else {
            /* All ports in the listen_address array should be the same */
            assert(arrayport == port);
        }
    }

    if (pfd_valid == 0) {
        ERRMSG("Failed to bind any addresses for %s",
               skSockaddrArrayGetHostPortPair(listen_address));
        goto END;
    }

    DEBUGMSG(("Bound %" PRIu32 "/%" PRIu32 " addresses for %s"),
             (uint32_t)pfd_valid, skSockaddrArrayGetSize(listen_address),
             skSockaddrArrayGetHostPortPair(listen_address));

    assert(arrayport != 0);
    base = udpSourceCreateBase(skSockaddrArrayGetHostname(listen_address),
                               arrayport, pfd_array,
                               skSockaddrArrayGetSize(listen_address),
                               pfd_valid, itemsize);
    if (base == NULL) {
        goto END;
    }
    /* Mark base as destroyable on cleanup */
    cleanup_base = base;

    /* The base steals the reference to the array */
    pfd_array = NULL;

    base->listen_address = listen_address;

    /* Add the skUDPSource_t to the skUDPSourceBase_t */
    if (updSourceBaseAddUDPSource(base, source)) {
        goto END;
    }

    if (source_bases == NULL) {
        source_bases = skDLListCreate(NULL);
        if (source_bases == NULL) {
            goto END;
        }
    }

    rv = skDLListPushTail(source_bases, base);
    if (rv != 0) {
        goto END;
    }
    /* Base is good.  Don't destroy it on cleanup */
    cleanup_base = NULL;

    ++source_bases_count;
    sockets_count += pfd_valid;

    adjust_socketbuffers();

    /* successful */
    retval = 0;

  END:
    pthread_mutex_unlock(&source_bases_mutex);

    free(pfd_array);
    if (cleanup_base) {
        /* This may lock source_bases_mutex, so must be it must be
         * unlocked beforehand. */
        udpSourceDestroyBase(cleanup_base);
    }

    return retval;
}


/*
 *    Completes the creatation a UDP source representing a UNIX domain
 *    socket.
 */
static int
udpSourceCreateFromUnixDomain(
    skUDPSource_t      *source,
    uint32_t            itemsize)
{
    const char *uds;
    sk_sockaddr_t addr;
    skUDPSourceBase_t *base = NULL;
    struct pollfd *pfd_array = NULL;
    int sock;

    assert(source);
    assert(source->probe);

    uds = skpcProbeGetListenOnUnixDomainSocket(source->probe);
    assert(uds);

    /* Create a socket */
    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock == -1) {
        ERRMSG("Failed to create socket: %s", strerror(errno));
        goto ERROR;
    }

    /* Remove the domain socket if it exists. */
    if ((unlink(uds) == -1) && (errno != ENOENT)) {
        ERRMSG("Failed to unlink existing socket '%s': %s",
               uds, strerror(errno));
        goto ERROR;
    }

    /* Fill in sockaddr */
    memset(&addr, 0, sizeof(addr));
    addr.un.sun_family = AF_UNIX;
    strncpy(addr.un.sun_path, uds, sizeof(addr.un.sun_path) - 1);

    /* Bind socket to port */
    if (bind(sock, &addr.sa, skSockaddrGetLen(&addr)) == -1) {
        ERRMSG("Failed to bind address '%s': %s", uds, strerror(errno));
        goto ERROR;
    }

    /* Create the pfd object */
    pfd_array = (struct pollfd*)calloc(1, sizeof(struct pollfd));
    if (pfd_array == NULL) {
        close(sock);
        goto ERROR;
    }
    pfd_array->fd = sock;
    pfd_array->events = POLLIN;
    /* pdf_array owns this now */
    sock = -1;

    /* Create a base object */
    base = udpSourceCreateBase(uds, 0, pfd_array, 1, 1, itemsize);
    if (base == NULL) {
        goto ERROR;
    }
    /* base owns this now */
    pfd_array = NULL;

    /* Add the skUDPSource_t to the skUDPSourceBase_t */
    if (updSourceBaseAddUDPSource(base, source)) {
        goto ERROR;
    }

    return 0;

  ERROR:
    free(pfd_array);
    if (base != NULL) {
        udpSourceDestroyBase(base);
    }
    if (-1 != sock) {
        close(sock);
    }
    return -1;
}


/*
 *    Completes the creatation a UDP source representing a file of
 *    collected traffic.
 */
static int
udpSourceCreateFromFile(
    skUDPSource_t      *source,
    uint32_t            itemsize,
    const char         *path)
{
    skUDPSourceBase_t *base;

    assert(path);

    /* Create and initialize base structure */
    base = (skUDPSourceBase_t*)calloc(1, sizeof(skUDPSourceBase_t));
    if (base == NULL) {
        goto ERROR;
    }
    pthread_mutex_init(&base->mutex, NULL);
    base->file = 1;
    base->data_size = itemsize;
    base->file_buffer = (uint8_t *)malloc(base->data_size);
    if (base->file_buffer == NULL) {
        goto ERROR;
    }

    /* open the file */
#if SK_ENABLE_ZLIB
    base->udpfile = gzopen(path, "r");
#else
    base->udpfile = fopen(path, "r");
#endif
    if (base->udpfile == NULL) {
        ERRMSG("Unable to open file '%s': %s", path, strerror(errno));
        goto ERROR;
    }

    source->base = base;
    base->refcount = 1;
    base->active_sources = 1;

    return 0;

  ERROR:
    if (base != NULL) {
        udpSourceDestroyBase(base);
    }
    return -1;
}


skUDPSource_t *
skUDPSourceCreate(
    const skpc_probe_t         *probe,
    const skFlowSourceParams_t *params,
    uint32_t                    itemsize,
    udp_source_reject_fn        reject_pkt_fn,
    void                       *fn_callback_data)
{
    skUDPSource_t *source;
    int rv;

    source = (skUDPSource_t*)calloc(1, sizeof(skUDPSource_t));
    if (source == NULL) {
        return NULL;
    }
    source->reject_pkt_fn = reject_pkt_fn;
    source->fn_callback_data = fn_callback_data;
    source->probe = probe;

    if (NULL != skpcProbeGetPollDirectory(probe)
        || NULL != skpcProbeGetFileSource(probe))
    {
        /* This is a file-based probe---either handles a single file
         * or files pulled from a directory poll */
        if (NULL == params || NULL == params->path_name) {
            free(source);
            return NULL;
        }
        rv = udpSourceCreateFromFile(source, itemsize, params->path_name);

    } else {
        /* A socket-based probe */

        /* Create circular buffer */
        if (skCircBufCreate(&source->data_buffer, itemsize, params->max_pkts)){
            free(source);
            return NULL;
        }
        if (skCircBufGetWriterBlock(
                source->data_buffer, &source->pkt_buffer, NULL))
        {
            skAbort();
        }

        if (NULL != skpcProbeGetListenOnUnixDomainSocket(probe)) {
            /* UNIX domain socket */
            rv = udpSourceCreateFromUnixDomain(source, itemsize);
        } else {
            /* must be a Berkeley-socket based source */
            rv = udpSourceCreateFromSockaddr(source, itemsize);
        }
    }
    if (rv) {
        skUDPSourceDestroy(source);
        return NULL;
    }
    return source;
}


void
skUDPSourceStop(
    skUDPSource_t      *source)
{
    assert(source);

    if (!source->stopped) {
        skUDPSourceBase_t *base = source->base;

        /* Mark the source as stopped */
        source->stopped = 1;

        /* Notify the base that the source has stopped */
        if (base) {
            pthread_mutex_lock(&base->mutex);

            /* Decrement the base's active source count */
            assert(base->active_sources);
            --base->active_sources;

            /* If the count has reached zero, wait for the base thread
             * to stop running. */
            if (base->active_sources == 0) {
                while (base->running) {
                    pthread_cond_wait(&base->cond, &base->mutex);
                }
            }

            pthread_mutex_unlock(&base->mutex);
        }

        /* Unblock the data buffer */
        if (source->data_buffer) {
            skCircBufStop(source->data_buffer);
        }
    }
}


void
skUDPSourceDestroy(
    skUDPSource_t      *source)
{
    skUDPSourceBase_t *base;
    const sk_sockaddr_array_t **accept_from;
    peeraddr_source_t target;
    const peeraddr_source_t *found;
    uint32_t accept_from_count;
    uint32_t i;
    uint32_t j;

    if (!source) {
        return;
    }
    /* Stop the source */
    if (!source->stopped) {
        skUDPSourceStop(source);
    }

    base = source->base;

    if (NULL == base) {
        skCircBufDestroy(source->data_buffer);
        free(source);
        return;
    }
    accept_from_count = skpcProbeGetAcceptFromHost(source->probe,&accept_from);

    pthread_mutex_lock(&base->mutex);

    if (base->addr_to_source && accept_from) {
        /* Remove the source's accept-from-host addresses from
         * base->addr_to_source */
        for (j = 0; j < accept_from_count; ++j) {
            for (i = 0; i < skSockaddrArrayGetSize(accept_from[j]); ++i) {
                target.addr = skSockaddrArrayGet(accept_from[j], i);
                found = ((const peeraddr_source_t *)
                         rbdelete(&target, base->addr_to_source));
                if (found && (found->source == source)) {
                    free((void*)found);
                }
            }
        }
    }

    /* Destroy the circular buffer */
    skCircBufDestroy(source->data_buffer);

    /* Decref and possibly delete the base */
    assert(base->refcount);
    --base->refcount;
    if (base->refcount == 0) {
        pthread_mutex_unlock(&base->mutex);
        udpSourceDestroyBase(base);
    } else {
        pthread_mutex_unlock(&base->mutex);
    }

    free(source);
}


uint8_t *
skUDPSourceNext(
    skUDPSource_t      *source)
{
    skUDPSourceBase_t *base;
    uint8_t *data;

    assert(source);
    assert(source->base);

    base = source->base;

    pthread_mutex_lock(&base->mutex);

    if (base->stop) {
        data = NULL;
        goto END;
    }
    if (!base->file) {
        /* network based UDP source. skCircBufGetReaderBlock() blocks
         * until data is ready */
        pthread_mutex_unlock(&base->mutex);
        if (source->data_buffer) {
            if (skCircBufGetReaderBlock(source->data_buffer, &data, NULL)
                == SK_CIRCBUF_OK)
            {
                return data;
            }
        }
        return NULL;
    }
    /* else file-based "UDP" source */

    for (;;) {
        int size;
#if SK_ENABLE_ZLIB
        size = gzread(base->udpfile, base->file_buffer, base->data_size);
#else
        size = (int)fread(base->file_buffer, 1, base->data_size,
                          base->udpfile);
#endif
        if (size <= 0 || (uint32_t)size < base->data_size) {
            /* error, end of file, or short read */
            data = NULL;
            break;
        }
        if (source->reject_pkt_fn
            && source->reject_pkt_fn(base->data_size, base->file_buffer,
                                     source->fn_callback_data))
        {
            /* reject the packet */
            continue;
        }
        data = base->file_buffer;
        break;
    }

  END:
    pthread_mutex_unlock(&base->mutex);

    return data;
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
