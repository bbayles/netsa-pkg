/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
 *  ipfixsource.c
 *
 *    This file and skipfix.c are tightly coupled, and together they
 *    read IPFIX records and convert them to SiLK flow records.
 *
 *    This file is primary about setting up and tearing down the data
 *    structures used when processing IPFIX.
 *
 *    The skipfix.c file primarly handles the conversion, and it is
 *    where the reading functions exist.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: ipfixsource.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "ipfixsource.h"
#include <silk/redblack.h>
#include <silk/skthread.h>
#include <silk/skvector.h>
#include "infomodel.h"

#ifdef  SKIPFIXSOURCE_TRACE_LEVEL
#define TRACEMSG_LEVEL SKIPFIXSOURCE_TRACE_LEVEL
#endif
#define TRACEMSG(lvl, msg)    TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>


/*
 *  IMPLEMENTATION NOTES
 *
 *  Each probe is represented by a single skIPFIXSource_t object.
 *
 *  For probes that process file-based IPFIX sources, the
 *  skIPFIXSource_t object contains an fBuf_t object.  When the caller
 *  invokes skIPFIXSourceGetGeneric(), the next record is read from
 *  the fBuf_t and the record is returned.  For consistency with
 *  network processing (described next), the file-based
 *  skIPFIXSource_t has an skIPFIXSourceBase_t object, but that object
 *  does little for file-based sources.
 *
 *  For probes that process network-based IPFIX sources, the
 *  combination of the following four values must be unique: protocol,
 *  listen-on-port, listen-as-address, accept-from-host.  (Note that
 *  an ADDR_ANY value for listen-as-address or accept-from-host
 *  matches all other addresses.)
 *
 *  Each skIPFIXSource_t references an skIPFIXSourceBase_t object.
 *  Each unique listen-as-address/listen-to-port/protocol triple is
 *  handled by a single fbListener_t object, which is contained in the
 *  skIPFIXSourceBase_t object.  When two skIPFIXSource_t's differ
 *  only by their accept-from-host addreses, the skIPFIXSource_t's
 *  reference the same skIPFIXSourceBase_t object.  The
 *  skIPFIXSourceBase_t objects contain a reference-count.  The
 *  skIPFIXSourceBase_t is destroyed when the last skIPFIXSource_t
 *  referring to it is destroyed.
 *
 *  An skIPFIXConnection_t represents a connection, which is one of
 *  two things: In the TCP case, a connection is equivalent to a TCP
 *  connection.  In the UDP case, a connection is a given set of IPFIX
 *  or NFv9 UDP packets sent from a given address, to a given address,
 *  on a given port, with a given domain ID.  The skIPFIXConnection_t
 *  object is ipfixsource's way of mapping to the fbSession_t object
 *  in libfixbuf.
 *
 *  There can be multiple active connections on a probe---consider a
 *  probe that collects from two machines that load-balance.  In the
 *  code, this is represented by having each skIPFIXConnection_t
 *  object point to its skIPFIXSource_t.  As described below, the
 *  skIPFIXConnection_t is stored as the context pointer on the
 *  libfixbuf fbCollector_t object.
 *
 *  When a new TCP connection arrives or if a new UDP connection is
 *  seen and we are using a fixbuf that supports multi-UDP, the
 *  fixbufConnect() callback function first determines whether the
 *  peer is allowed to connect.  If the peer is allowed, the function
 *  sets the context pointer for the fbCollector_t object to the a new
 *  skIPFIXConnection_t object which contains statistics information
 *  for the connection and the skIPFIXSource_t object associated with
 *  the connection.  These skIPFIXConnection_t objects are destroyed
 *  in the fixbufDisconnect() callback.
 *
 *  When a new UDP peer sends data to the listener, the actual address
 *  is not known until the underlying recvmesg() call itself, rather
 *  than in an accept()-like call similar to TCP.  What this means is
 *  that in this scenario the fixbufConnect() appInit function is not
 *  called until a call to fBufNext() or fBufNextCollectionTemplate()
 *  is called.
 *
 *  There is a similar fixbufConnectUDP() function to handle UDP
 *  connections when libfixbuf does not support multi-UDP.  However,
 *  the fundamental difference is this: TCP connections are associated
 *  with a new fbCollector_t at connection time.  Non-multi-UDP
 *  connections are associated with a new fbCollector_t during the
 *  fbListenerAlloc() call.
 *
 *  FIXBUF API ISSUE: The source objects connected to the
 *  fbCollector_t objects have to be passed to the
 *  fixbufConnect*() calls via global objects---newly created
 *  sources are put into a red-black tree; the call to
 *  fixbufConnect*() attempts to find the value in the red-black tree.
 *  It would have made more sense if fbListenerAlloc() took a
 *  caller-specified context pointer which would get passed to the
 *  fbListenerAppInit_fn() and fbListenerAppFree_fn() functions.
 *
 *  There is one ipfix_reader() thread per skIPFIXSourceBase_t object.
 *  This thread loops around fbListenerWait() returning fBuf_t
 *  objects.  The underlying skIPFIXConnection_t containing the source
 *  information is grabbed from the fBuf_t's collector.  The
 *  fBufNext() is used to read the data from the fBuf_t and this data
 *  is associated with the given source by either inserting it into
 *  the source's circular buffer, or by adding the stats information
 *  to the source.  Then we loop back determining any new connection
 *  and dealing with the next piece of data until the fBuf_t empties.
 *  We then return to fbListenerWait() to get the next fBuf_t.

 *  Since there is one thread per listener, if one source attached to
 *  a listener blocks due to the circular buffer becoming full, all
 *  sources attached to the listener will block as well.  Solving this
 *  problem would involve more threads, and moving away from the
 *  fbListenerWait() method of doing things.  We could instead have a
 *  separate thread per connection.  This would require us to handle
 *  the connections (bind/listen/accept) ourselves, and then create
 *  fBufs from the resulting file descriptors.
 */


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Name of environment variable that, when set, cause SiLK to
 *    ignore any G_LOG_LEVEL_WARNING messages.
 */
#define SK_ENV_FIXBUF_SUPPRESS_WARNING "SILK_LIBFIXBUF_SUPPRESS_WARNINGS"

/*
 *  SILK_PROTO_TO_FIXBUF_TRANSPORT(silk_proto, &fb_trans);
 *
 *    Set the fbTransport_t value in the memory referenced by
 *    'fb_trans' based on the SiLK protocol value 'silk_proto'.
 */
#define SILK_PROTO_TO_FIXBUF_TRANSPORT(silk_proto, fb_trans)    \
    switch (silk_proto) {                                       \
      case SKPC_PROTO_SCTP:                                     \
        *(fb_trans) = FB_SCTP;                                  \
        break;                                                  \
      case SKPC_PROTO_TCP:                                      \
        *(fb_trans) = FB_TCP;                                   \
        break;                                                  \
      case SKPC_PROTO_UDP:                                      \
        *(fb_trans) = FB_UDP;                                   \
        break;                                                  \
      default:                                                  \
        skAbortBadCase(silk_proto);                             \
    }

/*
 *    The 'addr_to_source' member of 'skIPFIXSourceBase_t' is a
 *    red-black tree whose data members are 'peeraddr_source_t'
 *    objects.  The tree is used when multiple sources listen on the
 *    same port and the accept-from-host addresses are used to choose
 *    the source based on the peer address of the sender.
 *
 *    The 'addr_to_source' tree uses the peeraddr_compare() comparison
 *    function.
 */
typedef struct peeraddr_source_st {
    const sk_sockaddr_t *addr;
    skIPFIXSource_t     *source;
} peeraddr_source_t;


/* EXPORTED VARIABLE DEFINITIONS */

/* descriptions are in ipfixsource.h */

/* do the names of IE 48, 49, 50 follow fixbuf-1.x or 2.x? */
uint32_t sampler_flags = 0;


/* LOCAL VARIABLE DEFINITIONS */

/* Mutex around calls to skiCreateListener. */
static pthread_mutex_t create_listener_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex around listener_to_source_base tree and count. */
static pthread_mutex_t global_tree_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Map from listeners to skIPFIXSourceBase_t objects.  Objects in
 * rbtree are skIPFIXSourceBase_t pointers. */
static struct rbtree *listener_to_source_base = NULL;

/* Number of ipfix sources (both networked and file-based) */
static uint32_t source_base_count = 0;


/*
 *    There is a single infomation model.
 */
static fbInfoModel_t *ski_model = NULL;

/*
 *    When processing files with fixbuf, the session object
 *    (fbSession_t) is owned the reader/write buffer (fBuf_t).
 *
 *    When doing network processing, the fBuf_t does not own the
 *    session.  We use this global vector to maintain those session
 *    pointers so they can be freed at shutdown.
 */
static sk_vector_t *session_list = NULL;



/* FUNCTION DEFINITIONS */

/*
 *     The listener_to_source_base_find() function is used as the
 *     comparison function for the listener_to_source_base red-black
 *     tree.  Stores objects of type skIPFIXSourceBase_t, orders by
 *     fbListener_t pointer value.
 */
static int
listener_to_source_base_find(
    const void         *va,
    const void         *vb,
    const void         *ctx)
{
    const fbListener_t *a = ((const skIPFIXSourceBase_t *)va)->listener;
    const fbListener_t *b = ((const skIPFIXSourceBase_t *)vb)->listener;
    SK_UNUSED_PARAM(ctx);

    return ((a < b) ? -1 : (a > b));
}


/*
 *     The peeraddr_compare() function is used as the comparison
 *     function for the skIPFIXSourceBase_t's red-black tree,
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
 *     The pointer_cmp() function is used compare skIPFIXConnection_t
 *     pointers in the 'connections' red-black tree on skIPFIXSource_t
 *     objects.
 */
static int
pointer_cmp(
    const void         *va,
    const void         *vb,
    const void         *ctx)
{
    SK_UNUSED_PARAM(ctx);
    return ((va < vb) ? -1 : (va > vb));
}


/*
 *     The free_source() function is used to free an skIPFIXSource_t
 *     object.  This only frees the object and its data, it does not
 *     mark up any connected skIPFIXSourceBase_t object in the
 *     process.
 */
static void
free_source(
    skIPFIXSource_t    *source)
{
    TRACE_ENTRY;

    if (source == NULL) {
        TRACEMSG(3, ("source was null"));
        TRACE_RETURN;
    }

    assert(source->connection_count == 0);

    pthread_mutex_destroy(&source->stats_mutex);
    if (source->circbuf) {
        skCircBufDestroy(source->circbuf);
    }
    if (source->connections) {
        rbdestroy(source->connections);
    }
    if (source->readbuf) {
        TRACEMSG(3, ("freeing fbuf"));
        fBufFree(source->readbuf);
    }
    if (source->fileptr.of_fp) {
        TRACEMSG(3, ("closing file"));
        skFileptrClose(&source->fileptr, &WARNINGMSG);
    }
    if (source->file_conn) {
        TRACEMSG(3, ("freeing file_conn (%zu bytes)",
                     sizeof(source->file_conn)));
        free(source->file_conn);
    }

    free(source);
    TRACE_RETURN;
}


/*
 *     The fixbufConnect() function is passed to fbListenerAlloc() as
 *     its 'appinit' callback (fbListenerAppInit_fn).
 *     This function is called from within the fbListenerWait() call
 *     when a new connection to the listening socket is made.  (In
 *     addition, for UDP sources, it is called directly by
 *     fbListenerAlloc() with a NULL peer.)
 *
 *     Its primary purposes are to accept/reject the connection,
 *     create an skIPFIXConnection_t, and set the the collector's
 *     context to the skIPFIXConnection_t.  The skIPFIXConnection_t
 *     remembers the peer information, contains the stats for this
 *     connection, and references the source object.
 */
static gboolean
fixbufConnect(
    fbListener_t       *listener,
    void              **ctx,
    int                 fd,
    struct sockaddr    *peer,
    size_t              peerlen,
    GError            **err)
{
    fbCollector_t *collector;
    char addr_buf[2 * SKIPADDR_STRLEN];
    skIPFIXSourceBase_t target_base;
    skIPFIXSourceBase_t *base;
    const peeraddr_source_t *found_peer;
    peeraddr_source_t target_peer;
    skIPFIXSource_t *source;
    skIPFIXConnection_t *conn = NULL;
    sk_sockaddr_t addr;
    gboolean retval = 0;

    TRACE_ENTRY;
    SK_UNUSED_PARAM(fd);

    if (peer == NULL) {
        /* This function is being called for a UDP listener at init
         * time.  Ignore this. */
        TRACE_RETURN(1);
    }
    if (peerlen > sizeof(addr)) {
        TRACEMSG(1, (("ipfixsource rejected connection:"
                      " peerlen too large: %" SK_PRIuZ " > %" SK_PRIuZ),
                     peerlen, sizeof(addr)));
        g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                    ("peerlen unexpectedly large: %" SK_PRIuZ), peerlen);
        TRACE_RETURN(0);
    }

    memcpy(&addr.sa, peer, peerlen);
    skSockaddrString(addr_buf, sizeof(addr_buf), &addr);

    TRACEMSG(3, (("ipfixsource processing connection from '%s'"), addr_buf));

    /* Find the skIPFIXSourceBase_t object associated with this
     * listener */
    target_base.listener = listener;
    pthread_mutex_lock(&global_tree_mutex);
    base = ((skIPFIXSourceBase_t *)
            rbfind(&target_base, listener_to_source_base));
    pthread_mutex_unlock(&global_tree_mutex);
    if (base == NULL) {
        TRACEMSG(1, (("ipfixsource rejected connection from '%s':"
                      " unable to find base given listener"), addr_buf));
        g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                    "Unable to find base for listener");
        TRACE_RETURN(0);
    }

    conn = (skIPFIXConnection_t*)calloc(1, sizeof(skIPFIXConnection_t));
    if (conn == NULL) {
        TRACEMSG(1, (("ipfixsource rejected connection from '%s':"
                      " unable to allocate connection object"), addr_buf));
        g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                    "Unable to allocate connection object");
        TRACE_RETURN(0);
    }

    pthread_mutex_lock(&base->mutex);

    if (base->any) {
        /* When there is no accept-from address on the probe, there is
         * a one-to-one mapping between source and base, and all
         * connections are permitted. */
        source = base->any;
    } else {
        /* Using the address of the incoming connection, search for
         * the source object associated with this address. */
        assert(base->addr_to_source);
        target_peer.addr = &addr;
        found_peer = ((const peeraddr_source_t*)
                      rbfind(&target_peer, base->addr_to_source));
        if (NULL == found_peer) {
            /* Reject hosts that do not appear in accept-from-host */
            TRACEMSG(1, (("ipfixsource rejected connection from '%s':"
                          " host prohibited"), addr_buf));
            g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                        "Connection prohibited from %s", addr_buf);
            free(conn);
            goto END;
        }
        source = found_peer->source;
    }

    if (source->stopped) {
        TRACEMSG(1, (("ipfixsource rejected connection from '%s':"
                      " source is stopping"), addr_buf));
        g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                    "Source is stopping");
        free(conn);
        goto END;
    }

    /* If this is an NetFlowV9/sFLow source, store the
     * skIPFIXConnection_t in the red-black tree on the source so we
     * can log about missing NetFlowV9/sFlow packets. */
    if (source->connections) {
        skIPFIXConnection_t *found_conn;

        pthread_mutex_lock(&source->stats_mutex);
        found_conn = ((skIPFIXConnection_t*)
                      rbsearch(conn, source->connections));
        pthread_mutex_unlock(&source->stats_mutex);
        if (found_conn != conn) {
            TRACEMSG(1, (("ipfixsource rejected connection from '%s':"
                          " unable to store connection on source"), addr_buf));
            g_set_error(err, SK_IPFIXSOURCE_DOMAIN, SK_IPFIX_ERROR_CONN,
                        "Unable to store connection on source");
            free(conn);
            goto END;
        }
    }

    /* Update the skIPFIXConnection_t with the information necessary
     * to provide a useful log message at disconnect.  This info is
     * also used to get NetFlowV9/sFlow missed packets. */
    if (peerlen <= sizeof(conn->peer_addr)) {
        memcpy(&conn->peer_addr.sa, peer, peerlen);
        conn->peer_len = peerlen;
    }

    TRACEMSG(4, ("Creating new conn = %p for source = %p", conn, source));

    /* Set the skIPFIXConnection_t to point to the source, increment
     * the source's connection_count, and set the context pointer to
     * the connection.  */
    conn->source = source;
    ++source->connection_count;
    retval = 1;
    *ctx = conn;

    /* Get the domain (also needed for NetFlowV9/sFlow missed pkts).
     * In the TCP case, the collector does not exist yet, and the
     * GetCollector call returns false.  In the UDP-IPFIX case, the
     * domain of the collector always returns 0. */
    if (source->connections
        && fbListenerGetCollector(listener, &collector, NULL))
    {
        conn->ob_domain = fbCollectorGetObservationDomain(collector);
        INFOMSG("'%s': accepted connection from %s, domain %#06x",
                source->name, addr_buf, conn->ob_domain);
    } else {
        INFOMSG("'%s': accepted connection from %s",
                source->name, addr_buf);
    }

  END:
    pthread_mutex_unlock(&base->mutex);
    TRACE_RETURN(retval);
}


/*
 *     The fixbufDisconnect() function is passed to fbListenerAlloc()
 *     as its 'appfree' callback (fbListenerAppFree_fn).  This
 *     function is called by fBufFree().  The argument to this
 *     function is the context (the skIPFIXConnection_t) that was set
 *     by fixbufConnect().
 *
 *     The function decrefs the source and frees it if the
 *     connection_count hits zero and the source has been asked to be
 *     destroyed.  It then frees the connection object.
 */
static void
fixbufDisconnect(
    void               *ctx)
{
    skIPFIXConnection_t *conn = (skIPFIXConnection_t *)ctx;

    TRACE_ENTRY;

    if (conn == NULL) {
        TRACE_RETURN;
    }

    TRACEMSG(3, (("fixbufDisconnection connection_count = %" PRIu32),
                 conn->source->connection_count));

    /* Remove the connection from the source. */
    --conn->source->connection_count;
    if (conn->source->connections) {
        pthread_mutex_lock(&conn->source->stats_mutex);
        rbdelete(conn, conn->source->connections);
        pthread_mutex_unlock(&conn->source->stats_mutex);
    }

    /* For older fixbuf, only TCP connections contain the peer addr */
    if (conn->peer_len) {
        char addr_buf[2 * SKIPADDR_STRLEN];

        skSockaddrString(addr_buf, sizeof(addr_buf), &conn->peer_addr);
        if (conn->ob_domain) {
            INFOMSG("'%s': noticed disconnect by %s, domain %#06x",
                    conn->source->name, addr_buf, conn->ob_domain);
        } else {
            INFOMSG("'%s': noticed disconnect by %s",
                    conn->source->name, addr_buf);
        }
    }

    TRACEMSG(4, ("Destroying conn = %p for source %p", conn, conn->source));

    /* Destroy it if this is the last reference to the source. */
    if (conn->source->destroy && conn->source->connection_count == 0) {
        free_source(conn->source);
    }
    free(conn);
    TRACE_RETURN;
}


/*
 *    Return a pointer to the single information model.  If necessary
 *    create and initialize it.
 */
fbInfoModel_t *
skiInfoModel(
    void)
{
    fbInfoModel_t *m = ski_model;

    if (!m) {
        TRACEMSG(4, ("Allocating an info model"));
        m = fbInfoModelAlloc();
        /* call a function in infomodel.c to update the info model
         * with the info elements defined in the .xml file(s) in the
         * infomodel subdirectory */
        infomodelAddGlobalElements(m);
        ski_model = m;
    }
    return ski_model;
}

/*
 *    Free the single information model.
 */
void
skiInfoModelFree(
    void)
{
    fbInfoModel_t *m = ski_model;

    ski_model = NULL;
    if (m) {
        TRACEMSG(4, ("Freeing an info model"));
        fbInfoModelFree(m);
    }
}


/**
 *    Free the memory associated with the Info Model---note that doing
 *    so is not tread safe.
 */
void
skiTeardown(
    void)
{
    size_t i;
    fbSession_t *session;

    if (session_list) {
        for (i = 0; i < skVectorGetCount(session_list); i++) {
            skVectorGetValue(&session, session_list, i);
            fbSessionFree(session);
        }
        skVectorDestroy(session_list);
        session_list = NULL;
    }

    skiInfoModelFree();
}


/**
 *    Create an IPFIX Collecting Process listener.
 */
static fbListener_t *
skiCreateListener(
    skIPFIXSourceBase_t    *base,
    GError                **err)
{
    fbSession_t *session;
    fbListener_t *listener;
    int created_vec = 0;

    TRACE_ENTRY;

    ASSERT_MUTEX_LOCKED(&create_listener_mutex);

    /* The session is not owned by the buffer or the listener, so
     * maintain a vector of them for later destruction. */
    if (!session_list) {
        session_list = skVectorNew(sizeof(fbSession_t *));
        if (session_list == NULL) {
            TRACE_RETURN(NULL);
        }
        created_vec = 1;
    }
    /* fixbuf (glib) exits on allocation error */
    session = fbSessionAlloc(skiInfoModel());

    /* Initialize session for reading */
    if (!skiSessionInitReader(session, err)) {
        goto ERROR;
    }
    if (skVectorAppendValue(session_list, &session) != 0) {
        goto ERROR;
    }

    /* Allocate a listener.  'fixbufConnect' is called on each
     * collection attempt; vetoes connection attempts and creates
     * application context. */
    listener = fbListenerAlloc(base->connspec, session, fixbufConnect,
                               fixbufDisconnect, err);
    TRACE_RETURN(listener);

  ERROR:
    fbSessionFree(session);
    if (created_vec) {
        skVectorDestroy(session_list);
        session_list = NULL;
    }
    TRACE_RETURN(NULL);
}


/**
 *    Create a buffer pointer suitable for use for
 *    ski_fixrec_next(). The file pointer must be opened for reading.
 */
static fBuf_t *
skiCreateReadBufferForFP(
    void               *ctx,
    FILE               *fp,
    GError            **err)
{
    fbSession_t    *session;
    fBuf_t         *fbuf;

    /* Allocate a session.  The session will be owned by the fbuf, so
     * don't save it for later freeing. */
    session = fbSessionAlloc(skiInfoModel());

    /* Initialize session for reading */
    if (!skiSessionInitReader(session, err)) {
        fbSessionFree(session);
        return NULL;
    }

    /* Create a buffer with the session and a collector */
    fbuf = fBufAllocForCollection(session, fbCollectorAllocFP(ctx, fp));

    /* Make certain the fbuf has an internal template */
    if (!fBufSetInternalTemplate(fbuf, SKI_YAFSTATS_TID, err)) {
        fBufFree(fbuf);
        return NULL;
    }

    return fbuf;
}




/*
 *     The free_connspec() function frees a fbConnSpec_t object.
 */
static void
free_connspec(
    fbConnSpec_t       *connspec)
{
    TRACE_ENTRY;

    if (connspec->host) {
        free(connspec->host);
    }
    if (connspec->svc) {
        free(connspec->svc);
    }
    free(connspec);

    TRACE_RETURN;
}


/*
 *     The ipfixSourceCreateBase() function allocates a new
 *     skIPFIXSourceBase_t object.
 */
static skIPFIXSourceBase_t *
ipfixSourceCreateBase(
    void)
{
    skIPFIXSourceBase_t *base;

    TRACE_ENTRY;

    base = (skIPFIXSourceBase_t*)calloc(1, sizeof(skIPFIXSourceBase_t));
    if (base == NULL) {
        TRACE_RETURN(NULL);
    }

    pthread_mutex_init(&base->mutex, NULL);
    pthread_cond_init(&base->cond, NULL);

    TRACE_RETURN(base);
}


/*
 *     The ipfixSourceCreateFromFile() function creates a new
 *     skIPFIXSource_t object and associated base object for a
 *     file-based IPFIX stream.
 */
static skIPFIXSource_t *
ipfixSourceCreateFromFile(
    const skpc_probe_t *probe,
    const char         *path_name)
{
    skIPFIXSourceBase_t *base   = NULL;
    skIPFIXSource_t     *source = NULL;
    GError              *err    = NULL;
    int                  rv;

    TRACE_ENTRY;

    /* Create the base object */
    base = ipfixSourceCreateBase();
    if (base == NULL) {
        goto ERROR;
    }
    pthread_mutex_lock(&global_tree_mutex);
    ++source_base_count;
    pthread_mutex_unlock(&global_tree_mutex);

    /* Create the source object */
    source = (skIPFIXSource_t*)calloc(1, sizeof(*source));
    if (source == NULL) {
        goto ERROR;
    }

    /* Open the file */
    source->fileptr.of_name = path_name;
    rv = skFileptrOpen(&source->fileptr, SK_IO_READ);
    if (rv) {
        ERRMSG("Unable to open file '%s': %s",
               path_name, skFileptrStrerror(rv));
        goto ERROR;
    }
    if (SK_FILEPTR_IS_PROCESS == source->fileptr.of_type) {
        skAppPrintErr("Reading from gzipped files is not supported");
        goto ERROR;
    }

    /* Attach the source and base objects */
    source->base = base;
    base->any = source;
    ++base->source_count;

    /* Set the source's name from the probe name */
    source->probe = probe;
    source->name = skpcProbeGetName(probe);

    /* Create a connection object that points to the source, and store
     * it on the source */
    source->file_conn =
        (skIPFIXConnection_t *)calloc(1, sizeof(skIPFIXConnection_t));
    if (NULL == source->file_conn) {
        goto ERROR;
    }
    source->file_conn->source = source;

    /* Create a file-based fBuf_t for the source */
    source->readbuf = skiCreateReadBufferForFP((void *)source->file_conn,
                                               source->fileptr.of_fp, &err);
    if (source->readbuf == NULL) {
        if (err) {
            ERRMSG("%s: %s", "skiCreateReadBufferForFP", err->message);
        }
        goto ERROR;
    }

    pthread_mutex_init(&source->stats_mutex, NULL);

    TRACE_RETURN(source);

  ERROR:
    g_clear_error(&err);
    if (source) {
        if (NULL != source->fileptr.of_fp) {
            skFileptrClose(&source->fileptr, &WARNINGMSG);
        }
        if (source->readbuf) {
            fBufFree(source->readbuf);
        }
        free(source->file_conn);
        free(source);
    }
    if (base) {
        free(base);
        pthread_mutex_lock(&global_tree_mutex);
        --source_base_count;
        if (0 == source_base_count) {
            skiInfoModelFree();
        }
        pthread_mutex_unlock(&global_tree_mutex);
    }
    TRACE_RETURN(NULL);
}


/*
 *    Add the 'source' object to the 'base' object (or for an
 *    alternate view, have the 'source' wrap the 'base').  Return 0 on
 *    success, or -1 on failure.
 */
static int
ipfixSourceBaseAddIPFIXSource(
    skIPFIXSourceBase_t *base,
    skIPFIXSource_t     *source)
{
    const sk_sockaddr_array_t **accept_from;
    peeraddr_source_t *peeraddr;
    const peeraddr_source_t *found;
    fbTransport_t transport;
    uint32_t accept_from_count;
    uint32_t i;
    uint32_t j;
    int rv = -1;

    TRACE_ENTRY;

    assert(base);
    assert(source);
    assert(source->probe);
    assert(NULL == source->base);

    accept_from_count = skpcProbeGetAcceptFromHost(source->probe,&accept_from);

    /* Lock the base */
    pthread_mutex_lock(&base->mutex);

    /* Base must not be configured to accept packets from any host. */
    if (base->any) {
        goto END;
    }
    if (NULL == accept_from || 0 == accept_from_count) {
        /* When no accept-from-host is specified, this source accepts
         * packets from any address and there should be a one-to-one
         * mapping between source and base */
        if (base->addr_to_source) {
            /* The base already references another source. */
            goto END;
        }
        base->any = source;
        source->base = base;
        ++base->source_count;
    } else {
        /* Make sure the sources's protocol match the base's protocol */
        SILK_PROTO_TO_FIXBUF_TRANSPORT(
            skpcProbeGetProtocol(source->probe), &transport);
        if (base->connspec->transport != transport) {
            goto END;
        }

        /* Connect the base to the source */
        source->base = base;

        if (NULL == base->addr_to_source) {
            base->addr_to_source = rbinit(peeraddr_compare, NULL);
            if (base->addr_to_source == NULL) {
                goto END;
            }
        }

        /* Add a mapping on the base for each accept-from-host address
         * on this source. */
        for (j = 0; j < accept_from_count; ++j) {
            for (i = 0; i < skSockaddrArrayGetSize(accept_from[j]); ++i) {
                peeraddr = ((peeraddr_source_t*)
                            calloc(1, sizeof(peeraddr_source_t)));
                if (peeraddr == NULL) {
                    goto END;
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
                    goto END;
                }
            }
        }

        ++base->source_count;
    }

    rv = 0;

  END:
    pthread_mutex_unlock(&base->mutex);
    TRACE_RETURN(rv);
}


void
ipfixSourceBaseFreeListener(
    skIPFIXSourceBase_t    *base)
{
    ASSERT_MUTEX_LOCKED(&base->mutex);

    /* Remove this base object from the listener_to_source_base
     * red-black tree */
    pthread_mutex_lock(&global_tree_mutex);
    rbdelete(base, listener_to_source_base);
    pthread_mutex_unlock(&global_tree_mutex);

    TRACEMSG(3, ("base %p calling fbListenerFree", base));

    /* Destroy the fbListener_t object.  This destroys the fbuf if the
     * stream is UDP. */
    fbListenerFree(base->listener);
    base->listener = NULL;
}


/*
 *    Adds the skIPFIXSourceBase_t object 'base' to the global
 *    red-black tree of base objects, creating the tree if it does not
 *    exist.  Returns 0 on success and -1 on failure.
 */
static int
ipfixSourceBaseAddToGlobalList(
    skIPFIXSourceBase_t    *base)
{
    const void *rv;

    pthread_mutex_lock(&global_tree_mutex);

    if (listener_to_source_base == NULL) {
        listener_to_source_base = rbinit(listener_to_source_base_find, NULL);
        if (listener_to_source_base == NULL) {
            pthread_mutex_unlock(&global_tree_mutex);
            return -1;
        }
    }

    rv = rbsearch(base, listener_to_source_base);
    pthread_mutex_unlock(&global_tree_mutex);

    if (base != rv) {
        if (NULL == rv) {
            CRITMSG("Out of memory");
        } else {
            CRITMSG("Duplicate listener created");
        }
        return -1;
    }
    return 0;
}


#if 0
/*
 *    The following is #if 0'ed out because it fails to do what it
 *    is intended to do.
 *
 *    The issue appears to be that fixbuf and SiLK use different
 *    flags to getaddrinfo(), which changes the set of addresses
 *    that are returned.
 */
/*
 *    fixbuf does not return an error when it cannot bind to any
 *    listening address, which means the application can start
 *    correctly but not be actively listening.  The following code
 *    attempts to detect this situation before creating the fixbuf
 *    listener by binding to the port.
 *
 *    Return 0 when able to successfully bind to the address or -1
 *    otherwise.
 */
static int
ipfixSourceBaseVerifyOpenPort(
    const sk_sockaddr_array_t  *listen_address)
{
    const sk_sockaddr_t *addr;
    char addr_name[PATH_MAX];
    int *sock_array;
    int *s;
    uint16_t port = 0;

    s = sock_array = (int *)calloc(skSockaddrArrayGetSize(listen_address),
                                   sizeof(int));
    if (sock_array == NULL) {
        return -1;
    }

    DEBUGMSG(("Attempting to bind %" PRIu32 " addresses for %s"),
             skSockaddrArrayGetSize(listen_address),
             skSockaddrArrayGetHostPortPair(listen_address));
    for (i = 0; i < skSockaddrArrayGetSize(listen_address); ++i) {
        addr = skSockaddrArrayGet(listen_address, i);
        skSockaddrString(addr_name, sizeof(addr_name), addr);

        /* Get a socket */
        *s = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
        if (-1 == *s) {
            DEBUGMSG("Skipping %s: Unable to create dgram socket: %s",
                     addr_name, strerror(errno));
            continue;
        }
        /* Bind socket to port */
        if (bind(*s, &addr->sa, skSockaddrLen(addr)) == -1) {
            DEBUGMSG("Skipping %s: Unable to bind: %s",
                     addr_name, strerror(errno));
            close(*s);
            *s = -1;
            continue;
        }
        DEBUGMSG("Bound %s for listening", addr_name);
        ++s;
        if (0 == port) {
            port = skSockaddrGetPort(addr);
        }
        assert(port == skSockaddrGetPort(addr));
    }

    if (s == sock_array) {
        ERRMSG("Failed to bind any addresses for %s",
               skSockaddrArrayGetHostPortPair(listen_address));
        free(sock_array);
        return -1;
    }
    DEBUGMSG(("Bound %" PRIu32 "/%" PRIu32 " addresses for %s"),
             (uint32_t)(s-sock_array),
             skSockaddrArrayGetSize(listen_address),
             skSockaddrArrayGetHostPortPair(listen_address));
    while (s != sock_array) {
        --s;
        close(*s);
    }
    free(sock_array);
    return 0;
}
#endif  /* 0 */


/*
 *    Creates a IPFIX source listening on the network.
 *
 *    'probe' is the probe associated with the source.  'max_flows' is
 *    the number of IPFIX flows the created source can buffer in
 *    memory.
 *
 *    Returns a IPFIX source on success, or NULL on failure.
 */
static skIPFIXSource_t *
ipfixSourceCreateFromSockaddr(
    const skpc_probe_t *probe,
    uint32_t            max_flows)
{
    skIPFIXSource_t *source = NULL;
    skIPFIXSourceBase_t *localbase = NULL;
    skIPFIXSourceBase_t *base;
    const sk_sockaddr_array_t *listen_address;
    const sk_sockaddr_array_t **accept_from;
    peeraddr_source_t target;
    const peeraddr_source_t *found;
    skpc_proto_t protocol;
    GError *err = NULL;
    char port_string[7];
    uint32_t accept_from_count;
    uint32_t i;
    uint32_t j;
    int rv;

    TRACE_ENTRY;

    /* Check the protocol */
    protocol = skpcProbeGetProtocol(probe);

    /* Get the list of accept-from-host addresses. */
    accept_from_count = skpcProbeGetAcceptFromHost(probe, &accept_from);

    /* Get the listen address. */
    rv = skpcProbeGetListenOnSockaddr(probe, &listen_address);
    if (rv == -1) {
        goto ERROR;
    }

    /* Check to see if there is an existing base object for that
     * listen address */
    pthread_mutex_lock(&global_tree_mutex);
    if (!listener_to_source_base) {
        base = NULL;
    } else {
        /* Loop through all current bases, and compare based on
         * listen_address and protocol */
        fbTransport_t transport;
        RBLIST *iter;

        SILK_PROTO_TO_FIXBUF_TRANSPORT(protocol, &transport);
        iter = rbopenlist(listener_to_source_base);
        while ((base = (skIPFIXSourceBase_t *)rbreadlist(iter)) != NULL) {
            if (transport == base->connspec->transport
                && skSockaddrArrayMatches(base->listen_address,
                                          listen_address, 0))
            {
                /* Found a match.  'base' is now set to the matching
                 * base */
                break;
            }
        }
        rbcloselist(iter);
    }
    pthread_mutex_unlock(&global_tree_mutex);

#if 0
    if (NULL == base) {
        if (ipfixSourceBaseVerifyOpenPort(listen_address)) {
            goto ERROR;
        }
    }
#endif  /* 0 */

    /* if there is an existing base on this listen-address, compare
     * its accept-from settings with those on this probe */
    if (base) {
        if (accept_from == NULL) {
            /* The new listener wants to be promiscuous but another
             * listener already exists. */
            goto ERROR;
        }
        pthread_mutex_lock(&base->mutex);
        if (base->any) {
            /* Already have a listener, and it is promiscuous. */
            pthread_mutex_unlock(&base->mutex);
            goto ERROR;
        }
        /* Ensure the accept-from addresses are unique. */
        for (j = 0; j < accept_from_count; ++j) {
            for (i = 0; i < skSockaddrArrayGetSize(accept_from[j]); ++i) {
                target.addr = skSockaddrArrayGet(accept_from[j], i);
                found = ((const peeraddr_source_t*)
                         rbfind(&target, base->addr_to_source));
                if (found != NULL) {
                    pthread_mutex_unlock(&base->mutex);
                    goto ERROR;
                }
            }
        }
        pthread_mutex_unlock(&base->mutex);
    }

    /* Create a new source object */
    source = (skIPFIXSource_t *)calloc(1, sizeof(*source));
    if (source == NULL) {
        goto ERROR;
    }

    /* Keep a handle to the probe and the probe's name */
    source->probe = probe;
    source->name = skpcProbeGetName(probe);

    if (PROBE_ENUM_NETFLOW_V9 == skpcProbeGetType(probe)
        || PROBE_ENUM_SFLOW == skpcProbeGetType(probe))
    {
        /* Create the look-up table for skIPFIXConnection_t's */
        source->connections = rbinit(pointer_cmp, NULL);
        if (NULL == source->connections) {
            goto ERROR;
        }
    }

    /* Create the circular buffer */
    if (skCircBufCreate(&source->circbuf, sizeof(rwRec), max_flows)) {
        goto ERROR;
    }
    /* Ready the first location in the circular buffer for writing */
    if (skCircBufGetWriterBlock(
            source->circbuf, &source->current_record, NULL))
    {
        skAbort();
    }

    pthread_mutex_init(&source->stats_mutex, NULL);

    if (base != NULL) {
        /* If there is an existing base, add the source to it. */
        if (ipfixSourceBaseAddIPFIXSource(base, source)) {
            goto ERROR;
        }
    } else {
        /* No existing base, create a new one */

        /* Create the base object */
        base = localbase = ipfixSourceCreateBase();
        if (base == NULL) {
            goto ERROR;
        }
        pthread_mutex_lock(&global_tree_mutex);
        ++source_base_count;
        pthread_mutex_unlock(&global_tree_mutex);

        /* Set the listen_address */
        base->listen_address = listen_address;

        /* Create a connspec in order to create a listener */
        base->connspec = (fbConnSpec_t *)calloc(1, sizeof(*base->connspec));
        if (base->connspec == NULL) {
            goto ERROR;
        }
        if (skSockaddrArrayGetHostname(listen_address)
            != sk_sockaddr_array_anyhostname)
        {
            base->connspec->host
                = strdup(skSockaddrArrayGetHostname(listen_address));
            if (base->connspec->host == NULL) {
                goto ERROR;
            }
        }
        rv = snprintf(port_string, sizeof(port_string), "%i",
                      skSockaddrGetPort(skSockaddrArrayGet(listen_address, 0)));
        assert((size_t)rv < sizeof(port_string));
        base->connspec->svc = strdup(port_string);
        if (base->connspec->svc == NULL) {
            goto ERROR;
        }
        SILK_PROTO_TO_FIXBUF_TRANSPORT(protocol, &base->connspec->transport);

        /* Create the listener */
        pthread_mutex_lock(&create_listener_mutex);
        base->listener = skiCreateListener(base, &err);
        if (NULL == base->listener) {
            pthread_mutex_unlock(&create_listener_mutex);
            goto ERROR;
        }
        if (SKPC_PROTO_UDP == protocol) {
            fbCollector_t *collector;

            if (!fbListenerGetCollector(base->listener, &collector, &err)) {
                pthread_mutex_unlock(&create_listener_mutex);
                goto ERROR;
            }
            /* Enable the multi-UDP support in libfixbuf. */
            fbCollectorSetUDPMultiSession(collector, 1);

#if !FIXBUF_CHECK_VERSION(2,0,0)
            /* Treat UDP streams from the same address but different
             * ports as different streams, in accordance with the
             * IPFIX/NetFlow v9 RFCs. */
            fbCollectorManageUDPStreamByPort(collector, TRUE);
#endif  /* FIXBUF_CHECK_VERSION */

            /* If this is a Netflow v9 source or an sFlow source, tell
             * the collector. */
            switch (skpcProbeGetType(source->probe)) {
              case PROBE_ENUM_IPFIX:
                break;
              case PROBE_ENUM_NETFLOW_V9:
                if (!fbCollectorSetNetflowV9Translator(collector, &err)) {
                    pthread_mutex_unlock(&create_listener_mutex);
                    goto ERROR;
                }
                break;
              case PROBE_ENUM_SFLOW:
                if (!fbCollectorSetSFlowTranslator(collector, &err)) {
                    pthread_mutex_unlock(&create_listener_mutex);
                    goto ERROR;
                }
                break;
              default:
                skAbortBadCase(skpcProbeGetType(source->probe));
            }
        }
        pthread_mutex_unlock(&create_listener_mutex);

        pthread_mutex_init(&base->mutex, NULL);
        pthread_cond_init(&base->cond, NULL);

        /* add the source to the base */
        if (ipfixSourceBaseAddIPFIXSource(base, source)) {
            goto ERROR;
        }

        /* Add base to list of bases, creating the list if needed */
        if (ipfixSourceBaseAddToGlobalList(base)) {
            goto ERROR;
        }

        /* Start the listener thread */
        pthread_mutex_lock(&base->mutex);
        rv = skthread_create(skSockaddrArrayGetHostPortPair(listen_address),
                             &base->thread, ipfix_reader, (void*)base);
        if (rv != 0) {
            pthread_mutex_unlock(&base->mutex);
            WARNINGMSG("Unable to spawn new thread for '%s': %s",
                       skSockaddrArrayGetHostPortPair(listen_address),
                       strerror(rv));
            goto ERROR;
        }

        /* Wait for the thread to really begin */
        do {
            pthread_cond_wait(&base->cond, &base->mutex);
        } while (!base->started);
        pthread_mutex_unlock(&base->mutex);
    }

    TRACE_RETURN(source);

  ERROR:
    if (err) {
        ERRMSG("'%s': %s", source->name, err->message);
    }
    g_clear_error(&err);
    if (localbase) {
        if (localbase->listener) {
            fbListenerFree(localbase->listener);
        }
        if (localbase->connspec) {
            free_connspec(localbase->connspec);
        }
        if (localbase->addr_to_source) {
            rbdestroy(localbase->addr_to_source);
        }
        free(localbase);
        pthread_mutex_lock(&global_tree_mutex);
        --source_base_count;
        if (0 == source_base_count) {
            skiInfoModelFree();
            if (listener_to_source_base) {
                rbdestroy(listener_to_source_base);
                listener_to_source_base = NULL;
            }
        }
        pthread_mutex_unlock(&global_tree_mutex);
    }
    if (source) {
        if (source->circbuf) {
            skCircBufDestroy(source->circbuf);
        }
        if (source->connections) {
            rbdestroy(source->connections);
        }
        free(source);
    }
    TRACE_RETURN(NULL);
}


/*
 *    Handler to print log messages.  This will be invoked by g_log()
 *    and the other logging functions from GLib2.
 */
static void
ipfixGLogHandler(
    const gchar        *log_domain,
    GLogLevelFlags      log_level,
    const gchar        *message,
    gpointer            user_data)
{
    /* In syslog, CRIT is worse than ERR; in Glib2 ERROR is worse than
     * CRITICAL. */
    SK_UNUSED_PARAM(log_domain);
    SK_UNUSED_PARAM(user_data);

    switch (log_level & G_LOG_LEVEL_MASK) {
      case G_LOG_LEVEL_CRITICAL:
        ERRMSG("%s", message);
        break;
      case G_LOG_LEVEL_WARNING:
        WARNINGMSG("%s", message);
        break;
      case G_LOG_LEVEL_MESSAGE:
        NOTICEMSG("%s", message);
        break;
      case G_LOG_LEVEL_INFO:
        INFOMSG("%s", message);
        break;
      case G_LOG_LEVEL_DEBUG:
        DEBUGMSG("%s", message);
        break;
      default:
        CRITMSG("%s", message);
        break;
    }
}

/*
 *    GLib Log handler to discard messages.
 */
static void
ipfixGLogHandlerVoid(
    const gchar        *log_domain,
    GLogLevelFlags      log_level,
    const gchar        *message,
    gpointer            user_data)
{
    SK_UNUSED_PARAM(*log_domain);
    SK_UNUSED_PARAM(log_level);
    SK_UNUSED_PARAM(*message);
    SK_UNUSED_PARAM(user_data);
    return;
}


/*
 *  ipfixSourceGlibInitialize();
 *
 *    Initialize the GLib slice allocator.  Since there is no way to
 *    de-initialize the slice allocator, valgrind will report this
 *    memory as "still-reachable".  We would rather have this
 *    "still-reachable" memory reported in a well-known location,
 *    instead of hidden somewhere within fixbuf.
 */
static void
ipfixSourceGlibInitialize(
    void)
{
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 10)
#define MEMORY_SIZE 128
    gpointer memory;

    memory = g_slice_alloc(MEMORY_SIZE);
    g_slice_free1(MEMORY_SIZE, memory);
#endif
}


/*
 *    Performs any initialization required prior to creating the IPFIX
 *    sources.  Returns 0 on success, or -1 on failure.
 */
int
skIPFIXSourcesSetup(
    void)
{
    const char *env;
    GLogLevelFlags log_levels = (GLogLevelFlags)(G_LOG_LEVEL_CRITICAL
                                                 | G_LOG_LEVEL_WARNING
                                                 | G_LOG_LEVEL_MESSAGE
                                                 | G_LOG_LEVEL_INFO
                                                 | G_LOG_LEVEL_DEBUG);

    /* initialize the slice allocator */
    ipfixSourceGlibInitialize();

    /* As of glib 2.32, g_thread_init() is deprecated. */
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 32)
    /* tell fixbuf (glib) we are a threaded program.  this will abort
     * if glib does not have thread support. */
    if (!g_thread_supported()) {
        g_thread_init(NULL);
    }
#endif

    /* set a log handler for messages from glib, which we always want
     * to include in our log file.
     * http://developer.gnome.org/glib/stable/glib-Message-Logging.html */
    g_log_set_handler("GLib", log_levels, &ipfixGLogHandler, NULL);

    /* set a log handler for messages from fixbuf, maybe using a void
     * handler for warnings. */
    env = getenv(SK_ENV_FIXBUF_SUPPRESS_WARNING);
    if (env && *env && 0 == strcmp("1", env)) {
        /* suppress warnings by setting a void handler */
        log_levels = (GLogLevelFlags)((unsigned int)log_levels
                                      & ~(unsigned int)G_LOG_LEVEL_WARNING);
        g_log_set_handler(
            NULL, G_LOG_LEVEL_WARNING, &ipfixGLogHandlerVoid, NULL);
    }
    g_log_set_handler(NULL, log_levels, &ipfixGLogHandler, NULL);

    /* Determine which information elements should be used when
     * defining the NetFlow v9 Sampling template. */
    ski_nf9sampling_check_spec();

    return 0;
}


/*
 *    Free any state allocated by skIPFIXSourcesSetup().
 */
void
skIPFIXSourcesTeardown(
    void)
{
    skiTeardown();
}


/*
 *    Creates a IPFIX source based on an skpc_probe_t.
 *
 *    If the source is a network-based probe, this function also
 *    starts the collection process.
 *
 *    When creating a source from a network-based probe, the 'params'
 *    union should have the 'max_pkts' member specify the maximum
 *    number of packets to buffer in memory for this source.
 *
 *    When creating a source from a probe that specifies either a file
 *    or a directory that is polled for files, the 'params' union must
 *    have the 'path_name' specify the full path of the file to
 *    process.
 *
 *    Return the new source, or NULL on error.
 */
skIPFIXSource_t *
skIPFIXSourceCreate(
    const skpc_probe_t         *probe,
    const skFlowSourceParams_t *params)
{
    skIPFIXSource_t *source;

    TRACE_ENTRY;

    /* Check whether this is a file-based probe---either handles a
     * single file or files pulled from a directory poll */
    if (NULL != skpcProbeGetPollDirectory(probe)
        || NULL != skpcProbeGetFileSource(probe))
    {
        if (NULL == params->path_name) {
            TRACE_RETURN(NULL);
        }
        source = ipfixSourceCreateFromFile(probe, params->path_name);

    } else {
        /* must be a network-based source */
        source = ipfixSourceCreateFromSockaddr(probe, params->max_pkts);
    }

    TRACE_RETURN(source);
}


/*
 *    Stops processing of packets.  This will cause a call to any
 *    skIPFIXSourceGetGeneric() function to stop blocking.  Meant to
 *    be used as a prelude to skIPFIXSourceDestroy() in threaded code.
 */
void
skIPFIXSourceStop(
    skIPFIXSource_t    *source)
{
    TRACE_ENTRY;

    assert(source);

    /* Mark the source as stopped, and unblock the circular buffer */
    source->stopped = 1;
    if (source->circbuf) {
        skCircBufStop(source->circbuf);
    }
    TRACE_RETURN;
}


/*
 *    Destroys an IPFIX source.
 */
void
skIPFIXSourceDestroy(
    skIPFIXSource_t    *source)
{
    skIPFIXSourceBase_t *base;
    const sk_sockaddr_array_t **accept_from;
    peeraddr_source_t target;
    const peeraddr_source_t *found;
    uint32_t accept_from_count;
    uint32_t i;
    uint32_t j;

    TRACE_ENTRY;

    if (!source) {
        TRACE_RETURN;
    }

    accept_from_count = skpcProbeGetAcceptFromHost(source->probe,&accept_from);

    assert(source->base);

    base = source->base;

    pthread_mutex_lock(&base->mutex);

    /* Remove the source from the red-black tree */
    if (base->addr_to_source && accept_from) {
        /* Remove the source's accept-from-host addresses from
         * base->addr_to_source */
        for (j = 0; j < accept_from_count; ++j) {
            for (i = 0; i < skSockaddrArrayGetSize(accept_from[j]); ++i) {
                target.addr = skSockaddrArrayGet(accept_from[j], i);
                found = ((const peeraddr_source_t*)
                         rbdelete(&target, base->addr_to_source));
                if (found && (found->source == source)) {
                    free((void*)found);
                }
            }
        }
    }

    /* Stop the source */
    skIPFIXSourceStop(source);

    /* If the source is not currently being referenced by an fBuf_t,
     * free it, otherwise mark it to be destroyed when the fBuf_t is
     * freed by fixbufDisconnect(). */
    if (source->connection_count == 0) {
        free_source(source);
    } else {
        source->destroy = 1;
    }

    /* Decrement the source reference count */
    assert(base->source_count);
    --base->source_count;

    TRACEMSG(3, ("base %p source_count is %u", base, base->source_count));

    /* If this base object is still referenced by sources, return */
    if (base->source_count != 0) {
        pthread_mutex_unlock(&base->mutex);
        TRACE_RETURN;
    }

    /* Otherwise, we must destroy the base stop its thread */
    base->destroyed = 1;

    if (base->listener) {
        TRACEMSG(3, ("base %p calling fbListenerInterrupt", base));

        /* Unblock the fbListenerWait() call */
        fbListenerInterrupt(base->listener);

        /* Signal that the thread is to exit */
        pthread_cond_broadcast(&base->cond);

        TRACEMSG(3, ("base %p waiting for running variable", base));

        /* Wait for the thread to exit */
        while (base->running) {
            pthread_cond_wait(&base->cond, &base->mutex);
        }

        TRACEMSG(3, ("base %p joining its thread", base));

        /* Acknowledge that the thread has exited */
        pthread_join(base->thread, NULL);

        assert(base->listener == NULL);

        /* Free the connspec */
        free_connspec(base->connspec);

        /* Destroy the red-black tree */
        if (base->addr_to_source) {
            rbdestroy(base->addr_to_source);
        }

        pthread_cond_destroy(&base->cond);

        pthread_mutex_unlock(&base->mutex);
        pthread_mutex_destroy(&base->mutex);
    }

    TRACEMSG(3, ("base %p is free", base));

    free(base);

    pthread_mutex_lock(&global_tree_mutex);
    --source_base_count;
    if (0 == source_base_count) {
        /* When the last base is removed, destroy the global base
         * list, and call the teardown function for the libskipfix
         * library to free any global objects allocated there. */
        if (listener_to_source_base) {
            rbdestroy(listener_to_source_base);
            listener_to_source_base = NULL;
        }
        skiTeardown();
    }
    pthread_mutex_unlock(&global_tree_mutex);
    TRACE_RETURN;
}




/*
 *    Requests a SiLK Flow record from the IPFIX source 'source'.
 *
 *    This function will block if there are no IPFIX flows available
 *    from which to create a SiLK Flow record.
 *
 *    Returns 0 on success, -1 on failure.
 */
int
skIPFIXSourceGetGeneric(
    skIPFIXSource_t    *source,
    rwRec              *rwrec)
{
    rwRec *rec;
    int rv;

    TRACE_ENTRY;

    assert(source);
    assert(rwrec);

    if (source->circbuf) {
        /* Reading from the circular buffer */
        if (skCircBufGetReaderBlock(source->circbuf, &rec, NULL)) {
            TRACE_RETURN(-1);
        }
        RWREC_COPY(rwrec, rec);
        TRACE_RETURN(0);
    }

    rv = ipfixSourceGetRecordFromFile(source, rwrec);
    TRACE_RETURN(rv);
}



/* Log statistics associated with a IPFIX source, and then clear the
 * statistics. */
void
skIPFIXSourceLogStatsAndClear(
    skIPFIXSource_t    *source)
{
    TRACE_ENTRY;

    pthread_mutex_lock(&source->stats_mutex);

    /* print log message giving the current statistics on the
     * skIPFIXSource_t pointer 'source' */
    {
        fbCollector_t *collector = NULL;
        GError *err = NULL;

        if (source->saw_yafstats_pkt) {
            /* IPFIX from yaf: print the stats */

            INFOMSG(("'%s': forward %" PRIu64
                     ", reverse %" PRIu64
                     ", ignored %" PRIu64
                     "; yaf: recs %" PRIu64
                     ", pkts %" PRIu64
                     ", dropped-pkts %" PRIu64
                     ", ignored-pkts %" PRIu64
                     ", bad-sequence-pkts %" PRIu64
                     ", expired-frags %" PRIu64),
                    source->name,
                    source->forward_flows,
                    source->reverse_flows,
                    source->ignored_flows,
                    source->yaf_exported_flows,
                    source->yaf_processed_packets,
                    source->yaf_dropped_packets,
                    source->yaf_ignored_packets,
                    source->yaf_notsent_packets,
                    source->yaf_expired_fragments);

        } else if (!source->connections
                   || !source->base
                   || !source->base->listener)
        {
            /* no data or other IPFIX; print count of SiLK flows
             * created */

            INFOMSG(("'%s': forward %" PRIu64
                     ", reverse %" PRIu64
                     ", ignored %" PRIu64),
                    source->name,
                    source->forward_flows,
                    source->reverse_flows,
                    source->ignored_flows);

        } else if (!fbListenerGetCollector(source->base->listener,
                                           &collector, &err))
        {
            /* sFlow or NetFlowV9, but no collector */

            DEBUGMSG("'%s': Unable to get collector for source: %s",
                     source->name, err->message);
            g_clear_error(&err);

            INFOMSG(("'%s': forward %" PRIu64
                     ", reverse %" PRIu64
                     ", ignored %" PRIu64),
                    source->name,
                    source->forward_flows,
                    source->reverse_flows,
                    source->ignored_flows);

        } else {
            /* sFlow or NetFlowV9 */
            skIPFIXConnection_t *conn;
            RBLIST *iter;
            uint64_t prev;

            iter = rbopenlist(source->connections);
            while ((conn = (skIPFIXConnection_t *)rbreadlist(iter)) != NULL) {
                /* store the previous number of dropped NF9/sFlow packets
                 * and get the new number of dropped packets. */
                prev = conn->prev_yafstats.droppedPacketTotalCount;
                if (skpcProbeGetType(source->probe) == PROBE_ENUM_SFLOW) {
                    conn->prev_yafstats.droppedPacketTotalCount
                        = fbCollectorGetSFlowMissed(
                            collector, &conn->peer_addr.sa, conn->peer_len,
                            conn->ob_domain);
                } else {
                    conn->prev_yafstats.droppedPacketTotalCount
                        = fbCollectorGetNetflowMissed(
                            collector, &conn->peer_addr.sa, conn->peer_len,
                            conn->ob_domain);
                }
                if (prev > conn->prev_yafstats.droppedPacketTotalCount) {
                    /* assume a new collector */
                    TRACEMSG(4, (("Assuming new collector: NF9 loss dropped"
                                  " old = %" PRIu64 ", new = %" PRIu64),
                                 prev,
                                 conn->prev_yafstats.droppedPacketTotalCount));
                    prev = 0;
                }
                source->yaf_dropped_packets
                    += conn->prev_yafstats.droppedPacketTotalCount - prev;
            }
            rbcloselist(iter);

            INFOMSG(("'%s': forward %" PRIu64
                     ", reverse %" PRIu64
                     ", ignored %" PRIu64
                     ", %s: missing-pkts %" PRIu64),
                    source->name,
                    source->forward_flows,
                    source->reverse_flows,
                    source->ignored_flows,
                    ((skpcProbeGetType(source->probe) == PROBE_ENUM_SFLOW)
                     ? "sflow" : "nf9"),
                    source->yaf_dropped_packets);
        }
    }

#if SOURCE_LOG_MAX_PENDING_WRITE
    if (skpcProbeGetLogFlags(source->probe) & SOURCE_LOG_MAX_PENDING_WRITE) {
        INFOMSG(("'%s': Maximum number of read records waiting to be written:"
                 " %" PRIu32), source->name, source->max_pending);
    }
#endif

    /* reset (set to zero) statistics on the skIPFIXSource_t
     * 'source' */
    {
        source->yaf_dropped_packets = 0;
        source->yaf_ignored_packets = 0;
        source->yaf_notsent_packets = 0;
        source->yaf_expired_fragments = 0;
        source->yaf_processed_packets = 0;
        source->yaf_exported_flows = 0;
        source->forward_flows = 0;
        source->reverse_flows = 0;
        source->ignored_flows = 0;
        source->max_pending = 0;
    }

    pthread_mutex_unlock(&source->stats_mutex);
    TRACE_RETURN;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
