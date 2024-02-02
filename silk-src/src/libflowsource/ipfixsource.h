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
 *  ipfixsource.h
 *
 *    The files ipfixsource.c and skipfix.c are tightly coupled, and
 *    together they read IPFIX records and convert them to SiLK flow
 *    records.
 *
 *    This file contains the necessary declarations so those files can
 *    work togehter.
 *
 *    The ipfixsource.c file is primary about setting up and tearing
 *    down the data structures used when processing IPFIX.
 *
 *    The skipfix.c file primarly handles the conversion, and it is
 *    where the reading functions exist.
 *
 */
#ifndef _IPFIXSOURCE_H
#define _IPFIXSOURCE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_IPFIXSOURCE_H, "$SiLK: ipfixsource.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/libflowsource.h>
#include <silk/skipfix.h>
#include <silk/sklog.h>
#include <silk/utils.h>
#include "circbuf.h"


/* DEFINES AND TYPEDEFS */

/*
 *  Logging messages for function entry/return.
 *
 *    Define the macro SKIPFIXSOURCE_ENTRY_RETURN to trace entry to
 *    and return from the functions in this file.
 *
 *    Developers must use "TRACE_ENTRY" at the beginning of every
 *    function.  Use "TRACE_RETURN(x);" for functions that return the
 *    value "x", and use "TRACE_RETURN;" for functions that have no
 *    return value.
 */
/* #define SKIPFIXSOURCE_ENTRY_RETURN 1 */

#ifndef SKIPFIXSOURCE_ENTRY_RETURN
#  define TRACE_ENTRY
#  define TRACE_RETURN       return
#else
/*
 *  this macro is used when the extra-level debugging statements write
 *  to the log, since we do not want the result of the log's printf()
 *  to trash the value of 'errno'
 */
#define WRAP_ERRNO(x)                                           \
    do { int _saveerrno = errno; x; errno = _saveerrno; }       \
    while (0)

#  define TRACE_ENTRY                                   \
    WRAP_ERRNO(DEBUGMSG("Entering %s", __func__))

#  define TRACE_RETURN                                          \
    WRAP_ERRNO(DEBUGMSG("Exiting %s", __func__)); return

#endif  /* SKIPFIXSOURCE_ENTRY_RETURN */


/*
 *    The NetFlowV9/IPFIX standard stays that a 'stream' is unique if
 *    the source-address and domain are unique.  SiLK violates the
 *    standard in that it also treats the sending port as part of the
 *    unique 'stream' key.
 *
 *    To have SiLK follow the standard---that is, to treat UDP packets
 *    coming from the same source address but different source ports
 *    as being part of the same protocol stream, set the following
 *    environment variable prior to invoking rwflowpack or flowcap.
 */
#define SK_IPFIX_UDP_IGNORE_SOURCE_PORT "SK_IPFIX_UDP_IGNORE_SOURCE_PORT"

/* error codes used in callback that fixbuf calls */
#define SK_IPFIXSOURCE_DOMAIN  g_quark_from_string("silkError")
#define SK_IPFIX_ERROR_CONN    1


/* Name of environment variable that, when set, cause SiLK to ignore
 * any G_LOG_LEVEL_WARNING messages. */
#define SK_ENV_FIXBUF_SUPPRESS_WARNING "SILK_LIBFIXBUF_SUPPRESS_WARNINGS"

/*     Whether to maintain and log the maximum number of pending
 *     records held by the circular buffer. */
#ifndef SOURCE_LOG_MAX_PENDING_WRITE
#define SOURCE_LOG_MAX_PENDING_WRITE 0
#endif


/*
 *  **********  YAF Statistics Options Template  **********
 *
 *    Information for statistics information exported by YAF.  The
 *    template and structure are based on the yaf 2.3.0 manual page.
 */

#define SKI_YAFSTATS_TID        0xD000

#define SKI_YAFSTATS_PADDING    4

#ifdef SKIPFIX_SOURCE
static fbInfoElementSpec_t ski_yafstats_spec[] = {
    { (char*)"systemInitTimeMilliseconds",         8, 0 },
    { (char*)"exportedFlowRecordTotalCount",       8, 0 },
    { (char*)"packetTotalCount",                   8, 0 },
    { (char*)"droppedPacketTotalCount",            8, 0 },
    { (char*)"ignoredPacketTotalCount",            8, 0 },
    { (char*)"notSentPacketTotalCount",            8, 0 },
    { (char*)"expiredFragmentCount",               4, 0 },
#if 0
    { (char*)"assembledFragmentCount",             4, 0 },
    { (char*)"flowTableFlushEventCount",           4, 0 },
    { (char*)"flowTablePeakCount",                 4, 0 },
    { (char*)"exporterIPv4Address",                4, 0 },
    { (char*)"exportingProcessId",                 4, 0 },
    { (char*)"meanFlowRate",                       4, 0 },
    { (char*)"meanPacketRate",                     4, 0 },
#endif  /* 0 */
#if SKI_YAFSTATS_PADDING != 0
    { (char*)"paddingOctets",   SKI_YAFSTATS_PADDING, 0 },
#endif
    FB_IESPEC_NULL
};
#endif  /* #ifdef SKIPFIX_SOURCE */

typedef struct ski_yafstats_st {
    /* The time in milliseconds of the last (re-)initialization of
     * yaf.  IE 161, 8 octets */
    uint64_t    systemInitTimeMilliseconds;

    /* Total amount of exported flows from yaf start time.  IE 42, 8
     * octets */
    uint64_t    exportedFlowRecordTotalCount;

    /* Total amount of packets processed by yaf from yaf start time.
     * IE 86, 8 octets */
    uint64_t    packetTotalCount;

    /* Total amount of dropped packets according to statistics given
     * by libpcap, libdag, or libpcapexpress.  IE 135, 8 octets */
    uint64_t    droppedPacketTotalCount;

    /* Total amount of packets ignored by the yaf packet decoder, such
     * as unsupported packet types and incomplete headers, from yaf
     * start time.  IE 164, 8 octets */
    uint64_t    ignoredPacketTotalCount;

    /* Total amount of packets rejected by yaf because they were
     * received out of sequence.  IE 167, 8 octets */
    uint64_t    notSentPacketTotalCount;

    /* Total amount of fragments that have been expired since yaf
     * start time.  CERT (PEN 6871) IE 100, 4 octets */
    uint32_t    expiredFragmentCount;

#if 0
    /* Total number of packets that been assembled from a series of
     * fragments since yaf start time. CERT (PEN 6871) IE 101, 4
     * octets */
    uint32_t    assembledFragmentCount;

    /* Total number of times the yaf flow table has been flushed since
     * yaf start time.  CERT (PEN 6871) IE 104, 4 octets */
    uint32_t    flowTableFlushEventCount;

    /* The maximum number of flows in the yaf flow table at any one
     * time since yaf start time.  CERT (PEN 6871) IE 105, 4 octets */
    uint32_t    flowTablePeakCount;

    /* The IPv4 Address of the yaf flow sensor.  IE 130, 4 octets */
    uint32_t    exporterIPv4Address;

    /* Set the ID of the yaf flow sensor by giving a value to
     * --observation-domain.  The default is 0.   IE 144, 4 octets */
    uint32_t    exportingProcessId;

    /* The mean flow rate of the yaf flow sensor since yaf start time,
     * rounded to the nearest integer.  CERT (PEN 6871) IE 102, 4
     * octets */
    uint32_t    meanFlowRate;

    /* The mean packet rate of the yaf flow sensor since yaf start
     * time, rounded to the nearest integer.  CERT (PEN 6871) IE 103,
     * 4 octets */
    uint32_t    meanPacketRate;
#endif  /* 0 */
#if SKI_YAFSTATS_PADDING != 0
    uint8_t     paddingOctets[SKI_YAFSTATS_PADDING];
#endif
} ski_yafstats_t;


/* forward declarations */
struct skIPFIXSourceBase_st;
typedef struct skIPFIXSourceBase_st skIPFIXSourceBase_t;

struct skIPFIXConnection_st;
typedef struct skIPFIXConnection_st skIPFIXConnection_t;

/*
 *    skIPFIXSource_t object represents a single source, as mapped to
 *    a single probe.
 */
struct skIPFIXSource_st {
    /* 'rvbuf' is a place to hold the reverse half of a record when we
     * read a bi-flow.  For a network source, the value in the 'rvbuf'
     * is immediately copied into the 'circbuf'.  When reading from a
     * file-based source, the record is held until the caller requests
     * it.  For file sources, the 'reverse' member says whether
     * 'rvbuf' contains a valid record.  */
    rwRec                   rvbuf;

    /* when reading from a file-based source, this contains the counts
     * of statistics for this file.  when reading from the network,
     * the statistics are maintained per connection on the
     * skIPFIXConnection_t object. */
    ski_yafstats_t          prev_yafstats;

    /* for yaf sources, packets dropped by libpcap, libdag,
     * libpcapexpress.  For NetFlowV9/sFlow sources, number of packets
     * that were missed. */
    uint64_t                yaf_dropped_packets;

    /* packets ignored by yaf (unsupported packet types; bad headers) */
    uint64_t                yaf_ignored_packets;

    /* packets rejected by yaf due to being out-of-sequence */
    uint64_t                yaf_notsent_packets;

    /* packet fragments expired by yaf (e.g., never saw first frag) */
    uint64_t                yaf_expired_fragments;

    /* packets processed by yaf */
    uint64_t                yaf_processed_packets;

    /* exported flow record count */
    uint64_t                yaf_exported_flows;

    /* these next values are based on records the ipfixsource gets
     * from skipfix */
    uint64_t                forward_flows;
    uint64_t                reverse_flows;
    uint64_t                ignored_flows;

    /* mutex to protect access to the above statistics */
    pthread_mutex_t         stats_mutex;

    /* source's base */
    skIPFIXSourceBase_t    *base;

    /* probe associated with this source and its name */
    const skpc_probe_t     *probe;
    const char             *name;

    /* when reading from the network, 'circbuf' holds packets
     * collected for this probe but not yet requested.
     * 'current_record' is the current location in the 'circbuf'. */
    sk_circbuf_t           *circbuf;
    rwRec                  *current_record;

    /* buffer for file based reads */
    fBuf_t                 *readbuf;

    /* file for file-based reads */
    sk_fileptr_t            fileptr;

    /* connection for file-based reads */
    skIPFIXConnection_t    *file_conn;

    /* for NetFlowV9/sFlow sources, a red-black tree of
     * skIPFIXConnection_t objects that currently point to this
     * skIPFIXSource_t, keyed by the skIPFIXConnection_t pointer. */
    struct rbtree          *connections;

    /* count of skIPFIXConnection_t's associated with this source */
    uint32_t                connection_count;

    /* used by SOURCE_LOG_MAX_PENDING_WRITE, the maximum number of
     * records sitting in the circular buffer since the previous
     * flush */
    uint32_t                max_pending;

    /* Whether this source has been stopped */
    unsigned                stopped             :1;

    /* Whether this source has been marked for destructions */
    unsigned                destroy             :1;

    /* whether the 'rvbuf' field holds a valid record (1==yes) */
    unsigned                reverse             :1;

    /* Whether this source has received a STATS packet from yaf.  The
     * yaf stats are only written to the log once a stats packet has
     * been received.  */
    unsigned                saw_yafstats_pkt   :1;
};
/* typedef struct skIPFIXSource_st skIPFIXSource_t;  // libflowsource.h */


/*
 *    skIPFIXSourceBase_t wraps an fbListener_t.  It represents a
 *    single listening port or file, and it is associated with one or
 *    more skIPFIXSource_t objecst.
 */
struct skIPFIXSourceBase_st {
    /* when a probe does not have an accept-from-host clause, any peer
     * may connect, and there is a one-to-one mapping between a source
     * object and a base object.  The 'any' member points to the
     * source, and the 'addr_to_source' member must be NULL. */
    skIPFIXSource_t    *any;

    /* if there is an accept-from clause, the 'addr_to_source'
     * red-black tree maps the address of the peer to a particular
     * source object (via 'peeraddr_source_t' objects), and the 'any'
     * member must be NULL. */
    struct rbtree      *addr_to_source;

    /* address we are listening to. This is an array to support a
     * hostname that maps to multiple IPs (e.g. IPv4 and IPv6). */
    const sk_sockaddr_array_t *listen_address;

    pthread_t           thread;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;

    /* the listener and connection objects from libfixbuf */
    fbListener_t       *listener;
    fbConnSpec_t       *connspec;

    /* A count of sources associated with this base object */
    uint32_t            source_count;

    /* whether the source is in the process of being destroyed */
    unsigned            destroyed : 1;

    /* Whether the reading thread was started */
    unsigned            started   : 1;

    /* Whether the reading thread is currently running */
    unsigned            running   : 1;
};
/* typedef struct skIPFIXSourceBase_st skIPFIXSourceBase_t;  // above */


/*
 *    skIPFIXConnection_t holds data for "active" connections.  One of
 *    these is set as the context pointer for an fbCollector_t, for
 *    both network and file based collectors.
 *
 *    In the networking case, there is a separate skIPFIXConnection_t
 *    for each peer that connects, even when they are connecting on
 *    the same port (the same skIPFIXSource_t).  This permits
 *    maintaining seprate statistics per peer.
 */
struct skIPFIXConnection_st {
    skIPFIXSource_t    *source;
    ski_yafstats_t      prev_yafstats;
    /* Address of the host that contacted us */
    sk_sockaddr_t       peer_addr;
    size_t              peer_len;
    /* The observation domain id. */
    uint32_t            ob_domain;
};


/* FUNCTION DECLARATIONS */

/*    Functions in ipfixsource.c */

/**
 *    Return a pointer to the single information model.  If necessary
 *    create and initialize it.
 */
fbInfoModel_t *
skiInfoModel(
    void);

/**
 *    Free the single information model.
 */
void
skiInfoModelFree(
    void);

/**
 *    Free each session in the global session list, free the session
 *    list itself, and free the infomation model.
 */
void
skiTeardown(
    void);

/**
 *    Free the fbListener_t object on 'base' and remove 'base' from
 *    the global list of bases.
 */
void
ipfixSourceBaseFreeListener(
    skIPFIXSourceBase_t *base);


/*    Functions in ipfixsource.c */

/**
 *    Initialize an fbSession object that reads from either the
 *    network or from a file by adding to the session all internal
 *    templates that SiLK uses when reading IPFIX records.
 */
int
skiSessionInitReader(
    fbSession_t        *session,
    GError            **err);

/**
 *    Determine which names the information model uses for certain
 *    information elements and set a global variable accordingly.
 */
void
ski_nf9sampling_check_spec(
    void);

/**
 *    THREAD ENTRY POINT
 *
 *    The ipfix_reader() function is the main thread for listening to
 *    data from a single fbListener_t object.
 */
void *
ipfix_reader(
    void               *vsource_base);

int
ipfixSourceGetRecordFromFile(
    skIPFIXSource_t        *source,
    rwRec                  *ipfix_rec);


/* VARIABLES */

/*
 *    Provide an extern of `show_templates` (defined in probeconf.c)
 *    that is visible to skipfix.c.  Since fixbuf does not set the
 *    context variables for UDP probes, skipfix.c has no access to the
 *    probe or its flags and must use this global variable instead.
 */
extern int show_templates;

/**
 *    The names of IE 48, 49, 50 used by fixbuf-1.x (flowSamplerFOO)
 *    do not match the names specified by IANA (samplerFOO).  In
 *    fixbuf-2.x, the names match the IANA names.  This variable
 *    reflects which names fixbuf uses.  It is set by skiInitialize().
 *
 *    Variables and structure members in SiLK use the IANA name.
 */
extern uint32_t sampler_flags;


#ifdef __cplusplus
}
#endif
#endif /* _IPFIXSOURCE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
