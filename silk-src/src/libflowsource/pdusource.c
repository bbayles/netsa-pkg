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
**  Interface to pull a single flow from a NetFlow v5 PDU
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: pdusource.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/rwrec.h>
#include <silk/libflowsource.h>
#include <silk/redblack.h>
#include <silk/sklog.h>
#include "udpsource.h"
#include "v5pdu.h"

#ifdef PDUSOURCE_TRACE_LEVEL
#  define TRACEMSG_LEVEL PDUSOURCE_TRACE_LEVEL
#endif
#define TRACEMSG(lvl, msg) TRACEMSG_TO_TRACEMSGLVL(lvl, msg)
#include <silk/sktracemsg.h>



/* One more than UINT32_MAX. */
#define ROLLOVER32  INT64_C(0x100000000)

/* Number of milliseconds the calculated router boot time for a PDU
 * packet must differ from boot time calculated using the previous
 * packet in order to consider the router as having rebooted. */
#define ROUTER_BOOT_FUZZ 1000

/* Messages about invalid PDUs are grouped togther.  This enum lists
 * the types of bad PDUs we may encounter.  Keep this list in sync
 * with pdusrc_badpdu_msgs[] below. */
typedef enum pdusrc_badpdu_status_en {
    PDU_OK = 0,
    PDU_BAD_VERSION,
    PDU_ZERO_RECORDS,
    PDU_OVERFLOW_RECORDS,
    PDU_TRUNCATED_HEADER,
    PDU_TRUNCATED_DATA
} pdusrc_badpdu_status_t;

/* error messages for invalid PDUs.  Keep in sync with
 * pdusrc_badpdu_status_t */
static const char *pdusrc_badpdu_msgs[] = {
    "No Error",
    "not marked as version 5",
    "reporting zero records",
    "reporting more than " V5PDU_MAX_RECS_STR " records",
    "due to truncated header",
    "due to truncated data section"
};


/* Per-engine data structures for a Netflow v5 stream */
typedef struct pdu_engine_info_st {
    /* holds (engine_type << 8) | engine_id.  Used to distinguish
     * multiple PDU streams arriving on a single port. */
    uint16_t id;
    /* flow sequence number we expect to see on the next packet. */
    uint32_t flow_sequence;
    /* router boot time as milliseconds since the UNIX epoch */
    intmax_t router_boot;
    /* milliseconds since the router booted */
    intmax_t sysUptime;
    /* Timestamp of last PDU */
    sktime_t last_timestamp;
} pdu_engine_info_t;

struct skPDUSource_st {
    skFlowSourceStats_t     statistics;
    pthread_mutex_t         stats_mutex;

    const skpc_probe_t     *probe;
    const char             *name;
    skUDPSource_t          *source;

    /* Current pdu */
    const v5PDU            *pdu;

    /* Per-engine data */
    struct rbtree          *engine_info_tree;

    /* Per-engine data for most recent engine */
    pdu_engine_info_t      *engine_info;

    /* Number of consecutive bad PDUs we have seen---other than the
     * first */
    uint32_t                badpdu_consec;

    /* Number of recs left in current PDU */
    uint8_t                 count;

    /* What to log regarding bad or missing PDUs, as set by the
     * log-flags statement in sensor.conf */
    uint8_t                 logopt;

    /* Why the last PDU packet was rejected; used to reduce number of
     * "bad packet" log messages */
    pdusrc_badpdu_status_t  badpdu_status;

    unsigned                stopped : 1;
};
/* typedef struct skPDUSource_st skPDUSource_t;   // libflowsource.h */

#define COUNT_BAD_RECORD(source, pdu)                   \
    {                                                   \
        pthread_mutex_lock(&((source)->stats_mutex));   \
        (source)->statistics.badRecs++;                 \
        pthread_mutex_unlock(&((source)->stats_mutex)); \
    }


/*
 *  TIME VALUES IN THE NETFLOW V5 PDU
 *
 *  The naive ordering of events with respect to time in the router
 *  would be to collect the flows and generate the PDU.  Thus, one
 *  would expect:
 *
 *      flow.Start  <  flow.End  <  hdr.sysUptime
 *
 *  where all values are given as milliseconds since the router's
 *  interface was booted, and hdr.sysUptime is advertised as the
 *  "current" time.
 *
 *  However, since values are given as 32bit numbers, the values will
 *  roll-over after about 49.7 days.  If the values roll-over in the
 *  middle of writing the PDU, we will see one of these two
 *  conditions:
 *
 *      hdr.sysUptime  <<  flow.Start  <  flow.End
 *
 *      flow.End  <  hdr.sysUptime  <<  flow.Start
 *
 *  Thus, if flow.End less than flow.Start, we need to account for the
 *  roll-over when computing the flow's duration.
 *
 *  In practice, the PDU's header gets filled in before flows are
 *  added, making the hdr.sysUptime not have any true time ordering
 *  with respect to the flow.Start and flow.End, and we have seen
 *  cases in real NetFlow data where hdr.sysUptime is slightly less
 *  than flow.End:
 *
 *      flow.Start  <  hdr.sysUptime  <  flow.End
 *
 *  Moreover, some naive NetFlow PDU generators simply pin the
 *  hdr.sysUptime to zero, and don't account for rollover at all.
 *  This can make hdr.sysUptime much less than flow.Start.
 *
 *  In order to make the determination whether the flow.Start or
 *  hdr.sysUptime values have overflown their values and rolled-over,
 *  we look at the difference between them.  If the absolute value of
 *  the difference is greater than some very large maximum defined in
 *  maximumFlowTimeDeviation (currently 45 days), we assume that one
 *  of the two has rolled over, and adjust based on that assumption.
 */
static const intmax_t maximumFlowTimeDeviation =
    (intmax_t)45 * 24 * 3600 * 1000; /* 45 days */

/*
 *  SEQUENCE NUMBERS IN NETFLOW V5 PDU
 *
 *  When the sequence number we receive is greater than the value we
 *  were expecting but within the maximumSequenceDeviation window,
 *  assume that we have lost flow records:
 *
 *  (received - expected) < maximumSequenceDeviation ==> LOST PACKETS
 *
 *
 *  If the value we receive is less than the expected value but within
 *  the maximumSequenceLateArrival window, assume the received packet
 *  is arriving late.
 *
 *  (expected - received) < maximumSequenceLateArrival ==> LATE PACKET
 *
 *
 *  If the values vary wildly, first check whether either of the above
 *  relationships hold if we take sequence number roll-over into
 *  account.
 *
 *  Otherwise, assume something caused the sequence numbers to reset.
 *
 *  maximumSequenceDeviation is set assuming we receive 1k flows/sec
 *  and we lost 1 hour (3600 seconds) of flows
 *
 *  maximumSequenceLateArrival is set assuming we receive 1k flows/sec
 *  and the packet is 1 minute (60 seconds) late
 *
 *  (1k flows/sec is 33 pkts/sec if all packets hold 30 flows)
 */

static const int64_t maximumSequenceDeviation = INT64_C(1000) * INT64_C(3600);

static const int64_t maximumSequenceLateArrival = INT64_C(1000) * INT64_C(60);



/* FUNCTION DEFINITIONS */

/*
 *  cmp = pdu_engine_compare(a, b, context);
 *
 *    Used by red-black tree to compare two engine values.
 */
static int
pdu_engine_compare(
    const void         *va,
    const void         *vb,
    const void         *ctx)
{
    const pdu_engine_info_t *a = (const pdu_engine_info_t*)va;
    const pdu_engine_info_t *b = (const pdu_engine_info_t*)vb;
    SK_UNUSED_PARAM(ctx);

    if (a->id < b->id) {
        return -1;
    }
    return (a->id > b->id);
}


/*
 *  reject_if_true = pduSourceRejectPacket(sz, data, pdu_source);
 *
 *    Return TRUE if the bytes in 'data' do not represent a valid PDU
 *    packet.  'sz' is the length of the packet.  'pdu_source' is
 *    PDU source object.
 *
 *    Callback function passed to the skUDPSource_t collector.
 */
static int
pduSourceRejectPacket(
    ssize_t             data_len,
    void               *data,
    void               *v_pdusource)
{
    skPDUSource_t *source = (skPDUSource_t*)v_pdusource;
    v5PDU *pdu = (v5PDU*)data;
    pdusrc_badpdu_status_t pdu_status = PDU_OK;
    uint16_t count;

    if ((size_t)data_len < sizeof(v5Header)) {
        /* length cannot even hold a PDU header */
        pdu_status = PDU_TRUNCATED_HEADER;
    } else if (ntohs(pdu->hdr.version) != 5) {
        /* reject packet */
        pdu_status = PDU_BAD_VERSION;
    } else if (0 == (count = ntohs(pdu->hdr.count))) {
        pdu_status = PDU_ZERO_RECORDS;
    } else if (count > V5PDU_MAX_RECS) {
        pdu_status = PDU_OVERFLOW_RECORDS;
    } else if ((size_t)data_len < count * sizeof(v5Record)) {
        pdu_status = PDU_TRUNCATED_DATA;
    } else {
        /* current status is PDU_OK */
        if (PDU_OK == source->badpdu_status) {
            /* previous status was also PDU_OK; return */
            pthread_mutex_lock(&source->stats_mutex);
            ++source->statistics.procPkts;
            pthread_mutex_unlock(&source->stats_mutex);
            return 0;
        }
        pdu_status = PDU_OK;
    }

    /* when here, one or both of the current status and the previous
     * status are not PDU_OKAY */

    /* if status is same as before, increment counters and return */
    if (pdu_status == source->badpdu_status) {
        ++source->badpdu_consec;
        pthread_mutex_lock(&source->stats_mutex);
        ++source->statistics.procPkts;
        ++source->statistics.badPkts;
        pthread_mutex_unlock(&source->stats_mutex);
        return 1;
    }

    /* status has changed; we need to write a log message about the
     * previous status unless it was PDU_OK */
    if (PDU_OK != source->badpdu_status) {
        /* note, we have already logged about 1 bad packet */
        if (source->badpdu_consec) {
            NOTICEMSG(("'%s': Rejected %" PRIu32 " additional PDU record%s %s"),
                      source->name, source->badpdu_consec,
                      ((source->badpdu_consec == 1) ? "" : "s"),
                      pdusrc_badpdu_msgs[source->badpdu_status]);
        }

        if (PDU_OK == pdu_status) {
            source->badpdu_status = PDU_OK;
            pthread_mutex_lock(&source->stats_mutex);
            ++source->statistics.procPkts;
            pthread_mutex_unlock(&source->stats_mutex);
            return 0;
        }
    }

    INFOMSG("'%s': Rejected PDU record %s",
            source->name, pdusrc_badpdu_msgs[pdu_status]);

    /* Since we logged about this packet, no need to count it */
    source->badpdu_consec = 0;
    source->badpdu_status = pdu_status;
    pthread_mutex_lock(&source->stats_mutex);
    ++source->statistics.procPkts;
    ++source->statistics.badPkts;
    pthread_mutex_unlock(&source->stats_mutex);
    return 1;
}


skPDUSource_t *
skPDUSourceCreate(
    const skpc_probe_t         *probe,
    const skFlowSourceParams_t *params)
{
    skPDUSource_t *source;

    assert(probe);

    /* Create and initialize source */
    source = (skPDUSource_t*)calloc(1, sizeof(*source));
    if (source == NULL) {
        goto ERROR;
    }
    source->probe = probe;
    source->name = skpcProbeGetName(probe);
    source->logopt = skpcProbeGetLogFlags(probe);

    source->engine_info_tree = rbinit(pdu_engine_compare, NULL);
    if (source->engine_info_tree == NULL) {
        goto ERROR;
    }

    source->source = skUDPSourceCreate(probe, params, V5PDU_LEN,
                                       &pduSourceRejectPacket, source);
    if (NULL == source->source) {
        goto ERROR;
    }

    pthread_mutex_init(&source->stats_mutex, NULL);

    return source;

  ERROR:
    if (source) {
        if (source->engine_info_tree) {
            rbdestroy(source->engine_info_tree);
        }
        free(source);
    }
    return NULL;
}


void
skPDUSourceStop(
    skPDUSource_t      *source)
{
    source->stopped = 1;
    skUDPSourceStop(source->source);
}


void
skPDUSourceDestroy(
    skPDUSource_t      *source)
{
    RBLIST *iter;
    pdu_engine_info_t *engine_info;

    if (!source) {
        return;
    }
    if (!source->stopped) {
        skPDUSourceStop(source);
    }
    skUDPSourceDestroy(source->source);
    pthread_mutex_destroy(&source->stats_mutex);
    iter = rbopenlist(source->engine_info_tree);
    if (iter != NULL) {
        while ((engine_info = (pdu_engine_info_t *)rbreadlist(iter))) {
            free(engine_info);
        }
        rbcloselist(iter);
    }
    rbdestroy(source->engine_info_tree);
    free(source);
}


/*
 *  pdu_packet = pduSourceNextPkt(source);
 *
 *    Get the next PDU packet to process.
 *
 *    This function processes the packet's header, sets the timestamp
 *    for the flows in the packet, and checks the flow sequence
 *    numbers.
 */
static const v5PDU *
pduSourceNextPkt(
    skPDUSource_t      *source)
{
    /* For log messages that report out of sequence flow records,
     * these macros hold the start of the format and the start of the
     * argument list  */
#define PDU_OOS_FORMAT(diff_is_neg)                                     \
    "'%s': Out-of-sequence packet:"                                     \
        " expecting %" PRIu32 ", received %" PRIu32                     \
        ", difference " diff_is_neg "%" PRId64 ", elapsed %f sec"       \
        ", engine %u.%u;"
#define PDU_OOS_ARGS(diff_value)                                \
    source->name,                                               \
        engine->flow_sequence, flow_sequence, diff_value,       \
        ((float)(now - engine->last_timestamp) / 1000.0),       \
        engine->id >> 8, engine->id & 0xFF

    const v5PDU       *pdu;
    intmax_t           now;
    uint16_t           count;
    uint32_t           flow_sequence;
    intmax_t           router_boot;
    intmax_t           sysUptime;
    int64_t            seq_differ;
    uint64_t           allrecs;
    pdu_engine_info_t *engine;
    pdu_engine_info_t  target;

    assert(source != NULL);

    pdu = (v5PDU *)skUDPSourceNext(source->source);
    if (pdu == NULL) {
        /* if we saw any bad PDUs, print message before returning */
        if (source->badpdu_status != PDU_OK
            && source->badpdu_consec)
        {
            NOTICEMSG(("'%s': Rejected %" PRIu32 " additional PDU record%s %s"),
                      source->name, source->badpdu_consec,
                      ((source->badpdu_consec == 1) ? "" : "s"),
                      pdusrc_badpdu_msgs[source->badpdu_status]);
            source->badpdu_status = PDU_OK;
        }
        return NULL;
    }

    /* number of flow records in this packet */
    count = ntohs(pdu->hdr.count);

    /* get the sequence number */
    flow_sequence = ntohl(pdu->hdr.flow_sequence);

    /* use the PDU header to get the "current" time as
     * milliseconds since the UNIX epoch. */
    now = ((intmax_t)1000 * ntohl(pdu->hdr.unix_secs)
           + (ntohl(pdu->hdr.unix_nsecs) / 1000000));

    /* get sysUptime, which is the "current" time in milliseconds
     * since the export device booted */
    sysUptime = ntohl(pdu->hdr.SysUptime);

    /* subtract sysUptime from current-time to get router boot time as
     * milliseconds since UNIX epoch */
    router_boot = now - sysUptime;

    /* Determine the current engine */
    target.id = ((uint16_t)pdu->hdr.engine_type << 8) | pdu->hdr.engine_id;
    engine = source->engine_info;
    if (engine == NULL || engine->id != target.id) {
        /* Current engine info must be updated */
        engine = (pdu_engine_info_t*)rbfind(&target, source->engine_info_tree);
        if (engine == NULL) {
            /* There's no entry for this engine.  Add one */
            TRACEMSG(1, ("'%s': New engine %u.%u noticed",
                         source->name, target.id >> 8, target.id & 0xFF));
            engine = (pdu_engine_info_t*)calloc(1, sizeof(pdu_engine_info_t));
            if (engine == NULL) {
                ERRMSG(("'%s': Memory allocation error allocating"
                        " PDU engine %u.%u.  Aborting."),
                       source->name, target.id >> 8, target.id & 0xFF);
                exit(EXIT_FAILURE);
            }
            engine->id = target.id;
            engine->router_boot = router_boot;
            engine->sysUptime = sysUptime;
            engine->flow_sequence = flow_sequence;
            rbsearch(engine, source->engine_info_tree);
        }
        source->engine_info = engine;
    }

    /* check for router reboot.  Determine whether the absolute
     * value of
     *   (router_boot - engine->router_boot)
     * is greater than ROUTER_BOOT_FUZZ.  If so, assume router
     * rebooted and reset the engine values. */
    if (((router_boot > engine->router_boot)
         && ((router_boot - engine->router_boot) > ROUTER_BOOT_FUZZ))
        || ((router_boot - engine->router_boot) < -ROUTER_BOOT_FUZZ))
    {
        if (source->logopt & SOURCE_LOG_TIMESTAMPS) {
            INFOMSG(("'%s': Router reboot for engine %u.%u."
                     " Last time %" PRIdMAX ", Current time %" PRIdMAX),
                    source->name, engine->id >> 8, engine->id & 0xFF,
                    engine->router_boot, router_boot);
        } else {
            DEBUGMSG(("'%s': Router reboot for engine %u.%u."
                      " Last time %" PRIdMAX ", Current time %" PRIdMAX),
                     source->name, engine->id >> 8, engine->id & 0xFF,
                     engine->router_boot, router_boot);
        }
        engine->flow_sequence = flow_sequence;
    }
    engine->router_boot = router_boot;
    engine->sysUptime = sysUptime;

    /* handle sequence numbers */
    if (flow_sequence == engine->flow_sequence) {
        /* This packet is in sequence.  Update the next expected seq */
        engine->flow_sequence = flow_sequence + count;

    } else if (flow_sequence > engine->flow_sequence) {
        /* received is greater than expected */
        seq_differ = (flow_sequence - engine->flow_sequence);

        if (seq_differ < maximumSequenceDeviation) {
            /* assume dropped packets; increase the missing flow
             * record count, and update the expected sequence
             * number */
            pthread_mutex_lock(&source->stats_mutex);
            source->statistics.missingRecs += seq_differ;
            if (source->logopt & SOURCE_LOG_MISSING) {
                allrecs = (source->statistics.goodRecs +
                           source->statistics.badRecs +
                           source->statistics.missingRecs);
                INFOMSG((PDU_OOS_FORMAT("")
                         " adding to missing records"
                         " %" PRId64 "/%" PRIu64 " == %7.4g%%"),
                        PDU_OOS_ARGS(seq_differ),
                        source->statistics.missingRecs, allrecs,
                        ((float)source->statistics.missingRecs
                         / (float)allrecs * 100.0));
            }
            pthread_mutex_unlock(&source->stats_mutex);

            /* Update the next expected seq */
            engine->flow_sequence = flow_sequence + count;

        } else if (seq_differ > (ROLLOVER32 - maximumSequenceLateArrival)) {
            /* assume expected has rolled-over and we received a
             * packet that was generated before the roll-over and is
             * arriving late; subtract from the missing record
             * count and do NOT change expected value */
            pthread_mutex_lock(&source->stats_mutex);
            source->statistics.missingRecs -= count;
            if (source->statistics.missingRecs < 0) {
                source->statistics.missingRecs = 0;
            }
            pthread_mutex_unlock(&source->stats_mutex);
            if (source->logopt & SOURCE_LOG_MISSING) {
                INFOMSG((PDU_OOS_FORMAT("")
                         " treating %u flows as arriving late after roll-over"
                         " (difference without roll-over %" PRId64 ")"),
                        PDU_OOS_ARGS(seq_differ), count,
                        seq_differ - ROLLOVER32);
            }

        } else {
            /* assume something caused the sequence numbers to change
             * radically; reset the expected sequence number and do
             * NOT add to missing record count */
            if (source->logopt & SOURCE_LOG_MISSING) {
                INFOMSG((PDU_OOS_FORMAT("")
                         " resetting sequence due to large difference;"
                         " next expected packet %" PRIu32),
                        PDU_OOS_ARGS(seq_differ), flow_sequence + count);
            }

            /* Update the next expected seq */
            engine->flow_sequence = flow_sequence + count;
        }

    } else {
        /* expected is greater than received */
        seq_differ = (engine->flow_sequence - flow_sequence);

        if (seq_differ > (ROLLOVER32 - maximumSequenceDeviation)) {
            /* assume received has rolled over but expected has not
             * and there are dropped packets; increase the missing
             * flow record count and update the expected sequence
             * number */
            pthread_mutex_lock(&source->stats_mutex);
            source->statistics.missingRecs += ROLLOVER32 - seq_differ;
            if (source->logopt & SOURCE_LOG_MISSING) {
                allrecs = (source->statistics.goodRecs +
                           source->statistics.badRecs +
                           source->statistics.missingRecs);
                INFOMSG((PDU_OOS_FORMAT("-")
                         " treating as missing packets during roll-over"
                         " (difference without roll-over %" PRId64 ");"
                         " adding to missing records"
                         " %" PRId64 "/%" PRIu64 " == %7.4g%%"),
                        PDU_OOS_ARGS(seq_differ), ROLLOVER32 - seq_differ,
                        source->statistics.missingRecs, allrecs,
                        ((float)source->statistics.missingRecs /
                         (float)allrecs * 100.0));
            }
            pthread_mutex_unlock(&source->stats_mutex);

            /* Update the next expected seq */
            engine->flow_sequence = flow_sequence + count;

        } else if (seq_differ < maximumSequenceLateArrival) {
            /* assume we received a packet that is arriving late; log
             * the fact and subtract from the missing record count */
            pthread_mutex_lock(&source->stats_mutex);
            source->statistics.missingRecs -= count;
            if (source->statistics.missingRecs < 0) {
                source->statistics.missingRecs = 0;
            }
            pthread_mutex_unlock(&source->stats_mutex);
            if (source->logopt & SOURCE_LOG_MISSING) {
                INFOMSG((PDU_OOS_FORMAT("-")
                         " treating %u flows as arriving late"),
                        PDU_OOS_ARGS(seq_differ), count);
            }

        } else {
            /* assume something caused the sequence numbers to change
             * radically; reset the expected sequence number and do
             * NOT add to missing record count */
            if (source->logopt & SOURCE_LOG_MISSING) {
                INFOMSG((PDU_OOS_FORMAT("-")
                         " resetting sequence due to large difference;"
                         " next expected packet %" PRIu32),
                        PDU_OOS_ARGS(seq_differ), flow_sequence + count);
            }

            /* Update the next expected seq */
            engine->flow_sequence = flow_sequence + count;
        }
    }

    engine->last_timestamp = (sktime_t)now;
    return pdu;
}


/*
 *  nf5_record = pduSourceGetNextRec(source);
 *
 *    Get the next NetFlow V5 record to process.
 */
static const v5Record *
pduSourceGetNextRec(
    skPDUSource_t      *source)
{
    assert(source != NULL);

    /* Infloop; exit by return only */
    for (;;) {
        const v5Record *v5RPtr;
        intmax_t  difference;

        if (source->stopped) {
            return NULL;
        }

        /* If we need a PDU, get a new one, otherwise we are not
         * finished with the last. */
        if (source->count == 0) {
            source->pdu = pduSourceNextPkt(source);
            if (source->pdu == NULL) {
                return NULL;
            }
            source->count = ntohs(source->pdu->hdr.count);
        }

        /* Get next record, and decrement counter*/
        v5RPtr = &source->pdu->data[ntohs(source->pdu->hdr.count)
                                    - source->count--];

        /* Check for zero packets or bytes.  No need for byteswapping
         * when checking zero. */
        if (v5RPtr->dPkts == 0 || v5RPtr->dOctets == 0) {
            if (source->logopt & SOURCE_LOG_BAD) {
                NOTICEMSG("'%s': Netflow record has zero packets or bytes",
                          source->name);
            }
            COUNT_BAD_RECORD(source, source->pdu);
            continue;
        }

        /* Check to see if more packets them bytes. */
        if (ntohl(v5RPtr->dPkts) > ntohl(v5RPtr->dOctets)) {
            if (source->logopt & SOURCE_LOG_BAD) {
                NOTICEMSG("'%s': Netflow record has more packets them bytes",
                          source->name);
            }
            COUNT_BAD_RECORD(source, source->pdu);
            continue;
        }

        /* Check to see if the First and Last timestamps for the flow
         * record are reasonable, accounting for rollover.  If the
         * absolute value of the difference is greater than
         * maximumFlowTimeDeviation, we assume it has rolled over. */
        difference = (intmax_t)ntohl(v5RPtr->Last) - ntohl(v5RPtr->First);
        if ((difference > maximumFlowTimeDeviation)
            || ((difference < 0)
                && (difference > (-maximumFlowTimeDeviation))))
        {
            if (source->logopt & SOURCE_LOG_BAD) {
                NOTICEMSG(("'%s': Netflow record has earlier end time"
                           " than start time"), source->name);
            }
            COUNT_BAD_RECORD(source, source->pdu);
            continue;
        }

        /* Check for bogosities in how the ICMP type/code are set.  It
         * should be in dest port, but sometimes it is backwards in
         * src port. */
        if (v5RPtr->prot == 1 &&  /* ICMP */
            v5RPtr->dstport == 0) /* No byteswapping for check against 0 */
        {
            uint32_t *ports = (uint32_t *)&v5RPtr->srcport;
            *ports = BSWAP32(*ports); /* This will swap src into dest,
                                         while byteswapping. */
        }

        pthread_mutex_lock(&source->stats_mutex);
        source->statistics.goodRecs++;
        pthread_mutex_unlock(&source->stats_mutex);

        return v5RPtr;
    }
}


int
skPDUSourceGetGeneric(
    skPDUSource_t      *source,
    rwRec              *rwrec)
{
    const char *rollover_first;
    const char *rollover_last = "";
    const v5Record *v5RPtr;
    intmax_t v5_first, v5_last;
    intmax_t sTime;
    intmax_t difference;

    v5RPtr = pduSourceGetNextRec(source);
    if (v5RPtr == NULL) {
        return -1;
    }

    /* v5_first and v5_last are milliseconds since the router booted.
     * To get UNIX epoch milliseconds, add the router's boot time. */
    v5_first = ntohl(v5RPtr->First);
    v5_last = ntohl(v5RPtr->Last);

    if (v5_first > v5_last) {
        /* End has rolled over, while start has not.  Adjust end by
         * 2^32 msecs in order to allow us to subtract start from end
         * and get a correct value for the duration. */
        v5_last += ROLLOVER32;
        rollover_last = ", assume Last rollover";
    }

    /* Check to see if the difference between the 32bit start time and
     * the sysUptime is overly large.  If it is, one of the two has
     * more than likely rolled over.  We need to adjust based on
     * this. */
    difference = source->engine_info->sysUptime - v5_first;
    if (difference > maximumFlowTimeDeviation) {
        /* sTime rollover */
        sTime = (source->engine_info->router_boot + v5_first + ROLLOVER32);
        rollover_first = ", assume First rollover";
    } else if (difference < (-maximumFlowTimeDeviation)) {
        /* sysUptime rollover */
        sTime = (source->engine_info->router_boot + v5_first - ROLLOVER32);
        rollover_first = ", assume Uptime rollover";
    } else {
        sTime = v5_first + source->engine_info->router_boot;
        rollover_first = "";
    }

    if (source->logopt & SOURCE_LOG_TIMESTAMPS) {
        INFOMSG(("'%s': Router boot (ms)=%" PRIdMAX ", Uptime=%" PRIdMAX
                 ", First=%" PRIuMAX ", Last=%" PRIu32 "%s%s"),
                source->name, source->engine_info->router_boot,
                source->engine_info->sysUptime, v5_first, ntohl(v5RPtr->Last),
                rollover_first, rollover_last);
    }

    RWREC_CLEAR(rwrec);

    /* Convert NetFlow v5 to SiLK */
    rwRecSetSIPv4(rwrec, ntohl(v5RPtr->srcaddr));
    rwRecSetDIPv4(rwrec, ntohl(v5RPtr->dstaddr));
    rwRecSetSPort(rwrec, ntohs(v5RPtr->srcport));
    rwRecSetDPort(rwrec, ntohs(v5RPtr->dstport));
    rwRecSetProto(rwrec, v5RPtr->prot);
    rwRecSetFlags(rwrec, v5RPtr->tcp_flags);
    rwRecSetInput(rwrec, ntohs(v5RPtr->input));
    rwRecSetOutput(rwrec, ntohs(v5RPtr->output));
    rwRecSetNhIPv4(rwrec, ntohl(v5RPtr->nexthop));
    rwRecSetStartTime(rwrec, (sktime_t)sTime);
    rwRecSetPkts(rwrec, ntohl(v5RPtr->dPkts));
    rwRecSetBytes(rwrec, ntohl(v5RPtr->dOctets));
    rwRecSetElapsed(rwrec, (uint32_t)(v5_last - v5_first));
    rwRecSetRestFlags(rwrec, 0);
    rwRecSetTcpState(rwrec, SK_TCPSTATE_NO_INFO);

    return 0;
}


/* Log statistics associated with a PDU source. */
void
skPDUSourceLogStats(
    skPDUSource_t      *source)
{
    pthread_mutex_lock(&source->stats_mutex);
    FLOWSOURCE_STATS_INFOMSG(source->name, &(source->statistics));
    pthread_mutex_unlock(&source->stats_mutex);
}

/* Log statistics associated with a PDU source, and then clear the
 * statistics. */
void
skPDUSourceLogStatsAndClear(
    skPDUSource_t      *source)
{
    pthread_mutex_lock(&source->stats_mutex);
    FLOWSOURCE_STATS_INFOMSG(source->name, &(source->statistics));
    memset(&source->statistics, 0, sizeof(source->statistics));
    pthread_mutex_unlock(&source->stats_mutex);
}

/* Clear out current statistics */
void
skPDUSourceClearStats(
    skPDUSource_t      *source)
{
    pthread_mutex_lock(&source->stats_mutex);
    memset(&source->statistics, 0, sizeof(source->statistics));
    pthread_mutex_unlock(&source->stats_mutex);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
