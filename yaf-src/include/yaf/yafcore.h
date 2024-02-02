/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *
 *  yafcore.h
 *  YAF core I/O routines
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

/**
 * @mainpage YAF Core Library
 *
 * @section Introduction
 *
 * The YAF Core Library (libyaf) provides YAF file and stream I/O primitives
 * for reading and writing YAF bidirectional flow data in IPFIX files and via
 * the IPFIX protocol. It also provides packet decode, fragment reassembly,
 * and flow generation routines for YAF.
 *
 * yafcore.h provides the YAF I/O interface. The packet decode interface is
 * defined in decode.h. The fragment reassembly interface is defined in
 * yafrag.h, and the flow generator interface is defined in yaftab.h.
 *
 * picq.h defines a generic pickable queue used in fragment reassembly and
 * flow generation.
 *
 * @section Building
 *
 * The YAF Core Library is automatically built and installed as part of the
 * YAF installation process.
 *
 * @section Copyright
 * YAF is copyright 2006-2023 Carnegie Mellon University, and is released
 * under the GNU General Public License.  See the COPYING file in the
 * distribution for details.
 *
 * YAF was developed at the CERT Network Situational Awareness Group by
 * Brian Trammell and the CERT Network Situational Awareness Group Engineering
 * Team.
 *
 */

/**
 * @file
 *
 * YAF Core Library. Defines API for reading and writing YAF files, and the
 * yfFlow_t data structures.
 */

#ifndef _YAF_CORE_H_
#define _YAF_CORE_H_

#include <yaf/autoinc.h>
#include <fixbuf/public.h>
#include <stdlib.h>
#include <math.h>
/**
 * This is the CERT Private Enterprise Number (PEN) assigned by
 * IANA, used to define our enterprise data elements to extend
 * IPFIX RFC 5103 data model
 */
#define CERT_PEN    6871

/**
 * GError domain for YAF errors. All YAF errors belong to this domain.
 * In addition, YAF core library routines can return libfixbuf errors if
 * reading or writing fails.
 */
#define YAF_ERROR_DOMAIN        (g_quark_from_string("certYAFError"))
/** A YAF file header was malformed. The file is probably not a YAF file. */
#define YAF_ERROR_HEADER        1
/** Illegal argument error. */
#define YAF_ERROR_ARGUMENT      2
/** General I/O error */
#define YAF_ERROR_IO            3
/** YAF could not accept IPFIX input due to missing fields. */
#define YAF_ERROR_IPFIX         4
/** Requested feature is not available */
#define YAF_ERROR_IMPL          5
/** Internal error occured (aka a bug)*/
#define YAF_ERROR_INTERNAL      6
/** Hard program limit reached */
#define YAF_ERROR_LIMIT         7
/** End of file */
#define YAF_ERROR_EOF           8
/** Internal alignment error */
#define YAF_ERROR_ALIGNMENT         9
/** Packet payload processing error */
#define YAF_ERROR_PACKET_PAYLOAD    10



/**
 * Pseudo end reason for flows still active during collection.
 * Not valid on disk.
 */
#define YAF_FLOW_ACTIVE         0
/** Flow ended due to idle timeout. */
#define YAF_END_IDLE            1
/** Flow ended due to active timeout. */
#define YAF_END_ACTIVE          2
/** Flow ended due to FIN or RST close. */
#define YAF_END_CLOSED          3
/** Flow ended due to YAF shutdown. */
#define YAF_END_FORCED          4
/** Flow flushed due to YAF resource exhaustion. */
#define YAF_END_RESOURCE        5
/** Flow flushed due to udp-uniflow on all or selected ports.*/
#define YAF_END_UDPFORCE        0x1F
/** Flow reason mask */
#define YAF_END_MASK            0x7F
/** SiLK mode flow reason flag - flow was created after active termination */
#define YAF_ENDF_ISCONT         0x80

/** Attribute bit flag: Flow has same size packets in this direction */
#define YAF_SAME_SIZE           0x01
/** Attribute bit flag: Flow was processed out of sequence */
#define YAF_OUT_OF_SEQUENCE     0x02
/** Attribute bit flag: Flow had MP_CAPABLE TCP Option */
#define YAF_MP_CAPABLE          0x04
/** Attribute bit flag: Flow contained packets that were fragmented */
#define YAF_FRAGMENTS           0x08
/** Flow contains partial fragments */
#define YAF_PARTIAL_FRAGS       0x10
/** Flow has fragments that have reached active timeout */
#define YAF_FRAG_ACTIVE         0x03
/** Flow has fragments that have reached passive timeout */
#define YAF_FRAG_PASSIVE        0x04

/** IP protocol identifier for ICMP */
#define YAF_IP_ICMP             1
/** IP protocol identifier for TCP */
#define YAF_IP_TCP              6
/** IP protocol identifier for UDP */
#define YAF_IP_UDP              17

/** This is the size of the packet to store away for use primarily in
 * passive OS fingerprinting, this value is only used if application
 * labeling is enabled */
#define YFP_IPTCPHEADER_SIZE    128
/** length of Ethernet MAC Address */
#define ETHERNET_MAC_ADDR_LENGTH 6
/** maximum number of hooks (plugins) allowed at one time */
#define YAF_MAX_HOOKS            4

/** this is the maximum amount of data that the plugins may export in sum total
 */
#define YAF_HOOKS_MAX_EXPORT    1500
/** Maximum Number of Packet Boundaries to keep around per payload */
#define YAF_MAX_PKT_BOUNDARY    25
/** Maximum length of PCAP output file - 5MB */
#define YAF_PCAP_MAX            5000000
/** Maximum number of labels we're going to keep around */
#define YAF_MAX_MPLS_LABELS     3

/** Upper bound of a packet's payload octets to be a "small packet" in the
 *  detailed flow-stats.  Payload octets must be less than this value. */
#define YAF_SMALL_PKT_BOUND     60
/** Lower bound of a packet's payload octets to be a "large packet" in the
 *  detailed flow-stats.  Payload octets must be greater than this value. */
#define YAF_LARGE_PKT_BOUND     225

/**
 * A YAF flow key.
 * Contains a flow's five-tuple; used at runtime in the flow table.
 */
typedef struct yfFlowKey_st {
    /** Source transport port */
    uint16_t   sp;
    /** Destination transport port. Contains type and code for ICMP */
    uint16_t   dp;
    /** IP protocol */
    uint8_t    proto;
    /** IP Version */
    uint8_t    version;
    /** VLAN Tag - only fwd */
    uint16_t   vlanId;
    /** Type of Service/Traffic Class */
    uint8_t    tos;
    /** for DAG cards need to record the interface, may only be seeing
     * unidirectional flows on each interface, and want to record what
     * direction that is happening on */
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    uint8_t    netIf;
#endif
    /** Layer 2 Id */
    uint32_t   layer2Id;
    /** IP address two-tuple union */
    union {
        struct {
            /** Source IPv4 address */
            uint32_t   sip;
            /** Destination IPv4 address */
            uint32_t   dip;
        } v4;
        struct {
            /** Source IPv6 address */
            uint8_t   sip[16];
            /** Destination IPv6 address */
            uint8_t   dip[16];
        } v6;
    } addr;
} yfFlowKey_t;

/**
 * yaf flow statistics
 */
typedef struct yfFlowStats_st {
    /** to calculate inter-packet delay */
    uint64_t   iaarray[10];
    /** to calculate distribution of packet payload size */
    uint32_t   pktsize[10];
    /** total amount of payload data */
    uint64_t   payoct;
    /** used to calculate interarrival time */
    uint64_t   ltime;
    /** Number of urgent packets */
    uint32_t   tcpurgct;
    /** Number of packets with fewer than YAF_SMALL_PKT_BOUND bytes of data */
    uint32_t   smallpktct;
    /** total number of non empty pkts */
    uint32_t   nonemptypktct;
    /** Number of packets with more than YAF_LARGE_PKT_BOUND bytes of data */
    uint32_t   largepktct;
    /** average interarrival time in milliseconds */
    uint32_t   aitime;
    /** payload length of first non-empty pkt */
    uint32_t   firstpktsize;
    /** largest pkt size */
    uint32_t   maxpktsize;
} yfFlowStats_t;

/**
 * A YAF uniflow value. Contains directional packet header fields and counters;
 * two of these are used to build a biflow.
 */
typedef struct yfFlowVal_st {
    /** Octet count */
    uint64_t        oct;
    /** Packet count */
    uint64_t        pkt;
#if YAF_ENABLE_PAYLOAD
    /** Payload length */
    uint32_t        paylen;
    /** Captured payload buffer */
    uint8_t        *payload;
    /** Offsets into the payload on packet boundaries */
    size_t         *paybounds;
#endif /* if YAF_ENABLE_PAYLOAD */
    /** Initial TCP sequence number */
    uint32_t        isn;
    /** Last TCP sequence number */
    uint32_t        lsn;
    /** First Packet Size - to determine whether to turn on fixed size flag*/
    uint16_t        first_pkt_size;
    /** flowAttributes */
    uint16_t        attributes;
    /** Initial TCP flags */
    uint8_t         iflags;
    /** Union of remaining TCP flags */
    uint8_t         uflags;
    /** packets with payload - don't care if this wraps. */
    uint8_t         appkt;
    /** VLAN TAG (also in key, but want to record both sides) */
    uint16_t        vlan;
#if YAF_ENABLE_SEPARATE_INTERFACES
    uint8_t         netIf;
#endif
#if YAF_ENABLE_ENTROPY
    /** Entropy value */
    uint8_t         entropy;
    /** Entropy padding */
    uint8_t         entpad[7];
#endif /* if YAF_ENABLE_ENTROPY */
#if YAF_ENABLE_P0F
    /** passive OS finger printing OS Name */
    const char     *osname;
    /** passive OS finger printing OS version */
    const char     *osver;
    /** required for libp0f */
    uint8_t         fuzzyMatch;
    /** required for libp0f */
    uint8_t         fuzzyPad[7];
    /** p0f OS FingerPrint */
    char           *osFingerPrint;
#endif /* if YAF_ENABLE_P0F */
#if YAF_ENABLE_FPEXPORT
    /** length of firstPacket Handshake header */
    uint32_t        firstPacketLen;
    /** length of secondPacket Handshake header */
    uint32_t        secondPacketLen;
    /** TCP Handshake header from first TCP packet */
    uint8_t        *firstPacket;
    /** TCP Handshake header from second TCP packet */
    uint8_t        *secondPacket;
#endif /* if YAF_ENABLE_FPEXPORT */
    /** yaf flow statistics */
    yfFlowStats_t  *stats;
} yfFlowVal_t;

#if YAF_MPLS
typedef struct yfMPLSNode_st {
    /** Flow Key Hash Tables */
    GHashTable  *tab;
    /** TOP 3 MPLS Labels */
    uint32_t     mpls_label[YAF_MAX_MPLS_LABELS];
    /** number of mpls nodes hash table */
    int          tab_count;
} yfMPLSNode_t;
#endif /* if YAF_MPLS */

typedef struct yfMPTCPFlow_st {
    /** initial data seq no. */
    uint64_t   idsn;
    /** receiver token */
    uint32_t   token;
    /** max segment size */
    uint16_t   mss;
    /** addr id */
    uint8_t    addrid;
    /** hash_flags */
    uint8_t    flags;
} yfMPTCPFlow_t;


/**
 * A YAF flow. Joins a flow key with forward and reverse flow values in time.
 *
 * @note if you edit the layout of this structure, you must make a
 * corresponding edit of the yfFlowIPv4_t structure in yaftab.c
 */
typedef struct yfFlow_st {
    /** Flow start time in epoch milliseconds */
    uint64_t        stime;
    /** Flow end time in epoch milliseconds */
    uint64_t        etime;
#ifdef YAF_ENABLE_HOOKS
    /**
     * Hook flow context array.  Used by extensions to store per-flow state.
     * An array of ptr's - one per hook.
     */
    void           *hfctx[YAF_MAX_HOOKS];
#endif
    /*
     * Reverse flow delta start time in milliseconds. Equivalent to initial
     * packet round-trip time; useful for decomposing biflows into uniflows.
     */
    int32_t         rdtime;
#if YAF_ENABLE_APPLABEL
    /** Application label for this flow */
    uint16_t        appLabel;
#endif
#if YAF_ENABLE_NDPI
    uint16_t        ndpi_master;
    uint16_t        ndpi_sub;
#endif
    /** Flow termination reason (YAF_END_ macros, per IPFIX standard) */
    uint8_t         reason;
    /** Keep track of number of pcap files for this flow */
    uint8_t         pcap_serial;
    /** src Mac Address */
    uint8_t         sourceMacAddr[ETHERNET_MAC_ADDR_LENGTH];
    /** destination Mac Address */
    uint8_t         destinationMacAddr[ETHERNET_MAC_ADDR_LENGTH];
    /** Pcap File "ID" so we know when to make entries in metadata file */
    uint8_t         pcap_file_no;
    /** non empty packet directions, 1, or 0 **/
    uint8_t         pktdir;
    /** reverse ToS  (fwd in flowKey) */
    uint8_t         rtos;
    /** Pcap File Ptr */
    pcap_dumper_t  *pcap;
#if YAF_MPLS
    /** MPLS Node that contains this flow */
    yfMPLSNode_t   *mpls;
#endif
    /** MPTCP Flow */
    yfMPTCPFlow_t   mptcp;
    /** Forward value */
    yfFlowVal_t     val;
    /** Reverse value */
    yfFlowVal_t     rval;
    /** Flow key */
    yfFlowKey_t     key;
} yfFlow_t;

/**
 * yfAlignmentCheck
 *
 * This is a purely internal diagnostic function.  It checks the alignment
 * of the internal data structures that are used with fixbuf and causes
 * the program to abort if there is an alignment issue.
 *
 */
void
yfAlignmentCheck(
    void);


/**
 * Prepare a static flow buffer for use with yaf_flow_read(). Call this before
 * the first yaf_flow_read() call; subsequent reads do not need initialization.
 * This is used to prepare storage for payload information.
 *
 * @param flow  a yfFlow_t to initialize
 */
void
yfFlowPrepare(
    yfFlow_t  *flow);

/**
 * Clean up after a static flow buffer prepared by yfFlowPrepare.
 * This is used to free storage for payload information.
 *
 * @param flow  a yfFlow_t to free
 */
void
yfFlowCleanup(
    yfFlow_t  *flow);

/**
 * Get an IPFIX message buffer for writing YAF flows to a named file.
 * Sets the observation domain of the buffer to the given value.
 *
 * @param path      Name of the file to write to, or - for stdout.
 * @param domain    observation domain
 * @param export_meta Export Template/IE Metadata
 * @param err       an error description, set on failure.
 * @return fBuf_t   a new writer, or a reused writer, for writing on the
 *                  given open file. NULL on failure.
 */
fBuf_t *
yfWriterForFile(
    const char  *path,
    uint32_t     domain,
    gboolean     export_meta,
    GError     **err);

/**
 * Get an IPFIX message buffer for writing YAF flows to an open file pointer.
 * Sets the observation domain of the buffer to the given value. Note that this
 * is intended for use with Airframe MIO based applications; non-MIO
 * applications writing YAF IPFIX files should use yfWriterForFile instead.
 *
 * @param fp    File pointer to open file to write to.
 * @param domain observation domain
 * @param export_meta Export Template/IE Metadata
 * @param err an error description, set on failure.
 * @return fBuf_t   a new writer, or a reused writer, for writing on the
 *                  given open file. NULL on failure.
 */
fBuf_t *
yfWriterForFP(
    FILE      *fp,
    uint32_t   domain,
    gboolean   export_meta,
    GError   **err);

/**
 * Get an IPFIX message buffer for writing YAF flows to a socket.
 *
 * @param spec  fixbuf connection specifier for remote end of socket.
 * @param domain observation domain
 * @param export_meta Export Template/IE Metadata
 * @param err an error description, set on failure.
 * @return a new writer for export to the given address.
 */
fBuf_t *
yfWriterForSpec(
    fbConnSpec_t  *spec,
    uint32_t       domain,
    gboolean       export_meta,
    GError       **err);


#ifdef HAVE_SPREAD
/**
 * Get an IPFIX message buffer for writing YAF flows to Spread.
 * If Groupby feature is used it will call yfInitExporterSpreadSession
 * to set up templates per group, otherwise it calls yfInitExporterSession.
 *
 * @param params fixbuf Spread parameters
 * @param domain observation domain
 * @param spreadGroupIndex an array of groups matched to IE values
 * @param export_meta Export Template/IE Metadata
 * @param err an error description, set on failure.
 * @return a new writer for export to the given address
 */
fBuf_t *
yfWriterForSpread(
    fbSpreadParams_t  *params,
    uint32_t           domain,
    uint16_t          *spreadGroupIndex,
    gboolean           export_meta,
    GError           **err);
#endif /* HAVE_SPREAD */

/**
 * A wrapper that calls both yfWriteStatsFlow and yfWriteDataFlow with
 * appropriate condition checking.
 *
 * @param yfContext Context pointer for the yaf state, used to get the
 *                  fbuf pointer.
 * @param pcap_drop Number of packets dropped reported by libpcap
 * @param timer     Pointer to yafstats GTimer
 * @param err       an error description; required.
 * @return          TRUE on success, FALSE otherwise.
 *
 */
gboolean
yfWriteOptionsDataFlows(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err);

/**
 * Write a statistics options data record to an IPFIX Message buffer.  To turn
 * off stats output - use --nostats. Sets the internal template to the stats
 * option template, builds the record, and sends it - then sets the internal
 * template back to the full flow record.
 *
 * @param yfContext Context pointer for the yaf state, used to get the
 *                  fbuf pointer.
 * @param pcap_drop Number of packets dropped reported by libpcap
 * @param timer     Pointer to yafstats GTimer
 * @param err       an error description; required.
 * @return          TRUE on success, FALSE otherwise.
 *
 */
gboolean
yfWriteStatsFlow(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err);

/**
 * Write a tombstone options data record to an IPFIX Message buffer.  Sets the
 * internal template to the tombstone option template, builds the record, and
 * sends it - then sets the internal template back to the full flow record.
 *
 * @param yfContext Context pointer for the yaf state, used to get the
 *                  fbuf pointer.
 * @param err       an error description; required.
 * @return          TRUE on success, FALSE otherwise.
 *
 */
gboolean
yfWriteTombstoneFlow(
    void    *yfContext,
    GError **err);

/**
 * Write a single flow to an IPFIX message buffer. The buffer must have been
 * returned by yfWriterForFP() or yfWriterForSpec().
 *
 * @param yfContext Context pointer for the yaf state, used to get the
 *              fbuf pointer, a buffer to write the message to, returned
 *              from yfWriterForFP() or yfWriterForSpec()
 * @param flow  pointer to yfFlow_t to write to file or stream.
 * @param err   an error description; required.
 * @return      TRUE on success, FALSE otherwise.
 */
gboolean
yfWriteFlow(
    void      *yfContext,
    yfFlow_t  *flow,
    GError   **err);

/**
 * Close the connection underlying an IPFIX message buffer created by
 * yfWriterForFP() or yfWriterForSpec(). If flush is TRUE, forces any message
 * in progress to be emitted before close; use FALSE if closing the buffer in
 * response to a write error. Does not free the buffer.
 *
 * @param fbuf buffer to close.
 * @param flush TRUE to flush buffer before closing.
 * @param err an error description, set on failure.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
yfWriterClose(
    fBuf_t    *fbuf,
    gboolean   flush,
    GError   **err);

/**
 * FIXME doc
 */
void
yfWriterExportPayload(
    int   max_payload);

#if YAF_ENABLE_APPLABEL
/**
 *  Limits payload export to the silkAppLabel values contained in `applabels`,
 *  a GArray of `long` values.  The values in `applabels` are copied to
 *  another data structure.
 */
void
yfWriterExportPayloadApplabels(
    const GArray   *applabels);
#endif  /* YAF_ENABLE_APPLABEL */

/**
 * FIXME doc
 */
void
yfWriterExportMappedV6(
    gboolean   map_mode);

/**
 * Get an IPFIX message buffer for reading YAF flows from an open file pointer.
 * Reuses an existing buffer if supplied.
 *
 * @param fbuf  IPFIX message buffer to reuse; must have been returned by a
 *              prior call to yfReaderForFP(). Pass NULL to create a new
 *              buffer.
 * @param fp    File pointer to open file to read from.
 * @param err an error description, set on failure.
 * @return a new reader, or a reused reader, for reading the
 *         given open file. NULL on failure.
 */
fBuf_t *
yfReaderForFP(
    fBuf_t  *fbuf,
    FILE    *fp,
    GError **err);

/**
 * Get an IPFIX connection listener for collecting YAF flows via IPFIX from
 * the network.
 *
 * @param spec  fixbuf connection specifier for local end of socket.
 * @param appinit Application context initialization function,
 *                for creating application-specific collector contexts.
 *                Pass NULL for no appinit function.
 * @param appfree Application context cleanup function.
 *                Pass NULL for no appfree function.
 * @param err an error description, set on failure.
 * @return  a new listener, initialized for reading YAF flows, for use
 *          with fbListenerWait(). Buffers returned from this call can
 *          then be used with yfReadFlow() and yfReadFlowExtended().
 */
fbListener_t *
yfListenerForSpec(
    fbConnSpec_t          *spec,
    fbListenerAppInit_fn   appinit,
    fbListenerAppFree_fn   appfree,
    GError               **err);

/**
 * Read a single flow from an IPFIX message buffer. The buffer must have been
 * returned by yfReaderForFP(), or by fbListenerWait() called on a listener
 * created by yfListenerForSpec().
 *
 * @param fbuf  Buffer to read message from, returned by yfReaderForFP()
 *              or from a YAF listener.
 * @param flow  pointer to yfFlow_t structure to fill from file or stream.
 * @param err   an error description; required.
 * @return      TRUE on success, FALSE otherwise. If false, check error against
 *              FB_ERROR_EOF to determine if the message reader is at end of
 *              file or stream, or against FB_ERROR_EOM to see if the listener
 *              should be waited upon.
 */
gboolean
yfReadFlow(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err);

/**
 * Read a single flow from an IPFIX message buffer. The buffer must have been
 * returned by yfReaderForFP(), or by fbListenerWait() called on a listener
 * created by yfListenerForSpec(). This function does not necessarily require
 * its input to have been written by yfWriteFlow(); it supports additional flow
 * timestamp and counter IEs that may be exported by other IPFIX exporting
 * processes.
 *
 * @param fbuf  Buffer to read message from, returned by yfReaderForFP()
 *              or from a YAF listener.
 * @param flow  pointer to yfFlow_t structure to fill from file or stream.
 * @param err   an error description; required.
 * @return      TRUE on success, FALSE otherwise. If false, check error against
 *              FB_ERROR_EOF to determine if the message reader is at end of
 *              file or stream, or against FB_ERROR_EOM to see if the listener
 *              should be waited upon.
 */
gboolean
yfReadFlowExtended(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err);

/**
 * Print a YAF flow to a GString.
 *
 * @param rstr string to append text representation of flow to.
 * @param flow flow to print.
 */
void
yfPrintString(
    GString   *rstr,
    yfFlow_t  *flow);

/**
 * Print a YAF flow to a GString in pipe-delimited (tabular) format.
 *
 * @param rstr string to append text representation of flow to.
 * @param flow flow to print.
 * @param yaft_mac Add mac addresses to tabular format.
 */
void
yfPrintDelimitedString(
    GString   *rstr,
    yfFlow_t  *flow,
    gboolean   yaft_mac);

/**
 * Print a YAF flow to a file.
 *
 * @param out file to print to.
 * @param flow flow to print.
 * @param err an error descriptor.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
yfPrint(
    FILE      *out,
    yfFlow_t  *flow,
    GError   **err);

/**
 * Print a YAF flow to a file in pipe-delimited (tabular) format.
 *
 * @param out file to print to.
 * @param flow flow to print.
 * @param yaft_mac print mac addresses in tabular format
 * @param err an error descriptor.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
yfPrintDelimited(
    FILE      *out,
    yfFlow_t  *flow,
    gboolean   yaft_mac,
    GError   **err);

/**
 * Print column headers for the pipe-delimited (tabular) format.
 *
 * @param out file to print to.
 * @param yaft_mac print mac address column headers if enabled
 * @param err an error descriptor.
 * @return TRUE on success, FALSE otherwise.
 */
void
yfPrintColumnHeaders(
    FILE      *out,
    gboolean   yaft_mac,
    GError   **err);

#if YAF_ENABLE_HOOKS
/**
 * Add all DPI info elements to info model
 *
 *
 */
fbInfoModel_t *
yfDPIInfoModel(
    void);
#endif /* if YAF_ENABLE_HOOKS */

#endif /* ifndef _YAF_CORE_H_ */
