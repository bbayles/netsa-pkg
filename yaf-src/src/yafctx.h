/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafctx.h
 *  YAF configuration
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

#ifndef _YAF_CTX_H_
#define _YAF_CTX_H_

#include <yaf/autoinc.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include <yaf/decode.h>
#include <yaf/ring.h>
#include <airframe/airlock.h>

typedef struct yfConfig_st {
    char              *inspec;
    char              *livetype;
    char              *outspec;
    char              *bpf_expr;
    char              *pcapdir;

    gboolean           pcap_per_flow;
    gboolean           lockmode;
    gboolean           ipfixNetTrans;
    gboolean           noerror;
    gboolean           exportInterface;
    gboolean           macmode;
    gboolean           silkmode;
    gboolean           nostats;

    gboolean           statsmode;
    gboolean           deltaMode;
    gboolean           no_output;
    gboolean           tmpl_metadata;
    gboolean           no_tombstone;
    gboolean           layer2IdExportMode;

    uint16_t           tombstone_configured_id;
    uint32_t           ingressInt;
    uint32_t           egressInt;
    uint64_t           stats;

    uint64_t           rotate_ms;
    /* in seconds - convert to ms in yaf.c */
    uint64_t           yaf_udp_template_timeout;
    uint64_t           max_pcap;
    uint64_t           pcap_timer;

    uint32_t           odid;
    fbConnSpec_t       connspec;
#ifdef HAVE_SPREAD
    gboolean           ipfixSpreadTrans;
    fbSpreadParams_t   spreadparams;
    uint16_t          *spreadGroupIndex;
    uint8_t            numSpreadGroups;
    uint8_t            spreadGroupby;
#endif /* ifdef HAVE_SPREAD */
} yfConfig_t;

/* Define yfConfig_t entries when Spread is enabled or disabled */
#ifdef HAVE_SPREAD
#define YAF_CONFIG_INIT_SPREAD                  \
    FALSE, FB_SPREADPARAMS_INIT, NULL, 0, 0
#else
#define YAF_CONFIG_INIT_SPREAD
#endif  /* HAVE_SPREAD */

#define YF_CONFIG_INIT                                       \
    {NULL, NULL, NULL, NULL, NULL,                           \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,               \
     0, 0, 0, 0,                                             \
     0, 0, 5, 0,                                             \
     0, FB_CONNSPEC_INIT,                                    \
     YAF_CONFIG_INIT_SPREAD}

typedef struct yfContext_st {
    /** Configuration */
    yfConfig_t     *cfg;
    /** Packet source */
    void           *pktsrc;
    /** Packet ring buffer */
    size_t          pbuflen;
    rgaRing_t      *pbufring;
    /** Decoder */
    yfDecodeCtx_t  *dectx;
    /** Flow table */
    yfFlowTab_t    *flowtab;
    /** Fragment table */
    yfFragTab_t    *fragtab;
    /** Output rotation state */
    uint64_t        last_rotate_ms;
    /** Output lock buffer */
    AirLock         lockbuf;
    /** Output IPFIX buffer */
    fBuf_t         *fbuf;
    /** UDP last template send time (in ms) */
    uint64_t        lastUdpTempTime;
    /** yaf start time */
    uint64_t        yaf_start_time;
    /** Error description */
    GError         *err;
    /** Pcap File Ptr for Rolling Pcap*/
    pcap_dumper_t  *pcap;
    /** Pcap Offset into Rolling Pcap */
    uint64_t        pcap_offset;
    /** Pcap Lock Buffer */
    AirLock         pcap_lock;
} yfContext_t;

#define YF_CTX_INIT                                           \
    {NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, AIR_LOCK_INIT, \
     NULL, 0, 0, NULL, NULL, 0, AIR_LOCK_INIT}

/* global quit flag, defined in yaf.c */
extern int yaf_quit;

#endif /* ifndef _YAF_CTX_H_ */
