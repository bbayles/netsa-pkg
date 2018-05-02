/**
 * @internal
 *
 ** yaftab.c
 ** YAF Active Flow Table
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2016 Carnegie Mellon University.
 ** All Rights Reserved.
 **
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell, Chris Inacio
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 */

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>
#include <yaf/picq.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include "yafctx.h"

#if YAF_ENABLE_APPLABEL
#include "yafapplabel.h"
#endif

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#if YAF_ENABLE_P0F
#include "applabel/p0f/yfp0f.h"
#endif

#if YAF_ENABLE_ENTROPY
#include <math.h>
#endif

#if YAF_ENABLE_NDPI
#include <libndpi/ndpi_main.h>
#endif

/**
 * YAF_MPLS:
 * If YAF was built with MPLS support, the MPLS labels are passed
 * to yfFlowPBuf, and the top 3 labels are hashed to create a key
 * into the Hash Table (flowtab->table).  The key retrieves a pointer
 * to a yfMPLSNode_t which contains a Hash Table, the MPLS labels, and
 * a counter.  This Hash Table is the new flow table.  The yfFlow_t struct
 * contains a pointer to the yfMPLSNode_t which contains a pointer to the
 * flow Hash Table that contains it.  Once the counter in the yfMPLSNode_t
 * is 0, the hash table is destroyed and the yfMPLSNode_t is freed.
 */

#ifndef YFDEBUG_FLOWTABLE
#define YFDEBUG_FLOWTABLE 0
#endif

#define YAF_STATE_ACTIVE        0x00000000
#define YAF_STATE_RST           0x00000001
#define YAF_STATE_FFIN          0x00000010
#define YAF_STATE_RFIN          0x00000020
#define YAF_STATE_FFINACK       0x00000040
#define YAF_STATE_RFINACK       0x00000080
#define YAF_STATE_FIN           0x000000F0
#define YAF_STATE_ATO           0x00000100

#define YF_FLUSH_DELAY 5000
#define YF_MAX_CQ      2500

#define YAF_PCAP_META_ROTATE 45000000
/* full path */
#define YAF_PCAP_META_ROTATE_FP 23000000

static int       pcap_meta_num = 0;
static int       pcap_meta_read = 0;

typedef struct yfFlowNode_st {
    struct yfFlowNode_st        *p;
    struct yfFlowNode_st        *n;
    struct yfFlowTab_t          *flowtab;
    uint32_t                    state;
    yfFlow_t                    f;
} yfFlowNode_t;

typedef struct yfFlowQueue_st {
    yfFlowNode_t      *tail;
    yfFlowNode_t      *head;
} yfFlowQueue_t;


#if YAF_ENABLE_COMPACT_IP4
/*
 * Compact IPv4 flow structures; allows the flow table to only allocate enough
 * space for IPv4 addresses for IPv4 flows. Requires the flow key to be the
 * last element of the flow, and the flow to be the last element of the
 * flow node. ALL CHANGES made to yfFlowKey_t and yfFlow_t in yafcore.h MUST
 * be reflected here or I'll not be held responsible for the results.
 */

typedef struct yfFlowKeyIPv4_st {
    uint16_t            sp;
    uint16_t            dp;
    uint8_t             proto;
    uint8_t             version;
    uint16_t            vlanId;
    uint8_t             tos;
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    uint8_t             netIf;
#endif
    union {
        struct {
            uint32_t    sip;
            uint32_t    dip;
        }               v4;
    }                   addr;
} yfFlowKeyIPv4_t;

typedef struct yfFlowIPv4_st {
    uint64_t        stime;
    uint64_t        etime;
#ifdef YAF_ENABLE_HOOKS
    void            *hfctx[YAF_MAX_HOOKS];
#endif
    uint32_t        rdtime;
#if YAF_ENABLE_APPLABEL || YAF_ENABLE_NDPI
    uint16_t        appLabel;
#endif
#if YAF_ENABLE_NDPI
    uint16_t        ndpi_master;
    uint16_t        ndpi_sub;
#endif
    uint8_t         reason;
    uint8_t         pcap_serial;
    uint8_t         sourceMacAddr[6];
    uint8_t         destinationMacAddr[6];

    uint8_t         pcap_file_no;
    uint8_t         pktdir;
    uint8_t         rtos;
    pcap_dumper_t   *pcap;
#if YAF_MPLS
    yfMPLSNode_t    *mpls;
#endif
    yfMPTCPFlow_t   mptcp;
    yfFlowVal_t     val;
    yfFlowVal_t     rval;
    yfFlowKeyIPv4_t key;
} yfFlowIPv4_t;

typedef struct yfFlowNodeIPv4_st {
    struct yfFlowNodeIPv4_st    *p;
    struct yfFlowNodeIPv4_st    *n;
    struct yfFlowTab_t          *flowtab;
    uint32_t                    state;
    yfFlowIPv4_t                f;
} yfFlowNodeIPv4_t;

#endif

struct yfFlowTabStats_st {
    uint64_t        stat_octets;
    uint64_t        stat_packets;
    uint64_t        stat_seqrej;
    uint64_t        stat_flows;
    uint64_t        stat_uniflows;
    uint32_t        stat_peak;
    uint32_t        stat_flush;
#if YAF_MPLS
    uint32_t        max_mpls_labels;
    uint32_t        stat_mpls_labels;
#endif
};

struct yfFlowTab_st {
    /* State */
    uint64_t        ctime;
    uint64_t        flushtime;
    GHashTable      *table;
    GHashFunc       hashfn;
    GEqualFunc      hashequalfn;
#ifdef YAF_ENABLE_HOOKS
    /** Plugin context array for this yaf **/
    void            **yfctx;
#endif
#if YAF_MPLS
    yfMPLSNode_t    *cur_mpls_node;
#endif
#if YAF_ENABLE_NDPI
    struct ndpi_detection_module_struct *ndpi_struct;
#endif
    yfFlowQueue_t   aq;
    yfFlowQueue_t   cq;
    uint32_t        count;
    uint32_t        cq_count;
    /* Configuration */
    uint64_t        idle_ms;
    uint64_t        active_ms;
    uint64_t        hash_search;
    uint64_t        stime_search;
    uint32_t        max_flows;
    uint32_t        max_payload;
    char            *pcap_dir;
    GString         *pcap_roll;
    char            *pcap_meta_name;
    FILE            *pcap_meta;
    uint8_t         pcap_file_no;
    uint64_t        max_pcap;
    long            last_offset;
    uint64_t        lasttime;
    gboolean        uniflow;
    gboolean        silkmode;
    gboolean        macmode;
    gboolean        applabelmode;
    gboolean        entropymode;
    gboolean        fingerprintmode;
    gboolean        fingerprintExport;
    gboolean        udp_max_payload;
    gboolean        force_read_all;
    gboolean        stats_mode;
    gboolean        index_pcap;
    uint16_t        udp_uniflow_port;
    /* Statistics */
    struct yfFlowTabStats_st stats;
};

/**
 * protypes
*/
static gboolean yfRotatePcapMetaFile(
    yfFlowTab_t                *flowtab);

/**
 * yfGetFlowTabStats
 *
 *
 */
void yfGetFlowTabStats(
    yfFlowTab_t *flowtab,
    uint64_t *packets,
    uint64_t *flows,
    uint64_t *rej_pkts,
    uint32_t *peak,
    uint32_t *flush)

{
    *packets = flowtab->stats.stat_packets;
    *flows = flowtab->stats.stat_flows;
    *rej_pkts = flowtab->stats.stat_seqrej;
    *peak = flowtab->stats.stat_peak;
    *flush = flowtab->stats.stat_flush;
}

#if YAF_MPLS
/**
 * yfMPLSHash
 *
 * hash function that takes the top 3 MPLS labels
 * and hashes them into a signle 32-bit integer.
 *
 * @param pointer to struct that holds MPLS values
 * @return 32-bit hashed integer of the 3 mpls labels
 */
static uint32_t yfMPLSHash(
    yfMPLSNode_t    *mpls)
{

    return ((mpls->mpls_label[1] << 10) ^ (mpls->mpls_label[2] << 6) ^
            mpls->mpls_label[0]);
}


/**
 * yfMPLSEqual
 *
 * Compare 2 MPLS Nodes to see if they're equal.
 *
 * @param a
 * @param b
 * @return true/false
 */
static gboolean yfMPLSEqual(
    yfMPLSNode_t       *a,
    yfMPLSNode_t       *b)
{

    if ((a->mpls_label[0] == b->mpls_label[0]) &&
        (a->mpls_label[1] == b->mpls_label[1]) &&
        (a->mpls_label[2] == b->mpls_label[2]))
    {
        return TRUE;
    } else {
        return FALSE;
    }
}

#endif
/**
 * yfFlowKeyHash
 *
 * hash function that takes the 6-tuple for flow
 * identification and turns it into a single
 * 32-bit integer
 *
 * @param key pointer the the flow key which holds
 *        the set of values that uniquely identify
 *        a flow within yaf
 *
 * @return 32-bit hashed integer of the flow
 */
static uint32_t yfFlowKeyHash(
    yfFlowKey_t       *key)
{

    /* Mask out priority/CFI bits */
    uint16_t vlan_mask = 0x0FFF & key->vlanId;

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    uint32_t netInterfaceHash;

    switch (key->netIf) {
        case 0:
            netInterfaceHash = 0x33333333;
            break;
        case 1:
            netInterfaceHash = 0x55555555;
            break;
        case 2:
            netInterfaceHash = 0xaaaaaaaa;
            break;
        case 3:
            netInterfaceHash = 0xbbbbbbbb;
            break;
        default:
            /* this is impossible because of the
               dag structure is a 2-bit field for
               this */
            g_warning("Invalid DAG interface code recorded: %d"
                      " - continuing processing", key->netIf);
            netInterfaceHash = 0xcccccccc;
    }

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            (vlan_mask << 20) ^ key->addr.v4.sip ^
            key->addr.v4.dip ^ netInterfaceHash;
    } else {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            (vlan_mask << 20) ^
            *((uint32_t *)&(key->addr.v6.sip[0])) ^
            *((uint32_t *)&(key->addr.v6.sip[4])) ^
            *((uint32_t *)&(key->addr.v6.sip[8])) ^
            *((uint32_t *)&(key->addr.v6.sip[12])) ^
            *((uint32_t *)&(key->addr.v6.dip[0])) ^
            *((uint32_t *)&(key->addr.v6.dip[4])) ^
            *((uint32_t *)&(key->addr.v6.dip[8])) ^
            *((uint32_t *)&(key->addr.v6.dip[12])) ^
            netInterfaceHash;
    }
#endif

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               (vlan_mask << 20) ^
               key->addr.v4.sip ^ key->addr.v4.dip;
    } else {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            (vlan_mask << 20) ^
            *((uint32_t *)&(key->addr.v6.sip[0])) ^
            *((uint32_t *)&(key->addr.v6.sip[4])) ^
            *((uint32_t *)&(key->addr.v6.sip[8])) ^
            *((uint32_t *)&(key->addr.v6.sip[12])) ^
            *((uint32_t *)&(key->addr.v6.dip[0])) ^
            *((uint32_t *)&(key->addr.v6.dip[4])) ^
            *((uint32_t *)&(key->addr.v6.dip[8])) ^
            *((uint32_t *)&(key->addr.v6.dip[12]));
    }
}


/**
 * yfFlowKeyHashNoVlan
 *
 * hash function that takes the 6-tuple for flow
 * identification and turns it into a single
 * 32-bit integer
 *
 * @param key pointer the the flow key which holds
 *        the set of values that uniquely identify
 *        a flow within yaf
 *
 * @return 32-bit hashed integer of the flow
 */
static uint32_t yfFlowKeyHashNoVlan(
    yfFlowKey_t       *key)
{

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    uint32_t netInterfaceHash;

    switch (key->netIf) {
      case 0:
        netInterfaceHash = 0x33333333;
        break;
      case 1:
        netInterfaceHash = 0x55555555;
        break;
      case 2:
        netInterfaceHash = 0xaaaaaaaa;
        break;
      case 3:
        netInterfaceHash = 0xbbbbbbbb;
        break;
      default:
        /* this is impossible because of the
               dag structure is a 2-bit field for
               this */
        g_warning("Invalid DAG interface code recorded: %d"
                  " - continuing processing", key->netIf);
        netInterfaceHash = 0xcccccccc;
    }

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            key->addr.v4.sip ^
            key->addr.v4.dip ^ netInterfaceHash;
    } else {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            *((uint32_t *)&(key->addr.v6.sip[0])) ^
            *((uint32_t *)&(key->addr.v6.sip[4])) ^
            *((uint32_t *)&(key->addr.v6.sip[8])) ^
            *((uint32_t *)&(key->addr.v6.sip[12])) ^
            *((uint32_t *)&(key->addr.v6.dip[0])) ^
            *((uint32_t *)&(key->addr.v6.dip[4])) ^
            *((uint32_t *)&(key->addr.v6.dip[8])) ^
            *((uint32_t *)&(key->addr.v6.dip[12])) ^
            netInterfaceHash;
    }
#endif
    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            key->addr.v4.sip ^ key->addr.v4.dip;
    } else {
        return (key->sp << 16) ^ key->dp ^
            (key->proto << 12) ^ (key->version << 4) ^
            *((uint32_t *)&(key->addr.v6.sip[0])) ^
            *((uint32_t *)&(key->addr.v6.sip[4])) ^
            *((uint32_t *)&(key->addr.v6.sip[8])) ^
            *((uint32_t *)&(key->addr.v6.sip[12])) ^
            *((uint32_t *)&(key->addr.v6.dip[0])) ^
            *((uint32_t *)&(key->addr.v6.dip[4])) ^
            *((uint32_t *)&(key->addr.v6.dip[8])) ^
            *((uint32_t *)&(key->addr.v6.dip[12]));
    }
}


/**
 * yfFlowKeyEqual
 *
 * compares two flows (a & b) based on their key value,
 * the hopefully unique 6-tuple of flow information to
 * see if the flows are the same
 *
 * @param
 *
 */
static gboolean yfFlowKeyEqual(
    yfFlowKey_t       *a,
    yfFlowKey_t       *b)
{

    uint16_t a_vlan_mask = 0x0FFF & a->vlanId;
    uint16_t b_vlan_mask = 0x0FFF & b->vlanId;

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    if (a->netIf != b->netIf) {
        return FALSE;
    }
#endif

    if ((a->sp      == b->sp)    &&
        (a->dp      == b->dp)    &&
        (a->proto   == b->proto) &&
        (a->version == b->version) &&
        (a_vlan_mask == b_vlan_mask))
    {
        if ((a->version     == 4) &&
            (a->addr.v4.sip == b->addr.v4.sip) &&
            (a->addr.v4.dip == b->addr.v4.dip))
        {
            return TRUE;
        } else if ((a->version == 6) &&
                   (memcmp(a->addr.v6.sip, b->addr.v6.sip, 16) == 0) &&
                   (memcmp(a->addr.v6.dip, b->addr.v6.dip, 16) == 0))
        {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        return FALSE;
    }
}

/**
 * yfFlowKeyEqualNoVlan
 *
 * compares two flows (a & b) based on their key value,
 * the hopefully unique 6-tuple of flow information to
 * see if the flows are the same
 *
 * @param
 *
 */
static gboolean yfFlowKeyEqualNoVlan(
    yfFlowKey_t       *a,
    yfFlowKey_t       *b)
{

#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    if (a->netIf != b->netIf) {
        return FALSE;
    }
#endif

    if ((a->sp      == b->sp)    &&
        (a->dp      == b->dp)    &&
        (a->proto   == b->proto) &&
        (a->version == b->version))
    {
        if ((a->version     == 4) &&
            (a->addr.v4.sip == b->addr.v4.sip) &&
            (a->addr.v4.dip == b->addr.v4.dip))
        {
            return TRUE;
        } else if ((a->version == 6) &&
                   (memcmp(a->addr.v6.sip, b->addr.v6.sip, 16) == 0) &&
                   (memcmp(a->addr.v6.dip, b->addr.v6.dip, 16) == 0))
        {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        return FALSE;
    }
}

/**
 * yfFlowKeyReverse
 *
 * reverses the direction of a flow key, swaping the
 * source and destination fields appropriately within
 * the key record
 *
 * @param src pointer to the forward record
 * @param dst pointer to the reversed destination record
 *
 */
static void yfFlowKeyReverse(
    yfFlowKey_t       *fwd,
    yfFlowKey_t       *rev)
{
    if (fwd->proto == YF_PROTO_ICMP || fwd->proto == YF_PROTO_ICMP6) {
        rev->sp = fwd->sp;
        rev->dp = fwd->dp;
    } else {
        rev->sp = fwd->dp;
        rev->dp = fwd->sp;
    }
    rev->proto = fwd->proto;
    rev->version = fwd->version;
    rev->vlanId = fwd->vlanId;
    if (fwd->version == 4) {
        rev->addr.v4.sip = fwd->addr.v4.dip;
        rev->addr.v4.dip = fwd->addr.v4.sip;
    } else if (fwd->version == 6) {
        memcpy(rev->addr.v6.sip, fwd->addr.v6.dip, 16);
        memcpy(rev->addr.v6.dip, fwd->addr.v6.sip, 16);
    }
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES
    rev->netIf = fwd->netIf;
#endif

}

/**
 * yfFlowKeyCopy
 *
 * copies a flow key from src to dst
 *
 * @param src pointer to the source flow key
 * @param dst pointer to the destination flow key
 *
 */
static void yfFlowKeyCopy(
    yfFlowKey_t       *src,
    yfFlowKey_t       *dst)
{
#if YAF_ENABLE_COMPACT_IP4
    if (src->version == 4) {
        memcpy(dst, src, sizeof(yfFlowKeyIPv4_t));
    } else {
#endif
        memcpy(dst, src, sizeof(yfFlowKey_t));
#if YAF_ENABLE_COMPACT_IP4
    }
#endif
}

/**
 *yfFlowIncrementUniflow
 *
 * simple helper function to allow counting of unidirectional flows
 * (vs. captured biflows on the wire)
 *
 */
static void
yfFlowIncrementUniflow (
    yfFlowTab_t  *flowtab)
{
    (flowtab->stats.stat_uniflows)++;
}


#if YFDEBUG_FLOWTABLE == 1
/**
 * yfFlowDebug
 *
 *
 * @param msg
 * @param flow
 *
 */
static void yfFlowDebug(
    const char        *msg,
    yfFlow_t          *flow)
{
    static GString      *str = NULL;

    if (!str) {
        str = g_string_new("");
    }

    g_string_printf(str,"%s ",msg);
    yfPrintString(str, flow);
    g_debug("%s", str->str);
}

/**
 * yfFlowTabVerifyIdleOrder
 *
 *
 * @param flowtab
 *
 */
static void yfFlowTabVerifyIdleOrder(
    yfFlowTab_t         *flowtab)
{
    yfFlowNode_t        *fn = NULL, *nfn = NULL;
    uint64_t            end;
    uint32_t            i;

    /* rip through the active queue making sure end time strictly decreases */
    for (fn = flowtab->aq.head, end = flowtab->aq.head->f.etime, i = 0;
         fn; end = fn->f.etime, fn = nfn, ++i)
    {
        nfn = fn->p;
        if (end < fn->f.etime) {
            g_debug("Flow inversion in active table position %u; "
                    "last end %llu, end %llu in flow:", i, end, fn->f.etime);
            yfFlowDebug("iiv", &(fn->f));
        }
    }
}
#endif

#if YAF_MPLS
/**
 * yfMPLSNodeFree
 *
 * Free table and struct when the last node associated with the
 * set of MPLS labels has been closed
 *
 */
static void yfMPLSNodeFree(
    yfFlowTab_t                    *flowtab,
    yfMPLSNode_t                   *mpls)
{
    g_hash_table_remove(flowtab->table, mpls);

    g_hash_table_destroy(mpls->tab);

    yg_slice_free(yfMPLSNode_t, mpls);

    --(flowtab->stats.stat_mpls_labels);
}
#endif

/**
 * yfFlowFree
 *
 * frees a flow (deallocates the memory and resets field
 * values to defaults) when the flow is no longer needed
 *
 * @param flowtab pointer to the flow table
 * @param fn node in the table to free
 *
 */
static void yfFlowFree(
    yfFlowTab_t         *flowtab,
    yfFlowNode_t        *fn)
{
#if YAF_ENABLE_PAYLOAD
    /* free payload if present */
    if (fn->f.val.payload) {
        yg_slice_free1(flowtab->max_payload, fn->f.val.payload);
        yg_slice_free1((sizeof(size_t) * YAF_MAX_PKT_BOUNDARY),
                       fn->f.val.paybounds);
    }
    if (fn->f.rval.payload) {
        yg_slice_free1(flowtab->max_payload, fn->f.rval.payload);
        yg_slice_free1((sizeof(size_t) * YAF_MAX_PKT_BOUNDARY),
                       fn->f.rval.paybounds);
    }
#endif
#if YAF_ENABLE_HOOKS
    /* let the hook free its context */
    yfHookFlowFree(&(fn->f));
#endif

#if YAF_ENABLE_FPEXPORT
    /* if present free the banner grabs for OS fingerprinting */
    if (fn->f.val.firstPacket) {
        yg_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.val.firstPacket);
    }
    if (fn->f.val.secondPacket) {
        yg_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.val.secondPacket);
    }
    if (fn->f.rval.firstPacket) {
        yg_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.rval.firstPacket);
    }
    if (fn->f.rval.secondPacket) {
        yg_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.rval.secondPacket);
    }
#endif
#if YAF_ENABLE_P0F
    if (fn->f.val.osFingerPrint) {
        g_free(fn->f.val.osFingerPrint);
    }
    if (fn->f.rval.osFingerPrint) {
        g_free(fn->f.rval.osFingerPrint);
    }
#endif

    if (flowtab->stats_mode) {
        if (fn->f.val.stats) {
            yg_slice_free(yfFlowStats_t, fn->f.val.stats);
        }
        if (fn->f.rval.stats) {
            yg_slice_free(yfFlowStats_t, fn->f.rval.stats);
        }
    }

#if YAF_MPLS
    --(fn->f.mpls->tab_count);
    if (fn->f.mpls->tab_count == 0) {
        /* remove node */
        yfMPLSNodeFree(flowtab, fn->f.mpls);
    }
#endif

    /* free flow */
#if YAF_ENABLE_COMPACT_IP4
    if (fn->f.key.version == 4) {
        yg_slice_free(yfFlowNodeIPv4_t, (yfFlowNodeIPv4_t *)fn);
    } else {
#endif
        yg_slice_free(yfFlowNode_t, fn);
#if YAF_ENABLE_COMPACT_IP4
    }
#endif
}

/**
 * yfFlowTick
 *
 * advances a flow to the head of the activity
 * queue so when flows get timed out, only the
 * bottom of the queue is examined
 *
 * @param flowtable pointer to the flow table
 * @param fn pointer to the flow node entry in the
 *        table
 *
 */
static void yfFlowTick(
    yfFlowTab_t                     *flowtab,
    yfFlowNode_t                    *fn)
{
    /* move flow node to head of queue */
    if (flowtab->aq.head != fn) {
        piqPick(&flowtab->aq, fn);
        piqEnQ(&flowtab->aq, fn);
    }
}

#if YAF_ENABLE_APPLABEL
/**
 * yfFlowLabelApp
 *
 * when closing a flow out, if applabel is enabled, send
 * the flow payload through the labeling mechanism in order
 * to identify the protocol via payload inspection
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the table
 *
 */
static void yfFlowLabelApp(
    yfFlowTab_t                     *flowtab,
    yfFlowNode_t                    *fn)
{
    /* If the app labeler is enabled, let it inspect the packet
       (for UDP & TCP packets anyway) */
    if (flowtab->applabelmode == TRUE &&
        ((fn->f.key.proto == 6) || (fn->f.key.proto == 17))) {
        yfAppLabelFlow(&(fn->f));
    } else {
        fn->f.appLabel = 0;
    }
}
#endif


#if YAF_ENABLE_ENTROPY
/**
 * yfFlowDoEntropy
 *
 * when closing a flow and entropy calculation is enabled,
 * call this calculation to calculate the Shannon entropy
 * on the data stream
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the table
 *
 */
static void yfFlowDoEntropy(
    yfFlowTab_t             *flowtab,
    yfFlowNode_t            *fn)
{
    uint8_t                 entropyDist[256];
    double                  entropyScratch;
    uint32_t                loop;

    /* if entropy is enabled, then we need to calculate it */
    /* FIXME deglobalize */
    if (flowtab->entropymode == TRUE) {
        /* forward entropy */
        if (fn->f.val.paylen) {
            entropyScratch = 0.0;
            memset(entropyDist, 0, 256);
            for (loop = 0; loop < fn->f.val.paylen; loop++) {
                entropyDist[fn->f.val.payload[loop]]++;
            }
            for (loop = 0; loop < 256; loop++) {
                if (0 == entropyDist[loop]) {
                    continue;
                }
                entropyScratch += ((double)entropyDist[loop] /
                                    (double)fn->f.val.paylen) *
                                   (log((double)entropyDist[loop] /
                                    (double)fn->f.val.paylen)/log(2.0));
            }
            entropyScratch *= -1;
            fn->f.val.entropy = (uint8_t)((entropyScratch / 8.0)*256.0);
        }

        /* reverse entropy */
        if (fn->f.rval.paylen) {
            entropyScratch = 0.0;
            memset(entropyDist, 0, 256);
            for (loop = 0; loop < fn->f.rval.paylen; loop++) {
                entropyDist[fn->f.rval.payload[loop]]++;
            }
            for (loop = 0; loop < 256; loop++) {
                if (0 == entropyDist[loop]) {
                    continue;
                }
                entropyScratch += ((double)entropyDist[loop] /
                                    (double)fn->f.rval.paylen) *
                                   (log((double)entropyDist[loop] /
                                    (double)fn->f.rval.paylen)/log(2.0));
            }
            entropyScratch *= -1;
            fn->f.rval.entropy = (uint8_t)((entropyScratch / 8.0)*256.0);
        }

    } else {
        fn->f.val.entropy = 0;
        fn->f.rval.entropy = 0;
    }
}
#endif

/**
 * yfFlowClose
 *
 * close a flow and remove it from the active list, it will get flushed
 * out based on another timer; record the reason for closing the flow:
 * (time out, session end, etc.)
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the flow table
 * @param reason reason code for closing the flow
 *
 */
static void yfFlowClose(
    yfFlowTab_t                     *flowtab,
    yfFlowNode_t                    *fn,
    uint8_t                         reason)
{

#if YAF_MPLS
    g_hash_table_remove(fn->f.mpls->tab, &(fn->f.key));
#else
    /* remove flow from table */
    g_hash_table_remove(flowtab->table, &(fn->f.key));
#endif

    /* store closure reason */
    fn->f.reason &= ~YAF_END_MASK;
    fn->f.reason |= reason;

    /* remove flow from active queue */
    piqPick(&flowtab->aq, fn);

    /* move flow node to close queue */
    piqEnQ(&flowtab->cq, fn);

#if YAF_ENABLE_PAYLOAD

#if YAF_ENABLE_APPLABEL
    /* do application label processing if necessary */
    if (flowtab->applabelmode) {
        yfFlowLabelApp(flowtab, fn);
    }
#endif

#if YAF_ENABLE_ENTROPY
    /* do entropy calculation if necessary */
    if (flowtab->entropymode) {
        yfFlowDoEntropy(flowtab, fn);
    }
#endif

#if YAF_ENABLE_HOOKS
    yfHookFlowClose(&(fn->f));
#endif

#endif

    /** count the flow in the close queue */
    ++(flowtab->cq_count);

    /* count the flow as inactive */
    --(flowtab->count);

    if (flowtab->pcap_dir) {
        if (fn->f.pcap) {
            pcap_dump_flush(fn->f.pcap);
            pcap_dump_close(fn->f.pcap);
        }
    }

}
#if YAF_ENABLE_PAYLOAD
/**
 * yfActiveFlowCleanUp
 *
 * clear out payload length to make way
 * for next packet payload
 *
 */

static void
yfActiveFlowCleanUp(
    yfFlowTab_t *flowtab,
    yfFlowNode_t *fn)
{
    fn->f.val.paylen = 0;
    fn->f.rval.paylen = 0;
}

#endif
/**
 * yfCloseActiveFlow
 *
 * close a flow and write it but keep it active
 * mainly for udp-uniflow option.
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the flow table
 * @param reason reason code for closing the flow
 *
 */


static void yfCloseActiveFlow(
    yfFlowTab_t                     *flowtab,
    yfFlowNode_t                    *fn,
    yfFlowVal_t                     *val,
    const uint8_t                   *pkt,
    uint32_t                        paylen,
    uint8_t                         reason,
    uint16_t                        iplen)
{
    yfFlowNode_t *tfn;  /*temp flow to write*/
    yfFlowVal_t *valtemp;

#if YAF_ENABLE_COMPACT_IP4
    if (fn->f.key.version == 4) {
        tfn = (yfFlowNode_t *) yg_slice_new0(yfFlowNodeIPv4_t);
        memcpy(tfn, fn, sizeof(yfFlowNodeIPv4_t));
    } else {
#endif
        tfn = yg_slice_new0(yfFlowNode_t);
        memcpy(tfn, fn, sizeof(yfFlowNode_t));
#if YAF_ENABLE_COMPACT_IP4
    }
#endif

    if (&(fn->f.rval) == val) {
        yfFlowKeyReverse(&(fn->f.key), &(tfn->f.key));
        memcpy(&(tfn->f.val), val, sizeof(yfFlowVal_t));
        tfn->f.key.tos = fn->f.rtos;
    }

    /*"Uniflow"*/
    memset(&(tfn->f.rval), 0, sizeof(yfFlowVal_t));

    /* Since we are creating a new node - we need to allocate
       hooks context for it */
#if YAF_ENABLE_HOOKS
    /*Let the hook allocate its context */
    yfHookFlowAlloc(&(tfn->f), flowtab->yfctx);
#endif

    tfn->f.rdtime = 0;
    tfn->f.val.pkt = 1;

    /* octet count of only this flow! */
    tfn->f.val.oct = iplen;

    /*Update start time of this flow - to now*/
    tfn->f.stime = flowtab->ctime;

    /* store closure reason - shouldn't have any other bits turned on */
    tfn->f.reason &= ~YAF_END_MASK;
    tfn->f.reason |= reason;

    tfn->n = NULL;
    tfn->p = NULL;
    valtemp = &(tfn->f.val);
    valtemp->stats = NULL;
#if YAF_ENABLE_PAYLOAD
    valtemp->payload = NULL;

    /* Short-circuit no payload capture */
    if (flowtab->max_payload && paylen && pkt) {

        valtemp->payload = yg_slice_alloc0(flowtab->max_payload);

        /* truncate capture length to payload limit */
        if (paylen  > flowtab->max_payload) {
            paylen = flowtab->max_payload;
        }

        /* only need 1 entry in paybounds */
        valtemp->paybounds = (size_t *)yg_slice_alloc0(sizeof(size_t) *
                                                       YAF_MAX_PKT_BOUNDARY);
        valtemp->paybounds[0] = paylen;

        memcpy(valtemp->payload, pkt, paylen);
        tfn->f.val.paylen = paylen;
    }
#endif
    /* move flow node to close queue */
    piqEnQ(&flowtab->cq, tfn);

#if YAF_MPLS
    /* Since yfFlowFree frees UDP uniflows, but they're never
       added to the mpls tables - we add one here, to account
       for subtracting it in yfflowfree */
    ++(fn->f.mpls->tab_count);
#endif

    ++(flowtab->cq_count);

#if YAF_ENABLE_PAYLOAD

#if YAF_ENABLE_APPLABEL
    /* do application label processing if necessary */
    tfn->f.appLabel = 0;
    if (flowtab->applabelmode) {
        yfFlowLabelApp(flowtab, tfn);
    }

    if (tfn->f.appLabel) {
        /* store in ongoing flow */
        fn->f.appLabel = tfn->f.appLabel;
    }
#endif

#if YAF_ENABLE_ENTROPY
        /* do entropy calculation if necessary */
    if (flowtab->entropymode) {
        yfFlowDoEntropy(flowtab, tfn);
    }
#endif

#if YAF_ENABLE_HOOKS
    yfHookFlowClose(&(tfn->f));
#endif

    yfActiveFlowCleanUp(flowtab, fn);
#endif
}


static void *yf_malloc(unsigned long size) {
    return g_malloc(size);
}

static void yf_free(void *mem) {
    g_free(mem);
}


/**
 * yfFlowTabAlloc
 *
 * allocate (preferably from the slab allocator) another entry
 * into the flow table for a new flow
 *
 *
 * @return a pointer to the flow node entry in the flow table
 */
yfFlowTab_t *yfFlowTabAlloc(
    uint64_t        idle_ms,
    uint64_t        active_ms,
    uint32_t        max_flows,
    uint32_t        max_payload,
    gboolean        uniflow,
    gboolean        silkmode,
    gboolean        macmode,
    gboolean        applabelmode,
    gboolean        entropymode,
    gboolean        fingerprintmode,
    gboolean        fpExportMode,
    gboolean        udp_max_payload,
    uint16_t        udp_uniflow_port,
    char            *pcap_dir,
    char            *pcap_meta_file,
    uint64_t        max_pcap,
    gboolean        pcap_per_flow,
    gboolean        force_read_all,
    gboolean        stats_mode,
    gboolean        index_pcap,
    gboolean        no_vlan_in_key,
    gboolean        ndpi,
    char            *ndpi_proto_file,
    char            *hash,
    char            *stime,
    void            **yfctx)
{
    yfFlowTab_t     *flowtab = NULL;

    /* Allocate a flow table */
    flowtab = yg_slice_new0(yfFlowTab_t);

/* FIXME consider a better mode selection interface */
/* FIXME max payload should not be settable if payload not enabled */

    /* Fill in the configuration */
    flowtab->idle_ms = idle_ms;
    flowtab->active_ms = active_ms;
    flowtab->max_flows = max_flows;
    flowtab->max_payload = max_payload;
    flowtab->uniflow = uniflow;
    flowtab->silkmode = silkmode;
    flowtab->macmode = macmode;
    flowtab->applabelmode = applabelmode;
    flowtab->entropymode = entropymode;
    flowtab->fingerprintmode = fingerprintmode;
    flowtab->fingerprintExport = fpExportMode;
    flowtab->udp_max_payload = udp_max_payload;
    flowtab->udp_uniflow_port = udp_uniflow_port;
    flowtab->force_read_all = force_read_all;
    flowtab->stats_mode = stats_mode;
    flowtab->index_pcap = index_pcap;

#if YAF_ENABLE_HOOKS
    flowtab->yfctx = yfctx;
#endif

    if (pcap_per_flow) {
        flowtab->pcap_dir = pcap_dir;
    } else if (pcap_dir) {
        flowtab->pcap_roll = g_string_new("");
    } else if (pcap_meta_file && index_pcap) {
        pcap_meta_read = -1;
    } else if (pcap_meta_file) {
        flowtab->pcap_roll = g_string_new("");
    }

    if (pcap_meta_file) {
        if ((strlen(pcap_meta_file) == 1) && pcap_meta_file[0] == '-') {
            flowtab->pcap_meta = stdout;
        } else {
            flowtab->pcap_meta_name = pcap_meta_file;
            yfRotatePcapMetaFile(flowtab);
        }
    }
    flowtab->max_pcap = max_pcap;


    if (hash) {
        flowtab->hash_search = strtoull(hash, NULL, 10);
    }

    if (stime) {
        flowtab->stime_search = strtoull(stime, NULL, 10);
    }

    if (no_vlan_in_key) {
        flowtab->hashfn = (GHashFunc)yfFlowKeyHashNoVlan;
        flowtab->hashequalfn = (GEqualFunc)yfFlowKeyEqualNoVlan;
    } else {
        flowtab->hashfn = (GHashFunc)yfFlowKeyHash;
        flowtab->hashequalfn = (GEqualFunc)yfFlowKeyEqual;
    }


#if YAF_MPLS
    flowtab->table = g_hash_table_new((GHashFunc)yfMPLSHash,
                                      (GEqualFunc)yfMPLSEqual);
#else

    flowtab->table = g_hash_table_new(flowtab->hashfn,
                                      flowtab->hashequalfn);

#endif

#if YAF_ENABLE_HOOKS
    yfHookValidateFlowTab(yfctx, max_payload, uniflow,
                          silkmode, applabelmode, entropymode,
                          fingerprintmode, fpExportMode, udp_max_payload,
                          udp_uniflow_port);
#endif

#if YAF_ENABLE_NDPI
    if (ndpi) {
        NDPI_PROTOCOL_BITMASK all;
        flowtab->ndpi_struct = ndpi_init_detection_module(1000,
                                                          yf_malloc,
                                                          yf_free,
                                                          NULL);
        if (flowtab->ndpi_struct == NULL) {
            g_warning("Could not initialize NDPI");
            return NULL;
        }

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(flowtab->ndpi_struct, &all);

        if (ndpi_proto_file) {
            ndpi_load_protocols_file(flowtab->ndpi_struct, ndpi_proto_file);
        }
    }
#endif

    /* Done */
    return flowtab;
}

/**
 * yfFlowTabFree
 *
 * free's the entry in the flow table for a given flow entry *
 */
void yfFlowTabFree(
    yfFlowTab_t             *flowtab)
{
    yfFlowNode_t            *fn = NULL, *nfn = NULL;

    /* zip through the close queue freeing flows */
    for (fn = flowtab->cq.head; fn; fn = nfn) {
        nfn = fn->p;
        yfFlowFree(flowtab, fn);
    }

    /* now do the same with the active queue */
    for (fn = flowtab->aq.head; fn; fn = nfn) {
        nfn = fn->p;
        yfFlowFree(flowtab, fn);
    }

    /* Free GString */
    if (flowtab->pcap_roll) {
        g_string_free(flowtab->pcap_roll, TRUE);
    }

    if (flowtab->pcap_meta) {
        long cp = ftell(flowtab->pcap_meta);
        fseek(flowtab->pcap_meta, flowtab->last_offset, SEEK_SET);
        fprintf(flowtab->pcap_meta, "%"PRIu64"|%010ld\n",
                flowtab->lasttime, cp);
        fclose(flowtab->pcap_meta);
    }

   /* free the key index table */
    g_hash_table_destroy(flowtab->table);

#if YAF_ENABLE_NDPI
    ndpi_exit_detection_module(flowtab->ndpi_struct, yf_free);
#endif

    /* now free the flow table */
    yg_slice_free(yfFlowTab_t, flowtab);
}

#if YAF_MPLS
/**
 * yfMPLSGetNode
 *
 * finds an MPLS node entry in the MPLS table
 * based on the labels in the MPLS header.
 */
static yfMPLSNode_t *yfMPLSGetNode(
    yfFlowTab_t             *flowtab,
    yfL2Info_t              *l2info)
{
    yfMPLSNode_t            *mpls;
    yfMPLSNode_t            key;

    memcpy(key.mpls_label, l2info->mpls_label, sizeof(uint32_t)*3);

    if ((mpls = g_hash_table_lookup(flowtab->table, &key)))
    {
        flowtab->cur_mpls_node = mpls;
        return mpls;
    }

    /* create new mpls node */
    mpls = yg_slice_new0(yfMPLSNode_t);

    memcpy(mpls->mpls_label, l2info->mpls_label, sizeof(uint32_t)*3);

    mpls->tab = g_hash_table_new(flowtab->hashfn,
                                 flowtab->hashequalfn);
    flowtab->cur_mpls_node = mpls;

    g_hash_table_insert(flowtab->table, mpls, mpls);

    /* creation is 1, increment on #2 */
    /*++(mpls->tab_count);*/

    ++(flowtab->stats.stat_mpls_labels);
    if (flowtab->stats.stat_mpls_labels > flowtab->stats.max_mpls_labels) {
        flowtab->stats.max_mpls_labels = flowtab->stats.stat_mpls_labels;
    }

    return mpls;
}
#endif
/**
 * yfFlowGetNode
 *
 * finds a flow node entry in the flow table for
 * the appropriate key value given
 *
 */
static yfFlowNode_t *yfFlowGetNode(
    yfFlowTab_t             *flowtab,
    yfFlowKey_t             *key,
    yfFlowVal_t             **valp)
{
    yfFlowKey_t             rkey;
    yfFlowNode_t            *fn;
    GHashTable              *ht;

#if YAF_MPLS
    ht = flowtab->cur_mpls_node->tab;
#else
    ht = flowtab->table;
#endif

    /* Look for flow in table */
    if ((fn = g_hash_table_lookup(ht, key))) {
        /* Forward flow found. */
        *valp = &(fn->f.val);
        return fn;
    }

    /* Okay. Check for reverse flow. */
    yfFlowKeyReverse(key, &rkey);
    if ((fn = g_hash_table_lookup(ht, &rkey))) {
        /* Reverse flow found. */
        *valp = &(fn->f.rval);
        fn->f.rtos = key->tos;
        return fn;
    }

    /* Neither exists. Create a new flow and put it in the table. */
#if YAF_ENABLE_COMPACT_IP4
    if (key->version == 4) {
        fn = (yfFlowNode_t *)yg_slice_new0(yfFlowNodeIPv4_t);
    } else {
#endif
        fn = yg_slice_new0(yfFlowNode_t);
#if YAF_ENABLE_COMPACT_IP4
    }
#endif
    /* Copy key */
    yfFlowKeyCopy(key, &(fn->f.key));

    /* set flow start time */
    fn->f.stime = flowtab->ctime;

    /* set flow end time as start time */
    fn->f.etime = flowtab->ctime;

    /* stuff the flow in the table */
    g_hash_table_insert(ht, &(fn->f.key), fn);

#if YAF_MPLS
    fn->f.mpls = flowtab->cur_mpls_node;
    ++(flowtab->cur_mpls_node->tab_count);
#endif

    /* This is a forward flow */
    *valp = &(fn->f.val);

    /* Count it */
    ++(flowtab->count);
    if (flowtab->count > flowtab->stats.stat_peak) {
        flowtab->stats.stat_peak = flowtab->count;
    }

#if YAF_ENABLE_HOOKS
    /*Let the hook allocate its context */
    yfHookFlowAlloc(&(fn->f), flowtab->yfctx);
#endif

    /* All done */
    return fn;
}

/**
 * yfRotatePcapMetaFile
 *
 * rotate the pcap_meta_file
 *
 */
static gboolean yfRotatePcapMetaFile(
    yfFlowTab_t                *flowtab)
{
    GString *namebuf = g_string_new("");

    g_string_append_printf(namebuf, "%s", flowtab->pcap_meta_name);
    air_time_g_string_append(namebuf, time(NULL), AIR_TIME_SQUISHED);
    g_string_append_printf(namebuf, "_%05u.meta", pcap_meta_num);

    /* close current pcap_meta file */
    if (flowtab->pcap_meta) {
        long cp = ftell(flowtab->pcap_meta);
        fseek(flowtab->pcap_meta, flowtab->last_offset, SEEK_SET);
        fprintf(flowtab->pcap_meta, "%"PRIu64"|%010ld\n",
                flowtab->lasttime, cp);
        if (fclose(flowtab->pcap_meta)) {
            g_warning("Error (%d) Could not close current pcap "
                      "meta file: %s", errno, strerror(errno));
        }
        g_debug("Rotating Pcap Meta File, opening %s", namebuf->str);
    } else {
        g_debug("Opening Pcap Meta File %s", namebuf->str);
    }


    flowtab->pcap_meta = fopen(namebuf->str, "w");
    flowtab->last_offset = 0;
    if (flowtab->pcap_meta == NULL) {
        g_warning("Could not open new pcap meta file %s",
                  namebuf->str);
        g_warning("Error (%d): %s", errno, strerror(errno));
        g_string_free(namebuf, TRUE);
        return FALSE;
    }

    if (flowtab->ctime) {
        fprintf(flowtab->pcap_meta, "%"PRIu64"|0000000000\n", flowtab->ctime);
        flowtab->lasttime = flowtab->ctime;
    }

    g_string_free(namebuf, TRUE);
    pcap_meta_num++;
    return TRUE;
}

/**
 * yfUpdateRollingPcapFile
 *
 * update the rolling pcap filename in the flowtab for meta output
 *
 *
 */
void yfUpdateRollingPcapFile(
    yfFlowTab_t                *flowtab,
    char                       *new_file_name)
{

    g_string_truncate(flowtab->pcap_roll, 0);

    g_string_append_printf(flowtab->pcap_roll, "%s", new_file_name);

    flowtab->pcap_file_no++;

    /* every 10 rolling pcaps change over the pcap meta file */
    if (flowtab->pcap_meta_name && flowtab->stats.stat_packets) {
        if (pcap_meta_read == -1) {
            if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE) == 0) {
                yfRotatePcapMetaFile(flowtab);
            }
        } else if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE_FP) == 0) {
            yfRotatePcapMetaFile(flowtab);
        }
    }
}


/**
 * yfWritePcap
 *
 * write pcap to pcap-per-flow pcap file
 *
 * @param flowtab
 * @param flow
 * @param key
 * @param pbuf
 */
static void yfWritePcap(
    yfFlowTab_t              *flowtab,
    yfFlow_t                 *flow,
    yfFlowKey_t              *key,
    yfPBuf_t                 *pbuf)
{

    GString                  *namebuf;
    gboolean                 fexists = FALSE;
    yfFlowNode_t             *node;
    FILE                     *pfile = NULL;
    uint32_t                 rem_ms;

    if (flowtab->hash_search) {
        if (flowtab->hashfn(key) == flowtab->hash_search) {
            if (flowtab->stime_search) {
                if (flow->stime != flowtab->stime_search) {
                    return;
                }
            }
        } else { return; }
        if (flow->pcap == NULL) {
            if (g_file_test(flowtab->pcap_dir, G_FILE_TEST_EXISTS)) {
                pfile = fopen(flowtab->pcap_dir, "ab");
                if (pfile == NULL) {
                    g_warning("Pcap Create File Error: %s",
                              pcap_geterr((pcap_t *)pbuf->pcapt));
                    return;
                }
                /* need to append to pcap - libpcap doesn't have an append fn*/
                flow->pcap = (pcap_dumper_t *)pfile;
            } else {
                flow->pcap = pcap_dump_open(pbuf->pcapt, flowtab->pcap_dir);
            }
            if (flow->pcap == NULL) {
                g_warning("Pcap Create File Error: %s",
                          pcap_geterr((pcap_t *)pbuf->pcapt));
                return;
            }
        }
    }

    if (flow->pcap == NULL) {
        namebuf = g_string_new("");
        rem_ms = (flow->stime % 1000);
        rem_ms = (rem_ms > 1000) ? (rem_ms / 10) : rem_ms;
        g_string_append_printf(namebuf, "%s/%03u", flowtab->pcap_dir,
                               rem_ms);
        g_mkdir(namebuf->str, 0777);
        g_string_append_printf(namebuf, "/%u-", flowtab->hashfn(key));
        air_time_g_string_append(namebuf, (flow->stime/1000),
                                 AIR_TIME_SQUISHED);
        g_string_append_printf(namebuf, "_%d.pcap", flow->pcap_serial);
        if (g_file_test(namebuf->str, G_FILE_TEST_EXISTS)) {
            fexists = TRUE;
            pfile = fopen(namebuf->str, "ab");
            if (pfile == NULL) {
                goto err;
            }
            /* need to append to pcap - libpcap doesn't have an append fn*/
            flow->pcap = (pcap_dumper_t *)pfile;
        } else {
            flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);
        }

        if (flow->pcap == NULL) {
            goto err;
        }

        g_string_free(namebuf, TRUE);
    } else if (flowtab->max_pcap) {

        pfile = pcap_dump_file(flow->pcap);

        if ((ftell(pfile) > flowtab->max_pcap)) {

            pcap_dump_flush(flow->pcap);
            pcap_dump_close(flow->pcap);
            flow->pcap_serial += 1;
            namebuf = g_string_new("");
            rem_ms = (flow->stime %1000);
            rem_ms = (rem_ms > 1000) ? (rem_ms / 10) : rem_ms;
            g_string_append_printf(namebuf, "%s/%03u", flowtab->pcap_dir,
                                   rem_ms);
            g_string_append_printf(namebuf, "/%u-", flowtab->hashfn(key));
            air_time_g_string_append(namebuf, (flow->stime/1000),
                                     AIR_TIME_SQUISHED);
            g_string_append_printf(namebuf, "_%d.pcap", flow->pcap_serial);
            flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);

            if (flow->pcap == NULL) {
                goto err;
            }
            g_string_free(namebuf, TRUE);
        }
    }

    pcap_dump((u_char *)flow->pcap, &(pbuf->pcap_hdr), pbuf->payload);
    return;

  err:

    /* close pcap files for stale flows */

    node = flowtab->aq.tail;
    /* go until we have closed 1 */
    while (node) {
        if (node->f.pcap) {
            pcap_dump_flush(node->f.pcap);
            pcap_dump_close(node->f.pcap);
            node->f.pcap = NULL;
            break;
        }
        node = node->n;
    }

    /* if the file exists - use fopen */
    if (fexists) {
        pfile = fopen(namebuf->str, "ab");
        if (pfile == NULL) {
            g_string_free(namebuf, TRUE);
            return;
        }
        flow->pcap = (pcap_dumper_t *)pfile;
    } else {
        flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);
    }

    if (flow->pcap == NULL) {
        g_warning("Pcap-per-flow Create File Error: %s",
                  pcap_geterr((pcap_t *)pbuf->pcapt));
        g_string_free(namebuf, TRUE);
        return;
    }

    g_string_free(namebuf, TRUE);
    pcap_dump((u_char *)flow->pcap, &(pbuf->pcap_hdr), pbuf->payload);
}

/**
 * yfWritePcapMetaIndex
 *
 *
 */
static void yfWritePcapMetaIndex(
    yfFlowTab_t *flowtab,
    gboolean     packets)
{
    long       cp;
    uint64_t   count;
    int        rotate = 10000;

    if (packets) {
        count = flowtab->stats.stat_packets;
    } else {
        count = flowtab->stats.stat_flows;
        rotate=5000;
    }

    if (flowtab->stats.stat_packets == 1) {
        fprintf(flowtab->pcap_meta, "%"PRIu64"|0000000000\n", flowtab->ctime);
        flowtab->lasttime = flowtab->ctime;
    }

    if (!count) {
        return;
    }

    if ((count % rotate) == 0) {
        cp = ftell(flowtab->pcap_meta);
        if (cp == 0) {
            fprintf(flowtab->pcap_meta, "%"PRIu64"|0000000000\n", flowtab->ctime);
            flowtab->lasttime = flowtab->ctime;
        } else {
            fseek(flowtab->pcap_meta, flowtab->last_offset, SEEK_SET);
            fprintf(flowtab->pcap_meta, "%"PRIu64"|%010ld\n", flowtab->lasttime, cp);
            fseek(flowtab->pcap_meta, cp, SEEK_SET);
            flowtab->last_offset = cp;
            fprintf(flowtab->pcap_meta, "%"PRIu64"|0000000000\n", flowtab->ctime);
            flowtab->lasttime = flowtab->ctime;
        }

    }

}




/**
 * yfWritePcapMetaFile
 *
 *
 */
static void yfWritePcapMetaFile(
    yfFlowTab_t                *flowtab,
    yfFlowNode_t               *fn,
    yfPBuf_t                   *pbuf,
    uint32_t                   hash,
    uint32_t                   pcap_len)
{
    int rv;

    if (pcap_meta_read == -1) {
        yfWritePcapMetaIndex(flowtab, TRUE);
        rv = fprintf(flowtab->pcap_meta, "%u|%llu|%d|%llu|%d\n",
                     hash, (long long unsigned int)fn->f.stime,
                     pbuf->pcap_caplist,
                     (long long unsigned int)pbuf->pcap_offset,
                     pcap_len);
        if (rv < 0) {
            if (yfRotatePcapMetaFile(flowtab)) {
                yfWritePcapMetaIndex(flowtab, TRUE);
                fprintf(flowtab->pcap_meta, "%u|%llu|%d|%llu|%d\n",
                        hash, (long long unsigned int)fn->f.stime,
                        pbuf->pcap_caplist,
                        (long long unsigned int)pbuf->pcap_offset,
                        pcap_len);
            }
        } else if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE) == 0) {
            yfRotatePcapMetaFile(flowtab);
        }
    } else {
        if (flowtab->index_pcap) {
            /* print every packet */
            yfWritePcapMetaIndex(flowtab, TRUE);
            rv = fprintf(flowtab->pcap_meta, "%u|%llu|%s|%llu|%d\n",
                         hash, (long long unsigned int)fn->f.stime,
                         flowtab->pcap_roll->str,
                         (long long unsigned int)pbuf->pcap_offset, pcap_len);
            if (rv < 0) {
                if (yfRotatePcapMetaFile(flowtab)) {
                    yfWritePcapMetaIndex(flowtab, TRUE);
                    fprintf(flowtab->pcap_meta, "%u|%llu|%s|%llu|%d\n",
                            hash, (long long unsigned int)fn->f.stime,
                            flowtab->pcap_roll->str,
                            (long long unsigned int)pbuf->pcap_offset,
                            pcap_len);
                }
            } else if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE_FP) == 0)
            {
                yfRotatePcapMetaFile(flowtab);
            }
        } else if (flowtab->pcap_file_no != fn->f.pcap_file_no) {
            /* print when the flow rolls over multiple files */
            yfWritePcapMetaIndex(flowtab, FALSE);
            fprintf(flowtab->pcap_meta, "%u|%llu|%s\n",
                    hash, (long long unsigned int)fn->f.stime,
                    flowtab->pcap_roll->str);
            fn->f.pcap_file_no = flowtab->pcap_file_no;
            return;
        }
    }

}



/**
 * yfFlowPktGenericTpt
 *
 * generate flow information about packets that are not TCP
 *
 *
 * @param flowtab
 * @param fn
 * @param val
 * @param pkt
 * @param caplen
 *
 */
static void yfFlowPktGenericTpt(
    yfFlowTab_t                 *flowtab,
    yfFlowNode_t                *fn,
    yfFlowVal_t                 *val,
    const uint8_t               *pkt,
    uint32_t                    caplen)
{
    int  p;

#if YAF_ENABLE_PAYLOAD
    /* Short-circuit nth packet or no payload capture */
    if (!flowtab->max_payload || (val->pkt && !flowtab->udp_max_payload) ||
        !caplen)
    {
        return;
    }

    /* truncate capture length to payload limit */
    if (caplen + val->paylen > flowtab->max_payload) {
        caplen = flowtab->max_payload - val->paylen;
    }

    /* allocate */

    if (!val->payload) {
        val->payload = yg_slice_alloc0(flowtab->max_payload);
        val->paybounds = (size_t *)yg_slice_alloc0(sizeof(size_t) *
                                                   YAF_MAX_PKT_BOUNDARY);
    }

    memcpy(val->payload + val->paylen, pkt, caplen);

    /* Set pointer to payload for packet boundary */
    if (val->pkt < YAF_MAX_PKT_BOUNDARY) {
        p = val->pkt;
        val->paybounds[p] = val->paylen;
    }

    val->paylen += caplen;

#endif
}


/**
 * yfFlowPktTCP
 *
 * process a TCP packet into the flow table specially, capture
 * all the special TCP information, flags, seq, etc.
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the node for the relevent flow in the flow table
 * @param val
 * @param pkt pointer to the packet payload
 * @param caplen length of the capture (length of pkt)
 * @param tcpinfo pointer to the parsed tcp information
 * @param headerVal pointer to the full packet information, including IP & TCP
 * @param headerLen length of headerVal
 *
 */
static void yfFlowPktTCP(
    yfFlowTab_t                 *flowtab,
    yfFlowNode_t                *fn,
    yfFlowVal_t                 *val,
    const uint8_t               *pkt,
    uint32_t                    caplen,
    yfTCPInfo_t                 *tcpinfo,
    uint8_t                     *headerVal,
    uint16_t                    headerLen)
{
    uint32_t                    appdata_po;
    uint32_t                    last_seq_num = val->lsn;
    int                         p;

    /*Update flags in flow record - may need to upload iflags if out of order*/
    if (val->pkt && (tcpinfo->seq > val->isn)) {
        /* Union flags */
        val->uflags |= tcpinfo->flags;
    } else {
        if (val->pkt && (tcpinfo->seq <= val->isn)) {
          /*if packets out of order - don't lose other flags - add to uflags*/
            val->uflags |= val->iflags;
        }
        /* Initial flags */
        val->iflags = tcpinfo->flags;
        /* Initial sequence number */
        val->isn = tcpinfo->seq;
    }

    val->lsn = tcpinfo->seq;

    /* Update flow state for FIN flag */
    if (val == &(fn->f.val)) {
        if (tcpinfo->flags & YF_TF_FIN)
            fn->state |= YAF_STATE_FFIN;
        if ((fn->state & YAF_STATE_RFIN) && (tcpinfo->flags & YF_TF_ACK))
            fn->state |= YAF_STATE_FFINACK;
    } else {
        if (tcpinfo->flags & YF_TF_FIN)
            fn->state |= YAF_STATE_RFIN;
        if ((fn->state & YAF_STATE_FFIN) && (tcpinfo->flags & YF_TF_ACK))
            fn->state |= YAF_STATE_RFINACK;
    }

    /* Update flow state for RST flag */
    if (tcpinfo->flags & YF_TF_RST) {
        fn->state |= YAF_STATE_RST;
    }

    if (flowtab->stats_mode && (tcpinfo->flags & YF_TF_URG)) {
        val->stats->tcpurgct++;
    }

    /** MPTCP stuff */
    if (tcpinfo->mptcp.flags & 0x01) {
        /* MP_CAPABLE */
        val->attributes |= YAF_MP_CAPABLE;
    }

    if (tcpinfo->flags & YF_TF_SYN) {
        if (!fn->f.mptcp.token && tcpinfo->mptcp.token) {
            fn->f.mptcp.token = tcpinfo->mptcp.token;
        }
        /* initial priority is set in the MP_JOIN SYN or SYN/ACK */
        if (tcpinfo->mptcp.flags & 0x02) {
            fn->f.mptcp.flags |= YF_MF_PRIORITY;
        }
    } else if (tcpinfo->mptcp.flags & 0x02) {
        fn->f.mptcp.flags |= YF_MF_PRIO_CHANGE;
    }

    if (!fn->f.mptcp.idsn) {
        fn->f.mptcp.idsn = tcpinfo->mptcp.idsn;
    }

    fn->f.mptcp.mss = tcpinfo->mptcp.mss;

    fn->f.mptcp.flags |= (tcpinfo->mptcp.flags & 0xFC);

    if (!fn->f.mptcp.addrid) {
        fn->f.mptcp.addrid = tcpinfo->mptcp.addrid;
    }


#if YAF_ENABLE_P0F

    /* run through p0f if it's enabled here */
    if (flowtab->fingerprintmode) {
        /* do os fingerprinting if enabled */
        if (NULL == val->osname) {
            GError *err = NULL;
            struct packetDecodeDetails_st packetDetails;
            gboolean fuzzyMatched;

            /* run everything through the p0f finger printer now */
            if (!yfpPacketParse(headerVal, headerLen, &packetDetails, &err)) {
                g_clear_error(&err);
            } else {
                if (!yfpSynFindMatch(&packetDetails, TRUE, &fuzzyMatched,
                                     &(val->osname), &(val->osver),
                                     &(val->osFingerPrint), &err))
                    {
                        g_warning("Error finger printing packet: %s",
                                  err->message);
                        g_clear_error(&err);
                    }
            }
        }
    }
#endif

#if YAF_ENABLE_FPEXPORT
    if (flowtab->fingerprintExport && headerVal) {
      /* Let's capture the detailed header information for the first 3 packets
         mostly for external OS id'ing*/
        if (&(fn->f.val) == val) {
            if (NULL == val->firstPacket) {
                val->firstPacket = yg_slice_alloc0(YFP_IPTCPHEADER_SIZE);
                val->firstPacketLen = headerLen;
                memcpy(val->firstPacket, headerVal, headerLen);
            } else if (NULL == val->secondPacket) {
                val->secondPacket = yg_slice_alloc0(YFP_IPTCPHEADER_SIZE);
                val->secondPacketLen = headerLen;
                memcpy(val->secondPacket, headerVal, headerLen);
            }
        } else {
            if (NULL == val->firstPacket) {
               val->firstPacket = yg_slice_alloc0(YFP_IPTCPHEADER_SIZE);
               val->firstPacketLen = headerLen;
               memcpy(val->firstPacket, headerVal, headerLen);
            }
        }
    }
#endif

#if YAF_ENABLE_PAYLOAD
    /* short circuit no payload capture, continuation,
       payload full, or no payload in packet */
    if (!flowtab->max_payload || !(val->iflags & YF_TF_SYN) ||
        caplen == 0)
    {
        return;
    }

    if (last_seq_num == (tcpinfo->seq + 1)) {
        /* TCP KEEP ALIVE */
        return;
    }

    /* Find app data offset in payload buffer */
    appdata_po = tcpinfo->seq - (val->isn + 1);

    /* allocate and copy */
    if (!val->payload) {
        val->payload = yg_slice_alloc0(flowtab->max_payload);
        val->paybounds = (size_t *)yg_slice_alloc0(sizeof(size_t) *
                                                   YAF_MAX_PKT_BOUNDARY);
    }

    if (val->pkt < YAF_MAX_PKT_BOUNDARY) {
        p = val->pkt;
        val->paybounds[p] = appdata_po;
    }

    /* leave open the case in which we receive an out of order packet */
    if ((val->paylen == flowtab->max_payload) &&
        (appdata_po >= flowtab->max_payload))
    {
        return;
    }

    /* Short circuit entire packet after capture filter */
    if (appdata_po >= flowtab->max_payload) return;

    /* truncate payload copy length to capture length */
    if ((appdata_po + caplen) > flowtab->max_payload) {
        caplen = flowtab->max_payload - appdata_po;
        if (caplen > flowtab->max_payload) {
            caplen = flowtab->max_payload;
        }
    }

    if (val->paylen < appdata_po + caplen) {
        val->paylen = appdata_po + caplen;
    }
    memcpy(val->payload + appdata_po, pkt, caplen);
#endif
}

static void
yfFlowStatistics(
    yfFlowNode_t            *fn,
    yfFlowVal_t             *val,
    uint64_t                ptime,
    uint16_t                datalen)
{

    if (val->stats->ltime) {
        val->stats->aitime += (ptime - val->stats->ltime);
    }

    if (val->pkt > 1 && val->pkt < 12) {
        val->stats->iaarray[val->pkt -2] = (ptime - val->stats->ltime);
    }

    val->stats->ltime = fn->f.etime;

    if (datalen) {
        /* that means there is some payload */
        if (val == &(fn->f.rval)) {
            fn->f.pktdir |= (1 << (fn->f.val.stats->nonemptypktct +
                                   val->stats->nonemptypktct));
        }
        if (val->stats->nonemptypktct < 10) {
            val->stats->pktsize[val->stats->nonemptypktct] = datalen;
        }
        val->stats->nonemptypktct++;
        if (datalen < 60) {
            val->stats->smallpktct++;
        } else if (datalen > 225) {
            val->stats->largepktct++;
        }
        val->stats->payoct += datalen;
        if (val->stats->firstpktsize== 0) {
            val->stats->firstpktsize= datalen;
        }
        if (datalen> val->stats->maxpktsize) {
            val->stats->maxpktsize =datalen;
        }
    }

}


static void
yfAddOutOfSequence(
    yfFlowTab_t             *flowtab,
    yfFlowKey_t             *key,
    size_t                  pbuflen,
    yfPBuf_t                *pbuf)
{
    yfFlowNode_t            *fn = NULL;
    yfFlowNode_t            *tn = NULL;
    yfFlowNode_t            *nfn = NULL;
    yfFlowKey_t             rkey;
    uint64_t                end;
    yfFlowVal_t             *val = NULL;
    yfTCPInfo_t             *tcpinfo = &(pbuf->tcpinfo);
    yfL2Info_t              *l2info = &(pbuf->l2info);
    uint8_t                 *payload = (pbuflen >= YF_PBUFLEN_BASE) ?
                                       pbuf->payload : NULL;
    size_t                  paylen = (pbuflen >= YF_PBUFLEN_BASE) ?
                                     pbuf->paylen : 0;
    uint16_t                datalen = (pbuf->iplen - pbuf->allHeaderLen +
                                       l2info->l2hlen);
    uint32_t                pcap_len = 0;
    gboolean                rev = FALSE;
    GHashTable              *ht;
#if YAF_MPLS
    yfMPLSNode_t            *mpls = NULL;

    ht = flowtab->cur_mpls_node->tab;
    mpls = yfMPLSGetNode(flowtab, l2info);
#else
    ht = flowtab->table;
#endif

    /* Count the packet and its octets */
    ++(flowtab->stats.stat_packets);
    flowtab->stats.stat_octets += pbuf->iplen;

    if (payload) {
        if (paylen >= pbuf->allHeaderLen) {
            paylen -= pbuf->allHeaderLen;
            payload += pbuf->allHeaderLen;
        } else {
            paylen = 0;
            payload = NULL;
        }
    }

    /* Look for flow in table */
    if ((fn = g_hash_table_lookup(ht, key))) {
        /* Forward flow found. */
        val = &(fn->f.val);
    }

    if (fn == NULL) {
        /* Okay. Check for reverse flow. */
        yfFlowKeyReverse(key, &rkey);
        rev = TRUE;
        if ((fn = g_hash_table_lookup(ht, &rkey))) {
            /* Reverse flow found. */
            val = &(fn->f.rval);
        }
    }

    if (fn == NULL) {
        /* Neither exists. Create a new flow and put it in the table. */
#if YAF_ENABLE_COMPACT_IP4
        if (key->version == 4) {
            fn = (yfFlowNode_t *)yg_slice_new0(yfFlowNodeIPv4_t);
        } else {
#endif
            fn = yg_slice_new0(yfFlowNode_t);
#if YAF_ENABLE_COMPACT_IP4
        }
#endif
        /* Copy key */
        yfFlowKeyCopy(key, &(fn->f.key));

        /* set flow start time */
        fn->f.stime = pbuf->ptime;

        /* set flow end time as start time */
        fn->f.etime = pbuf->ptime;

        /* stuff the flow in the table */
        g_hash_table_insert(ht, &(fn->f.key), fn);

        /* This is a forward flow */
        val = &(fn->f.val);

        /* Count it */
        ++(flowtab->count);
#if YAF_MPLS
        fn->f.mpls = flowtab->cur_mpls_node;
        ++(flowtab->cur_mpls_node->tab_count);
#endif

        if (flowtab->count > flowtab->stats.stat_peak) {
            flowtab->stats.stat_peak = flowtab->count;
        }

#if YAF_ENABLE_HOOKS
        /*Let the hook allocate its context */
        yfHookFlowAlloc(&(fn->f), flowtab->yfctx);
#endif
    }

    if (val->pkt == 0) {
        /* Note Mac Addr */
        if (flowtab->macmode && (val == &(fn->f.val))) {
            if (l2info) {
                memcpy(fn->f.sourceMacAddr, l2info->smac,
                       ETHERNET_MAC_ADDR_LENGTH);
                memcpy(fn->f.destinationMacAddr, l2info->dmac,
                       ETHERNET_MAC_ADDR_LENGTH);
            }
        }
        /* Allocate Flow Statistics */
        if (flowtab->stats_mode) {
            val->stats = yg_slice_new0(yfFlowStats_t);
        }
    }

    /* packet exists now, update info */

    /* Do payload and TCP stuff */
    if (fn->f.key.proto == YF_PROTO_TCP) {
        /* Handle TCP flows specially (flags, ISN, sequenced payload) */
        if (datalen) {
            if (val->appkt == 0) {
                val->first_pkt_size = datalen;
            } else {
                if (datalen == val->first_pkt_size) {
                    if (val->appkt == 1) {
                        val->attributes |= YAF_SAME_SIZE;
                    }
                } else {
                    /* Don't consider TCP KEEP ALIVE */
                    if (val->lsn != (tcpinfo->seq + 1)) {
                        val->attributes &= 0xFE;
                    }
                }
            }
            val->appkt += 1;
        }
#if YAF_ENABLE_P0F || YAF_ENABLE_FPEXPORT
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo,
                     pbuf->headerVal, pbuf->headerLen);
#else
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo, NULL, 0);
#endif

    } else {
        if (val->pkt == 0) {
            val->first_pkt_size = pbuf->iplen;
        } else {
            if (pbuf->iplen == val->first_pkt_size) {
                if (val->pkt == 1) {
                    val->attributes |= YAF_SAME_SIZE;
                }
            } else {
                val->attributes &= 0xFE;
            }
        }
        if ((val->pkt == 0 || flowtab->udp_max_payload)) {
            if (((flowtab->udp_uniflow_port != 1) &&
                 (flowtab->udp_uniflow_port != fn->f.key.sp) &&
                 (flowtab->udp_uniflow_port != fn->f.key.dp)))
            {
                /* Get first packet payload from non-TCP flows */
                yfFlowPktGenericTpt(flowtab, fn, val, payload, paylen);
            }
        }
    }

    /* set flow attributes - this flow is out of order */
    val->attributes |= YAF_OUT_OF_SEQUENCE;

    /* Mark if fragmented */
    if (pbuf->frag == 1) {
        val->attributes |= YAF_FRAGMENTS;
    }

    /* Count packets and octets */
    val->oct += pbuf->iplen;
    val->pkt += 1;

    /* don't update end time - stime could be greater than etime */

    /* Update stats */
    if (flowtab->stats_mode) {
        yfFlowStatistics(fn, val, pbuf->ptime, datalen);
    }


#if YAF_ENABLE_HOOKS
    /* Hook Flow Processing */
    yfHookFlowPacket(&(fn->f), val, payload,
                     paylen, pbuf->iplen, tcpinfo, l2info);
#endif

    pcap_len = pbuf->pcap_hdr.caplen + 16;

    /* Write Packet to Pcap-Per-Flow pcap file */
    if (flowtab->pcap_dir) {
        /* what we actually hold in yaf dependent on max-payload */
        pbuf->pcap_hdr.caplen = (pbuflen > YF_PBUFLEN_BASE) ? pbuf->paylen :0;
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcap(flowtab, &(fn->f), &rkey, pbuf);
        } else {
            yfWritePcap(flowtab, &(fn->f), key, pbuf);
        }
    }

    /* Write Pcap Meta Info */
    if (flowtab->pcap_meta) {
        if (rev) {
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(&rkey),
                                pcap_len);
        } else {
            yfWritePcapMetaFile(flowtab, fn, pbuf,flowtab->hashfn(key),pcap_len);
        }
    }

    /* if udp-uniflow-mode, close UDP flow now */
    if ((fn->f.key.proto == YF_PROTO_UDP) && (flowtab->udp_uniflow_port != 0)){
        if (((flowtab->udp_uniflow_port == 1) ||
             (flowtab->udp_uniflow_port == fn->f.key.sp) ||
             (flowtab->udp_uniflow_port == fn->f.key.dp)))
        {
            yfCloseActiveFlow(flowtab, fn, val, payload, paylen,
                              YAF_END_UDPFORCE, pbuf->iplen);
        }
    }

    /* close flow, or move it to head of queue */
    if ((fn->state & YAF_STATE_FIN) == YAF_STATE_FIN ||
        fn->state & YAF_STATE_RST)
    {
        yfFlowClose(flowtab, fn, YAF_END_CLOSED);
        return;
    }

    /* Check for inactive timeout - this flow might be idled out on arrival */
    if ((flowtab->ctime - pbuf->ptime) > flowtab->idle_ms) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    } else if (flowtab->idle_ms == 0) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    }

    if (flowtab->aq.head == NULL) {
        yfFlowTick(flowtab, fn);
        return;
    }

    /* rip through the active queue and put this in the right spot */
    /* first remove the node */
    piqPick(&flowtab->aq, fn);

    for (tn = flowtab->aq.head; tn; tn=nfn) {
        end = tn->f.etime;
        nfn = tn->p;
        if (end <= fn->f.etime) {
            if (tn != flowtab->aq.head) {
                /* nfn is previous node */
                nfn = tn->n;
                /* point previous (next) to new node */
                nfn->p = fn;
                /* point current previous to new node */
                tn->n = fn;
                /* point new node's next to current */
                fn->p = tn;
                /* point new node's previous to previous */
                fn->n = nfn;
                /*yfFlowTabVerifyIdleOrder(flowtab);*/
            } else {
                /* we're at the head */
                /* set new node's previous to current head */
                fn->p = tn;
                /* set current's head next to new node */
                tn->n = fn;
                /* set flowtab head to new node */
                flowtab->aq.head = fn;
            }
            return;
        }
    }

    /* if this happens, we are at the tail */
    if (flowtab->aq.tail) {
        nfn = flowtab->aq.tail;
        /* this flow's next (in non-Brian land - previous) is the tail */
        fn->n = nfn;
        /* the tail's previous (next) now points to new node */
        nfn->p = fn;
        /* tail is now new node */
        flowtab->aq.tail = fn;
    } else {
        /* shouldn't get here but if we do,just get rid of this troublemaker.*/
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
    }
}
#if YAF_ENABLE_NDPI

/**
 * yfNDPIApplabel
 *
 */
static void yfNDPIApplabel(
    yfFlowTab_t          *flowtab,
    yfFlow_t             *flow,
    uint8_t              *payload,
    size_t               paylen)
{
    struct ndpi_flow_struct *nflow;
    struct ndpi_id_struct src, dst;
    ndpi_protocol proto;

    if (paylen == 0) {
        return;
    }

    nflow = malloc(sizeof(struct ndpi_flow_struct));
    memset(nflow, 0, sizeof(struct ndpi_flow_struct));
    memset(&src, 0, sizeof(struct ndpi_id_struct));
    memset(&dst, 0, sizeof(struct ndpi_id_struct));

    proto = ndpi_detection_process_packet(flowtab->ndpi_struct, nflow, payload,
                                          paylen, flow->etime, &src, &dst);
    flow->ndpi_master = proto.master_protocol;
    flow->ndpi_sub = proto.protocol;

    /* g_debug("proto is %d other is %d", proto.master_protocol, proto.protocol); */
    ndpi_free_flow(nflow);

}
#endif

/**
 * yfFlowPBuf
 *
 * parse a packet buffer structure and turn it into a flow record
 * this may update an existing flow record, or get a new flow record
 * and populate it.  It calls various functions to decode the
 * packet buffer and extract protocol details
 *
 * @param flowtab pointer to the flow table
 * @param pbuflen length of the packet buffer
 * @param pbuf pointer to the packet data
 *
 */
void yfFlowPBuf(
    yfFlowTab_t                 *flowtab,
    size_t                      pbuflen,
    yfPBuf_t                    *pbuf)
{
    yfFlowKey_t                 *key = &(pbuf->key);
    yfFlowKey_t                 rkey;
    yfFlowVal_t                 *val = NULL;
    yfFlowNode_t                *fn = NULL;
    yfTCPInfo_t                 *tcpinfo = &(pbuf->tcpinfo);
    yfL2Info_t                  *l2info = &(pbuf->l2info);
    uint8_t                     *payload = (pbuflen >= YF_PBUFLEN_BASE) ?
                                           pbuf->payload : NULL;
    size_t                      paylen = (pbuflen >= YF_PBUFLEN_BASE) ?
                                         pbuf->paylen : 0;
    uint16_t                    datalen = (pbuf->iplen - pbuf->allHeaderLen +
                                           l2info->l2hlen);
    uint32_t                    pcap_len = 0;
#if YAF_MPLS
    yfMPLSNode_t                *mpls = NULL;
#endif
#if YAF_ENABLE_APPLABEL
    uint16_t                    tapp = 0;
#endif

    /* skip and count out of sequence packets */
    if (pbuf->ptime < flowtab->ctime) {
        if (!flowtab->force_read_all) {
            ++(flowtab->stats.stat_seqrej);
            return;
        } else {
            yfAddOutOfSequence(flowtab, key, pbuflen, pbuf);
            return;
        }
    }

    /* update flow table current time */
    flowtab->ctime = pbuf->ptime;

    /* Count the packet and its octets */
    ++(flowtab->stats.stat_packets);
    flowtab->stats.stat_octets += pbuf->iplen;

    if (payload) {
        if (paylen >= pbuf->allHeaderLen) {
            paylen -= pbuf->allHeaderLen;
            payload += pbuf->allHeaderLen;
        } else {
            paylen = 0;
            payload = NULL;
        }
    }

#if YAF_ENABLE_HOOKS
    /* Run packet hook; allow it to veto continued processing of the packet */
    if (!yfHookPacket(key, payload, paylen,
                      pbuf->iplen, tcpinfo, l2info))
    {
        return;
    }
#endif

#if YAF_MPLS
    mpls = yfMPLSGetNode(flowtab, l2info);
#endif
    /* Get a flow node for this flow */
    fn = yfFlowGetNode(flowtab, key, &val);
    /* Check for active timeout or counter overflow */
    if (((pbuf->ptime - fn->f.stime) > flowtab->active_ms) ||
        (flowtab->silkmode && (val->oct + pbuf->iplen > UINT32_MAX)))
    {
        yfFlowClose(flowtab, fn, YAF_END_ACTIVE);
#if YAF_ENABLE_APPLABEL
        /* copy applabel over */
        if (flowtab->applabelmode) tapp = fn->f.appLabel;
#endif
        /* get a new flow node containing this packet */
        fn = yfFlowGetNode(flowtab, key, &val);
        /* set continuation flag in silk mode */
        if (flowtab->silkmode) fn->f.reason = YAF_ENDF_ISCONT;
#if YAF_ENABLE_APPLABEL
        /* copy applabel into new flow */
        if (flowtab->applabelmode) fn->f.appLabel = tapp;
#endif
    }

    /* Check for inactive timeout - esp when reading from pcap */
    if ((pbuf->ptime - fn->f.etime) > flowtab->idle_ms) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        /* get a new flow node for the current packet */
        fn = yfFlowGetNode(flowtab, key, &val);
    }


    /* First Packet? */
    if (val->pkt == 0) {
        val->vlan = key->vlanId;
        if (flowtab->macmode && val == &(fn->f.val)) {
            /* Note Mac Addr */
            if (l2info) {
                memcpy(fn->f.sourceMacAddr, l2info->smac,
                       ETHERNET_MAC_ADDR_LENGTH);
                memcpy(fn->f.destinationMacAddr, l2info->dmac,
                       ETHERNET_MAC_ADDR_LENGTH);
            }
        }
        /* Allocate Flow Statistics */
        if (flowtab->stats_mode) {
            val->stats = yg_slice_new0(yfFlowStats_t);
        }
        /* Calculate reverse RTT */
        if (val == &(fn->f.rval)) {
            fn->f.rdtime = pbuf->ptime - fn->f.stime;
        }
    }

    /* Do payload and TCP stuff */
    if (fn->f.key.proto == YF_PROTO_TCP) {
        /* Handle TCP flows specially (flags, ISN, sequenced payload) */
        if (datalen) {
            if (val->appkt == 0) {
                val->first_pkt_size = datalen;
            } else {
                if (datalen == val->first_pkt_size) {
                    if (val->appkt == 1) {
                        val->attributes |= YAF_SAME_SIZE;
                    }
                } else {
                    /* Don't consider TCP KEEP ALIVE */
                    if (val->lsn != (tcpinfo->seq + 1)) {
                        val->attributes &= 0xFE;
                    }
                }
            }
            val->appkt += 1;
        }
#if YAF_ENABLE_P0F || YAF_ENABLE_FPEXPORT
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo,
                     pbuf->headerVal, pbuf->headerLen);
#else
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo, NULL, 0);
#endif
    } else {
        if (val->pkt == 0) {
            val->first_pkt_size = pbuf->iplen;
        } else {
            if (pbuf->iplen == val->first_pkt_size) {
                if (val->pkt == 1) {
                    val->attributes |= YAF_SAME_SIZE;
                }
            } else {
                val->attributes &= 0xFE;
            }
        }
        if ((val->pkt == 0 || flowtab->udp_max_payload)) {
            if (((flowtab->udp_uniflow_port != 1) &&
                 (flowtab->udp_uniflow_port != fn->f.key.sp) &&
                 (flowtab->udp_uniflow_port != fn->f.key.dp)))
            {
                /* Get first packet payload from non-TCP flows */
                yfFlowPktGenericTpt(flowtab, fn, val, payload, paylen);
            }
        }
    }

#if YAF_ENABLE_SEPARATE_INTERFACES
    val->netIf = pbuf->key.netIf;
#endif

    /* Count packets and octets */
    val->oct += pbuf->iplen;
    val->pkt += 1;

    /* Mark if fragmented */
    if (pbuf->frag == 1) {
        val->attributes |= YAF_FRAGMENTS;
    }

    /* update flow end time */
    fn->f.etime = pbuf->ptime;

    /* Update stats */
    if (flowtab->stats_mode) {
        yfFlowStatistics(fn, val, pbuf->ptime, datalen);
    }

#if YAF_ENABLE_HOOKS
    /* Hook Flow Processing */
    yfHookFlowPacket(&(fn->f), val, payload, paylen, pbuf->iplen,
                     tcpinfo, l2info);
#endif

    pcap_len = pbuf->pcap_hdr.caplen + 16;
    /* Write Packet to Pcap-Per-Flow pcap file */
    if (flowtab->pcap_dir) {
        /* what we actually hold in yaf dependent on max-payload */
        pbuf->pcap_hdr.caplen = (pbuflen > YF_PBUFLEN_BASE) ? pbuf->paylen :0;
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcap(flowtab, &(fn->f), &rkey, pbuf);
        } else {
            yfWritePcap(flowtab, &(fn->f), key, pbuf);
        }
    }

    /* Write Pcap Meta Info */
    if (flowtab->pcap_meta) {
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(&rkey),
                                pcap_len);
        } else {
            yfWritePcapMetaFile(flowtab, fn, pbuf,flowtab->hashfn(key),pcap_len);
        }
    }

#if YAF_ENABLE_NDPI
    if (flowtab->ndpi_struct && payload && (fn->f.ndpi_master == 0)) {
        yfNDPIApplabel(flowtab, &(fn->f),
                       payload - pbuf->allHeaderLen + l2info->l2hlen,
                       paylen + pbuf->allHeaderLen - l2info->l2hlen);
    }
#endif

    /* if udp-uniflow-mode, close UDP flow now */
    if ((fn->f.key.proto == YF_PROTO_UDP) && (flowtab->udp_uniflow_port != 0)){
        if (((flowtab->udp_uniflow_port == 1) ||
             (flowtab->udp_uniflow_port == fn->f.key.sp) ||
             (flowtab->udp_uniflow_port == fn->f.key.dp)))
        {
            yfCloseActiveFlow(flowtab, fn, val, payload, paylen,
                              YAF_END_UDPFORCE, pbuf->iplen);
        }
    }

    if (flowtab->idle_ms == 0) {
        /* each pkt as a flow */
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    }

    /* close flow, or move it to head of queue */
    if ((fn->state & YAF_STATE_FIN) == YAF_STATE_FIN ||
        fn->state & YAF_STATE_RST)
    {
        yfFlowClose(flowtab, fn, YAF_END_CLOSED);
    } else {
        yfFlowTick(flowtab, fn);
    }

}

/**
 * yfUniflow
 *
 * creates a uniflow record from a biflow record, in order to split
 * the record into a single record for uniflow only collection systems
 *
 * @param bf pointer to normal biflow yaf flow record
 * @param uf pointer to a new flow record, that will have its rev
 *           (reverse) values NULLed
 *
 */
static void yfUniflow(
    yfFlow_t          *bf,
    yfFlow_t          *uf)
{

#if YAF_ENABLE_COMPACT_IP4
    if (bf->key.version == 4) {
        memcpy(uf, bf, sizeof(yfFlowIPv4_t));
    } else {
#endif
        memcpy(uf, bf, sizeof(yfFlow_t));
#if YAF_ENABLE_COMPACT_IP4
    }
#endif
    memset(&(uf->rval), 0, sizeof(yfFlowVal_t));
    uf->rdtime = 0;
}

/**
 * yfUniflowReverse
 *
 * reverses the flow information in the biflow in order to generate
 * two uniflow outputs
 *
 *
 * @param bf pointer to biflow record
 * @param uf pointer to uniflow record to fill in
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean yfUniflowReverse(
    yfFlow_t          *bf,
    yfFlow_t          *uf)
{
    if (!(bf->rval.pkt)) return FALSE;

    /* calculate reverse time */
    uf->stime = bf->stime + bf->rdtime;
    uf->etime = bf->etime;
    uf->rdtime = 0;

    memcpy(uf->sourceMacAddr, bf->destinationMacAddr,
           ETHERNET_MAC_ADDR_LENGTH);
    memcpy(uf->destinationMacAddr, bf->sourceMacAddr,
           ETHERNET_MAC_ADDR_LENGTH);

    /* reverse key */
    yfFlowKeyReverse(&bf->key, &uf->key);

    /* copy and reverse value */
    memcpy(&(uf->val), &(bf->rval), sizeof(yfFlowVal_t));
    memset(&(uf->rval), 0, sizeof(yfFlowVal_t));

    /* copy reason */
    uf->reason = bf->reason;
    uf->key.tos = bf->rtos;

    /* all done */
    return TRUE;
}

/**
 * yfFlowTabFlush
 *
 *
 *
 */
gboolean yfFlowTabFlush(
    void            *yfContext,
    gboolean        close,
    GError          **err)
{
    gboolean        wok = TRUE;
    yfFlowNode_t    *fn = NULL;
    yfFlow_t        uf;
    yfContext_t     *ctx = (yfContext_t *)yfContext;
    yfFlowTab_t     *flowtab = ctx->flowtab;

    if (!close && flowtab->flushtime &&
        (flowtab->ctime < flowtab->flushtime + YF_FLUSH_DELAY)
        && (flowtab->cq_count < YF_MAX_CQ))
    {
        return TRUE;
    }

    flowtab->flushtime = flowtab->ctime;

    /* Count the flush */
    ++flowtab->stats.stat_flush;

    /* Verify flow table order */
    /* yfFlowTabVerifyIdleOrder(flowtab);*/
    /* close idle flows */
    while (flowtab->aq.tail &&
           (flowtab->ctime - flowtab->aq.tail->f.etime > flowtab->idle_ms))
    {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_IDLE);
    }

    /* close limited flows */
    while (flowtab->max_flows &&
           flowtab->aq.tail &&
           flowtab->count >= flowtab->max_flows)
    {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_RESOURCE);
    }

    /* close all flows if flushing all */
    while (close && flowtab->aq.tail) {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_FORCED);
    }

    /* flush flows from close queue */
    while ((fn = piqDeQ(&flowtab->cq))) {
        /* quick accounting of asymmetric/uniflow records present */
        if ((fn->f.rval.oct == 0) && (fn->f.rval.pkt == 0)) {
            ++(flowtab->stats.stat_uniflows);
        }
        /* write flow */
        if (flowtab->uniflow) {
            /* Uniflow mode. Split flow in two and write. */
            yfUniflow(&(fn->f), &uf);
            wok = yfWriteFlow(ctx, &uf, err);
            if (wok) {
                ++(flowtab->stats.stat_flows);
            }
            if (wok && yfUniflowReverse(&(fn->f), &uf)) {
                wok = yfWriteFlow(ctx, &uf, err);
                if (wok) {
                    ++(flowtab->stats.stat_flows);
                }
            }
        } else {
            /* Biflow mode. Write flow whole. */
            wok = yfWriteFlow(ctx, &(fn->f), err);
            if (wok) {
                ++(flowtab->stats.stat_flows);
            }
        }
        --(flowtab->cq_count);

        /* free it */
        yfFlowFree(flowtab, fn);

        /* return error if necessary */
        if (!wok) return wok;
    }

    return TRUE;
}

/**
 * yfFlowTabCurrentTime
 *
 *
 *
 *
 */
uint64_t yfFlowTabCurrentTime(
    yfFlowTab_t     *flowtab)
{
    return flowtab->ctime;
}


/**
 * yfFlowDumpStats
 *
 * prints out statistics about flow, packet rates along with some
 * internal diagnostic type statistics as requested
 *
 *
 * @param flowtab pointer to the flow table
 * @param timer a glib timer to calculate rates for the flow table
 *
 *
 */
uint64_t yfFlowDumpStats(
    yfFlowTab_t     *flowtab,
    GTimer          *timer)
{
    g_debug("Processed %llu packets into %llu flows:",
            (long long unsigned int)flowtab->stats.stat_packets,
            (long long unsigned int)flowtab->stats.stat_flows);
    if (timer) {
        g_debug("  Mean flow rate %.2f/s.",
                ((double)flowtab->stats.stat_flows / g_timer_elapsed(timer, NULL)));
        g_debug("  Mean packet rate %.2f/s.",
                ((double)flowtab->stats.stat_packets / g_timer_elapsed(timer, NULL)));
        g_debug("  Virtual bandwidth %.4f Mbps.",
                ((((double)flowtab->stats.stat_octets * 8.0) / 1000000) /
                 g_timer_elapsed(timer, NULL)));
    }
    g_debug("  Maximum flow table size %u.", flowtab->stats.stat_peak);
    g_debug("  %u flush events.", flowtab->stats.stat_flush);
#if YAF_MPLS
    g_debug("  %u Max. MPLS Nodes.", flowtab->stats.max_mpls_labels);
#endif
    if (flowtab->stats.stat_seqrej) {
        g_warning("Rejected %"PRIu64" out-of-sequence packets.",
                  flowtab->stats.stat_seqrej);
    }
    g_debug("  %"PRIu64" asymmetric/unidirectional flows detected (%2.2f%%)",
            flowtab->stats.stat_uniflows,
            (((double)flowtab->stats.stat_uniflows)/((double)flowtab->stats.stat_flows)) * 100);

    return flowtab->stats.stat_packets;
}
