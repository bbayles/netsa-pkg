/*
** Copyright (C) 2016-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: skaggbag.c fa795ed4016d 2023-09-05 20:52:36Z mthomas $");

#include <silk/skaggbag.h>
#include <silk/skipaddr.h>
#include <silk/redblack.h>
#include <silk/utils.h>
#include "skheader_priv.h"


/*
 *    Provides support for tracing the functions that implement the
 *    AggBag code.
 */
#ifndef AGGBAG_TRACE
#define AGGBAG_TRACE    0
#endif


/**
 *    ab_layout_t describes the fields that comprise the key or the
 *    counter of an AggBag.  The definition of this type is below.
 */
typedef struct ab_layout_st ab_layout_t;

/**
 *    rbtree_node_t represents the node of the red black tree that is
 *    used to implement the AggBag data structure.  The definition of
 *    this type is below.
 */
typedef struct rbtree_node_st rbtree_node_t;

/**
 *    sk_aggbag_t is the AggBag data structure.
 */
struct sk_aggbag_st {
    /* Description of the key ([0]) and counter ([1]) fields. */
    const ab_layout_t  *layout[2];

    /* The top of the tree */
    rbtree_node_t      *root;
    /* Options to use when writing the AggBag */
    const sk_aggbag_options_t  *options;
    /* Number of items in the tree */
    size_t              size;
    /* Length of a single data item in the tree */
    size_t              data_len;
    /* Size to use when allocating an rbtree_node_t */
    size_t              node_size;
    /* True once certain operations have occurred on the AggBag that
     * make it impossible to change the fields */
    unsigned            fixed_fields  : 1;
};
/* typedef struct sk_aggbag_st sk_aggbag_t; */


/**
 *    This value must be larger than the maximum SKAGGBAG_FIELD_*
 *    identifier that is supported by the code.
 */
#define AB_LAYOUT_BMAP_SIZE     65536


/**
 *    ab_field_t describes an individual field in the key or counter.
 *    The ab_layout_t has an array of these.
 */
struct ab_field_st {
    /*  The octet length of this field */
    uint16_t            f_len;
    /*  The octet offset of this field from the first field in the
     *  ab_layout_t */
    uint16_t            f_offset;
    /*  The type of this field */
    sk_aggbag_type_t    f_type;
};
typedef struct ab_field_st ab_field_t;


/*
 *    ab_layout_t describes the fields that comprise the key or the
 *    counter of an AggBag.  Create via abLayoutCreate() and destroy
 *    via abLayoutDestroy().
 */
struct ab_layout_st {
    /*  A bitmap of the fields in this layout.  Used to compare
     *  layouts between different AggBag structures */
    BITMAP_DECLARE(bitmap, AB_LAYOUT_BMAP_SIZE);
    /*  Number of times this layout has been referenced */
    unsigned int        ref_count;
    /*  Number of fields in this layout */
    unsigned int        field_count;
    /*  Sum of the octet lengths of the fields in this layout */
    unsigned int        field_octets;
    /*  List of fields in this layout */
    ab_field_t         *fields;
};
/* typedef struct ab_layout_st ab_layout_t;     // ABOVE */


/**
 *    ab_type_info_t is a structure that describes an individual field
 *    type that the AggBag code supports.
 */
struct ab_type_info_st {
    const char         *ti_name;
    uint8_t             ti_octets;
    sk_aggbag_type_t    ti_type;
    uint8_t             ti_key_counter;
    const char         *ti_description;
};
typedef struct ab_type_info_st ab_type_info_t;


/*
 *    Whether the custom field is supported.  The code assumes this is
 *    off.  Enabling the custom field requires more changes than just
 *    setting this parameter to a true value.
 */
#define AB_SUPPORT_CUSTOM       0


/*  LOCAL VARIABLES  */

/*
 *    A data structure to hold all the ab_layout_t structures that
 *    have been defined.
 */
static struct rbtree *layouts;

/*
 *    The number of those layouts.
 */
static unsigned int layouts_count;


static const ab_type_info_t ab_type_info_key[] = {
    {"sIPv4",            4, SKAGGBAG_FIELD_SIPv4,           SK_AGGBAG_KEY,
     "source IP address, IPv4 only"},
    {"dIPv4",            4, SKAGGBAG_FIELD_DIPv4,           SK_AGGBAG_KEY,
     "destination IP address, IPv4 only"},
    {"sPort",            2, SKAGGBAG_FIELD_SPORT,           SK_AGGBAG_KEY,
     "source port"},
    {"dPort",            2, SKAGGBAG_FIELD_DPORT,           SK_AGGBAG_KEY,
     "destination port"},
    {"protocol",         1, SKAGGBAG_FIELD_PROTO,           SK_AGGBAG_KEY,
     "IP protocol"},
    {"packets",          4, SKAGGBAG_FIELD_PACKETS,         SK_AGGBAG_KEY,
     "packet count in an individual record"},
    {"bytes",            4, SKAGGBAG_FIELD_BYTES,           SK_AGGBAG_KEY,
     "byte (octet) count in an individual record"},
    {"flags",            1, SKAGGBAG_FIELD_FLAGS,           SK_AGGBAG_KEY,
     "bit-wise OR of TCP flags over all packets"},
    {"sTime",            4, SKAGGBAG_FIELD_STARTTIME,       SK_AGGBAG_KEY,
     "starting time of the flow in seconds"},
    {"duration",         4, SKAGGBAG_FIELD_ELAPSED,         SK_AGGBAG_KEY,
     "duration of the flow in seconds"},
    {"eTime",            4, SKAGGBAG_FIELD_ENDTIME,         SK_AGGBAG_KEY,
     "ending time of the flow in seconds"},
    {"sensor",           2, SKAGGBAG_FIELD_SID,             SK_AGGBAG_KEY,
     "sensor name or ID at the collection point"},
    {"input",            2, SKAGGBAG_FIELD_INPUT,           SK_AGGBAG_KEY,
     "router SNMP ingress interface or vlanId"},
    {"output",           2, SKAGGBAG_FIELD_OUTPUT,          SK_AGGBAG_KEY,
     "router SNMP egress interface or postVlanId"},
    {"nhIPv4",           4, SKAGGBAG_FIELD_NHIPv4,          SK_AGGBAG_KEY,
     "next-hop IP address, IPv4 only"},
    {"initialFlags",     1, SKAGGBAG_FIELD_INIT_FLAGS,      SK_AGGBAG_KEY,
     "TCP flags on the first packet"},
    {"sessionFlags",     1, SKAGGBAG_FIELD_REST_FLAGS,      SK_AGGBAG_KEY,
     "bit-wise OR of TCP flags on the second through final packet"},
    {"attributes",       1, SKAGGBAG_FIELD_TCP_STATE,       SK_AGGBAG_KEY,
     "flow attributes set by the flow generator"},
    {"application",      2, SKAGGBAG_FIELD_APPLICATION,     SK_AGGBAG_KEY,
     "guess as to the content of the flow set by flow generator"},
    {"class",            1, SKAGGBAG_FIELD_FTYPE_CLASS,     SK_AGGBAG_KEY,
     "the class at collection point"},
    {"type",             1, SKAGGBAG_FIELD_FTYPE_TYPE,      SK_AGGBAG_KEY,
     "the type within the class at the collection point"},
    {NULL,/*sTime-ms*/   0, SKAGGBAG_FIELD_INVALID,         SK_AGGBAG_KEY,
     "unused"},
    {NULL,/*eTime-ms*/   0, SKAGGBAG_FIELD_INVALID,         SK_AGGBAG_KEY,
     "unused"},
    {NULL,/*dur-ms*/     0, SKAGGBAG_FIELD_INVALID,         SK_AGGBAG_KEY,
     "unused"},
    {"icmpType",         1, SKAGGBAG_FIELD_ICMP_TYPE,       SK_AGGBAG_KEY,
     "ICMP type"},
    {"icmpCode",         1, SKAGGBAG_FIELD_ICMP_CODE,       SK_AGGBAG_KEY,
     "ICMP code"},
    {"sIPv6",           16, SKAGGBAG_FIELD_SIPv6,           SK_AGGBAG_KEY,
     "source IP address, IPv6 only"},
    {"dIPv6",           16, SKAGGBAG_FIELD_DIPv6,           SK_AGGBAG_KEY,
     "destination IP address, IPv6 only"},
    {"nhIPv6",          16, SKAGGBAG_FIELD_NHIPv6,          SK_AGGBAG_KEY,
     "next-hop IP address, IPv6 only"},
    {"any-IPv4",         4, SKAGGBAG_FIELD_ANY_IPv4,        SK_AGGBAG_KEY,
     "a generic IPv4 address"},
    {"any-IPv6",        16, SKAGGBAG_FIELD_ANY_IPv6,        SK_AGGBAG_KEY,
     "a generic IPv6 address"},
    {"any-port",         2, SKAGGBAG_FIELD_ANY_PORT,        SK_AGGBAG_KEY,
     "a generic port"},
    {"any-snmp",         2, SKAGGBAG_FIELD_ANY_SNMP,        SK_AGGBAG_KEY,
     "a generic SNMP value"},
    {"any-time",         4, SKAGGBAG_FIELD_ANY_TIME,        SK_AGGBAG_KEY,
     "a generic time in seconds"},
    {"custom-key",       8, SKAGGBAG_FIELD_CUSTOM_KEY,      SK_AGGBAG_KEY,
     "a generic key"},
    {"scc",              2, SKAGGBAG_FIELD_SIP_COUNTRY,     SK_AGGBAG_KEY,
     "the country code of the source"},
    {"dcc",              2, SKAGGBAG_FIELD_DIP_COUNTRY,     SK_AGGBAG_KEY,
     "the country code of the destination"},
    {"any-cc",           2, SKAGGBAG_FIELD_ANY_COUNTRY,     SK_AGGBAG_KEY,
     "a generic country code"},
    {"sip-pmap",         4, SKAGGBAG_FIELD_SIP_PMAP,        SK_AGGBAG_KEY,
     "unimplemented"},
    {"dip-pmap",         4, SKAGGBAG_FIELD_DIP_PMAP,        SK_AGGBAG_KEY,
     "unimplemented"},
    {"any-ip-pmap",      4, SKAGGBAG_FIELD_ANY_IP_PMAP,     SK_AGGBAG_KEY,
     "unimplemented"},
    {"sport-pmap",       4, SKAGGBAG_FIELD_SPORT_PMAP,      SK_AGGBAG_KEY,
     "unimplemented"},
    {"dport-pmap",       4, SKAGGBAG_FIELD_DPORT_PMAP,      SK_AGGBAG_KEY,
     "unimplemented"},
    {"any-port-pmap",    4, SKAGGBAG_FIELD_ANY_PORT_PMAP,   SK_AGGBAG_KEY,
     "unimplemented"}
};

static const size_t ab_type_info_key_max = (sizeof(ab_type_info_key)
                                            / sizeof(ab_type_info_key[0]));

static const ab_type_info_t ab_type_info_counter[] = {
    {"records",          8, SKAGGBAG_FIELD_RECORDS,         SK_AGGBAG_COUNTER,
     "count of records that match the key"},
    {"sum-packets",      8, SKAGGBAG_FIELD_SUM_PACKETS,     SK_AGGBAG_COUNTER,
     "sum of packet counts for records that match the key"},
    {"sum-bytes",        8, SKAGGBAG_FIELD_SUM_BYTES,       SK_AGGBAG_COUNTER,
     "sum of byte (octet) counts for records that match the key"},
    {"sum-duration",     8, SKAGGBAG_FIELD_SUM_ELAPSED,     SK_AGGBAG_COUNTER,
     "sum of durations (in seconds) for records that match the key"},
    {"custom-counter",   8, SKAGGBAG_FIELD_CUSTOM_COUNTER,  SK_AGGBAG_COUNTER,
     "a generic counter"}
};

static const size_t ab_type_info_counter_max =
    (sizeof(ab_type_info_counter) / sizeof(ab_type_info_counter[0]));


#if AB_SUPPORT_CUSTOM
#define SKAGGBAG_FIELD_CUSTOM   65535
#define KEY_VALUE               (SK_AGGBAG_KEY | SK_AGGBAG_COUNTER)

static const ab_type_info_t ab_custom_info = {
    "custom",           0,  SKAGGBAG_FIELD_CUSTOM,          KEY_VALUE,
    "unimplemented"
};
#endif  /* AB_SUPPORT_CUSTOM */


/*  AGGBAG OPTIONS  */

enum aggbag_options_en {
    OPT_AGGBAG_INVOCATION_STRIP
    /* , OPT_AGGBAG_RECORD_VERSION */
};
static const struct option aggbag_options[] = {
    {"invocation-strip",    NO_ARG,       0, OPT_AGGBAG_INVOCATION_STRIP},
    /* {"record-version",      REQUIRED_ARG, 0, OPT_AGGBAG_RECORD_VERSION}, */
    {0, 0, 0, 0}            /* sentinel entry */
};
static const char *aggbag_options_help[] = {
    ("Strip invocation history from the Aggregate Bag\n"
     "\tfile.  Def. Record command used to create the file"),
    /* "Specify version when writing AggBag records.\n", */
    (char*)NULL
};



/*  LOCAL FUNCTION PROTOTYPES  */

static int
abLayoutFieldSorter(
    const void         *v_a,
    const void         *v_b);
static const ab_type_info_t *
aggBagGetTypeInfo(
    uint16_t            field_type);
static sk_aggbag_type_t
aggBagHentryGetFieldType(
    const sk_header_entry_t    *hentry,
    unsigned int                key_counter,
    unsigned int                pos);
static void
aggBagKeyCounterAdd(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter);
static int
aggBagKeyCounterDivide(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    const sk_aggbag_div_zero_t     *div_zero,
    sk_aggbag_aggregate_t          *new_counter);
static void
aggBagKeyCounterSubtract(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter);


/*  ****************************************************************  */
/*  ****************************************************************  */
/*  Support for tracing/debuging the code  */
/*  ****************************************************************  */
/*  ****************************************************************  */

#if AGGBAG_TRACE
#ifdef SK_HAVE_C99___FUNC__
#define ABTRACE_V(...)  abTrace(__func__, __LINE__, __VA_ARGS__)
#else
#define ABTRACE_V(...)  abTrace(__FILE__, __LINE__, __VA_ARGS__)
#endif  /* SK_HAVE_C99___FUNC__ */
#define ABTRACEQ_V(...) abTraceQuiet(__VA_ARGS__)

#define ABTRACE(t_t)    ABTRACE_V t_t
#define ABTRACEQ(q_q)   ABTRACEQ_V q_q

#define V(v_v)          (void *)(v_v)

static void abTrace(const char *func, int lineno, const char *fmt, ...)
    SK_CHECK_PRINTF(3, 4);
static void abTraceQuiet(const char *fmt, ...)
    SK_CHECK_PRINTF(1, 2);

static void
abTrace(
    const char         *func,
    int                 lineno,
    const char         *fmt,
    ...)
{
    va_list ap;

#ifdef SK_HAVE_C99___FUNC__
    fprintf(stderr, "%s():%d: ", func, lineno);
#else
    fprintf(stderr, "%s:%d: ", func, lineno);
#endif
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void
abTraceQuiet(
    const char *fmt,
    ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
#endif  /* AGGBAG_TRACE */

#ifndef ABTRACE
#define ABTRACE(x_x)
#define ABTRACEQ(x_x)
#endif  /* #ifndef ABTRACE */



/*  ****************************************************************  */
/*  ****************************************************************  */
/*  AggBag uses a red black tree.  This is the rbtree implementation  */
/*  ****************************************************************  */
/*  ****************************************************************  */

/*
 *  Red Black balanced tree library
 *
 *    This code is based on the following:
 *    http://eternallyconfuzzled.com/jsw_home.aspx
 *
 *  ************************************************************
 *
 *    Red Black balanced tree library
 *
 *      > Created (Julienne Walker): August 23, 2003
 *      > Modified (Julienne Walker): March 14, 2008
 *
 *    This code is in the public domain. Anyone may
 *    use it or change it in any way that they see
 *    fit. The author assumes no responsibility for
 *    damages incurred through use of the original
 *    code or any variations thereof.
 *
 *    It is requested, but not required, that due
 *    credit is given to the original author and
 *    anyone who has modified the code through
 *    a header comment, such as this one.
 *
 *  ************************************************************
 *
 */

/*
 *    rbtree_node_t defines the elements in the red-black tree.
 *
 *    The size of an rbtree_node_t is variable, though all nodes in a
 *    tree have the same size, which is given by the 'data_len' member
 *    of an sk_aggbag_t.
 *
 *    The final member of this structure uses bytes 0 to data_len-1
 *    for the data and the final byte (at position 'data_len') for the
 *    color.
 */
struct rbtree_node_st {
    /* The children: Left (0) and Right (1) */
    rbtree_node_t      *link[2];
    /* Variable-sized: User-defined content and final byte is color */
    uint8_t             data_color[1];
};
/* typedef struct rbtree_node_st rbtree_node_t;  // ABOVE */

/**
 *    Since the data-size is variable and the color follows it, create
 *    a structure to hold the maximum sized data object.
 */
struct rbtree_false_root_st {
    rbtree_node_t      *link[2];
    uint8_t             data_color[SKAGGBAG_AGGREGATE_MAXLEN + 1u];
};
typedef struct rbtree_false_root_st rbtree_false_root_t;

/**
 *    sk_rbtree_status_t defines the values returned by the functions
 *    declared below.
 */
enum sk_rbtree_status_en {
    SK_RBTREE_OK = 0,
    SK_RBTREE_ERR_DUPLICATE = -1,
    SK_RBTREE_ERR_NOT_FOUND = -2,
    SK_RBTREE_ERR_ALLOC = -3,
    SK_RBTREE_ERR_PARAM = -4
};
typedef enum sk_rbtree_status_en sk_rbtree_status_t;

/**
 *    Signature of a user-defined function for printing the data.
 */
typedef void
(*sk_rbtree_print_data_fn_t)(
     const sk_aggbag_t  *tree,
     FILE               *fp,
     const void         *data);

/*  Tallest allowable tree */
#ifndef RBT_HEIGHT_LIMIT
#define RBT_HEIGHT_LIMIT     64
#endif

/*  Color of a node */
#define RBT_BLACK       0
#define RBT_RED         1

/*  The tree uses an array[2] for the left and right nodes */
#define RBT_LEFT        0
#define RBT_RIGHT       1

/*  Typedef for the terminal node */
#define RBT_NIL      ((rbtree_node_t *)&rbt_false_root)

/*
 *    Compare the octet array in 'rcd_a' with the array in 'rcd_b' for
 *    the tree 'rcd_tree'.
 */
#define rbtree_compare_data(rcd_tree, rcd_a, rcd_b)                     \
    memcmp((rcd_a), (rcd_b), (rcd_tree)->layout[0]->field_octets)

/*
 *    Return true if 'rnir_node' is red.  If the return value is
 *    false, 'rnir_node' must be black.
 */
#define rbtree_node_is_red(rnir_tree, rnir_node)                \
    (RBT_RED == (rnir_node)->data_color[(rnir_tree)->data_len])

/*
 *    Helper for rbtree_set_node_black(), rbtree_set_node_red()
 *
 *    Set color of 'rsnc_node' in 'rsnc_tree' to 'rsnc_color'.
 */
#define rbtree_set_node_color(rsnc_tree, rsnc_node, rsnc_color) \
    (rsnc_node)->data_color[(rsnc_tree)->data_len] = rsnc_color

/*
 *    Set color of 'rsnb_node' in 'rsnb_tree' to BLACK.
 */
#define rbtree_set_node_black(rsnb_tree, rsnb_node)             \
    rbtree_set_node_color(rsnb_tree, rsnb_node, RBT_BLACK)

/*
 *    Set color of 'rsnr_node' in 'rsnr_tree' to RED.
 */
#define rbtree_set_node_red(rsnr_tree, rsnr_node)               \
    rbtree_set_node_color(rsnr_tree, rsnr_node, RBT_RED)

/*
 *    Copy 'rsnd_data' into the node 'rsnd_node' of the tree
 *    'rsnd_tree'.
 */
#define rbtree_set_node_data(rsnd_tree, rsnd_node, rsnd_data)           \
    memcpy((rsnd_node)->data_color, (rsnd_data), (rsnd_tree)->data_len)

/**
 *    sk_rbtree_iter_t is a handle for iterating over the objects in
 *    the Red Black Tree Structure.
 */
struct sk_rbtree_iter_st {
    /* Paired tree */
    const sk_aggbag_t      *tree;
    /* Current node */
    const rbtree_node_t    *cur;
    /* Data on previous node */
    const void             *prev_data;
    /* Traversal path */
    const rbtree_node_t    *path[RBT_HEIGHT_LIMIT];
    /* Current depth in 'path' */
    size_t                  depth;
};
typedef struct sk_rbtree_iter_st sk_rbtree_iter_t;

#if 0
/*
 *    The red-black tree sk_rbtree_t.  Not defined since the
 *    sk_aggbag_t structure incorporates it directly.
 */
struct sk_rbtree_st {
    /* The top of the tree */
    rbtree_node_t      *root;
    /* The comparison function */
    sk_rbtree_cmp_fn_t  cmp_fn;
    /* The data free() function: May be NULL */
    sk_rbtree_free_fn_t free_fn;
    /* User's context pointer */
    const void         *ctx;
    /* Number of items in the tree */
    size_t              size;
    /* Length of a single data item in the tree */
    size_t              data_len;
    /* Size to use when allocating an rbtree_node_t */
    size_t              node_size;
};
typedef struct sk_rbtree_st sk_rbtree_t;
#endif  /* 0 */

/* LOCAL VARIABLES */

/*
 *    Global variable used as the terminal node.
 */
static const rbtree_false_root_t rbt_false_root = {{RBT_NIL, RBT_NIL}, {0}};

/* FUNCTION DEFINITIONS */

/**
 *    Perform a single red black rotation in the specified direction.
 *    This function assumes that all nodes are valid for a rotation.
 *
 *    'root' is the original root to rotate around.
 *    'dir' is the direction to rotate (0 = left, 1 = right).
 *
 *    Return the new root ater rotation
 */
static rbtree_node_t *
rbtree_rotate_single(
    const sk_aggbag_t  *tree,
    rbtree_node_t      *root,
    int                 dir)
{
    rbtree_node_t *save = root->link[!dir];

    root->link[!dir] = save->link[dir];
    save->link[dir] = root;

    rbtree_set_node_red(tree, root);
    rbtree_set_node_black(tree, save);

    return save;
}


/**
 *    Perform a double red black rotation in the specified direction.
 *    This function assumes that all nodes are valid for a rotation.
 *
 *    'root' is the original root to rotate around.
 *    'dir' is the direction to rotate (0 = left, 1 = right).
 *
 *    Return the new root after rotation.
 */
static rbtree_node_t *
rbtree_rotate_double(
    const sk_aggbag_t  *tree,
    rbtree_node_t      *root,
    int                 dir)
{
    root->link[!dir] = rbtree_rotate_single(tree, root->link[!dir], !dir);

    return rbtree_rotate_single(tree, root, dir);
}


/**
 *    Initialize the iterator object 'iter' and attach it to 'tree'.
 *    The user-specified direction 'dir' determines whether to begin
 *    iterator at the smallest (0) or largest (1) valued node.
 *
 *    Return a pointer to the smallest or largest data value.
 */
static void *
rbtree_iter_start(
    sk_rbtree_iter_t   *iter,
    const sk_aggbag_t  *tree,
    int                 dir)
{
    iter->tree = tree;
    iter->cur = tree->root;
    iter->depth = 0;

    if (RBT_NIL == iter->cur) {
        return NULL;
    }
    while (iter->cur->link[dir] != RBT_NIL) {
        assert(iter->depth < RBT_HEIGHT_LIMIT);
        iter->path[iter->depth++] = iter->cur;
        iter->cur = iter->cur->link[dir];
    }
    return (void*)iter->cur->data_color;
}


/**
 *    Move the initialized iterator 'iter' in the user-specified
 *    direction 'dir' (0 = ascending, 1 = descending).
 *
 *    Return a pointer to the next data value in the specified
 *    direction.
 *
 */
static void *
rbtree_iter_move(
    sk_rbtree_iter_t   *iter,
    int                 dir)
{
    if (iter->cur->link[dir] != RBT_NIL) {
        /* Continue down this branch */
        assert(iter->depth < RBT_HEIGHT_LIMIT);
        iter->path[iter->depth++] = iter->cur;
        iter->cur = iter->cur->link[dir];

        while (iter->cur->link[!dir] != RBT_NIL) {
            assert(iter->depth < RBT_HEIGHT_LIMIT);
            iter->path[iter->depth++] = iter->cur;
            iter->cur = iter->cur->link[!dir];
        }
    } else {
        /* Move to the next branch */
        const rbtree_node_t *last;

        do {
            if (0 == iter->depth) {
                iter->cur = RBT_NIL;
                return NULL;
            }
            last = iter->cur;
            iter->cur = iter->path[--iter->depth];
        } while (last == iter->cur->link[dir]);
    }

    return ((iter->cur == RBT_NIL) ? NULL : (void*)iter->cur->data_color);
}


/**
 *    Print the address of the data pointer.
 *
 *    This is a helper function for rbtree_node_debug_print() to print
 *    the data when the user does not provide a printing function.
 *
 *    Must have the signature of sk_rbtree_print_data_fn_t.
 */
static void
rbtree_node_default_data_printer(
    const sk_aggbag_t  *tree,
    FILE               *fp,
    const void         *data)
{
    SK_UNUSED_PARAM(tree);
    fprintf(fp, "%p", (void *)data);
}


/**
 *    Print the address of the data pointer.
 *
 *    This is a helper function for rbtree_node_debug_print() to print
 *    the data when the user does not provide a printing function.
 */
static void
rbtree_node_debug_print(
    const sk_aggbag_t          *tree,
    const rbtree_node_t        *node,
    FILE                       *fp,
    sk_rbtree_print_data_fn_t   print_data,
    int                         indentation)
{
    unsigned int i;

    if (node != RBT_NIL) {
        ++indentation;
        fprintf(fp,
                "Tree: %*s %p: left=%p, right=%p, color=%s, data=",
                indentation, "", (void *)node,
                (void *)node->link[RBT_LEFT], (void *)node->link[RBT_RIGHT],
                (rbtree_node_is_red(tree, node) ? "RED" : "BLACK"));
        print_data(tree, fp, node->data_color);
        fprintf(fp, "\n");
        for (i = RBT_LEFT; i <= RBT_RIGHT; ++i) {
            rbtree_node_debug_print(
                tree, node->link[i], fp, print_data, indentation);
        }
    }
}


static int
rbtree_assert(
    const sk_aggbag_t      *tree,
    const rbtree_node_t    *root,
    FILE                   *fp)
{
    const rbtree_node_t *ln;
    const rbtree_node_t *rn;
    unsigned int lh, rh;

    if (RBT_NIL == root) {
        return 1;
    }

    ln = root->link[RBT_LEFT];
    rn = root->link[RBT_RIGHT];

    /* Consecutive red links */
    if (rbtree_node_is_red(tree, root)) {
        if (rbtree_node_is_red(tree, ln) || rbtree_node_is_red(tree, rn)) {
            fprintf(fp, "Red violation at %p\n", (void *)root);
            return 0;
        }
    }

    lh = rbtree_assert(tree, ln, fp);
    rh = rbtree_assert(tree, rn, fp);

    /* Invalid binary search tree */
    if ((ln != RBT_NIL
         && rbtree_compare_data(tree, ln->data_color, root->data_color) >= 0)
        || (rn != RBT_NIL
            && rbtree_compare_data(tree, rn->data_color, root->data_color)<=0))
    {
        fprintf(fp, "Binary tree violation at %p\n", (void *)root);
        return 0;
    }

    /* Black height mismatch */
    if (lh != 0 && rh != 0 && lh != rh) {
        fprintf(fp, "Black violation at %p (left = %u, right = %u\n",
                    (void *)root, lh, rh);
        return 0;
    }

    /* Only count black links */
    if (lh != 0 && rh != 0) {
        return rbtree_node_is_red(tree, root) ? lh : lh + 1;
    }
    return 0;
}


/*
 *    Destroy the nodes on the tree.
 */
static void
sk_rbtree_destroy(
    sk_aggbag_t        *tree)
{
    rbtree_node_t *node;
    rbtree_node_t *save;

    if (!tree || !tree->root || tree->root == RBT_NIL) {
        return;
    }

    /* Rotate away the left links so that we can treat this like the
     * destruction of a linked list */
    node = tree->root;
    for (;;) {
        if (RBT_NIL != node->link[RBT_LEFT]) {
            /* Rotate away the left link and check again */
            save = node->link[RBT_LEFT];
            node->link[RBT_LEFT] = save->link[RBT_RIGHT];
            save->link[RBT_RIGHT] = node;
            node = save;
        } else {
            /* No left links, just kill the node and move on */
            save = node->link[RBT_RIGHT];
            free(node);
            if (RBT_NIL == save) {
                break;
            }
            node = save;
        }
    }
}


/*
 *    Find the node in 'tree' that has 'data' as its key.
 */
static rbtree_node_t *
sk_rbtree_find(
    const sk_aggbag_t  *tree,
    const void         *data)
{
    const rbtree_node_t *node;
    const uint8_t *u_data = (const uint8_t *)data;
    size_t i;
    int cmp;

    assert(tree);
    assert(tree->data_len);

    ABTRACE(("searching for key ="));
    for (i = 0; i < tree->layout[0]->field_octets; ++i, ++u_data) {
        ABTRACEQ((" %02x", *u_data));
    }
    ABTRACEQ(("\n"));

    node = tree->root;
    ABTRACE(("root = %p, RBT_NIL = %p\n", V(node), V(RBT_NIL)));
    while (node != RBT_NIL) {
        ABTRACE(("node's data ="));
        u_data = node->data_color;
        for (i = 0; i < tree->data_len; ++i, ++u_data) {
            if (i == tree->layout[0]->field_octets) {
                ABTRACEQ((" |"));
            }
            ABTRACEQ((" %02x", *u_data));
        }
        ABTRACEQ((" | %02x\n", *u_data));

        cmp = rbtree_compare_data(tree, node->data_color, data);
        ABTRACE(("node = %p, cmp = %d\n", V(node), cmp));
        if (cmp < 0) {
            node = node->link[RBT_RIGHT];
        } else if (cmp > 0) {
            node = node->link[RBT_LEFT];
        } else {
            return (rbtree_node_t *)node;
        }
        /* If the tree supports duplicates, they should be chained to
         * the right subtree for this to work */
        /* node = node->link[cmp < 0]; */
    }
    ABTRACE(("return NULL\n"));
    return NULL;
}


/*
 *    Add 'key' and 'counter' to 'tree', overwriting an existing 'key'
 *    with 'counter'.
 */
static int
sk_rbtree_insert(
    sk_aggbag_t        *tree,
    const void         *key_data,
    const void         *counter_data)
{
    rbtree_false_root_t head;
    rbtree_node_t *t, *g, *p, *q;
    int dir, last, cmp;
    int inserted = 0;
    int rv = SK_RBTREE_OK;

    assert(tree);
    assert(tree->data_len);

    memset(&head, 0, sizeof(head));
    head.link[0] = head.link[1] = RBT_NIL;

    /* 't' is great-grandparent; 'g' is grandparent; 'p' is parent;
     * and 'q' is iterator. */
    t = g = p = (rbtree_node_t *)&head;
    q = t->link[RBT_RIGHT] = tree->root;
    dir = last = RBT_RIGHT;

#if AGGBAG_TRACE
    {
        size_t i;
        const uint8_t *u;

        ABTRACE(("t = p = g = &head = %p, RBT_NIL = %p, q = tree->root = %p",
                 V(t), V(RBT_NIL), V(q)));
        ABTRACEQ(("  data ="));
        u = (const uint8_t *)key_data;
        for (i = 0; i < tree->layout[0]->field_octets; ++i, ++u) {
            ABTRACEQ((" %02x", *u));
        }
        ABTRACEQ((" |"));
        u = (const uint8_t *)counter_data;
        for (i = 0; i < tree->layout[1]->field_octets; ++i, ++u) {
            ABTRACEQ((" %02x", *u));
        }
        ABTRACEQ(("\n"));
    }
#endif  /* AGGBAG_TRACE */

    /* Search down the tree for a place to insert */
    for (;;) {
        if (q == RBT_NIL) {
            uint8_t *node_data;

            /* Insert a new node at the first null link */
            q = (rbtree_node_t*)malloc(tree->node_size);
            if (NULL == q) {
                return SK_RBTREE_ERR_ALLOC;
            }
            inserted = 1;
            node_data = q->data_color;

            rbtree_set_node_red(tree, q);
            /* do not use macro here since we copy the key and counter
             * data separately */
            memcpy(node_data, key_data, tree->layout[0]->field_octets);
            memcpy(node_data + tree->layout[0]->field_octets, counter_data,
                   tree->layout[1]->field_octets);
            q->link[RBT_LEFT] = q->link[RBT_RIGHT] = RBT_NIL;

            ABTRACE(("inserted new node %p as %s child of %p\n",
                     V(q), (dir ? "RIGHT" : "LEFT"), V(p)));

            p->link[dir] = q;
            ++tree->size;
        } else if (rbtree_node_is_red(tree, q->link[RBT_LEFT])
                   && rbtree_node_is_red(tree, q->link[RBT_RIGHT]))
        {
            /* Simple red violation: color flip */
            ABTRACE(("simple red violation on q = %p\n", V(q)));

            rbtree_set_node_red(tree, q);
            rbtree_set_node_black(tree, q->link[RBT_LEFT]);
            rbtree_set_node_black(tree, q->link[RBT_RIGHT]);
        }

        if (rbtree_node_is_red(tree, p) && rbtree_node_is_red(tree, q)) {
            /* Hard red violation: rotations necessary */
            int dir2 = (t->link[RBT_RIGHT] == g);

            ABTRACE((("hard red violation on p = %p, q = %p, g = %p, t = %p,"
                      " performing %s rotation\n"),
                     V(p), V(q), V(g), V(t),
                     ((q == p->link[last]) ? "single" : "double")));

            if (q == p->link[last]) {
                t->link[dir2] = rbtree_rotate_single(tree, g, !last);
            } else {
                t->link[dir2] = rbtree_rotate_double(tree, g, !last);
            }
        }

        /* Stop working if we inserted a node */
        if (inserted) {
            ABTRACE(("stop after insertion\n"));
            break;
        }

        /* Choose a direction and check for a match */
        cmp = rbtree_compare_data(tree, q->data_color, key_data);
        if (0 == cmp) {
            uint8_t *node_data = q->data_color;
            memcpy(node_data + tree->layout[0]->field_octets, counter_data,
                   tree->layout[1]->field_octets);
            rv = SK_RBTREE_ERR_DUPLICATE;
            ABTRACE(("stop after duplicate\n"));
            break;
        }

        last = dir;
        dir = (cmp < 0);

        /* Move the helpers down */
        t = g;
        g = p;
        p = q;
        q = q->link[dir];
        ABTRACE(("descent direction is %d, t = %p, g = %p, p = %p, q = %p\n",
                 dir, V(t), V(g), V(p), V(q)));

    }

    ABTRACE(("updating root from %p[%s] to %p[black]\n",
             V(tree->root),
             (rbtree_node_is_red(tree, tree->root) ? "red" : "black"),
             V(head.link[RBT_RIGHT])));

    /* Update the root (it may be different) */
    tree->root = head.link[RBT_RIGHT];

    /* Make the root black for simplified logic */
    rbtree_set_node_black(tree, tree->root);

    return rv;
}


/*
 *    Remove from 'tree' the node whose key is 'data'.  Return
 *    SK_RBTREE_OK if removed or SK_RBTREE_ERR_NOT_FOUND if no node
 *    has the key 'data'.
 */
static int
sk_rbtree_remove(
    sk_aggbag_t        *tree,
    const void         *data)
{
    rbtree_false_root_t head;
    rbtree_node_t *q, *p, *g, *s; /* Helpers */
    rbtree_node_t *f;             /* Found item */
    int dir;
    int last;
    int cmp;
    int rv = SK_RBTREE_ERR_NOT_FOUND;

    assert(tree);
    assert(tree->data_len);

    if (RBT_NIL == tree->root) {
        return rv;
    }
    memset(&head, 0, sizeof(head));
    head.link[0] = head.link[1] = RBT_NIL;

    /* Set up our helpers */
    p = NULL;
    q = (rbtree_node_t *)&head;
    q->link[RBT_RIGHT] = tree->root;
    dir = RBT_RIGHT;
    f = NULL;

    /* Search and push a red node down to fix red violations as we
     * go */
    do {
        /* Move the helpers down */
        g = p;
        p = q;
        q = q->link[dir];

        cmp = rbtree_compare_data(tree, q->data_color, data);
        last = dir;
        dir = cmp < 0;

        /* Save the node with matching data and keep going; we'll do
         * removal tasks at the end */
        if (0 == cmp) {
            f = q;
        }

        /* Push the red node down with rotations and color flips */
        if (!rbtree_node_is_red(tree, q)
            && !rbtree_node_is_red(tree, q->link[dir]))
        {
            if (rbtree_node_is_red(tree, q->link[!dir])) {
                p = p->link[last] = rbtree_rotate_single(tree, q, dir);
            } else if ((s = p->link[!last]) != RBT_NIL) {
                if (!rbtree_node_is_red(tree, s->link[RBT_LEFT])
                    && !rbtree_node_is_red(tree, s->link[RBT_RIGHT]))
                {
                    /* Color flip */
                    rbtree_set_node_black(tree, p);
                    rbtree_set_node_red(tree, s);
                    rbtree_set_node_red(tree, q);
                } else {
                    int dir2 = (g->link[RBT_RIGHT] == p);

                    if (rbtree_node_is_red(tree, s->link[last])) {
                        g->link[dir2] = rbtree_rotate_double(tree, p, last);
                    } else if (rbtree_node_is_red(tree, s->link[!last])) {
                        g->link[dir2] = rbtree_rotate_single(tree, p, last);
                    }

                    /* Ensure correct coloring */
                    rbtree_set_node_red(tree, q);
                    rbtree_set_node_red(tree, g->link[dir2]);
                    rbtree_set_node_black(tree,g->link[dir2]->link[RBT_LEFT]);
                    rbtree_set_node_black(tree,g->link[dir2]->link[RBT_RIGHT]);
                }
            }
        }
    } while (q->link[dir] != RBT_NIL);

    /* Replace and remove the saved node */
    if (f != NULL) {
        rbtree_set_node_data(tree, f, q->data_color);
        p->link[p->link[RBT_RIGHT] == q] =
            q->link[q->link[RBT_LEFT] == RBT_NIL];
        free(q);
        --tree->size;
        rv = SK_RBTREE_OK;
    }

    /* Update the root (it may be different) */
    tree->root = head.link[RBT_RIGHT];

    /* Make the root black for simplified logic */
    rbtree_set_node_black(tree, tree->root);

    return rv;
}


#if 0
static size_t
sk_rbtree_size(
    const sk_aggbag_t  *tree)
{
    return tree->size;
}
#endif  /* 0 */


static sk_rbtree_iter_t *
sk_rbtree_iter_create(
    const sk_aggbag_t  *tree)
{
    sk_rbtree_iter_t *iter;

    iter = (sk_rbtree_iter_t*)calloc(1, sizeof(sk_rbtree_iter_t));
    if (iter) {
        iter->prev_data = rbtree_iter_start(iter, tree, 0);
    }
    return iter;
}


static void
sk_rbtree_iter_free(
    sk_rbtree_iter_t   *iter)
{
    free(iter);
}


#if 0
static void *
sk_rbtree_iter_bind_first(
    sk_rbtree_iter_t   *iter,
    const sk_aggbag_t  *tree)
{
    /* Min value */
    return rbtree_iter_start(iter, tree, 0);
}


static void *
sk_rbtree_iter_bind_last(
    sk_rbtree_iter_t   *iter,
    const sk_aggbag_t  *tree)
{
    /* Max value */
    return rbtree_iter_start(iter, tree, 1);
}
#endif  /* 0 */


static const void *
sk_rbtree_iter_next(
    sk_rbtree_iter_t   *iter)
{
    const void *data;

    /* Toward larger items */
    data = iter->prev_data;
    iter->prev_data = rbtree_iter_move(iter, 1);
    return data;
}


#if 0
static void *
sk_rbtree_iter_prev(
    sk_rbtree_iter_t   *iter)
{
    /* Toward smaller items */
    return rbtree_iter_move(iter, 0);
}
#endif  /* 0 */


static void
sk_rbtree_debug_print(
    const sk_aggbag_t          *tree,
    FILE                       *fp,
    sk_rbtree_print_data_fn_t   print_data)
{
    if (NULL == tree) {
        fprintf(fp, "Tree: Pointer is NULL\n");
        return;
    }
    if (NULL == print_data) {
        print_data = rbtree_node_default_data_printer;
    }

    fprintf(fp, "Tree: %p has %" SK_PRIuZ " nodes\n", (void*)tree, tree->size);
    rbtree_node_debug_print(tree, tree->root, fp, print_data, 0);

    rbtree_assert(tree, tree->root, fp);
}



/*  ****************************************************************  */
/*  ****************************************************************  */
/*  For serializing an AggBag, this is the header that describes the
 *  key and the counter and the functions to manipulate it. */
/*  ****************************************************************  */
/*  ****************************************************************  */

/**
 *    When writing a Bag to a stream, this header entry is used to
 *    contain information about the bag.
 */
typedef struct sk_hentry_aggbag_st {
    sk_header_entry_spec_t  he_spec;
    uint32_t                header_version;
    /*    Total number of fields: both keys and counters */
    uint16_t                field_count;
    /*    Number of fields that are keys */
    uint16_t                key_count;
    uint16_t               *fields;
} sk_hentry_aggbag_t;

/*
 *    Version to specify in the header entry.  Version 1 uses a bitmap
 *    with 64 entries.
 */
#define AB_HENTRY_VERSION       1

/*
 *    Create and return a new header entry for AggBag files that is a
 *    copy of the header entry 'hentry'.
 *
 *    This is the 'copy_fn' callback for skHentryTypeRegister().
 */
static sk_header_entry_t *
aggBagHentryCopy(
    const sk_header_entry_t    *hentry)
{
    const sk_hentry_aggbag_t *ab_hdr = (const sk_hentry_aggbag_t *)hentry;
    sk_hentry_aggbag_t *new_hdr;

    assert(SK_HENTRY_AGGBAG_ID == skHeaderEntryGetTypeId(hentry));
    assert(AB_HENTRY_VERSION == ab_hdr->header_version);

    new_hdr = (sk_hentry_aggbag_t *)malloc(sizeof(*new_hdr));
    if (NULL == new_hdr) {
        return NULL;
    }
    memcpy(new_hdr, ab_hdr, sizeof(*new_hdr));
    new_hdr->fields = (uint16_t *)calloc(new_hdr->field_count,sizeof(uint16_t));
    if (NULL == new_hdr->fields) {
        free(new_hdr);
        return NULL;
    }
    memcpy(new_hdr->fields, ab_hdr->fields,
           new_hdr->field_count * sizeof(uint16_t));

    return (sk_header_entry_t *)new_hdr;
}

/*
 *    Create and return a new header entry for AggBag files.  'key_type'
 *    is the type of the key, 'key_length' is the octet length of a
 *    key, 'counter_type' is the type of the counter, 'counter_length'
 *    is the octet length of a counter.
 */
static sk_header_entry_t *
aggBagHentryCreate(
    const sk_aggbag_t  *ab)
{
    sk_hentry_aggbag_t *ab_hdr;
    uint16_t *u16;
    unsigned int i;
    unsigned int field_count;
    size_t len;

    if (NULL == ab->layout[0] || NULL == ab->layout[1]) {
        return NULL;
    }
    if (ab->layout[0]->field_count + ab->layout[1]->field_count > UINT16_MAX) {
        return NULL;
    }

    field_count= ab->layout[0]->field_count + ab->layout[1]->field_count;

    /* compute the required length of the header */
    len = (sizeof(ab_hdr->he_spec) + sizeof(uint32_t)
           + (sizeof(uint16_t) * (2 + field_count)));

    ABTRACE(("Computed length of header is %" SK_PRIuZ "\n", len));
    ab_hdr = (sk_hentry_aggbag_t*)calloc(1, sizeof(sk_hentry_aggbag_t));
    if (NULL == ab_hdr) {
        return NULL;
    }
    ab_hdr->he_spec.hes_id  = SK_HENTRY_AGGBAG_ID;
    ab_hdr->he_spec.hes_len = len;
    ab_hdr->header_version = AB_HENTRY_VERSION;
    ab_hdr->key_count = ab->layout[0]->field_count;
    ab_hdr->field_count = field_count;

    ab_hdr->fields = (uint16_t *)calloc(field_count, sizeof(uint16_t));
    if (NULL == ab_hdr->fields) {
        free(ab_hdr);
        return NULL;
    }
    u16 = ab_hdr->fields;
    for (i = 0; i < ab->layout[0]->field_count; ++i, ++u16) {
        *u16 = ab->layout[0]->fields[i].f_type;
    }
    for (i = 0; i < ab->layout[1]->field_count; ++i, ++u16) {
        *u16 = ab->layout[1]->fields[i].f_type;
    }

    ABTRACE(("Created new aggbag header entry %p\n", V(ab_hdr)));
    return (sk_header_entry_t*)ab_hdr;
}

/*
 *    Release any memory that is used by the in-memory representation
 *    of the file header for AggBag files.
 *
 *    This is the 'free_fn' callback for skHentryTypeRegister().
 */
static void
aggBagHentryFree(
    sk_header_entry_t  *hentry)
{
    sk_hentry_aggbag_t *ab_hdr = (sk_hentry_aggbag_t *)hentry;

    if (ab_hdr) {
        assert(skHeaderEntryGetTypeId(ab_hdr) == SK_HENTRY_AGGBAG_ID);
        ab_hdr->he_spec.hes_id = UINT32_MAX;
        free(ab_hdr->fields);
        free(ab_hdr);
    }
}

#define aggBagHentryGetCounterCount(hentry)                             \
    ((unsigned int)(((sk_hentry_aggbag_t *)(hentry))->field_count       \
                    - ((sk_hentry_aggbag_t *)(hentry))->key_count))

#define aggBagHentryGetCounterFieldType(hentry, pos)            \
    aggBagHentryGetFieldType((hentry), SK_AGGBAG_COUNTER, (pos))

#define aggBagHentryGetKeyCount(hentry)                  \
    (((sk_hentry_aggbag_t *)(hentry))->key_count)

static sk_aggbag_type_t
aggBagHentryGetFieldType(
    const sk_header_entry_t    *hentry,
    unsigned int                key_counter,
    unsigned int                pos)
{
    const sk_hentry_aggbag_t *ab_hdr = (const sk_hentry_aggbag_t *)hentry;

    assert(SK_AGGBAG_KEY == key_counter || SK_AGGBAG_COUNTER == key_counter);

    if (NULL == ab_hdr || NULL == ab_hdr->fields) {
        return SKAGGBAG_FIELD_INVALID;
    }
    if (SK_AGGBAG_KEY == key_counter) {
        if (pos >= ab_hdr->key_count) {
            return SKAGGBAG_FIELD_INVALID;
        }
        return (sk_aggbag_type_t)ab_hdr->fields[pos];
    } else {
        pos += ab_hdr->key_count;
        if (pos >= ab_hdr->field_count) {
            return SKAGGBAG_FIELD_INVALID;
        }
        return (sk_aggbag_type_t)ab_hdr->fields[pos];
    }
}

#define aggBagHentryGetKeyFieldType(hentry, pos)        \
    aggBagHentryGetFieldType((hentry), SK_AGGBAG_KEY, (pos))

#define aggBagHentryGetVersion(hentry)                  \
    (((sk_hentry_aggbag_t *)(hentry))->header_version)

/*
 *    Pack the contents of the header entry for AggBag files,
 *    'in_hentry' into the buffer 'out_packed', whose size is
 *    'bufsize', for writing the file to disk.
 *
 *    This the 'pack_fn' callback for skHentryTypeRegister().
 */
static ssize_t
aggBagHentryPacker(
    const sk_header_entry_t    *in_hentry,
    uint8_t                    *out_packed,
    size_t                      bufsize)
{
    sk_hentry_aggbag_t *ab_hdr = (sk_hentry_aggbag_t *)in_hentry;
    unsigned int i;
    uint32_t u32;
    uint16_t u16;
    size_t len;
    uint8_t *b;

    assert(in_hentry);
    assert(out_packed);
    assert(skHeaderEntryGetTypeId(ab_hdr) == SK_HENTRY_AGGBAG_ID);

    /* compute the required size */
    len = (sizeof(ab_hdr->he_spec) + sizeof(uint32_t)
           + (sizeof(uint16_t) * (2 + ab_hdr->field_count)));
    if (len > ab_hdr->he_spec.hes_len) {
        ab_hdr->he_spec.hes_len = len;
    }

    if (bufsize >= len) {
        b = out_packed;
        skHeaderEntrySpecPack(&(ab_hdr->he_spec), b, len);
        b += sizeof(ab_hdr->he_spec);
        u32 = htonl(ab_hdr->header_version);
        memcpy(b, &u32, sizeof(u32));
        b += sizeof(u32);
        u16 = htons(ab_hdr->field_count);
        memcpy(b, &u16, sizeof(u16));
        b += sizeof(u16);
        u16 = htons(ab_hdr->key_count);
        memcpy(b, &u16, sizeof(u16));
        b += sizeof(u16);
        for (i = 0; i < ab_hdr->field_count; ++i) {
            u16 = htons(ab_hdr->fields[i]);
            memcpy(b, &u16, sizeof(u16));
            b += sizeof(u16);
        }
        assert((ssize_t)bufsize >= (b - out_packed));
    }

    return len;
}

/*
 *    Print a textual representation of a file's AggBag header entry in
 *    'hentry' to the FILE pointer 'fh'.
 *
 *    This is the 'print_fn' callback for skHentryTypeRegister().
 */
static void
aggBagHentryPrint(
    const sk_header_entry_t    *hentry,
    FILE                       *fh)
{
    const sk_hentry_aggbag_t *ab_hdr = (const sk_hentry_aggbag_t *)hentry;
    const ab_type_info_t *info;
    char sep;
    unsigned int i;

    assert(ab_hdr);
    assert(skHeaderEntryGetTypeId(ab_hdr) == SK_HENTRY_AGGBAG_ID);

    fprintf(fh, "key:");
    sep = ' ';
    for (i = 0; i < ab_hdr->key_count; ++i) {
        if (NULL == (info = aggBagGetTypeInfo(ab_hdr->fields[i]))) {
            fprintf(fh, "%cUNKNOWN[%u]", sep, ab_hdr->fields[i]);
        } else {
            assert(SK_AGGBAG_COUNTER != info->ti_key_counter);
            fprintf(fh, "%c%s", sep, info->ti_name);
        }
        sep = ',';
    }

    fprintf(fh, "; counter:");
    sep = ' ';
    for ( ; i < ab_hdr->field_count; ++i) {
        if (NULL == (info = aggBagGetTypeInfo(ab_hdr->fields[i]))) {
            fprintf(fh, "%cUNKNOWN[%u]", sep, ab_hdr->fields[i]);
        } else {
            assert(SK_AGGBAG_KEY != info->ti_key_counter);
            fprintf(fh, "%c%s", sep, info->ti_name);
        }
        sep = ',';
    }
}

/*
 *    Unpack the data in 'in_packed' to create an in-memory
 *    representation of a file's AggBag header entry.
 *
 *    This is the 'unpack_fn' callback for skHentryTypeRegister().
 */
static sk_header_entry_t *
aggBagHentryUnpacker(
    uint8_t            *in_packed)
{
    sk_hentry_aggbag_t *ab_hdr;
    const uint8_t *b;
    unsigned int i;
    uint32_t u32;
    uint16_t u16;
    size_t len;

    assert(in_packed);

    /* create space for new header */
    ab_hdr = (sk_hentry_aggbag_t *)calloc(1, sizeof(sk_hentry_aggbag_t));
    if (NULL == ab_hdr) {
        ABTRACE(("Header allocation failed\n"));
        return NULL;
    }

    /* copy the spec */
    b = in_packed;
    skHeaderEntrySpecUnpack(&(ab_hdr->he_spec), in_packed);
    assert(skHeaderEntryGetTypeId(ab_hdr) == SK_HENTRY_AGGBAG_ID);
    len = ab_hdr->he_spec.hes_len;
    ABTRACE(("Header length is %" SK_PRIuZ "\n", len));
    assert(len > sizeof(ab_hdr->he_spec));
    b += sizeof(ab_hdr->he_spec);
    len -= sizeof(ab_hdr->he_spec);

    /* header_version */
    if (len < sizeof(uint32_t)) {
        ABTRACE(("Remaining header length (%" SK_PRIuZ ") is too small\n",
                 len));
        free(ab_hdr);
        return NULL;
    }
    memcpy(&u32, b, sizeof(u32));
    ab_hdr->header_version = ntohl(u32);
    b += sizeof(u32);
    len -= sizeof(u32);
    if (AB_HENTRY_VERSION != ab_hdr->header_version) {
        ABTRACE(("Header version (%u) is unsupported\n",
                 ab_hdr->header_version));
        free(ab_hdr);
        return NULL;
    }

    /* field_count */
    if (len < sizeof(uint16_t)) {
        ABTRACE(("Remaining header length (%" SK_PRIuZ ") is too small\n",
                 len));
        free(ab_hdr);
        return NULL;
    }
    memcpy(&u16, b, sizeof(u16));
    ab_hdr->field_count = ntohs(u16);
    b += sizeof(u16);
    len -= sizeof(u16);
    if (ab_hdr->field_count < 2) {
        ABTRACE(("Field count (%u) is too small\n", ab_hdr->field_count));
        free(ab_hdr);
        return NULL;
    }

    /* key_count */
    if (len < sizeof(uint16_t)) {
        ABTRACE(("Remaining header length (%" SK_PRIuZ ") is too small\n",
                 len));
        free(ab_hdr);
        return NULL;
    }
    memcpy(&u16, b, sizeof(u16));
    ab_hdr->key_count = ntohs(u16);
    b += sizeof(u16);
    len -= sizeof(u16);
    if (ab_hdr->key_count >= ab_hdr->field_count) {
        ABTRACE(("Key count (%u) should not be larger than field count (%u)\n",
                 ab_hdr->key_count, ab_hdr->field_count));
        free(ab_hdr);
        return NULL;
    }

    /* remainder of length is for the fields */
    if (len != ab_hdr->field_count * sizeof(uint16_t)) {
        ABTRACE((("Remaining header length (%" SK_PRIuZ ") does not"
                  " match expected length (%u %" SK_PRIuZ "-byte fieldIDs)\n"),
                 len, ab_hdr->field_count, sizeof(uint16_t)));
        free(ab_hdr);
        return NULL;
    }

    /* allocate an array for the fields */
    ab_hdr->fields = (uint16_t *)calloc(ab_hdr->field_count, sizeof(uint16_t));
    if (NULL == ab_hdr->fields) {
        ABTRACE(("Unable to allocate array of %u %" SK_PRIuZ "-byte fieldIDs\n",
                 ab_hdr->field_count, sizeof(uint16_t)));
        free(ab_hdr);
        return NULL;
    }

    /* fill that array */
    for (i = 0; i < ab_hdr->field_count; ++i) {
        memcpy(&u16, b, sizeof(u16));
        ab_hdr->fields[i] = ntohs(u16);
        b += sizeof(u16);
    }

    return (sk_header_entry_t*)ab_hdr;
}


/**
 *    A function called during application setup that registers the
 *    callback functions needed to operate on the AggBag header entry.
 *
 *    The prototype for this function is in skheader_priv.h
 */
int
skAggBagRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id)
{
    assert(SK_HENTRY_AGGBAG_ID == entry_id);
    return (skHentryTypeRegister(
                entry_id, &aggBagHentryPacker, &aggBagHentryUnpacker,
                &aggBagHentryCopy, &aggBagHentryFree, &aggBagHentryPrint));
}



/*  ****************************************************************  */
/*  ****************************************************************  */
/*  Functions to handle the ab_layout_t which describes the fields
 *  that comprise an aggregate key or counter */
/*  ****************************************************************  */
/*  ****************************************************************  */

/**
 *    Comparison function required by the redblack tree code to
 *    compare two ab_layout_t structures.
 */
static int
abLayoutCompare(
    const void         *v_lo_a,
    const void         *v_lo_b,
    const void         *config)
{
    const ab_layout_t *lo_a = (ab_layout_t *)v_lo_a;
    const ab_layout_t *lo_b = (ab_layout_t *)v_lo_b;

    SK_UNUSED_PARAM(config);

    return ((lo_a->field_count == lo_b->field_count)
            ? memcmp(lo_a->bitmap, lo_b->bitmap, sizeof(lo_a->bitmap))
            : (lo_a->field_count > lo_b->field_count ? 1 : -1));
}


/**
 *    Check for a layout that matches the fields specified in
 *    'fields'.  If found (regardless of field ordering), increment
 *    its reference count and return it.  Otherwise create a new one
 *    and return it.
 */
static const ab_layout_t *
abLayoutCreate(
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[])
{
    const ab_type_info_t *info;
    ab_layout_t *lo_found;
    ab_layout_t *lo_new = NULL;
    ab_layout_t search;
    ab_field_t *f;
    unsigned int i;

    search.field_count = 0;
    BITMAP_INIT(search.bitmap);
    for (i = 0; i < field_count; ++i) {
        if (0 == BITMAP_GETBIT(search.bitmap, fields[i])) {
            BITMAP_SETBIT(search.bitmap, fields[i]);
            ++search.field_count;
        }
    }
    ABTRACE(("search bmap: %08x ... %08x\n",
             search.bitmap[0], search.bitmap[0xc000 >> 5]));
#if AGGBAG_TRACE && 0
    ABTRACE(("search bmap:"));
    for (i = 0; (i << 5) < AB_LAYOUT_BMAP_SIZE; ++i) {
        ABTRACEQ((" %08x", search.bitmap[i]));
    }
    ABTRACEQ(("\n"));
#endif  /* AGGBAG_TRACE */

    if (NULL == layouts) {
        layouts = rbinit(&abLayoutCompare, NULL);
        if (NULL == layouts) {
            goto ERROR;
        }
    } else {
        lo_found = (ab_layout_t *)rbfind(&search, layouts);
        if (lo_found) {
            ABTRACE(("match found %p\n", V(lo_found)));
            ++lo_found->ref_count;
            return lo_found;
        }
    }

    lo_new = (ab_layout_t *)calloc(1, sizeof(*lo_new));
    if (NULL == lo_new) {
        return NULL;
    }

    BITMAP_INIT(lo_new->bitmap);
    lo_new->fields = ((ab_field_t *)
                      malloc(search.field_count * sizeof(ab_field_t)));
    if (NULL == lo_new->fields) {
        goto ERROR;
    }
    f = lo_new->fields;

    /* set the field types */
    for (i = 0; i < field_count; ++i) {
        if (0 == BITMAP_GETBIT(lo_new->bitmap, fields[i])) {
            BITMAP_SETBIT(lo_new->bitmap, fields[i]);
            f->f_type = fields[i];
            ++lo_new->field_count;
            ++f;
        }
    }
    assert(search.field_count == lo_new->field_count);
    assert(0 == memcmp(search.bitmap, lo_new->bitmap, sizeof(search.bitmap)));

    /* sort the fields by ID */
    skQSort(lo_new->fields, lo_new->field_count, sizeof(ab_field_t),
            &abLayoutFieldSorter);

    /* set lengths and offsets for each field */
    for (i = 0, f = lo_new->fields; i < lo_new->field_count; ++i, ++f) {
        info = aggBagGetTypeInfo(f->f_type);
        assert(info);
        f->f_len = info->ti_octets;
        f->f_offset = lo_new->field_octets;
        lo_new->field_octets += f->f_len;
    }

    ABTRACE(("new bmap: %08x ... %08x\n",
             lo_new->bitmap[0], lo_new->bitmap[0xc000 >> 5]));
    lo_found = (ab_layout_t *)rbsearch(lo_new, layouts);
    if (lo_found != lo_new) {
        skAbort();
    }

    ABTRACE(("new layout %p fields %p count %u\n",
             V(lo_new), V(lo_new->fields), lo_new->field_count));
    for (i = 0; i < lo_new->field_count; ++i) {
        ABTRACEQ(("    field %u type %d, len %2u, offset %2u,",
                  i, lo_new->fields[i].f_type,  lo_new->fields[i].f_len,
                  lo_new->fields[i].f_offset));
        info = aggBagGetTypeInfo(lo_new->fields[i].f_type);
        assert(info);
        ABTRACEQ((" name '%s'\n", info->ti_name));
    }

    lo_new->ref_count = 1;
    ++layouts_count;

    return lo_found;

  ERROR:
    if (layouts && !layouts_count) {
        rbdestroy(layouts);
        layouts = NULL;
    }
    if (lo_new) {
        if (lo_new->fields) {
            free(lo_new->fields);
        }
        free(lo_new);
    }
    return NULL;
}


/**
 *    Decrement the reference count of the layout in 'layout' and
 *    destroy it if its reference count is 0.
 *
 *    Also, destroy the redblack tree of existing layouts if all
 *    layouts have been destroyed.
 */
static void
abLayoutDestroy(
    const ab_layout_t  *layout)
{
    if (layout) {
        ab_layout_t *LO = (ab_layout_t *)layout;
        const void *found;

        if (LO->ref_count > 1) {
            --LO->ref_count;
            return;
        }

        /* remove from redblack tree */
        if (layouts) {
            found = rbdelete(LO, layouts);
            if (found) {
                --layouts_count;
            }
            if (0 == layouts_count) {
                rbdestroy(layouts);
                layouts = NULL;
            }
        }

        free(LO->fields);
        free(LO);
    }
}


/**
 *    A callback function used by skQSort() to sort the fields that
 *    comprise the key and counter.
 */
static int
abLayoutFieldSorter(
    const void         *v_a,
    const void         *v_b)
{
    const ab_field_t *a = (const ab_field_t *)v_a;
    const ab_field_t *b = (const ab_field_t *)v_b;

    ABTRACE(("sorter  a = %u, b = %u  ==> %d\n",
             a->f_type, b->f_type, (int)a->f_type - (int)b->f_type));

    return ((int)a->f_type - (int)b->f_type);
}


/*  ****************************************************************  */
/*  ****************************************************************  */
/*  Internal functions that operate on the AggBag structure. */
/*  ****************************************************************  */
/*  ****************************************************************  */



/**
 *    Confirms that AggBags `ab1_` and `ab2_` have the same keys and counters.
 *    Returns from the function if they do not.
 */
#define aggBagReturnIfMismatchAggBagKeyCounter(ab1_, ab2_)      \
    do {                                                        \
        if ((ab1_)->layout[0] != (ab2_)->layout[0]) {           \
            return SKAGGBAG_E_FIELDS_DIFFER_KEY;                \
        }                                                       \
        if ((ab1_)->layout[1] != (ab2_)->layout[1]) {           \
            return SKAGGBAG_E_FIELDS_DIFFER_COUNTER;            \
        }                                                       \
    } while (0)


/**
 *    Confirms that AggBag `ab_` is not NULL and has defined the fields in its
 *    key and counter.  Returns from the function if it has not.
 */
#define aggBagReturnIfUndefinedKeyCounter(ab_)                  \
    if ((ab_) && (ab_)->layout[0] && (ab_)->layout[1]) {        \
        /* all good */                                          \
    } else if (NULL == (ab_)) {                                 \
        return SKAGGBAG_E_NULL_PARM;                            \
    } else if (NULL == (ab_)->layout[0]) {                      \
        return SKAGGBAG_E_UNDEFINED_KEY;                        \
    } else if (NULL == (ab_)->layout[1]) {                      \
        return SKAGGBAG_E_UNDEFINED_COUNTER;                    \
    } else {                                                    \
        skAbort();                                              \
    }

/**
 *    Confirms that `key_` is not NULL and matches the key on AggBag `ab_`.
 *    Returns from the function if it has not.
 */
#define aggBagReturnIfMismatchedKey(ab_, key_)                  \
    if ((key_) && ((ab_)->layout[0] == (key_)->opaque)) {       \
        /* all good */                                          \
    } else if (NULL == (key_)) {                                \
        return SKAGGBAG_E_NULL_PARM;                            \
    } else if ((ab_)->layout[0] != (key_)->opaque) {            \
        return SKAGGBAG_E_FIELDS_DIFFER_KEY;                    \
    } else {                                                    \
        skAbort();                                              \
    }


/**
 *    Confirms that `counter_` is not NULL and matches the counter on AggBag
 *    `ab_`.  Returns from the function if it has not.
 */
#define aggBagReturnIfMismatchedCounter(ab_, counter_)                  \
    if ((counter_) && ((ab_)->layout[1] == (counter_)->opaque)) {       \
        /* all good */                                                  \
    } else if (NULL == (counter_)) {                                    \
        return SKAGGBAG_E_NULL_PARM;                                    \
    } else if ((ab_)->layout[1] != (counter_)->opaque) {                \
        return SKAGGBAG_E_FIELDS_DIFFER_COUNTER;                        \
    } else {                                                            \
        skAbort();                                                      \
    }


/**
 *    Initialize the aggregate 'agg' and the field iterator
 *    'field_iter' to work on the key or counter fields of 'ab'
 *    depending other whether 'key_counter_flag' is SK_AGGBAG_KEY or
 *    SK_AGGBAG_COUNTER.
 */
static void
aggBagInitializeAggregate(
    const sk_aggbag_t      *ab,
    unsigned int            key_counter_flag,
    sk_aggbag_aggregate_t  *agg,
    sk_aggbag_field_t      *field_iter)
{
    unsigned int idx;

    assert(SK_AGGBAG_KEY == key_counter_flag
           || SK_AGGBAG_COUNTER == key_counter_flag);
    idx = (SK_AGGBAG_COUNTER == key_counter_flag);

    if (ab && ab->layout[idx]) {
        if (agg) {
            agg->opaque = ab->layout[idx];
            memset(agg->data, 0, ab->layout[idx]->field_octets);
        }
        if (field_iter) {
            field_iter->opaque = ab->layout[idx];
            field_iter->pos = 0;
        }
    }
}


/**
 *    Return the type info structure for the type whose ID is
 *    'field_type', or return NULL if no such type exists.
 */
static const ab_type_info_t *
aggBagGetTypeInfo(
    uint16_t            field_type)
{
    size_t cur;

    if ((size_t)field_type < ab_type_info_key_max) {
        if (ab_type_info_key[field_type].ti_octets > 0) {
            assert(field_type == ab_type_info_key[field_type].ti_type);
            return &ab_type_info_key[field_type];
        }
    } else if (field_type >= SKAGGBAG_FIELD_RECORDS
               && ((cur = field_type - SKAGGBAG_FIELD_RECORDS)
                   < ab_type_info_counter_max))
    {
        if (ab_type_info_counter[cur].ti_octets > 0) {
            assert(field_type == ab_type_info_counter[cur].ti_type);
            return &ab_type_info_counter[cur];
        }
#if AB_SUPPORT_CUSTOM
    } else if (SKAGGBAG_FIELD_CUSTOM == field_type) {
        return &ab_custom_info;
#endif  /* AB_SUPPORT_CUSTOM */
    }
    return NULL;
}


/*
 *  status = aggbagOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Parse an option that was registered by skAggBagOptionsRegister().
 *    Return 0 on success, or non-zero on failure.
 */
static int
aggbagOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    sk_aggbag_options_t *ab_opts = (sk_aggbag_options_t*)cData;

    SK_UNUSED_PARAM(opt_arg);

    switch (opt_index) {
#if 0
      case OPT_AGGBAG_RECORD_VERSION:
        uint32_t tmp32;
        int rv;
        rv = skStringParseUint32(&tmp32, opt_arg, AGGBAG_REC_VERSION_MIN,
                                 AGGBAG_REC_VERSION_MAX);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          aggbag_options_record_version[0].name, opt_arg,
                          skStringParseStrerror(rv));
            return -1;
        }
        if (1 == tmp32) {
            skAppPrintErr("Invalid %s '%s': Illegal version number",
                          aggbag_options_record_version[0].name,
                          opt_arg);
            return -1;
        }
        ab_opts->record_version = (uint16_t)tmp32;
        break;
#endif  /* 0 */
      case OPT_AGGBAG_INVOCATION_STRIP:
        ab_opts->invocation_strip = 1;
        break;

      default:
        skAbortBadCase(opt_index);
    }

    return 0;
}


/**
 *    Print the contents of 'data' to 'fp'.  For debugging.
 */
static void
aggBagPrintData(
    const sk_aggbag_t  *tree,
    FILE               *fp,
    const void         *data)
{
    const uint8_t *u_data = (const uint8_t *)data;
    unsigned int i;

    for (i = 0; i < tree->data_len; ++i, ++u_data) {
        if (i == tree->layout[0]->field_octets) {
            fprintf(fp, " |");
        }
        fprintf(fp, " %02x", *u_data);
    }
}


/**
 *    Create a new layout from the 'field_count' fields in the array
 *    'fields' and store the layout in the either the key or counter
 *    of 'ab' depending other whether 'key_counter_flag' is
 *    SK_AGGBAG_KEY or SK_AGGBAG_COUNTER.
 */
static int
aggBagSetLayout(
    sk_aggbag_t            *ab,
    unsigned int            key_counter_flag,
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[])
{
    const ab_type_info_t *info;
    const ab_layout_t *new_lo;
    unsigned int i;
    unsigned int idx;

    assert(ab);
    assert(SK_AGGBAG_KEY == key_counter_flag
           || SK_AGGBAG_COUNTER == key_counter_flag);

    if (ab->fixed_fields) {
        return SKAGGBAG_E_FIXED_FIELDS;
    }
    idx = (SK_AGGBAG_COUNTER == key_counter_flag);

    /* confirm types make sense */
    for (i = 0; i < field_count; ++i) {
        info = aggBagGetTypeInfo(fields[i]);
        if (NULL == info || 0 == (info->ti_key_counter & key_counter_flag)) {
            return SKAGGBAG_E_FIELD_CLASS;
        }
#if !SK_ENABLE_IPV6
        if (16 == info->ti_octets) {
            return SKAGGBAG_E_UNSUPPORTED_IPV6;
        }
#endif
    }

#if AGGBAG_TRACE
    ABTRACE(("%s layout (%u fields): %u",
             (SK_AGGBAG_KEY == key_counter_flag) ? "key" : "counter",
             field_count, fields[0]));
    for (i = 1; i < field_count; ++i) {
        ABTRACEQ((", %u", fields[i]));
    }
    ABTRACEQ(("\n"));
#endif  /* AGGBAG_TRACE */

    new_lo = abLayoutCreate(field_count, fields);
    if (NULL == new_lo) {
        return SKAGGBAG_E_ALLOC;
    }

    abLayoutDestroy(ab->layout[idx]);
    ab->layout[idx] = new_lo;

    /* update values used by the red-black tree */
    ab->data_len
        = (((ab->layout[0]) ? ab->layout[0]->field_octets : 0)
           + ((ab->layout[1]) ? ab->layout[1]->field_octets : 0));
    ab->node_size = (offsetof(rbtree_node_t, data_color) + ab->data_len + 1u);

    return SKAGGBAG_OK;


}



/*  ****************************************************************  */
/*  ****************************************************************  */
/*  Public functions that operate on the AggBag structure. */
/*  ****************************************************************  */
/*  ****************************************************************  */

int
skAggBagAddAggBag(
    sk_aggbag_t        *ab_augend,
    const sk_aggbag_t  *ab_addend)
{
    sk_aggbag_iter_t iter = SK_AGGBAG_ITER_INITIALIZER;

    aggBagReturnIfMismatchAggBagKeyCounter(ab_augend, ab_addend);

    skAggBagIteratorBind(&iter, ab_addend);

    while (skAggBagIteratorNext(&iter) == SK_ITERATOR_OK) {
        aggBagKeyCounterAdd(ab_augend, &iter.key, &iter.counter, NULL);
    }
    skAggBagIteratorFree(&iter);

    return SKAGGBAG_OK;
}


int
skAggBagSubtractAggBag(
    sk_aggbag_t        *ab_minuend,
    const sk_aggbag_t  *ab_subtrahend)
{
    sk_aggbag_iter_t iter = SK_AGGBAG_ITER_INITIALIZER;
    const ab_layout_t *layout;
    const ab_field_t *f;
    const rbtree_node_t *node;
    sk_rbtree_iter_t *it;
    unsigned int key_len;
    unsigned int i;
    uint64_t dst;
    uint64_t src;
    uint8_t *data;

    /*
     *  This function iterates over the ab_minuend and search for its keys in
     *  ab_subtrahend.  It uses the sk_rbtree_t functions to allow modifying
     *  values directly, which the sk_aggbag_iter_t does not allow.
     *
     *  Question: Instead of searching for each key in ab_subtrahend, would it
     *  make more sense to have iterators for each sk_rbtree?
     */

    aggBagReturnIfMismatchAggBagKeyCounter(ab_minuend, ab_subtrahend);

    /* Iterate over the data in the destination file */
    skAggBagIteratorBind(&iter, ab_minuend);

    /* Length of key and location where counters begin */
    key_len = ab_minuend->layout[0]->field_octets;

    /* Order of the counters */
    layout = ab_minuend->layout[1];

    /* Get a handle to the low-level red-black iterator */
    it = (sk_rbtree_iter_t *)iter.opaque;

    /* Iterate over the tree */
    while ((data = (uint8_t *)sk_rbtree_iter_next(it))) {
        /* Fill the AggBag iterator */
        memcpy(iter.key.data, data, key_len);
        /* Find the key in the other AggBag */
        node = sk_rbtree_find(ab_subtrahend, iter.key.data);
        if (node) {
            /* If found, loop over counters and subtract them */
            for (i = 0, f = layout->fields; i < layout->field_count; ++i, ++f)
            {
                assert(sizeof(uint64_t) == f->f_len);
                memcpy(&dst, data + key_len + f->f_offset, f->f_len);
                memcpy(&src, node->data_color+ key_len+ f->f_offset,
                       f->f_len);
                dst = ntoh64(dst);
                src = ntoh64(src);
                if (dst <= src) {
                    dst = 0;
                } else {
                    dst -= src;
                }
                dst = hton64(dst);
                memcpy(data + key_len + f->f_offset, &dst, f->f_len);
            }
        }
    }

    skAggBagIteratorFree(&iter);
    return SKAGGBAG_OK;
}

int
skAggBagDivideAggBag(
    sk_aggbag_t                *ab_dividend,
    const sk_aggbag_t          *ab_divisor,
    const sk_aggbag_div_zero_t *div_zero)
{
    sk_aggbag_iter_t iter = SK_AGGBAG_ITER_INITIALIZER;
    const ab_layout_t *layout;
    const ab_field_t *f;
    const rbtree_node_t *node;
    sk_rbtree_iter_t *it;
    unsigned int key_len;
    unsigned int i;
    uint64_t dst;
    uint64_t src;
    uint8_t *data;
    int rv;

    /*
     *  This function iterates over the ab_dividend and searches for its keys
     *  in ab_divisor.  It uses the sk_rbtree_t functions to allow modifying
     *  values directly, which the sk_aggbag_iter_t does not allow.  This is
     *  also needed to handle errors when ab_dividend has a key that is not
     *  present in ab_divisor.
     */

    aggBagReturnIfMismatchAggBagKeyCounter(ab_dividend, ab_divisor);

    rv = SKAGGBAG_OK;

    /* Iterator over the data in the destination file */
    skAggBagIteratorBind(&iter, ab_dividend);

    /* Length of key and location where counters begin */
    key_len = ab_dividend->layout[0]->field_octets;

    /* Order of the counters */
    layout = ab_dividend->layout[1];

    /* Get a handle to the low-level red-black iterator */
    it = (sk_rbtree_iter_t *)iter.opaque;

    /* Iterate over the tree */
    while ((data = (uint8_t *)sk_rbtree_iter_next(it))) {
        /* Fill the AggBag iterator */
        memcpy(iter.key.data, data, key_len);
        /* Find the key in the other AggBag */
        node = sk_rbtree_find(ab_divisor, iter.key.data);
        /* If found, loop over counters and divide them; if not found, handle
         * according to div_zero->action */
        if (node) {
            for (i = 0, f = layout->fields; i < layout->field_count; ++i, ++f)
            {
                assert(sizeof(uint64_t) == f->f_len);
                memcpy(&dst, data + key_len + f->f_offset, f->f_len);
                memcpy(&src, node->data_color+ key_len+ f->f_offset,
                       f->f_len);
                dst = ntoh64(dst);
                src = ntoh64(src);

                if (src > 0) {
                    /* divide and add one if (remainder >= 0.5 * src) */
                    dst = ((dst / src)
                           + ((dst % src) >= (src >> 1) + (src & 1)));
                } else {
                    switch (div_zero->action) {
                      case SKAGGBAG_DIV_ZERO_NOCHANGE:
                        break;
                      case SKAGGBAG_DIV_ZERO_VALUE:
                        dst = div_zero->value;
                        break;
                      case SKAGGBAG_DIV_ZERO_ERROR:
                        rv = SKAGGBAG_E_DIVIDE_BY_ZERO;
                        goto END;
                      case SKAGGBAG_DIV_ZERO_DELETE:
                        /* set all counters to 0 */
                        memset(data + key_len, 0, layout->field_octets);
                        /* try the next key */
                        goto AFTER_FOR;
                    }
                }
                dst = hton64(dst);
                memcpy(data + key_len + f->f_offset, &dst, f->f_len);
            }
          AFTER_FOR:
            ; /* empty */
        } else {
            switch (div_zero->action) {
              case SKAGGBAG_DIV_ZERO_NOCHANGE:
                break;
              case SKAGGBAG_DIV_ZERO_VALUE:
                /* set each counter to the specified value */
                for (i = 0, f = layout->fields;
                     i < layout->field_count;
                     ++i, ++f)
                {
                    dst = hton64(div_zero->value);
                    memcpy(data + key_len + f->f_offset, &dst, f->f_len);
                }
                break;
              case SKAGGBAG_DIV_ZERO_ERROR:
                rv = SKAGGBAG_E_DIVIDE_BY_ZERO;
                goto END;
              case SKAGGBAG_DIV_ZERO_DELETE:
                /* cannot delete from tree while iterating over it; set all
                 * counters to 0 instead */
                memset(data + key_len, 0, layout->field_octets);
                break;
            }
        }
    }

  END:
    skAggBagIteratorFree(&iter);
    return rv;
}

int
skAggBagAggregateGetDatetime(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field_iter,
    sktime_t                       *time_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;
    uint64_t tmp;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    switch (field->f_type) {
      case SKAGGBAG_FIELD_STARTTIME:
      case SKAGGBAG_FIELD_ENDTIME:
      case SKAGGBAG_FIELD_ANY_TIME:
        assert(sizeof(sktime_t) == field->f_len);
        memcpy(&tmp, agg->data + field->f_offset, field->f_len);
        *time_value = (sktime_t)ntoh64(tmp);
        break;
      default:
        return SKAGGBAG_E_GET_SET_MISMATCH;
    }

    return SKAGGBAG_OK;
}

int
skAggBagAggregateGetIPAddress(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field_iter,
    skipaddr_t                     *ip_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    switch (field->f_type) {
      case SKAGGBAG_FIELD_SIPv4:
      case SKAGGBAG_FIELD_DIPv4:
      case SKAGGBAG_FIELD_NHIPv4:
      case SKAGGBAG_FIELD_ANY_IPv4:
        {
            uint32_t tmp;
            assert(sizeof(tmp) == field->f_len);
            memcpy(&tmp, agg->data + field->f_offset, sizeof(tmp));
            tmp = ntohl(tmp);
            skipaddrSetV4(ip_value, &tmp);
        }
        break;
      case SKAGGBAG_FIELD_SIPv6:
      case SKAGGBAG_FIELD_DIPv6:
      case SKAGGBAG_FIELD_NHIPv6:
      case SKAGGBAG_FIELD_ANY_IPv6:
#if !SK_ENABLE_IPV6
        return SKAGGBAG_E_UNSUPPORTED_IPV6;
#else
        assert(16 == field->f_len);
        skipaddrSetV6(ip_value, agg->data + field->f_offset);
        break;
#endif  /* SK_ENABLE_IPV6 */
      default:
        return SKAGGBAG_E_GET_SET_MISMATCH;
    }

    return SKAGGBAG_OK;
}

int
skAggBagAggregateGetUnsigned(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field_iter,
    uint64_t                       *unsigned_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    switch (field->f_type) {
      case SKAGGBAG_FIELD_SIPv4:
      case SKAGGBAG_FIELD_DIPv4:
      case SKAGGBAG_FIELD_NHIPv4:
      case SKAGGBAG_FIELD_ANY_IPv4:
      case SKAGGBAG_FIELD_SIPv6:
      case SKAGGBAG_FIELD_DIPv6:
      case SKAGGBAG_FIELD_NHIPv6:
      case SKAGGBAG_FIELD_ANY_IPv6:
      /* case SKAGGBAG_FIELD_STARTTIME: */
      /* case SKAGGBAG_FIELD_ENDTIME: */
      /* case SKAGGBAG_FIELD_ANY_TIME: */
        return SKAGGBAG_E_GET_SET_MISMATCH;
      default:
        break;
    }

    switch (field->f_len) {
      case 1:
        *unsigned_value = agg->data[field->f_offset];
        break;
      case 2:
        {
            uint16_t tmp;
            assert(sizeof(tmp) == field->f_len);
            memcpy(&tmp, agg->data + field->f_offset, sizeof(tmp));
            *unsigned_value = ntohs(tmp);
        }
        break;
      case 4:
        {
            uint32_t tmp;
            assert(sizeof(tmp) == field->f_len);
            memcpy(&tmp, agg->data + field->f_offset, sizeof(tmp));
            *unsigned_value = ntohl(tmp);
        }
        break;
      case 8:
        assert(sizeof(*unsigned_value) == field->f_len);
        memcpy(unsigned_value, agg->data + field->f_offset,
               sizeof(*unsigned_value));
        *unsigned_value = ntoh64(*unsigned_value);
        break;
      case 16:
        return SKAGGBAG_E_GET_SET_MISMATCH;
      default:
        skAbortBadCase(field->f_len);
    }

    return SKAGGBAG_OK;
}

int
skAggBagAggregateSetDatetime(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field_iter,
    sktime_t                    time_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;
    uint64_t tmp;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);
    assert(sizeof(tmp) == sizeof(time_value));

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    switch (field->f_type) {
      case SKAGGBAG_FIELD_STARTTIME:
      case SKAGGBAG_FIELD_ENDTIME:
      case SKAGGBAG_FIELD_ANY_TIME:
        assert(sizeof(sktime_t) == field->f_len);
        tmp = hton64((uint64_t)time_value);
        memcpy(agg->data + field->f_offset, &tmp, field->f_len);
        break;
      default:
        return SKAGGBAG_E_GET_SET_MISMATCH;
    }

    return SKAGGBAG_OK;
}

int
skAggBagAggregateSetIPAddress(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field_iter,
    const skipaddr_t           *ip_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    switch (field->f_type) {
      case SKAGGBAG_FIELD_SIPv4:
      case SKAGGBAG_FIELD_DIPv4:
      case SKAGGBAG_FIELD_NHIPv4:
      case SKAGGBAG_FIELD_ANY_IPv4:
        {
            uint32_t tmp;
            assert(sizeof(tmp) == field->f_len);
            if (skipaddrGetAsV4(ip_value, &tmp)) {
                return SKAGGBAG_E_GET_SET_MISMATCH;
            }
            tmp = htonl(tmp);
            memcpy(agg->data + field->f_offset, &tmp, field->f_len);
        }
        break;
      case SKAGGBAG_FIELD_SIPv6:
      case SKAGGBAG_FIELD_DIPv6:
      case SKAGGBAG_FIELD_NHIPv6:
      case SKAGGBAG_FIELD_ANY_IPv6:
#if !SK_ENABLE_IPV6
        return SKAGGBAG_E_UNSUPPORTED_IPV6;
#else
        assert(16 == field->f_len);
        skipaddrGetAsV6(ip_value, agg->data + field->f_offset);
        break;
#endif  /* SK_ENABLE_IPV6 */
      default:
        return SKAGGBAG_E_GET_SET_MISMATCH;
    }

    return SKAGGBAG_OK;
}

int
skAggBagAggregateSetUnsigned(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field_iter,
    uint64_t                    unsigned_value)
{
    const ab_layout_t *layout;
    const ab_field_t *field;

    assert(agg);
    assert(field_iter);
    assert(agg->opaque == field_iter->opaque);
    assert(agg->opaque);

    layout = (const ab_layout_t *)agg->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_E_BAD_INDEX;
    }
    field = &layout->fields[field_iter->pos];

    ABTRACE(("set unsigned id = %u, value = %" PRIu64 "\n",
             field->f_type, unsigned_value));

    switch (field->f_type) {
      case SKAGGBAG_FIELD_SIPv4:
      case SKAGGBAG_FIELD_DIPv4:
      case SKAGGBAG_FIELD_NHIPv4:
      case SKAGGBAG_FIELD_ANY_IPv4:
      case SKAGGBAG_FIELD_SIPv6:
      case SKAGGBAG_FIELD_DIPv6:
      case SKAGGBAG_FIELD_NHIPv6:
      case SKAGGBAG_FIELD_ANY_IPv6:
      /* case SKAGGBAG_FIELD_STARTTIME: */
      /* case SKAGGBAG_FIELD_ENDTIME: */
      /* case SKAGGBAG_FIELD_ANY_TIME: */
        return SKAGGBAG_E_GET_SET_MISMATCH;
      default:
        break;
    }

    switch (field->f_len) {
      case 1:
        agg->data[field->f_offset] = unsigned_value;
        break;
      case 2:
        {
            uint16_t tmp = unsigned_value;
            assert(sizeof(tmp) == field->f_len);
            tmp = htons(tmp);
            memcpy(agg->data + field->f_offset, &tmp, sizeof(tmp));
        }
        break;
      case 4:
        {
            uint32_t tmp = unsigned_value;
            assert(sizeof(tmp) == field->f_len);
            tmp = htonl(tmp);
            memcpy(agg->data + field->f_offset, &tmp, sizeof(tmp));
        }
        break;
      case 8:
        assert(sizeof(unsigned_value) == field->f_len);
        unsigned_value = hton64(unsigned_value);
        memcpy(agg->data + field->f_offset, &unsigned_value,
               sizeof(unsigned_value));
        break;
      case 16:
        return SKAGGBAG_E_GET_SET_MISMATCH;
      default:
        skAbortBadCase(field->f_len);
    }

    return SKAGGBAG_OK;
}


int
skAggBagCreate(
    sk_aggbag_t       **ab_param)
{
    sk_aggbag_t *ab;

    if (NULL == ab_param) {
        return SKAGGBAG_E_NULL_PARM;
    }

    ab = (sk_aggbag_t *)calloc(1, sizeof(sk_aggbag_t));
    if (NULL == ab) {
        *ab_param = NULL;
        return SKAGGBAG_E_ALLOC;
    }

    /* Initialize values used by the red-black tree */
    ab->root = RBT_NIL;
    ab->size = 0;
    ab->data_len = 0;
    ab->node_size = (offsetof(rbtree_node_t, data_color) + ab->data_len + 1u);

    *ab_param = ab;
    return SKAGGBAG_OK;
}

void
skAggBagDestroy(
    sk_aggbag_t       **ab_param)
{
    sk_aggbag_t *ab;

    if (ab_param && *ab_param) {
        ab = *ab_param;
        *ab_param = NULL;

        sk_rbtree_destroy(ab);
        abLayoutDestroy(ab->layout[0]);
        abLayoutDestroy(ab->layout[1]);
        free(ab);
    }
}


sk_aggbag_type_t
skAggBagFieldIterGetType(
    const sk_aggbag_field_t    *field_iter)
{
    const ab_layout_t *layout;

    assert(field_iter);
    assert(field_iter->opaque);

    layout = (const ab_layout_t *)field_iter->opaque;
    if (field_iter->pos >= layout->field_count) {
        return SKAGGBAG_FIELD_INVALID;
    }
    return layout->fields[field_iter->pos].f_type;
}

int
skAggBagFieldIterNext(
    sk_aggbag_field_t  *field_iter)
{
    const ab_layout_t *layout;

    assert(field_iter);
    if (field_iter && field_iter->opaque) {
        ++field_iter->pos;
        layout = (const ab_layout_t *)field_iter->opaque;
        if (layout->field_count > field_iter->pos) {
            return SK_ITERATOR_OK;
        }
        field_iter->pos = layout->field_count;
    }
    return SK_ITERATOR_NO_MORE_ENTRIES;
}

void
skAggBagFieldIterReset(
    sk_aggbag_field_t  *field_iter)
{
    assert(field_iter);
    if (field_iter) {
        field_iter->pos = 0;
    }
}


const char *
skAggBagFieldTypeGetDescription(
    sk_aggbag_type_t    field_type)
{
    const ab_type_info_t *info;

    info = aggBagGetTypeInfo(field_type);
    if (info) {
        return info->ti_description;
    }
    return NULL;
}


unsigned int
skAggBagFieldTypeGetDisposition(
    sk_aggbag_type_t    field_type)
{
    const ab_type_info_t *info;

    info = aggBagGetTypeInfo(field_type);
    if (info) {
        return info->ti_key_counter;
    }
    return 0;
}

const char *
skAggBagFieldTypeGetName(
    sk_aggbag_type_t    field_type)
{
    const ab_type_info_t *info;

    info = aggBagGetTypeInfo(field_type);
    if (info) {
        return info->ti_name;
    }
    return NULL;
}


void
skAggBagFieldTypeIteratorBind(
    sk_aggbag_type_iter_t  *type_iter,
    unsigned int            key_counter_flag)
{
    assert(type_iter);
    if (type_iter) {
        type_iter->key_counter_flag = key_counter_flag;
        skAggBagFieldTypeIteratorReset(type_iter);
    }
}


const char *
skAggBagFieldTypeIteratorNext(
    sk_aggbag_type_iter_t  *type_iter,
    sk_aggbag_type_t       *field_type)
{
    const ab_type_info_t *info = NULL;
    size_t cur;

    /* when entering this function, type_iter is expected to be on the
     * type to return */

    assert(type_iter);
    if (NULL == type_iter) {
        goto END;
    }

    if (type_iter->pos >= SKAGGBAG_FIELD_INVALID) {
#if AB_SUPPORT_CUSTOM
        if (SKAGGBAG_FIELD_CUSTOM == type_iter->pos) {
            info = &ab_custom_info;
            type_iter->pos = SKAGGBAG_FIELD_INVALID;
        }
#endif  /* AB_SUPPORT_CUSTOM */
        goto END;
    }

    if (SK_AGGBAG_KEY == type_iter->key_counter_flag) {
        cur = type_iter->pos;
        if (cur >= ab_type_info_key_max) {
            /* value out of range */
            goto END;
        }
        info = &ab_type_info_key[cur];
        /* update type_iter for next iteration */
        for (++cur; cur < ab_type_info_key_max; ++cur) {
            if (ab_type_info_key[cur].ti_octets > 0
                && 0 != strcmp(ab_type_info_key[cur].ti_description,
                               "unimplemented"))
            {
                type_iter->pos = (sk_aggbag_type_t)cur;
                goto END;
            }
        }

    } else if (SK_AGGBAG_COUNTER == type_iter->key_counter_flag) {
        if (type_iter->pos < SKAGGBAG_FIELD_RECORDS
            || ((cur = type_iter->pos - SKAGGBAG_FIELD_RECORDS)
                >= ab_type_info_counter_max))
        {
            /* value out of range */
            goto END;
        }
        info = &ab_type_info_counter[cur];
        for (++cur; cur < ab_type_info_counter_max; ++cur) {
            if (ab_type_info_counter[cur].ti_octets > 0
                && 0 != strcmp(ab_type_info_counter[cur].ti_description,
                               "unimplemented"))
            {
                type_iter->pos
                    = (sk_aggbag_type_t)(SKAGGBAG_FIELD_RECORDS + cur);
                goto END;
            }
        }

    } else {
        assert((SK_AGGBAG_KEY == type_iter->key_counter_flag)
               || (SK_AGGBAG_COUNTER == type_iter->key_counter_flag));
    }

#if AB_SUPPORT_CUSTOM
    type_iter->pos = SKAGGBAG_FIELD_CUSTOM;
#else
    type_iter->pos = SKAGGBAG_FIELD_INVALID;
#endif  /* AB_SUPPORT_CUSTOM */

  END:
    if (field_type) {
        if (info) {
            *field_type = info->ti_type;
        } else {
            *field_type = SKAGGBAG_FIELD_INVALID;
        }
    }
    if (info) {
        return info->ti_name;
    }
    return NULL;
}


void
skAggBagFieldTypeIteratorReset(
    sk_aggbag_type_iter_t  *type_iter)
{
    assert(type_iter);
    if (type_iter) {
        switch (type_iter->key_counter_flag) {
          case SK_AGGBAG_KEY:
            type_iter->pos = SKAGGBAG_FIELD_SIPv4;
            break;
          case SK_AGGBAG_COUNTER:
            type_iter->pos = SKAGGBAG_FIELD_RECORDS;
            break;
          default:
            type_iter->pos = SKAGGBAG_FIELD_INVALID;
            type_iter->key_counter_flag = SK_AGGBAG_KEY;
            break;
        }
    }
}


void
skAggBagInitializeCounter(
    const sk_aggbag_t      *ab,
    sk_aggbag_aggregate_t  *counter,
    sk_aggbag_field_t      *counter_iter)
{
    aggBagInitializeAggregate(ab, SK_AGGBAG_COUNTER, counter, counter_iter);
}

void
skAggBagInitializeKey(
    const sk_aggbag_t      *ab,
    sk_aggbag_aggregate_t  *key,
    sk_aggbag_field_t      *key_iter)
{
    aggBagInitializeAggregate(ab, SK_AGGBAG_KEY, key, key_iter);
}


void
skAggBagIteratorBind(
    sk_aggbag_iter_t       *iter,
    const sk_aggbag_t      *ab)
{
    sk_rbtree_iter_t *it;

    if (ab && iter) {
        memset(iter, 0, sizeof(*iter));
        it = sk_rbtree_iter_create(ab);
        if (NULL == it) {
            return;
        }
        skAggBagInitializeKey(ab, &iter->key, &iter->key_field_iter);
        skAggBagInitializeCounter(
            ab, &iter->counter, &iter->counter_field_iter);
        iter->opaque = it;
    }
}

void
skAggBagIteratorFree(
    sk_aggbag_iter_t   *iter)
{
    if (iter) {
        if (iter->opaque) {
            sk_rbtree_iter_free((sk_rbtree_iter_t *)iter->opaque);
        }
        memset(iter, 0, sizeof(*iter));
    }
}

int
skAggBagIteratorNext(
    sk_aggbag_iter_t   *iter)
{
    sk_rbtree_iter_t *it;
    const void *data;
    size_t key_len;

    if (NULL == iter || NULL == iter->opaque) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    it = (sk_rbtree_iter_t *)iter->opaque;
    data = sk_rbtree_iter_next(it);
    if (NULL == data) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    key_len = ((ab_layout_t *)iter->key.opaque)->field_octets;
    memcpy(iter->key.data, data, key_len);
    memcpy(iter->counter.data, (const uint8_t *)data + key_len,
           ((ab_layout_t *)iter->counter.opaque)->field_octets);
    iter->key_field_iter.pos = 0;
    iter->counter_field_iter.pos = 0;

    return SK_ITERATOR_OK;
}

void
skAggBagIteratorReset(
    sk_aggbag_iter_t   *iter)
{
    sk_rbtree_iter_t *it;

    if (iter) {
        it = (sk_rbtree_iter_t *)iter->opaque;
        it->prev_data = rbtree_iter_start(it, it->tree, 0);
    }
}


int
skAggBagKeyCounterAdd(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter)
{
    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);
    aggBagReturnIfMismatchedCounter(ab, counter);

    aggBagKeyCounterAdd(ab, key, counter, new_counter);

    return SKAGGBAG_OK;
}

/*
 *  Helper for skAggBagKeyCounterAdd() that does no error checking.
 */
static void
aggBagKeyCounterAdd(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter)
{
    const ab_layout_t *layout;
    const ab_field_t *f;
    rbtree_node_t *node;
    unsigned int i;
    uint64_t dst;
    uint64_t src;
    uint64_t tmp;

    if (new_counter) {
        new_counter->opaque = counter->opaque;
    }
    ab->fixed_fields = 1;

    node = sk_rbtree_find(ab, key->data);
    if (NULL == node) {
        sk_rbtree_insert(ab, key->data, counter->data);
        if (new_counter) {
            memcpy(new_counter->data, counter->data,
                   ab->layout[1]->field_octets);
        }
    } else {
        layout = ab->layout[1];
        for (i = 0, f = layout->fields; i < layout->field_count; ++i, ++f) {
            assert(sizeof(uint64_t) == f->f_len);
            memcpy(&dst,
                   node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   f->f_len);
            memcpy(&src, counter->data + f->f_offset, f->f_len);
            dst = tmp = ntoh64(dst);
            src = ntoh64(src);
            dst += src;
            /* sum must be >= each number; if not, overflow detected */
            if (dst < src || dst < tmp) {
                /* overflow */
                dst = UINT64_MAX;
            }
            dst = hton64(dst);
            memcpy(node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   &dst, f->f_len);
            if (new_counter) {
                memcpy(new_counter->data + f->f_offset, &dst, f->f_len);
            }
        }
    }
    if (/* DISABLES CODE*/ (0)) {
        sk_rbtree_debug_print(ab, stderr, aggBagPrintData);
    }
}


/*
 *  Find `key` in `ab` and divide its counter by `counter`.
 */
int
skAggBagKeyCounterDivide(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    const sk_aggbag_div_zero_t     *div_zero,
    sk_aggbag_aggregate_t          *new_counter)
{
    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);
    aggBagReturnIfMismatchedCounter(ab, counter);

    return aggBagKeyCounterDivide(ab, key, counter, div_zero, new_counter);
}


/*
 *  Helper for skAggBagKeyCounterDivide().
 */
static int
aggBagKeyCounterDivide(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    const sk_aggbag_div_zero_t     *div_zero,
    sk_aggbag_aggregate_t          *new_counter)
{
    const ab_layout_t *layout;
    const ab_field_t *f;
    rbtree_node_t *node;
    unsigned int i;
    /* dst is dividend and src is divisor */
    uint64_t dst;
    uint64_t src;

    if (new_counter) {
        new_counter->opaque = counter->opaque;
    }

    ab->fixed_fields = 1;

    node = sk_rbtree_find(ab, key->data);
    if (node) {
        layout = ab->layout[1];
        for (i = 0, f = layout->fields; i < layout->field_count; ++i, ++f) {
            assert(sizeof(uint64_t) == f->f_len);
            memcpy(&dst,
                   node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   f->f_len);
            memcpy(&src, counter->data + f->f_offset, f->f_len);
            dst = ntoh64(dst);
            src = ntoh64(src);
            if (src > 0) {
                /* divide; add one if (remainder >= 0.5 * src) */
                dst = ((dst / src)
                       + ((dst % src) >= (src >> 1) + (src & 1)));
            } else {
                switch (div_zero->action) {
                  case SKAGGBAG_DIV_ZERO_NOCHANGE:
                    break;
                  case SKAGGBAG_DIV_ZERO_VALUE:
                    dst = div_zero->value;
                    break;
                  case SKAGGBAG_DIV_ZERO_ERROR:
                    return SKAGGBAG_E_DIVIDE_BY_ZERO;
                  case SKAGGBAG_DIV_ZERO_DELETE:
                    /* remove the key */
                    sk_rbtree_remove(ab, key->data);
                    if (new_counter) {
                        /* set all values in new_counter to zero */
                        memset(new_counter->data, 0, layout->field_octets);
                    }
                    return SKAGGBAG_OK;
                }
            }
            dst = hton64(dst);
            memcpy(node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   &dst, f->f_len);
            if (new_counter) {
                memcpy(new_counter->data + f->f_offset, &dst, f->f_len);
            }
        }
    }

    return SKAGGBAG_OK;
}

int
skAggBagKeyCounterGet(
    const sk_aggbag_t              *ab,
    const sk_aggbag_aggregate_t    *key,
    sk_aggbag_aggregate_t          *counter)
{
    rbtree_node_t *node;

    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);
    if (NULL == counter) {
        return SKAGGBAG_E_NULL_PARM;
    }

    counter->opaque = ab->layout[1];

    node = sk_rbtree_find(ab, key->data);
    if (NULL == node) {
        memset(counter->data, 0, ab->layout[1]->field_octets);
    } else {
        memcpy(counter->data, node->data_color + ab->layout[0]->field_octets,
               ab->layout[1]->field_octets);
    }

    return SKAGGBAG_OK;
}

int
skAggBagKeyCounterRemove(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key)
{
    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);

    ab->fixed_fields = 1;

    sk_rbtree_remove(ab, key->data);
    return SKAGGBAG_OK;
}

int
skAggBagKeyCounterSet(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter)
{
    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);
    aggBagReturnIfMismatchedCounter(ab, counter);

    ab->fixed_fields = 1;

    switch (sk_rbtree_insert(ab, key->data, counter->data)) {
      case SK_RBTREE_OK:
      case SK_RBTREE_ERR_DUPLICATE:
        return SKAGGBAG_OK;
      case SK_RBTREE_ERR_ALLOC:
        return SKAGGBAG_E_ALLOC;
      default:
        return SKAGGBAG_E_INSERT;
    }
}

/*
 *  Find `key` in `ab` and subtract `counter` from its counter.
 */
int
skAggBagKeyCounterSubtract(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter)
{
    aggBagReturnIfUndefinedKeyCounter(ab);
    aggBagReturnIfMismatchedKey(ab, key);
    aggBagReturnIfMismatchedCounter(ab, counter);

    aggBagKeyCounterSubtract(ab, key, counter, new_counter);

    return SKAGGBAG_OK;
}

/*
 *  Helper for skAggBagKeyCounterSubtract() that does no error checking.
 */
static void
aggBagKeyCounterSubtract(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter)
{
    const ab_layout_t *layout;
    const ab_field_t *f;
    rbtree_node_t *node;
    unsigned int i;
    uint64_t dst;
    uint64_t src;

    if (new_counter) {
        new_counter->opaque = counter->opaque;
    }

    ab->fixed_fields = 1;

    node = sk_rbtree_find(ab, key->data);
    if (node) {
        layout = ab->layout[1];
        for (i = 0, f = layout->fields; i < layout->field_count; ++i, ++f) {
            assert(sizeof(uint64_t) == f->f_len);
            memcpy(&dst,
                   node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   f->f_len);
            memcpy(&src, counter->data + f->f_offset, f->f_len);
            dst = ntoh64(dst);
            src = ntoh64(src);
            if (dst <= src) {
                dst = 0;
            } else {
                dst -= src;
            }
            dst = hton64(dst);
            memcpy(node->data_color+ ab->layout[0]->field_octets+ f->f_offset,
                   &dst, f->f_len);
            if (new_counter) {
                memcpy(new_counter->data + f->f_offset, &dst, f->f_len);
            }
        }
    }
}


/* Read 'ab' from filename---a wrapper around skAggBagRead(). */
int
skAggBagLoad(
    sk_aggbag_t       **ab,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int err = SKAGGBAG_OK;
    ssize_t rv;

    if (NULL == filename || NULL == ab) {
        ABTRACE(("Got a null parameter ab=%p, filename=%p\n",
                 V(ab), V(filename)));
        return SKAGGBAG_E_NULL_PARM;
    }

    ABTRACE(("Creating stream for file '%s'\n", filename));
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        ABTRACE(("Failed to create stream\n"));
        err = SKAGGBAG_E_READ;
        goto END;
    }

    ABTRACE(("Reading from stream...\n"));
    err = skAggBagRead(ab, stream);

  END:
    ABTRACE(("Destroying stream and returning %d\n", err));
    skStreamDestroy(&stream);
    return err;
}




/* Set the parameters to use when writing an Aggbag */
void
skAggBagOptionsBind(
    sk_aggbag_t                *ab,
    const sk_aggbag_options_t  *ab_opts)
{
    assert(ab);
    ab->options = ab_opts;
}

/* Initialize 'ab_opts' and register options */
int
skAggBagOptionsRegister(
    sk_aggbag_options_t    *ab_opts)
{
    assert(ab_opts);
    assert(sizeof(aggbag_options)/sizeof(aggbag_options[0])
           == sizeof(aggbag_options_help)/sizeof(aggbag_options_help[0]));

    if (skOptionsRegister(aggbag_options, aggbagOptionsHandler,
                          (clientData)ab_opts)
        || skOptionsNotesRegister(ab_opts->existing_silk_files
                                  ? &ab_opts->note_strip
                                  : NULL)
        || skCompMethodOptionsRegister(&ab_opts->comp_method))
    {
        return -1;
    }
    return 0;
}

/* Clean up memory used by the Aggbag options */
void
skAggBagOptionsTeardown(
    void)
{
    skOptionsNotesTeardown();
}

/* Print the usage strings for the options that the library registers */
void
skAggBagOptionsUsage(
    FILE               *fh)
{
    unsigned int i;

    for (i = 0; aggbag_options[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n",
                aggbag_options[i].name, SK_OPTION_HAS_ARG(aggbag_options[i]),
                aggbag_options_help[i]);
    }
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
}


int
skAggBagRead(
    sk_aggbag_t       **ab_param,
    skstream_t         *stream)
{
    sk_aggbag_t *ab = NULL;
    sk_file_header_t *hdr;
    sk_header_entry_t *hentry;
    int swap_flag;
    size_t entry_read_len;
    unsigned int i;
    sk_aggbag_type_t field_array[UINT8_MAX];
    int err = SKAGGBAG_OK;
    ssize_t b;
    uint8_t entrybuf[128];
    ssize_t rv;

    if (NULL == ab_param || NULL == stream) {
        ABTRACE(("Got a null parameter ab_param=%p, stream=%p\n",
                 V(ab_param), V(stream)));
        return SKAGGBAG_E_NULL_PARM;
    }

    /* read header */
    ABTRACE(("Reading stream header\n"));
    rv = skStreamReadSilkHeader(stream, &hdr);
    if (rv) {
        ABTRACE(("Failure while reading stream header\n"));
        return SKAGGBAG_E_READ;
    }

    ABTRACE(("Checking stream header\n"));
    rv = skStreamCheckSilkHeader(stream, FT_AGGREGATEBAG, 1,1, &skAppPrintErr);
    if (rv) {
        ABTRACE(("Failure while checking stream header\n"));
        return SKAGGBAG_E_HEADER;
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    ABTRACE(("Checking for aggbag header entry\n"));
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_AGGBAG_ID);
    if (NULL == hentry) {
        ABTRACE(("Failure while checking for aggbag header entry \n"));
        return SKAGGBAG_E_HEADER;
    }
    if (AB_HENTRY_VERSION != aggBagHentryGetVersion(hentry)) {
        ABTRACE(("Aggbag header entry version (%u) is not supported\n",
                 aggBagHentryGetVersion(hentry)));
        return SKAGGBAG_E_HEADER;
    }

    /* allocate the new aggbag */
    ABTRACE(("Creating a new aggbag\n"));
    err = skAggBagCreate(&ab);
    if (err) {
        ABTRACE(("Failure (%d) while creating new aggbag\n", err));
        return err;
    }

    for (i = 0; i < aggBagHentryGetKeyCount(hentry); ++i) {
        field_array[i] = aggBagHentryGetKeyFieldType(hentry, i);
    }
    err = aggBagSetLayout(ab, SK_AGGBAG_KEY, i, field_array);
    if (err) {
        ABTRACE(("Failure (%d) while setting key layout\n", err));
        goto END;
    }

    for (i = 0; i < aggBagHentryGetCounterCount(hentry); ++i) {
        field_array[i] = aggBagHentryGetCounterFieldType(hentry, i);
    }
    err = aggBagSetLayout(ab, SK_AGGBAG_COUNTER, i, field_array);
    if (err) {
        ABTRACE(("Failure (%d) while setting counter layout\n", err));
        goto END;
    }

    /* compute size of a complete entry, and double check that sizes
     * are reasonable */
    entry_read_len = ab->layout[0]->field_octets + ab->layout[1]->field_octets;
    if (entry_read_len != skHeaderGetRecordLength(hdr)) {
        ABTRACE((("Record length reported in header"
                  " (%" SK_PRIuZ ") does not match computed entry length"
                  " (%" SK_PRIuZ "==key=%u + counter=%u)\n"),
                 skHeaderGetRecordLength(hdr), entry_read_len,
                 ab->layout[0]->field_octets, ab->layout[1]->field_octets));
        goto END;
    }

    ab->fixed_fields = 1;

    /* set up is complete; read key/counter pairs */
    if (!swap_flag) {
        ABTRACE(("Starting to read data from stream\n"));
        while ((b = skStreamRead(stream, &entrybuf, entry_read_len))
               == (ssize_t)entry_read_len)
        {
            if (sk_rbtree_insert(ab, entrybuf,
                                 entrybuf + ab->layout[0]->field_octets)
                != SK_RBTREE_OK)
            {
                err = SKAGGBAG_E_ALLOC;
                goto END;
            }
        }
        ABTRACE(("Finished reading data from stream\n"));
    } else {
        /* FIXME: Values in tree always in big endian.  no need for
         * this branch of the read function */
        union val_un {
            uint64_t    u64;
            uint32_t    u32;
            uint16_t    u16;
            uint8_t     u8;
        } val;
        const ab_field_t *f;
        unsigned int field_count;
        unsigned int q;
        uint8_t *buf;

        ABTRACE(("Starting to read data from stream\n"));
        while ((b = skStreamRead(stream, &entrybuf, entry_read_len))
               == (ssize_t)entry_read_len)
        {
            for (q = 0; q < 2; ++q) {
                f = ab->layout[q]->fields;
                field_count = ab->layout[q]->field_count;
                if (0 == q) {
                    buf = entrybuf;
                } else {
                    buf = entrybuf + ab->layout[0]->field_octets;
                }
                for (i = 0; i < field_count; ++i, ++f) {
                    switch (f->f_len) {
                      case 1:
                      case 16:
                        break;
                      case 2:
                        memcpy(&val.u16, buf + f->f_offset, f->f_len);
                        val.u16 = BSWAP16(val.u16);
                        memcpy(buf + f->f_offset, &val.u16, f->f_len);
                        break;
                      case 4:
                        memcpy(&val.u32, buf + f->f_offset, f->f_len);
                        val.u32 = BSWAP32(val.u32);
                        memcpy(buf + f->f_offset, &val.u32, f->f_len);
                        break;
                      case 8:
                        memcpy(&val.u64, buf + f->f_offset, f->f_len);
                        val.u64 = BSWAP64(val.u64);
                        memcpy(buf + f->f_offset, &val.u64, f->f_len);
                        break;
                      default:
                        skAbortBadCase(f->f_len);
                    }
                }
            }
            if (sk_rbtree_insert(ab, entrybuf,
                                 entrybuf + ab->layout[0]->field_octets)
                != SK_RBTREE_OK)
            {
                err = SKAGGBAG_E_ALLOC;
                goto END;
            }
        }
        ABTRACE(("Finished reading data from stream\n"));
    }

    ABTRACE(("Checking the integrity of the red black tree returns %d\n",
             rbtree_assert(ab, ab->root, stderr)));

    /* check for a read error or a partially read entry */
    if (b != 0) {
        ABTRACE(("Result of read return unexpected value %" SK_PRIdZ "\n", b));
        err = SKAGGBAG_E_READ;
        ABTRACE(("Returning error code %d\n", err));
        goto END;
    }

    ABTRACE(("Reading aggbag from file was successful\n"));
    *ab_param = ab;
    err = SKAGGBAG_OK;

  END:
    if (err) {
        skAggBagDestroy(&ab);
    }
    return err;
}


/* Write 'ab' to 'filename'--a wrapper around skAggBagWrite(). */
int
skAggBagSave(
    const sk_aggbag_t  *ab,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int err = SKAGGBAG_OK;
    ssize_t rv;

    if (NULL == filename || NULL == ab) {
        return SKAGGBAG_E_NULL_PARM;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        err = SKAGGBAG_E_WRITE;
        goto END;
    }

    err = skAggBagWrite(ab, stream);

    rv = skStreamClose(stream);
    if (rv) {
        err = SKAGGBAG_E_WRITE;
    }

  END:
    skStreamDestroy(&stream);
    return err;
}


int
skAggBagSetCounterFields(
    sk_aggbag_t            *ab,
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[])
{
    if (NULL == ab || 0 == field_count || NULL == fields) {
        return SKAGGBAG_E_NULL_PARM;
    }

    return aggBagSetLayout(ab, SK_AGGBAG_COUNTER, field_count, fields);
}

int
skAggBagSetKeyFields(
    sk_aggbag_t            *ab,
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[])
{
    if (NULL == ab || 0 == field_count || NULL == fields) {
        return SKAGGBAG_E_NULL_PARM;
    }

    return aggBagSetLayout(ab, SK_AGGBAG_KEY, field_count, fields);
}


const char *
skAggBagStrerror(
    int                 err_code)
{
    static char buf[PATH_MAX];

    switch ((sk_aggbag_retval_t)err_code) {
      case SKAGGBAG_OK:
        return "Aggregate Bag command succeeded";
      case SKAGGBAG_E_ALLOC:
        return "Allocation failed";
      case SKAGGBAG_E_NULL_PARM:
        return "NULL or invalid parameter passed to function";
      case SKAGGBAG_E_FIXED_FIELDS:
        return "Aggregate Bag's fields are immutable";
      case SKAGGBAG_E_UNDEFINED_KEY:
        return "Aggregate Bag's key fields are undefined";
      case SKAGGBAG_E_UNDEFINED_COUNTER:
        return "Aggregate Bag's counter fields are undefined";
      case SKAGGBAG_E_FIELD_CLASS:
        return "Incorrect field type (key vs counter)";
      case SKAGGBAG_E_FIELDS_DIFFER_KEY:
        return "Set of key fields do not match";
      case SKAGGBAG_E_FIELDS_DIFFER_COUNTER:
        return "Set of counter fields do not match";
      case SKAGGBAG_E_GET_SET_MISMATCH:
        return "Incorrect get/set function called for field type";
      case SKAGGBAG_E_BAD_INDEX:
        return "Iterator points to invalid field";
      case SKAGGBAG_E_READ:
        return "Error while reading Aggregate Bag from stream";
      case SKAGGBAG_E_WRITE:
        return "Error while writing Aggregate Bag to stream";
      case SKAGGBAG_E_HEADER:
        return "File header contains unexpected value";
      case SKAGGBAG_E_INSERT:
        return "Unexpected error during insert";
      case SKAGGBAG_E_UNSUPPORTED_IPV6:
        return "SiLK is compiled without IPv6 support";
      case SKAGGBAG_E_DIVIDE_BY_ZERO:
        return "Aggregate Bag divisor has a value of zero or key is absent";
    }

    snprintf(buf, sizeof(buf),
             "Unrecognized Aggregate Bag error code (%d)", err_code);
    return buf;
}


int
skAggBagWrite(
    const sk_aggbag_t  *ab,
    skstream_t         *stream)
{
    uint8_t zero_buf[SKAGGBAG_AGGREGATE_MAXLEN];
    sk_rbtree_iter_t *it;
    sk_file_header_t *hdr;
    sk_header_entry_t *hentry;
    const uint8_t *data;
    ssize_t rv;

    if (NULL == ab || NULL == stream) {
        ABTRACE(("Got a null parameter ab=%p, stream=%p\n", V(ab), V(stream)));
        return SKAGGBAG_E_NULL_PARM;
    }

    if (NULL == ab->layout[0] || NULL == ab->layout[1]) {
        ABTRACE(("AggBag is not fully configured, key = %p, counter = %p\n",
                 V(ab->layout[0]), V(ab->layout[1])));
        return ((NULL == ab->layout[0])
                ? SKAGGBAG_E_UNDEFINED_KEY : SKAGGBAG_E_UNDEFINED_COUNTER);
    }

    hdr = skStreamGetSilkHeader(stream);
    ABTRACE(("Header for stream %p is %p\n", V(stream), V(hdr)));
    skHeaderSetByteOrder(hdr, SILK_ENDIAN_NATIVE);
    skHeaderSetFileFormat(hdr, FT_AGGREGATEBAG);
    skHeaderSetRecordVersion(hdr, 1);
    skHeaderSetRecordLength(hdr, ab->data_len);

    hentry = aggBagHentryCreate(ab);
    ABTRACE(("Created the aggbag header entry %p\n", V(hentry)));
    if (NULL == hentry) {
        return SKAGGBAG_E_ALLOC;
    }

    rv = skHeaderAddEntry(hdr, hentry);
    ABTRACE(("Result of adding hentry to header is %" SK_PRIdZ "\n", rv));
    if (rv) {
        aggBagHentryFree(hentry);
        return SKAGGBAG_E_ALLOC;
    }

    if (ab->options) {
        const sk_aggbag_options_t *opts = ab->options;
        if (opts->note_strip) {
            skHeaderRemoveAllMatching(hdr, SK_HENTRY_ANNOTATION_ID);
        }
        if (opts->invocation_strip) {
            skHeaderRemoveAllMatching(hdr, SK_HENTRY_INVOCATION_ID);
        } else if (opts->argc && opts->argv) {
            rv = skHeaderAddInvocation(hdr, 1, opts->argc, opts->argv);
            if (rv) {
                return SKAGGBAG_E_WRITE;
            }
        }
        if ((rv = skHeaderSetCompressionMethod(hdr, opts->comp_method))
            || (rv = skOptionsNotesAddToStream(stream)))
        {
            return SKAGGBAG_E_WRITE;
        }
    }

    /* write the file's header */
    ABTRACE(("Preparing to write header\n"));
    rv = skStreamWriteSilkHeader(stream);
    ABTRACE(("Result of writing header is %" SK_PRIdZ "\n", rv));
    if (rv) {
        return SKAGGBAG_E_WRITE;
    }

#if 0
    /* THIS BLOCK OF CODE WRITES THE FIELDS TO THE OUTPUT IN ORDER OF
     * THEIR FIELD IDS, LOWEST FIELD ID (e.g., sIPv4) FIRST. */
    sk_aggbag_field_t fields[AB_LAYOUT_BMAP_SIZE];
    sk_aggbag_field_t *f;
    uint8_t buffer[UINT16_MAX];
    uint8_t *b;

    /* determine the fields in numerical order */
    field_count = 0;
    for (i = 0; i < sizeof(ab->layout[0]->bitmap)/sizeof(uint32_t); ++i) {
        uint32_t merged;

        merged = ab->layout[0]->bitmap[i] | ab->layout[1]->bitmap[i];
        do {
            j = 1 + (i << 5);
            if ((merged & 0xffff) == 0) {
                merged >>= 16;
                j += 16;
            }
            if ((merged & 0xff) == 0) {
                merged >>= 8;
                j += 8;
            }
            if ((merged & 0xf) == 0) {
                merged >>= 4;
                j += 4;
            }
            if ((merged & 0x3) == 0) {
                merged >>= 2;
                j += 2;
            }
            j -= merged & 0x1;
            merged >>= 1;
            fields[field_count] = j;
            ++field_count;
        } while (merged);
    }

    ab_field_t fields[AB_LAYOUT_BMAP_SIZE];
    unsigned int field_count;
    ab_field_t *f;

    field_count = ab->layout[0]->field_count;
    memcpy(fields, ab->layout[0]->fields, field_count * sizeof(ab_field_t));

    memcpy(fields + field_count, ab->layout[1]->fields,
           ab->layout[1]->field_count * sizeof(ab_field_t));
    field_count += ab->layout[1]->field_count;

    ABTRACE(("Fields in unsorted order:\n"));
    for (i = 0, f = fields; i < ab->layout[0]->field_count; ++i, ++f) {
        const ab_type_info_t *info = aggBagGetTypeInfo(f->f_type);
        ABTRACEQ(("  %u  %3u  %3u  %s(%u)\n",
                  i, f->f_offset, f->f_len, info->ti_name, f->f_type));
    }
    for ( ; i < field_count; ++i, ++f) {
        const ab_type_info_t *info = aggBagGetTypeInfo(f->f_type);
        f->f_offset += ab->layout[0]->field_octets;
        ABTRACEQ(("  %u  %3u  %3u  %s(%u)\n",
                  i, f->f_offset, f->f_len, info->ti_name, f->f_type));
    }

    skQSort(fields, field_count, sizeof(ab_field_t), &abLayoutFieldSorter);

    ABTRACE(("Fields in sorted order:\n"));
    for (i = 0, f = fields; i < field_count; ++i, ++f) {
        const ab_type_info_t *info = aggBagGetTypeInfo(f->f_type);
        ABTRACEQ(("  %u  %3u  %3u  %s(%u)\n",
                  i, f->f_offset, f->f_len, info->ti_name, f->f_type));
    }

    /* create an iterator to visit the contents */
    ABTRACE(("Creating redblack iterator\n"));
    it = sk_rbtree_iter_create(ab);
    if (NULL == it) {
        ABTRACE(("Failure while creating redblack iterator\n"));
        return SKAGGBAG_E_ALLOC;
    }

    /* write keys and counters */
    ABTRACE(("Writing keys and counters...\n"));
    while ((data = (const uint8_t *)sk_rbtree_iter_next(it)) != NULL) {
        b = buffer;
        for (i = 0, f = fields; i < field_count; ++i, ++f) {
            memcpy(b, data + f->f_offset, f->f_len);
            b += f->f_len;
        }
        rv = skStreamWrite(stream, buffer, ab->data_len);
        if (rv != (ssize_t)ab->data_len) {
            sk_rbtree_iter_free(it);
            return SKAGGBAG_E_WRITE;
        }
    }
    ABTRACE(("Writing keys and counters...done.\n"));
    /* FROM HERE, SHOULD FLUSH STREAM AND RETURN.  DO NOT FALL INTO
     * THE CODE BELOW */
#endif  /* 0 */

    memset(zero_buf, 0, sizeof(zero_buf));

    /* create an iterator to visit the contents */
    ABTRACE(("Creating iterator to visit bag contents\n"));
    it = sk_rbtree_iter_create(ab);
    if (NULL == it) {
        ABTRACE(("Failure while creating iterator to visit bag contents\n"));
        return SKAGGBAG_E_ALLOC;
    }

    /* write keys and counters */
    ABTRACE(("Iterating over keys and counters...\n"));
    while ((data = (const uint8_t *)sk_rbtree_iter_next(it)) != NULL) {
        /* only print counters that are non-zero */
        if (0 != memcmp(zero_buf, data + ab->layout[0]->field_octets,
                        ab->layout[1]->field_octets))
        {
            rv = skStreamWrite(stream, data, ab->data_len);
            if (rv != (ssize_t)ab->data_len) {
                sk_rbtree_iter_free(it);
                return SKAGGBAG_E_WRITE;
            }
        }
    }

    ABTRACE(("Iterating over keys and counters...done.\n"));
    sk_rbtree_iter_free(it);

    ABTRACE(("Flushing stream and returning\n"));
    rv = skStreamFlush(stream);
    if (rv) {
        return SKAGGBAG_E_WRITE;
    }

    return SKAGGBAG_OK;
}


#if 0
/**
 *    Clear any memory that was allocated on 'key'.
 */
void
skAggBagClearKey(
    const sk_aggbag_t      *ab,
    sk_aggbag_aggregate_t  *key);

/**
 *    Initialize 'key_field_iter' to iterate over the fields that
 *    comprise the aggregate key in 'ab' and initialize
 *    'counter_field_iter' to iterate over the fields that comprise
 *    the aggregate counter in 'ab'.  Either 'key_field_iter' or
 *    'counter_field_iter' may be NULL.
 *
 *    After calling this function, a call to skAggBagFieldIterNext()
 *    on 'key_field_iter' or 'counter_field_iter' sets the iterator to
 *    first field in the key or the counter, respectively.
 *
 *    Take no action if 'ab' is NULL.
 */
void
skAggBagFieldItersBind(
    const sk_aggbag_t  *ab,
    sk_aggbag_field_t  *key_field_iter,
    sk_aggbag_field_t  *counter_field_iter);
#endif  /* 0 */


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
